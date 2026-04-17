using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Drawing;

namespace WmpfOffsetGenGui
{
    internal struct Section
    {
        public string Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
    }

    internal struct RuntimeFunction
    {
        public uint Begin;
        public uint End;
        public uint UnwindInfo;
    }

    internal struct ScoredLoadStart
    {
        public RuntimeFunction Function;
        public int[] SceneOffsets;
        public int Score;
    }

    internal sealed class GenerationResult
    {
        public int Version { get; set; }
        public uint LoadStartHookOffset { get; set; }
        public uint CdpFilterHookOffset { get; set; }
        public int[] SceneOffsets { get; set; }
        public string OutputPath { get; set; }
    }

    internal sealed class PEFile
    {
        private readonly byte[] _buffer;
        private readonly List<Section> _sections = new List<Section>();
        private readonly List<RuntimeFunction> _runtimeFunctions = new List<RuntimeFunction>();
        private readonly Section _textSection;

        public PEFile(byte[] buffer)
        {
            _buffer = buffer;

            ushort mz = ReadUInt16(0);
            if (mz != 0x5A4D)
            {
                throw new InvalidOperationException("Invalid PE file: MZ header missing");
            }

            uint peOffset = ReadUInt32(0x3C);
            if (ReadUInt32((int)peOffset) != 0x00004550)
            {
                throw new InvalidOperationException("Invalid PE file: PE signature missing");
            }

            int coffOffset = (int)peOffset + 4;
            ushort numberOfSections = ReadUInt16(coffOffset + 2);
            ushort sizeOfOptionalHeader = ReadUInt16(coffOffset + 16);
            int optionalHeaderOffset = coffOffset + 20;
            ushort magic = ReadUInt16(optionalHeaderOffset);
            if (magic != 0x20B)
            {
                throw new InvalidOperationException(
                    string.Format("Only PE32+ is supported, got magic 0x{0:X}", magic)
                );
            }

            int sectionOffset = optionalHeaderOffset + sizeOfOptionalHeader;
            for (int i = 0; i < numberOfSections; i++)
            {
                int off = sectionOffset + i * 40;
                Section section = new Section
                {
                    Name = ReadAscii(off, 8).TrimEnd('\0'),
                    VirtualSize = ReadUInt32(off + 8),
                    VirtualAddress = ReadUInt32(off + 12),
                    SizeOfRawData = ReadUInt32(off + 16),
                    PointerToRawData = ReadUInt32(off + 20),
                };
                _sections.Add(section);
            }

            Section? textSection = _sections.FirstOrDefault(s => s.Name == ".text");
            if (!textSection.HasValue)
            {
                throw new InvalidOperationException("PE parse failed: .text section not found");
            }

            _textSection = textSection.Value;

            int dataDirectoryOffset = optionalHeaderOffset + 112;
            uint exceptionDirRva = ReadUInt32(dataDirectoryOffset + 3 * 8);
            uint exceptionDirSize = ReadUInt32(dataDirectoryOffset + 3 * 8 + 4);
            _runtimeFunctions = ReadRuntimeFunctions(exceptionDirRva, exceptionDirSize);
        }

        public List<uint> FindAsciiRvas(string text)
        {
            byte[] needle = Encoding.ASCII.GetBytes(text);
            List<uint> result = new List<uint>();
            int cursor = 0;

            while (true)
            {
                int hit = IndexOf(_buffer, needle, cursor);
                if (hit < 0)
                {
                    break;
                }

                uint? rva = FileOffsetToRva((uint)hit);
                if (rva.HasValue)
                {
                    result.Add(rva.Value);
                }

                cursor = hit + 1;
            }

            return result;
        }

        public List<uint> ScanRipLeaRefs(uint targetRva)
        {
            List<uint> hits = new List<uint>();
            uint start = _textSection.PointerToRawData;
            uint end = _textSection.PointerToRawData + _textSection.SizeOfRawData;

            for (uint fileOffset = start; fileOffset + 7 < end; fileOffset++)
            {
                byte b0 = _buffer[fileOffset];
                byte b1 = _buffer[fileOffset + 1];
                byte b2 = _buffer[fileOffset + 2];
                int instructionLength = 0;
                uint displacementOffset = 0;

                if (b0 >= 0x40 && b0 <= 0x4F && b1 == 0x8D && (b2 & 0xC7) == 0x05)
                {
                    instructionLength = 7;
                    displacementOffset = fileOffset + 3;
                }
                else if (b0 == 0x8D && (b1 & 0xC7) == 0x05)
                {
                    instructionLength = 6;
                    displacementOffset = fileOffset + 2;
                }
                else
                {
                    continue;
                }

                uint? instructionRva = FileOffsetToRva(fileOffset);
                if (!instructionRva.HasValue)
                {
                    continue;
                }

                int displacement = ReadInt32((int)displacementOffset);
                uint nextRva = instructionRva.Value + (uint)instructionLength;
                uint resolvedRva = unchecked((uint)((int)nextRva + displacement));
                if (resolvedRva == targetRva)
                {
                    hits.Add(instructionRva.Value);
                }
            }

            return hits;
        }

        public RuntimeFunction? FindFunctionForRva(uint rva)
        {
            int low = 0;
            int high = _runtimeFunctions.Count - 1;
            while (low <= high)
            {
                int mid = (low + high) / 2;
                RuntimeFunction func = _runtimeFunctions[mid];
                if (rva < func.Begin)
                {
                    high = mid - 1;
                }
                else if (rva >= func.End)
                {
                    low = mid + 1;
                }
                else
                {
                    return func;
                }
            }
            return null;
        }

        public bool ContainsImm32(RuntimeFunction func, int value)
        {
            uint? start = RvaToFileOffset(func.Begin);
            uint? end = RvaToFileOffset(func.End);
            if (!start.HasValue || !end.HasValue || end.Value <= start.Value)
            {
                return false;
            }

            byte[] pattern = BitConverter.GetBytes(unchecked((uint)value));
            int max = (int)(end.Value - 4);
            for (int i = (int)start.Value; i <= max; i++)
            {
                if (_buffer[i] == pattern[0] &&
                    _buffer[i + 1] == pattern[1] &&
                    _buffer[i + 2] == pattern[2] &&
                    _buffer[i + 3] == pattern[3])
                {
                    return true;
                }
            }

            return false;
        }

        public List<Tuple<uint, uint>> ListCalls(RuntimeFunction func)
        {
            List<Tuple<uint, uint>> calls = new List<Tuple<uint, uint>>();
            uint? start = RvaToFileOffset(func.Begin);
            uint? end = RvaToFileOffset(func.End);
            if (!start.HasValue || !end.HasValue || end.Value <= start.Value)
            {
                return calls;
            }

            for (uint fileOffset = start.Value; fileOffset + 5 <= end.Value; fileOffset++)
            {
                if (_buffer[fileOffset] != 0xE8)
                {
                    continue;
                }

                uint? atRva = FileOffsetToRva(fileOffset);
                if (!atRva.HasValue)
                {
                    continue;
                }

                int disp = ReadInt32((int)(fileOffset + 1));
                uint target = unchecked((uint)((int)atRva.Value + 5 + disp));
                calls.Add(Tuple.Create(atRva.Value, target));
            }

            return calls;
        }

        private List<RuntimeFunction> ReadRuntimeFunctions(uint exceptionDirRva, uint exceptionDirSize)
        {
            List<RuntimeFunction> funcs = new List<RuntimeFunction>();
            if (exceptionDirRva == 0 || exceptionDirSize == 0)
            {
                return funcs;
            }

            uint? tableOffset = RvaToFileOffset(exceptionDirRva);
            if (!tableOffset.HasValue)
            {
                return funcs;
            }

            uint end = tableOffset.Value + exceptionDirSize;
            for (uint p = tableOffset.Value; p + 12 <= end; p += 12)
            {
                RuntimeFunction f = new RuntimeFunction
                {
                    Begin = ReadUInt32((int)p),
                    End = ReadUInt32((int)p + 4),
                    UnwindInfo = ReadUInt32((int)p + 8),
                };
                if (f.Begin == 0 && f.End == 0)
                {
                    continue;
                }
                funcs.Add(f);
            }

            funcs.Sort((a, b) => a.Begin.CompareTo(b.Begin));
            return funcs;
        }

        private uint? RvaToFileOffset(uint rva)
        {
            foreach (Section section in _sections)
            {
                uint start = section.VirtualAddress;
                uint end = section.VirtualAddress + Math.Max(section.VirtualSize, section.SizeOfRawData);
                if (rva >= start && rva < end)
                {
                    return section.PointerToRawData + (rva - section.VirtualAddress);
                }
            }
            return null;
        }

        private uint? FileOffsetToRva(uint fileOffset)
        {
            foreach (Section section in _sections)
            {
                uint start = section.PointerToRawData;
                uint end = section.PointerToRawData + section.SizeOfRawData;
                if (fileOffset >= start && fileOffset < end)
                {
                    return section.VirtualAddress + (fileOffset - section.PointerToRawData);
                }
            }
            return null;
        }

        private ushort ReadUInt16(int offset)
        {
            return BitConverter.ToUInt16(_buffer, offset);
        }

        private uint ReadUInt32(int offset)
        {
            return BitConverter.ToUInt32(_buffer, offset);
        }

        private int ReadInt32(int offset)
        {
            return BitConverter.ToInt32(_buffer, offset);
        }

        private string ReadAscii(int offset, int length)
        {
            return Encoding.ASCII.GetString(_buffer, offset, length);
        }

        private static int IndexOf(byte[] haystack, byte[] needle, int start)
        {
            if (needle.Length == 0)
            {
                return start <= haystack.Length ? start : -1;
            }

            int max = haystack.Length - needle.Length;
            for (int i = start; i <= max; i++)
            {
                bool matched = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j])
                    {
                        matched = false;
                        break;
                    }
                }

                if (matched)
                {
                    return i;
                }
            }
            return -1;
        }
    }

    internal sealed class OffsetGenerator
    {
        private const string MarkerCdp = "SendToClientFilter";
        private const string MarkerOnLoad = "OnLoadStart";
        private const string MarkerAppletFile = "applet_index_container.cc";

        public GenerationResult Generate(
            string inputPath,
            int? explicitVersion,
            string outputDir,
            string templateConfigDir,
            bool verbose,
            Action<string> log
        )
        {
            string runtimeDir = ResolveRuntimeDir(inputPath);
            string dllPath = Path.Combine(runtimeDir, "flue.dll");
            int version = InferVersionByPath(runtimeDir, explicitVersion);

            string finalOutputDir = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory);
            if (!string.IsNullOrWhiteSpace(outputDir))
            {
                log("[提示] 已忽略自定义输出目录，固定输出到工具目录: " + finalOutputDir);
            }

            Directory.CreateDirectory(finalOutputDir);

            string finalTemplateDir;
            if (!string.IsNullOrWhiteSpace(templateConfigDir))
            {
                finalTemplateDir = Path.GetFullPath(templateConfigDir);
            }
            else
            {
                string cwdConfigDir = Path.Combine(Environment.CurrentDirectory, "frida", "config");
                finalTemplateDir = Directory.Exists(cwdConfigDir)
                    ? cwdConfigDir
                    : finalOutputDir;
            }

            List<int[]> knownCombos = LoadKnownSceneOffsetCombos(finalTemplateDir);
            if (knownCombos.Count == 0)
            {
                knownCombos.Add(new[] { 1376, 1312, 456 });
            }

            PEFile pe = new PEFile(File.ReadAllBytes(dllPath));
            List<uint> cdpStringRvas = pe.FindAsciiRvas(MarkerCdp);
            List<uint> onLoadStringRvas = pe.FindAsciiRvas(MarkerOnLoad);
            List<uint> appletStringRvas = pe.FindAsciiRvas(MarkerAppletFile);

            if (cdpStringRvas.Count == 0 || onLoadStringRvas.Count == 0)
            {
                throw new InvalidOperationException("在 flue.dll 中未找到关键标记字符串");
            }

            List<RuntimeFunction> cdpRefFunctions = ResolveRefFunctions(pe, cdpStringRvas);
            List<RuntimeFunction> onLoadRefFunctions = ResolveRefFunctions(pe, onLoadStringRvas);
            List<RuntimeFunction> appletRefFunctions = ResolveRefFunctions(pe, appletStringRvas);

            uint cdpFilterHookOffset = PickCdpFilterHookOffset(pe, cdpRefFunctions);
            ScoredLoadStart loadStart = PickLoadStartHookAndSceneOffsets(
                pe,
                onLoadRefFunctions,
                appletRefFunctions,
                knownCombos
            );

            int[] sceneOffsets = loadStart.SceneOffsets ?? new[] { 1376, 1312, 456 };
            if (loadStart.SceneOffsets == null)
            {
                log("[警告] SceneOffsets 未高置信匹配，已回退到 [1376,1312,456]");
            }

            if (verbose)
            {
                log("[调试] runtime目录: " + runtimeDir);
                log("[调试] 版本号: " + version);
                log("[调试] 模板配置目录: " + finalTemplateDir);
                log("[调试] 已知 SceneOffsets 组合: " + string.Join(" | ", knownCombos.Select(c => "[" + string.Join(",", c) + "]")));
                log("[调试] 标记 RVA (" + MarkerCdp + "): " + string.Join(", ", cdpStringRvas.Select(ToHex)));
                log("[调试] 标记 RVA (" + MarkerOnLoad + "): " + string.Join(", ", onLoadStringRvas.Select(ToHex)));
                log("[调试] 标记 RVA (" + MarkerAppletFile + "): " + string.Join(", ", appletStringRvas.Select(ToHex)));
            }

            string outputPath = Path.Combine(finalOutputDir, string.Format("addresses.{0}.json", version));
            string json = BuildOutputJson(version, loadStart.Function.Begin, cdpFilterHookOffset, sceneOffsets);
            File.WriteAllText(outputPath, json, new UTF8Encoding(false));

            return new GenerationResult
            {
                Version = version,
                LoadStartHookOffset = loadStart.Function.Begin,
                CdpFilterHookOffset = cdpFilterHookOffset,
                SceneOffsets = sceneOffsets,
                OutputPath = outputPath,
            };
        }

        private static List<RuntimeFunction> ResolveRefFunctions(PEFile pe, List<uint> stringRvas)
        {
            List<RuntimeFunction> list = new List<RuntimeFunction>();
            foreach (uint rva in stringRvas)
            {
                List<uint> refs = pe.ScanRipLeaRefs(rva);
                foreach (uint refRva in refs)
                {
                    RuntimeFunction? func = pe.FindFunctionForRva(refRva);
                    if (func.HasValue)
                    {
                        list.Add(func.Value);
                    }
                }
            }
            return list;
        }

        private static uint PickCdpFilterHookOffset(PEFile pe, List<RuntimeFunction> cdpRefFunctions)
        {
            List<RuntimeFunction> candidates = UniqueFunctions(cdpRefFunctions);
            if (candidates.Count == 0)
            {
                throw new InvalidOperationException("未找到引用 SendToClientFilter 的候选函数");
            }

            int bestScore = int.MinValue;
            uint bestTarget = 0;
            bool found = false;

            foreach (RuntimeFunction func in candidates)
            {
                List<Tuple<uint, uint>> calls = pe.ListCalls(func);
                if (calls.Count == 0)
                {
                    continue;
                }

                Tuple<uint, uint> first = calls[0];
                RuntimeFunction? targetFunc = pe.FindFunctionForRva(first.Item2);
                int score = 0;
                if (targetFunc.HasValue)
                {
                    score += 3;
                }
                uint delta = first.Item1 - func.Begin;
                if (delta < 0x100)
                {
                    score += 2;
                }
                score += Math.Max(0, 100 - (int)delta);

                if (!found || score > bestScore)
                {
                    found = true;
                    bestScore = score;
                    bestTarget = first.Item2;
                }
            }

            if (!found)
            {
                throw new InvalidOperationException("未找到 CDPFilterHookOffset");
            }
            return bestTarget;
        }

        private static ScoredLoadStart PickLoadStartHookAndSceneOffsets(
            PEFile pe,
            List<RuntimeFunction> onLoadRefFunctions,
            List<RuntimeFunction> appletRefFunctions,
            List<int[]> knownCombos
        )
        {
            List<RuntimeFunction> candidates = UniqueFunctions(onLoadRefFunctions);
            if (candidates.Count == 0)
            {
                throw new InvalidOperationException("未找到引用 OnLoadStart 的候选函数");
            }

            HashSet<uint> appletBegins = new HashSet<uint>(appletRefFunctions.Select(f => f.Begin));
            bool found = false;
            ScoredLoadStart best = new ScoredLoadStart { Score = int.MinValue };

            foreach (RuntimeFunction func in candidates)
            {
                int score = 0;
                if (appletBegins.Contains(func.Begin))
                {
                    score += 2;
                }

                uint size = func.End - func.Begin;
                if (size >= 200 && size <= 3000)
                {
                    score += 1;
                }

                List<Tuple<uint, uint>> calls = pe.ListCalls(func);
                List<RuntimeFunction> calledFunctions = new List<RuntimeFunction>();
                foreach (Tuple<uint, uint> call in calls)
                {
                    RuntimeFunction? called = pe.FindFunctionForRva(call.Item2);
                    if (called.HasValue)
                    {
                        calledFunctions.Add(called.Value);
                    }
                }

                int[] selected = null;
                foreach (int[] combo in knownCombos)
                {
                    int s0 = combo[0];
                    int s1 = combo[1];
                    int s2 = combo[2];
                    if (!pe.ContainsImm32(func, s0))
                    {
                        continue;
                    }

                    bool sceneMatch = calledFunctions.Any(cf => pe.ContainsImm32(cf, s1) && pe.ContainsImm32(cf, s2));
                    if (!sceneMatch)
                    {
                        continue;
                    }

                    selected = new[] { s0, s1, s2 };
                    score += 20;
                    break;
                }

                if (selected == null)
                {
                    HashSet<int> knownFirsts = new HashSet<int>(knownCombos.Select(c => c[0]));
                    foreach (int v in knownFirsts)
                    {
                        if (pe.ContainsImm32(func, v))
                        {
                            score += 1;
                            break;
                        }
                    }
                }

                ScoredLoadStart current = new ScoredLoadStart
                {
                    Function = func,
                    SceneOffsets = selected,
                    Score = score,
                };

                if (!found || current.Score > best.Score)
                {
                    found = true;
                    best = current;
                }
            }

            if (!found)
            {
                throw new InvalidOperationException("未找到 LoadStartHookOffset");
            }

            return best;
        }

        private static string ResolveRuntimeDir(string inputPath)
        {
            if (string.IsNullOrWhiteSpace(inputPath))
            {
                throw new InvalidOperationException("输入路径不能为空");
            }

            string full = Path.GetFullPath(inputPath.Trim().Trim('"'));
            if (File.Exists(full))
            {
                if (!string.Equals(Path.GetFileName(full), "flue.dll", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("如果输入的是文件，必须是 flue.dll");
                }
                return Path.GetDirectoryName(full);
            }

            if (!Directory.Exists(full))
            {
                throw new InvalidOperationException("输入路径不存在: " + full);
            }

            string direct = Path.Combine(full, "flue.dll");
            if (File.Exists(direct))
            {
                return full;
            }

            string runtime = Path.Combine(full, "runtime", "flue.dll");
            if (File.Exists(runtime))
            {
                return Path.Combine(full, "runtime");
            }

            string extractedRuntime = Path.Combine(full, "extracted", "runtime", "flue.dll");
            if (File.Exists(extractedRuntime))
            {
                return Path.Combine(full, "extracted", "runtime");
            }

            throw new InvalidOperationException(
                "未找到 flue.dll。请选择以下之一：195xx 目录 / extracted 目录 / runtime 目录 / flue.dll"
            );
        }

        private static int InferVersionByPath(string runtimeDir, int? explicitVersion)
        {
            if (explicitVersion.HasValue && explicitVersion.Value > 0)
            {
                return explicitVersion.Value;
            }

            MatchCollection matches = Regex.Matches(runtimeDir, @"\d+");
            List<int> candidates = new List<int>();
            foreach (Match m in matches)
            {
                int v;
                if (int.TryParse(m.Value, out v) && v >= 10000)
                {
                    candidates.Add(v);
                }
            }

            if (candidates.Count == 0)
            {
                throw new InvalidOperationException("无法从路径推断版本号，请手动填写版本号");
            }

            return candidates[candidates.Count - 1];
        }

        private static List<int[]> LoadKnownSceneOffsetCombos(string configDir)
        {
            List<int[]> combos = new List<int[]>();
            HashSet<string> uniq = new HashSet<string>(StringComparer.Ordinal);
            if (string.IsNullOrWhiteSpace(configDir) || !Directory.Exists(configDir))
            {
                return combos;
            }

            Regex fileRegex = new Regex(@"^addresses\.\d+\.json$", RegexOptions.IgnoreCase);
            Regex sceneRegex = new Regex(
                "\"SceneOffsets\"\\s*:\\s*\\[\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)\\s*\\]",
                RegexOptions.Singleline
            );

            foreach (string file in Directory.GetFiles(configDir, "addresses.*.json"))
            {
                string name = Path.GetFileName(file);
                if (!fileRegex.IsMatch(name))
                {
                    continue;
                }

                string content;
                try
                {
                    content = File.ReadAllText(file);
                }
                catch
                {
                    continue;
                }

                Match m = sceneRegex.Match(content);
                if (!m.Success)
                {
                    continue;
                }

                int a, b, c;
                if (!int.TryParse(m.Groups[1].Value, out a) ||
                    !int.TryParse(m.Groups[2].Value, out b) ||
                    !int.TryParse(m.Groups[3].Value, out c))
                {
                    continue;
                }

                string key = string.Format("{0},{1},{2}", a, b, c);
                if (uniq.Add(key))
                {
                    combos.Add(new[] { a, b, c });
                }
            }

            return combos;
        }

        private static List<RuntimeFunction> UniqueFunctions(List<RuntimeFunction> input)
        {
            Dictionary<uint, RuntimeFunction> map = new Dictionary<uint, RuntimeFunction>();
            foreach (RuntimeFunction f in input)
            {
                map[f.Begin] = f;
            }
            return map.Values.OrderBy(v => v.Begin).ToList();
        }

        private static string BuildOutputJson(int version, uint loadStart, uint cdp, int[] sceneOffsets)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendFormat("    \"Version\": {0},\n", version);
            sb.AppendFormat("    \"LoadStartHookOffset\": \"{0}\",\n", ToHex(loadStart));
            sb.AppendFormat("    \"CDPFilterHookOffset\": \"{0}\",\n", ToHex(cdp));
            sb.AppendFormat("    \"SceneOffsets\": [{0}, {1}, {2}]\n", sceneOffsets[0], sceneOffsets[1], sceneOffsets[2]);
            sb.AppendLine("}");
            return sb.ToString();
        }

        private static string ToHex(uint value)
        {
            return string.Format("0x{0:X}", value);
        }
    }

    internal sealed class MainForm : Form
    {
        private readonly TextBox _txtInput = new TextBox();
        private readonly TextBox _txtVersion = new TextBox();
        private readonly TextBox _txtOutput = new TextBox();
        private readonly TextBox _txtTemplate = new TextBox();
        private readonly CheckBox _chkVerbose = new CheckBox();
        private readonly Button _btnGenerate = new Button();
        private readonly RichTextBox _log = new RichTextBox();

        public MainForm()
        {
            Text = "WMPF 偏移量生成工具";
            Width = 980;
            Height = 720;
            StartPosition = FormStartPosition.CenterScreen;
            AllowDrop = true;

            DragEnter += OnDragEnter;
            DragDrop += OnDragDrop;

            TableLayoutPanel layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 4,
                RowCount = 8,
                Padding = new Padding(10),
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
            for (int i = 0; i < 7; i++)
            {
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            }
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            Label lblHint = new Label
            {
                Text = "可将 195xx/extracted/runtime/flue.dll 拖入窗口，或在下方手动选择路径。",
                AutoSize = true,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
            };
            layout.Controls.Add(lblHint, 0, 0);
            layout.SetColumnSpan(lblHint, 4);

            AddPathRow(layout, 1, "输入路径", _txtInput, OnBrowseInputClick);
            AddPathRow(layout, 2, "输出目录（固定为工具目录）", _txtOutput, OnBrowseOutputClick);
            AddPathRow(layout, 3, "模板配置目录（可选）", _txtTemplate, OnBrowseTemplateClick);
            _txtOutput.Text = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory);
            _txtOutput.ReadOnly = true;

            Label lblVersion = new Label
            {
                Text = "版本号（可选）",
                AutoSize = true,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
            };
            layout.Controls.Add(lblVersion, 0, 4);
            _txtVersion.Dock = DockStyle.Fill;
            layout.Controls.Add(_txtVersion, 1, 4);

            _chkVerbose.Text = "详细日志";
            _chkVerbose.AutoSize = true;
            _chkVerbose.Dock = DockStyle.Fill;
            layout.Controls.Add(_chkVerbose, 2, 4);

            _btnGenerate.Text = "生成 JSON";
            _btnGenerate.Dock = DockStyle.Fill;
            _btnGenerate.Click += OnGenerateClick;
            layout.Controls.Add(_btnGenerate, 3, 4);

            _log.Dock = DockStyle.Fill;
            _log.ReadOnly = true;
            _log.Font = new Font("Consolas", 10f);
            layout.Controls.Add(_log, 0, 7);
            layout.SetColumnSpan(_log, 4);

            Controls.Add(layout);
        }

        private void AddPathRow(
            TableLayoutPanel layout,
            int row,
            string labelText,
            TextBox textBox,
            EventHandler browseHandler
        )
        {
            Label label = new Label
            {
                Text = labelText,
                AutoSize = true,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
            };
            layout.Controls.Add(label, 0, row);

            textBox.Dock = DockStyle.Fill;
            layout.Controls.Add(textBox, 1, row);

            Button browse = new Button
            {
                Text = "浏览...",
                Dock = DockStyle.Fill,
            };
            browse.Click += browseHandler;
            layout.Controls.Add(browse, 2, row);
            layout.SetColumnSpan(browse, 2);
        }

        private void OnDragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy;
            }
        }

        private void OnDragDrop(object sender, DragEventArgs e)
        {
            string[] paths = e.Data.GetData(DataFormats.FileDrop) as string[];
            if (paths != null && paths.Length > 0)
            {
                _txtInput.Text = paths[0];
                AppendLog("[界面] 已通过拖拽设置输入路径: " + paths[0]);
            }
        }

        private void OnBrowseInputClick(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dlg = new FolderBrowserDialog())
            {
                dlg.Description = "选择 195xx / extracted / runtime 目录";
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    _txtInput.Text = dlg.SelectedPath;
                }
            }
        }

        private void OnBrowseOutputClick(object sender, EventArgs e)
        {
            MessageBox.Show(this, "输出目录固定为工具运行目录，无法修改。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void OnBrowseTemplateClick(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dlg = new FolderBrowserDialog())
            {
                dlg.Description = "选择模板配置目录（包含 addresses.*.json）";
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    _txtTemplate.Text = dlg.SelectedPath;
                }
            }
        }

        private async void OnGenerateClick(object sender, EventArgs e)
        {
            _btnGenerate.Enabled = false;
            _log.Clear();
            AppendLog("[开始] 正在生成...");

            try
            {
                string input = _txtInput.Text.Trim();
                int parsedVersion;
                int? version = int.TryParse(_txtVersion.Text.Trim(), out parsedVersion)
                    ? (int?)parsedVersion
                    : null;

                string output = _txtOutput.Text.Trim();
                string template = _txtTemplate.Text.Trim();
                bool verbose = _chkVerbose.Checked;

                OffsetGenerator generator = new OffsetGenerator();
                GenerationResult result = await Task.Run(() =>
                    generator.Generate(input, version, output, template, verbose, AppendLogFromWorker)
                );

                AppendLog("[完成] 已生成: " + result.OutputPath);
                AppendLog("{");
                AppendLog("  \"Version\": " + result.Version + ",");
                AppendLog("  \"LoadStartHookOffset\": \"" + ToHex(result.LoadStartHookOffset) + "\",");
                AppendLog("  \"CDPFilterHookOffset\": \"" + ToHex(result.CdpFilterHookOffset) + "\",");
                AppendLog("  \"SceneOffsets\": [" + string.Join(", ", result.SceneOffsets) + "]");
                AppendLog("}");
                MessageBox.Show(this, "已生成文件：\n" + result.OutputPath, "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                AppendLog("[错误] " + ex.Message);
                MessageBox.Show(this, ex.Message, "生成失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                _btnGenerate.Enabled = true;
            }
        }

        private void AppendLogFromWorker(string message)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action<string>(AppendLog), message);
            }
            else
            {
                AppendLog(message);
            }
        }

        private void AppendLog(string message)
        {
            _log.AppendText(message + Environment.NewLine);
            _log.SelectionStart = _log.TextLength;
            _log.ScrollToCaret();
        }

        private static string ToHex(uint value)
        {
            return string.Format("0x{0:X}", value);
        }
    }

    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            // CLI 模式（用于测试/自动化）:
            // WMPFOffsetGen.GUI.exe --cli --input <path> [--version 195xx] [--output-dir <dir>] [--template-config-dir <dir>] [--verbose]
            if (args.Contains("--cli"))
            {
                return RunCli(args);
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            return 0;
        }

        private static int RunCli(string[] args)
        {
            string input = GetArgValue(args, "--input");
            if (string.IsNullOrWhiteSpace(input))
            {
                Console.Error.WriteLine("缺少参数 --input");
                return 2;
            }

            int versionValue;
            int? version = int.TryParse(GetArgValue(args, "--version"), out versionValue)
                ? (int?)versionValue
                : null;
            string outputDir = GetArgValue(args, "--output-dir");
            string templateDir = GetArgValue(args, "--template-config-dir");
            bool verbose = args.Contains("--verbose");

            try
            {
                OffsetGenerator generator = new OffsetGenerator();
                GenerationResult result = generator.Generate(
                    input,
                    version,
                    outputDir,
                    templateDir,
                    verbose,
                    msg => Console.WriteLine(msg)
                );

                Console.WriteLine("[完成] 已生成: " + result.OutputPath);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[错误] " + ex.Message);
                return 1;
            }
        }

        private static string GetArgValue(string[] args, string key)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], key, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    return args[i + 1];
                }
            }
            return null;
        }
    }
}
