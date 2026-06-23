using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Drawing;
using System.Reflection;

[assembly: AssemblyTitle("WMPFOffsetGen.GUI")]
[assembly: AssemblyDescription("WMPF offset generator for WMPFDebugger")]
[assembly: AssemblyCompany("flagqaz")]
[assembly: AssemblyProduct("WMPFOffsetGen.GUI")]
[assembly: AssemblyVersion("1.1.0.0")]
[assembly: AssemblyFileVersion("1.1.0.0")]
[assembly: AssemblyInformationalVersion("1.1")]

namespace WmpfOffsetGenGui
{
    internal static class ToolInfo
    {
        public const string Version = "1.1";
    }

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

                int stringStart = hit;
                while (stringStart > 0 && _buffer[stringStart - 1] != 0)
                {
                    stringStart--;
                }

                uint? rva = FileOffsetToRva((uint)stringStart);
                if (rva.HasValue)
                {
                    if (!result.Contains(rva.Value))
                    {
                        result.Add(rva.Value);
                    }
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

        public List<int> FindAlignedImm32Values(RuntimeFunction func, int minValue, int maxValue)
        {
            HashSet<int> values = new HashSet<int>();
            uint? start = RvaToFileOffset(func.Begin);
            uint? end = RvaToFileOffset(func.End);
            if (!start.HasValue || !end.HasValue || end.Value <= start.Value)
            {
                return values.ToList();
            }

            int max = (int)(end.Value - 4);
            for (int i = (int)start.Value; i <= max; i++)
            {
                int value = ReadInt32(i);
                if (value >= minValue && value <= maxValue && value % 8 == 0)
                {
                    values.Add(value);
                }
            }

            return values.OrderBy(v => v).ToList();
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
        private const int BuiltInSceneOffsetCount = 6;

        private static List<int[]> CreateBuiltInSceneOffsetCombos()
        {
            return new List<int[]>
            {
                new[] { 56, 1208, 8, 1160, 16, 488 },
                new[] { 56, 1272, 8, 1224, 16, 488 },
                new[] { 56, 1280, 8, 1232, 16, 488 },
                new[] { 56, 1360, 8, 1312, 16, 488 },
                new[] { 56, 1416, 8, 1360, 16, 488 },
                new[] { 56, 1408, 8, 1352, 16, 488 },
                new[] { 56, 1416, 8, 1352, 16, 488 },
                new[] { 56, 1408, 8, 1344, 16, 488 },
                new[] { 56, 1376, 8, 1312, 16, 456 },
                new[] { 64, 1408, 8, 1344, 16, 456 },
                new[] { 64, 1472, 8, 1408, 16, 456 },
                new[] { 64, 1480, 8, 1416, 16, 456 },
            };
        }

        public GenerationResult Generate(
            string inputPath,
            int? explicitVersion,
            string debuggerProjectPath,
            bool verbose,
            Action<string> log
        )
        {
            string runtimeDir = ResolveRuntimeDir(inputPath);
            string dllPath = Path.Combine(runtimeDir, "flue.dll");
            int version = InferVersionByPath(runtimeDir, explicitVersion);

            string finalOutputDir = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory);
            Directory.CreateDirectory(finalOutputDir);

            string debuggerRoot = null;
            string finalTemplateDir = null;
            int requiredSceneOffsetCount = BuiltInSceneOffsetCount;
            List<int[]> knownCombos = CreateBuiltInSceneOffsetCombos();

            if (!string.IsNullOrWhiteSpace(debuggerProjectPath))
            {
                debuggerRoot = ResolveDebuggerProjectDir(debuggerProjectPath);
                string hookPath = Path.Combine(debuggerRoot, "frida", "hook.js");
                finalTemplateDir = Path.Combine(debuggerRoot, "frida", "config");
                requiredSceneOffsetCount = ValidateHookScript(hookPath);
                MergeSceneOffsetCombos(knownCombos, LoadKnownSceneOffsetCombos(finalTemplateDir));
                log("[模式] 双目录模式：已读取用户提供的 WMPFDebugger");
            }
            else
            {
                log("[模式] 单目录模式：未提供 WMPFDebugger，使用内置 Hook 规则和历史结构样本");
                log("[建议] 推荐同时选择 WMPFDebugger 项目目录，以校验实际 hook.js 和历史配置");
            }

            if (requiredSceneOffsetCount != 6)
            {
                throw new InvalidOperationException(
                    string.Format(
                        "当前生成器只支持 6 项 SceneOffsets，但所选 WMPFDebugger 的 hook.js 需要 {0} 项",
                        requiredSceneOffsetCount
                    )
                );
            }

            if (knownCombos.Count == 0)
            {
                throw new InvalidOperationException(
                    "没有可用的 6 项 SceneOffsets 历史结构样本"
                );
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

            if (loadStart.SceneOffsets == null || loadStart.SceneOffsets.Length != requiredSceneOffsetCount)
            {
                throw new InvalidOperationException(
                    "无法高置信识别 SceneOffsets，已停止生成。请更新分析规则或人工核验该 WMPF 版本"
                );
            }
            int[] sceneOffsets = loadStart.SceneOffsets;

            if (verbose)
            {
                log("[调试] runtime目录: " + runtimeDir);
                log("[调试] 版本号: " + version);
                log("[调试] WMPFDebugger目录: " + (debuggerRoot ?? "未提供（内置模式）"));
                log("[调试] hook.js要求 SceneOffsets 项数: " + requiredSceneOffsetCount);
                log("[调试] 历史配置目录: " + (finalTemplateDir ?? "生成器内置样本"));
                log("[调试] 已知 SceneOffsets 组合: " + string.Join(" | ", knownCombos.Select(c => "[" + string.Join(",", c) + "]")));
                log("[调试] 标记 RVA (" + MarkerCdp + "): " + string.Join(", ", cdpStringRvas.Select(ToHex)));
                log("[调试] 标记 RVA (" + MarkerOnLoad + "): " + string.Join(", ", onLoadStringRvas.Select(ToHex)));
                log("[调试] 标记 RVA (" + MarkerAppletFile + "): " + string.Join(", ", appletStringRvas.Select(ToHex)));
            }

            string outputPath = Path.Combine(finalOutputDir, string.Format("addresses.{0}.json", version));
            string json = BuildOutputJson(version, loadStart.Function.Begin, cdpFilterHookOffset, sceneOffsets);
            File.WriteAllText(outputPath, json, new UTF8Encoding(false));
            log("[校验] 所有关键特征均已确认，结果保存到生成器运行目录");

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
                if (!targetFunc.HasValue || targetFunc.Value.Begin != first.Item2)
                {
                    continue;
                }

                int score = 0;
                score += 3;
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
                    if (combo.Length != 6)
                    {
                        continue;
                    }

                    int s0 = combo[1];
                    int s1 = combo[3];
                    int s2 = combo[5];
                    if (!pe.ContainsImm32(func, s0))
                    {
                        continue;
                    }

                    bool sceneMatch = calledFunctions.Any(cf => pe.ContainsImm32(cf, s1) && pe.ContainsImm32(cf, s2));
                    if (!sceneMatch)
                    {
                        continue;
                    }

                    selected = combo.ToArray();
                    score += 20;
                    break;
                }

                if (selected == null)
                {
                    List<int> callerValues = pe.FindAlignedImm32Values(func, 1000, 1800);
                    foreach (RuntimeFunction called in calledFunctions)
                    {
                        if (!pe.ContainsImm32(called, 1101))
                        {
                            continue;
                        }

                        List<int> calledValues = pe.FindAlignedImm32Values(called, 1000, 1800);
                        int sceneValue = pe.ContainsImm32(called, 456)
                            ? 456
                            : pe.ContainsImm32(called, 488) ? 488 : 0;
                        if (sceneValue == 0)
                        {
                            continue;
                        }

                        var pair = (
                            from outer in callerValues
                            from inner in calledValues
                            let delta = outer - inner
                            where delta >= 48 && delta <= 80
                            orderby Math.Abs(delta - 64)
                            select new { Outer = outer, Inner = inner }
                        ).FirstOrDefault();

                        if (pair == null)
                        {
                            continue;
                        }

                        int[] nearest = knownCombos
                            .Where(c => c.Length == 6)
                            .OrderBy(c => Math.Abs(c[1] - pair.Outer) + Math.Abs(c[3] - pair.Inner))
                            .FirstOrDefault();
                        selected = new[]
                        {
                            nearest != null ? nearest[0] : 64,
                            pair.Outer,
                            nearest != null ? nearest[2] : 8,
                            pair.Inner,
                            nearest != null ? nearest[4] : 16,
                            sceneValue,
                        };
                        score += 30;
                        break;
                    }
                }

                if (selected == null)
                {
                    HashSet<int> knownFirsts = new HashSet<int>(
                        knownCombos.Where(c => c.Length == 6).Select(c => c[1])
                    );
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

        private static string ResolveDebuggerProjectDir(string inputPath)
        {
            if (string.IsNullOrWhiteSpace(inputPath))
            {
                throw new InvalidOperationException("请选择 WMPFDebugger 项目目录");
            }

            string full = Path.GetFullPath(inputPath.Trim().Trim('"'));
            if (!Directory.Exists(full))
            {
                throw new InvalidOperationException("WMPFDebugger 目录不存在: " + full);
            }

            string hookPath = Path.Combine(full, "frida", "hook.js");
            string configDir = Path.Combine(full, "frida", "config");
            if (!File.Exists(hookPath) || !Directory.Exists(configDir))
            {
                throw new InvalidOperationException(
                    "所选目录不是有效的 WMPFDebugger 项目，必须包含 frida/hook.js 和 frida/config"
                );
            }

            return full;
        }

        private static int ValidateHookScript(string hookPath)
        {
            string content = File.ReadAllText(hookPath);
            if (!content.Contains("LoadStartHookOffset") ||
                !content.Contains("CDPFilterHookOffset") ||
                !content.Contains("SceneOffsets"))
            {
                throw new InvalidOperationException(
                    "WMPFDebugger 的 frida/hook.js 缺少必要配置字段"
                );
            }

            MatchCollection matches = Regex.Matches(
                content,
                @"sceneOffsets\s*\[\s*(\d+)\s*\]",
                RegexOptions.IgnoreCase
            );
            HashSet<int> indexes = new HashSet<int>();
            foreach (Match match in matches)
            {
                int index;
                if (int.TryParse(match.Groups[1].Value, out index))
                {
                    indexes.Add(index);
                }
            }

            if (indexes.Count == 0)
            {
                throw new InvalidOperationException(
                    "无法从 WMPFDebugger 的 frida/hook.js 识别 SceneOffsets 访问方式"
                );
            }

            int max = indexes.Max();
            for (int i = 0; i <= max; i++)
            {
                if (!indexes.Contains(i))
                {
                    throw new InvalidOperationException(
                        "frida/hook.js 中的 SceneOffsets 索引不连续，无法安全生成配置"
                    );
                }
            }

            return max + 1;
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
                "\"SceneOffsets\"\\s*:\\s*\\[\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)\\s*\\]",
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

                int a, b, c, d, e, f;
                if (!int.TryParse(m.Groups[1].Value, out a) ||
                    !int.TryParse(m.Groups[2].Value, out b) ||
                    !int.TryParse(m.Groups[3].Value, out c) ||
                    !int.TryParse(m.Groups[4].Value, out d) ||
                    !int.TryParse(m.Groups[5].Value, out e) ||
                    !int.TryParse(m.Groups[6].Value, out f))
                {
                    continue;
                }

                string key = string.Format("{0},{1},{2},{3},{4},{5}", a, b, c, d, e, f);
                if (uniq.Add(key))
                {
                    combos.Add(new[] { a, b, c, d, e, f });
                }
            }

            return combos;
        }

        private static void MergeSceneOffsetCombos(List<int[]> target, List<int[]> source)
        {
            HashSet<string> known = new HashSet<string>(
                target.Select(c => string.Join(",", c)),
                StringComparer.Ordinal
            );
            foreach (int[] combo in source)
            {
                if (combo != null && combo.Length == 6 && known.Add(string.Join(",", combo)))
                {
                    target.Add(combo);
                }
            }
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
            if (sceneOffsets == null || sceneOffsets.Length != 6)
            {
                throw new InvalidOperationException("SceneOffsets 必须包含 6 个偏移值");
            }

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendFormat("    \"Version\": {0},\n", version);
            sb.AppendFormat("    \"LoadStartHookOffset\": \"{0}\",\n", ToHex(loadStart));
            sb.AppendFormat("    \"CDPFilterHookOffset\": \"{0}\",\n", ToHex(cdp));
            sb.AppendFormat(
                "    \"SceneOffsets\": [{0}, {1}, {2}, {3}, {4}, {5}]\n",
                sceneOffsets[0],
                sceneOffsets[1],
                sceneOffsets[2],
                sceneOffsets[3],
                sceneOffsets[4],
                sceneOffsets[5]
            );
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
        private readonly TextBox _txtDebugger = new TextBox();
        private readonly CheckBox _chkVerbose = new CheckBox();
        private readonly Button _btnGenerate = new Button();
        private readonly RichTextBox _log = new RichTextBox();

        public MainForm()
        {
            Text = "WMPF 偏移量生成工具 v" + ToolInfo.Version;
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
                Text = @"输入或拖拽 WMPF 目录 C:\Users\%当前用户%\AppData\Roaming\Tencent\xwechat\xplugin\Plugins\RadiumWMP\；推荐同时选择 WMPFDebugger。",
                AutoSize = true,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
            };
            layout.Controls.Add(lblHint, 0, 0);
            layout.SetColumnSpan(lblHint, 4);

            AddPathRow(layout, 1, "微信 WMPF 目录", _txtInput, OnBrowseInputClick);
            AddPathRow(layout, 2, "WMPFDebugger（推荐）", _txtDebugger, OnBrowseDebuggerClick);
            AddPathRow(layout, 3, "输出目录（工具运行目录）", _txtOutput, OnBrowseOutputClick);
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
                foreach (string path in paths)
                {
                    string full = Path.GetFullPath(path);
                    bool isDebugger = Directory.Exists(full) &&
                        File.Exists(Path.Combine(full, "frida", "hook.js")) &&
                        Directory.Exists(Path.Combine(full, "frida", "config"));
                    if (isDebugger)
                    {
                        _txtDebugger.Text = full;
                        AppendLog("[界面] 已识别 WMPFDebugger 目录: " + full);
                    }
                    else
                    {
                        _txtInput.Text = full;
                        AppendLog("[界面] 已设置微信 WMPF 路径: " + full);
                    }
                }
            }
        }

        private void OnBrowseInputClick(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dlg = new FolderBrowserDialog())
            {
                dlg.Description = "选择 WMPF 版本目录、extracted 目录或 runtime 目录";
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

        private void OnBrowseDebuggerClick(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dlg = new FolderBrowserDialog())
            {
                dlg.Description = "选择 WMPFDebugger 项目根目录（包含 frida/hook.js）";
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    _txtDebugger.Text = dlg.SelectedPath;
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

                string debuggerProject = _txtDebugger.Text.Trim();
                bool verbose = _chkVerbose.Checked;

                OffsetGenerator generator = new OffsetGenerator();
                GenerationResult result = await Task.Run(() =>
                    generator.Generate(input, version, debuggerProject, verbose, AppendLogFromWorker)
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
            // WMPFOffsetGen.GUI.v1.1.exe --cli --input <path> [--debugger <WMPFDebugger目录>] [--version 20001] [--verbose]
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

            string debuggerProject = GetArgValue(args, "--debugger");

            int versionValue;
            int? version = int.TryParse(GetArgValue(args, "--version"), out versionValue)
                ? (int?)versionValue
                : null;
            bool verbose = args.Contains("--verbose");

            try
            {
                OffsetGenerator generator = new OffsetGenerator();
                GenerationResult result = generator.Generate(
                    input,
                    version,
                    debuggerProject,
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
