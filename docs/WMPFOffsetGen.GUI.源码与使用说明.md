# WMPFOffsetGen.GUI v1.1 源码与使用说明

## 工作流程

工具至少需要一个输入目录：

1. 微信 WMPF 目录，用于读取 `extracted/runtime/flue.dll`。
2. 可选的 WMPFDebugger 项目根目录，用于读取：
   - `frida/hook.js`
   - `frida/config/addresses.*.json`

输出文件固定写入 `AppDomain.CurrentDomain.BaseDirectory`，即生成器 EXE 的运行目录。

## 单目录模式

未提供 WMPFDebugger 时，工具使用内置的：

- 6 项 `SceneOffsets` Hook 结构。
- 多个历史版本的结构样本。
- `OnLoadStart`、scene `1101` 和 `SendToClientFilter` 严格识别规则。

内置模式仍对当前 `flue.dll` 进行完整分析，不会直接复制历史 JSON。

## WMPFDebugger 兼容性分析（推荐）

提供 WMPFDebugger 后，工具验证项目根目录必须包含：

```text
frida/hook.js
frida/config
```

随后检查 `hook.js` 是否使用：

```text
LoadStartHookOffset
CDPFilterHookOffset
SceneOffsets
```

工具通过正则提取所有 `sceneOffsets[n]` 索引，要求索引从 `0` 连续排列。当前 v1.1 支持 6 项访问链；如果用户提供的 WMPFDebugger 要求其他长度，工具会停止生成。

## 历史配置学习

工具扫描用户提供的：

```text
frida/config/addresses.*.json
```

仅接受包含 6 项 `SceneOffsets` 的配置。历史配置用于：

- 确定固定指针层级。
- 比较相邻版本的结构漂移。
- 在发现新的外层和内层偏移时选择最接近的结构形式。

用户项目中的历史配置会与生成器内置样本合并。即使项目配置较少，仍可利用内置样本；实际 `hook.js` 兼容性校验仍以用户项目为准。

## flue.dll 分析

1. 解析 PE32+ 文件头和节表。
2. 从异常目录读取 x64 `RUNTIME_FUNCTION` 边界。
3. 搜索：
   - `OnLoadStart`
   - `applet_index_container.cc`
   - `SendToClientFilter`
4. 将子串命中位置回溯至完整字符串起点。
5. 扫描 `.text` 节中的 RIP 相对 `LEA` 引用。
6. 将引用地址映射到函数边界。

## LoadStartHookOffset 与 SceneOffsets

候选 `OnLoadStart` 函数必须满足历史结构或动态结构识别。

动态识别会：

1. 提取候选函数的调用目标。
2. 在调用目标中查找 scene `1101` 比较。
3. 识别 scene 字段末级偏移 `456` 或 `488`。
4. 提取对齐的外层和内层结构偏移。
5. 验证两级偏移的结构关系。
6. 结合历史配置构造完整 6 项访问链。

如果无法形成高置信的完整访问链，生成过程立即失败，不会使用回退值。

## CDPFilterHookOffset

工具定位引用 `SendToClientFilter` 的函数，并分析其第一个直接调用。

严格模式要求调用目标：

- 能映射到有效的 `RUNTIME_FUNCTION`。
- 调用地址恰好是目标函数入口。

否则不生成配置。

## WMPF 20001

已验证结果：

```json
{
    "Version": 20001,
    "LoadStartHookOffset": "0x25D1520",
    "CDPFilterHookOffset": "0x30B03A0",
    "SceneOffsets": [64, 1480, 8, 1416, 16, 456]
}
```

其中 `OnLoadStart` 的关键访问关系为：

```text
[this + 64] -> [对象 + 1480]
[[参数 + 8] + 1416] -> [+16] -> scene + 456
```

## GUI 操作

1. 选择微信 WMPF 目录。
2. 推荐选择 WMPFDebugger 根目录，也可以留空。
3. 可选填入版本号。
4. 点击“生成 JSON”。
5. 查看日志中的校验结果和输出路径。

两个目录也可以同时拖入窗口。包含 `frida/hook.js` 的目录会被识别为 WMPFDebugger，其余路径作为 WMPF 输入。

## CLI

```bat
WMPFOffsetGen.GUI.v1.1.exe --cli ^
  --input "C:\path\to\20035" ^
  --version 20035 ^
  --verbose
```

双目录模式可增加：

```bat
--debugger "C:\path\to\WMPFDebugger"
```

必需参数：

- `--input`

可选参数：

- `--debugger`
- `--version`
- `--verbose`

## 编译

```bat
build-gui.bat
```

输出：

```text
dist\WMPFOffsetGen.GUI.v1.1.exe
```

## 验收标准

- 程序版本为 `1.1`。
- 能识别用户提供的 WMPFDebugger Hook 格式。
- 不提供 WMPFDebugger 时也能使用内置模式生成。
- 对 WMPF `20001` 生成已验证配置。
- 无效 WMPFDebugger 目录必须失败。
- 识别不到 SceneOffsets 时必须失败。
- 输出只写入生成器运行目录。
