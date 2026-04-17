# WMPFOffsetGen.GUI 源码与使用说明

本文档用于说明图形化偏移量生成工具 `WMPFOffsetGen.GUI.exe` 的源码位置、编译方法和使用方式，便于直接上传到 GitHub。

## 1. 工具用途

`WMPFOffsetGen.GUI.exe` 用于从微信小程序运行时文件（`flue.dll`）自动生成：

- `addresses.<版本号>.json`

生成结果可用于 `WMPFDebugger` 的版本配置补充。

## 2. 源码位置

图形化 `exe` 源码（根目录）：

- `WMPFOffsetGenGUI/WmpfOffsetGenGui.cs`

历史工作路径（可选）：

- `tools/WmpfOffsetGenGui.cs`

命令行版（Node）源码：

- `tools/wmpf-offset-gen.js`

## 3. 编译 GUI EXE

### 3.1 通过 npm 脚本编译（推荐）

在项目根目录执行：

```bash
npm run build:addresses:gui
```

输出文件：

- `dist/WMPFOffsetGen.GUI.exe`

### 3.2 直接调用 csc 编译

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /target:winexe /out:dist\WMPFOffsetGen.GUI.exe /r:System.Windows.Forms.dll /r:System.Drawing.dll tools\WmpfOffsetGenGui.cs
```

## 4. GUI 使用说明

### 4.1 启动方式

- 双击 `dist/WMPFOffsetGen.GUI.exe`

### 4.2 输入支持

你可以输入或拖拽以下任意路径：

- `195xx` 版本目录
- `extracted` 目录
- `runtime` 目录
- `flue.dll` 文件

### 4.3 参数说明（界面）

- 输入路径：必填
- 版本号（可选）：不填时自动从路径推断
- 模板配置目录（可选）：用于读取已有 `addresses.*.json` 的 `SceneOffsets` 组合
- 输出目录：固定为工具运行目录（exe 所在目录），不可修改

### 4.4 输出结果

生成文件名：

- `addresses.<版本号>.json`

生成位置：

- `WMPFOffsetGen.GUI.exe` 所在目录

## 5. CLI 模式（可选）

GUI 程序支持命令行模式，便于自动化测试：

```bash
WMPFOffsetGen.GUI.exe --cli --input "C:\path\to\195xx" --template-config-dir "C:\path\to\frida\config" --verbose
```

常用参数：

- `--cli`：启用命令行模式
- `--input <path>`：输入路径（必填）
- `--version <num>`：手动指定版本号（可选）
- `--template-config-dir <dir>`：模板配置目录（可选）
- `--verbose`：输出详细日志

说明：

- 即使 CLI 传入 `--output-dir`，GUI 版逻辑仍固定输出到工具目录。

## 6. 生成算法简述

工具会执行以下步骤：

1. 解析 `flue.dll` 的 PE 结构和 `.pdata` 函数表。
2. 定位关键字符串（如 `SendToClientFilter`、`OnLoadStart`）并回溯引用函数。
3. 从候选函数调用关系中推断：
   - `CDPFilterHookOffset`
   - `LoadStartHookOffset`
4. 结合已有版本 `SceneOffsets` 模板匹配，得到最终 `SceneOffsets`。
5. 生成 JSON 并写入工具目录。

## 7. GitHub 上传建议

建议至少包含以下文件：

- `WMPFOffsetGenGUI/WmpfOffsetGenGui.cs`
- `tools/wmpf-offset-gen.js`
- `WMPFOffsetGen.GUI.源码与使用说明.md`
- `package.json`（含构建脚本）

如果你上传编译产物，可额外包含：

- `dist/WMPFOffsetGen.GUI.exe`

## 8. 常见问题

### Q1：提示找不到 `flue.dll`

请确认输入路径是以下之一：

- `195xx`
- `extracted`
- `runtime`
- `flue.dll`

### Q2：版本号识别失败

在界面里手动填写版本号后重试。

### Q3：输出目录为什么不能改

当前版本按需求固定输出到工具运行目录，便于分发和统一收集结果。
