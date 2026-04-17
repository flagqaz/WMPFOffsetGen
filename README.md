# WMPFOffsetGen.GUI

一个图形化工具，用于从微信小程序最新WMPF版本计算基地址偏移量自动生成 addresses.<版本号>.json文件保证WMPFDebugger正常使用：

- `addresses.<版本号>.json`

## 目录结构

- `src/WmpfOffsetGenGui.cs`：GUI 工具完整源码（含算法、界面、CLI 模式）
- `docs/WMPFOffsetGen.GUI.源码与使用说明.md`：详细使用文档
- `build-gui.bat`：Windows 一键编译脚本

## 快速编译

在项目目录双击 `build-gui.bat`，或命令行执行：

```bat
build-gui.bat
```

编译成功后输出：

- `dist/WMPFOffsetGen.GUI.exe`

## 使用方式

1. 双击 `WMPFOffsetGen.GUI.exe`
2. 输入或拖拽WMPF目录 `C:\Users\%当前用户%\AppData\Roaming\Tencent\xwechat\xplugin\Plugins\RadiumWMP\`
3. 点击“生成 JSON”
4. 在工具运行目录获得 `addresses.<版本号>.json`
5. 上传addresses.<版本号>.json文件到WMPFDebugger\frida\config目录下
