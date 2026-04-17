<img width="723" height="534" alt="Snipaste_2026-04-17_17-49-30" src="https://github.com/user-attachments/assets/f03a7007-0d86-447d-a6a3-943798387df3" /># WMPFOffsetGen.GUI

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
<img width="723" height="534" alt="1" src="https://github.com/user-attachments/assets/dfd74d6d-5e1c-4e09-8fc9-ebc9d6484d32" />
5. 在工具运行目录获得 `addresses.<版本号>.json`
7. 上传addresses.<版本号>.json文件到WMPFDebugger\frida\config目录下
<img width="361" height="493" alt="2" src="https://github.com/user-attachments/assets/43ddff42-5c7f-4629-a22f-daf94865b6b6" />
