# WMPFOffsetGen.GUI

一个图形化工具，用于从微信小程序运行时文件 `flue.dll` 自动生成：

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

1. 双击 `dist/WMPFOffsetGen.GUI.exe`
2. 输入或拖拽 `195xx / extracted / runtime / flue.dll`
3. 点击“生成 JSON”
4. 在工具运行目录获得 `addresses.<版本号>.json`

## 上传到 GitHub

先在 GitHub 网站创建空仓库，再在本地执行：

```bash
git add .
git commit -m "feat: add WMPFOffsetGen.GUI source and docs"
git branch -M main
git remote add origin https://github.com/<你的用户名>/<你的仓库名>.git
git push -u origin main
```

如果提示 `detected dubious ownership`，先执行：

```bash
git config --global --add safe.directory "C:/Users/Administrator/Desktop/微信WMPFDebugger偏移量生成/WMPFOffsetGenGUI-GitHub"
```
