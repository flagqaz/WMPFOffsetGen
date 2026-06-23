@echo off
setlocal
cd /d "%~dp0"

if not exist "dist" mkdir "dist"

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo [ERROR] C# compiler not found: %CSC%
    exit /b 1
)

"%CSC%" /nologo /target:winexe /optimize+ ^
    /out:"dist\WMPFOffsetGen.GUI.v1.1.exe" ^
    /r:System.Windows.Forms.dll ^
    /r:System.Drawing.dll ^
    "src\WmpfOffsetGenGui.cs"

if errorlevel 1 exit /b 1

echo [OK] dist\WMPFOffsetGen.GUI.v1.1.exe
endlocal
