@echo off
echo Setting up environment...
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64
echo Compiling...
cl /nologo /O2 /W4 /Fe:loader.exe loader_custom.c /link /machine:x64 /subsystem:console kernel32.lib user32.lib
if errorlevel 1 (
    echo Compilation failed with error code %errorlevel%
    exit /b 1
)
echo Compilation successful
dir loader.exe 