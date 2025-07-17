@echo off
set WINSDK=C:\Program Files (x86)\Windows Kits\10
set MSVC=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.38.33130

cl /nologo /Zi /W3 /WX- /O2 /Oi /GL ^
/I "%WINSDK%\Include\10.0.26100.0\um" ^
/I "%WINSDK%\Include\10.0.26100.0\shared" ^
/I "%WINSDK%\Include\10.0.26100.0\ucrt" ^
/I "%MSVC%\include" ^
/D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE" ^
loader_custom.c ^
/link /LIBPATH:"%WINSDK%\Lib\10.0.26100.0\um\x64" ^
/LIBPATH:"%WINSDK%\Lib\10.0.26100.0\ucrt\x64" ^
/LIBPATH:"%MSVC%\lib\x64" ^
/OUT:loader.exe 