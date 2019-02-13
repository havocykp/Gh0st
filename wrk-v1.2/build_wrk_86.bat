set path=%~dp0\tools\x86;%path%
cd %~dp0\base\ntos\
nmake -nologo x86=
pause