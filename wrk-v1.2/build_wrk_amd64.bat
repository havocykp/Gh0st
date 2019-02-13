set path=%~dp0\tools\amd64;%path%
cd %~dp0\base\ntos\
nmake -nologo amd64=
pause