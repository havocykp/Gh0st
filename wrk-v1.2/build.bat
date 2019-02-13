@ECHO OFF
set path="%2\tools\%1";%path%
cd base\ntos\
nmake -nologo %1=
cd ..\..