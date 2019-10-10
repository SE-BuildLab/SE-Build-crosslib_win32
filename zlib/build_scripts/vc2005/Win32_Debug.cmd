cd /d C:\git\SE-Build-crosslib_win32\zlib\src\build\vc2005\Win32_Debug

set CYGWIN=nodosfilewarning
set PATH=C:\Perl\bin;C:\ADMIN\nasm-2.11.08;%PATH%

call "C:\Program Files (x86)\Microsoft Visual Studio 8\VC\vcvarsall.bat" x86

perl -i.bak -p -e "s/-MD/-MTd/g" win32\Makefile.msc
perl -i.bak -p -e "s/-O2/-Od/g" win32\Makefile.msc
perl -i.bak -p -e "s/-Zi/-Z7/g" win32\Makefile.msc


nmake /f win32\Makefile.msc clean
nmake /f win32\Makefile.msc



mkdir C:\git\SE-Build-crosslib_win32\zlib\output\Library\vc2005\Win32_Debug

copy zlib.lib C:\git\SE-Build-crosslib_win32\zlib\output\Library\vc2005\Win32_Debug\ /y


