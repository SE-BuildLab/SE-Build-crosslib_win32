cd /d C:\git\SE-Build-crosslib_win32\zlib\src\build\vc2005\x64_Release

set CYGWIN=nodosfilewarning
set PATH=C:\Perl\bin;C:\ADMIN\nasm-2.11.08;%PATH%

call "C:\Program Files (x86)\Microsoft Visual Studio 8\VC\vcvarsall.bat" amd64

perl -i.bak -p -e "s/-MD/-MT/g" win32\Makefile.msc
perl -i.bak -p -e "s/-debug//g" win32\Makefile.msc
perl -i.bak -p -e "s/-Zi/-Z7/g" win32\Makefile.msc


nmake /f win32\Makefile.msc clean
nmake /f win32\Makefile.msc



mkdir C:\git\SE-Build-crosslib_win32\zlib\output\Library\vc2005\x64_Release

copy zlib.lib C:\git\SE-Build-crosslib_win32\zlib\output\Library\vc2005\x64_Release\ /y


