cd /d C:\git\SE-Build-crosslib_win32\OpenSSL\src\build\vc2005\Win32_Release

set CYGWIN=nodosfilewarning
set PATH=C:\Strawberry\perl\bin;C:\ADMIN\nasm-2.11.08;%PATH%

call "C:\Program Files (x86)\Microsoft Visual Studio 8\VC\vcvarsall.bat" x86

perl Configure --release VC-WIN32 no-engine no-shared enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method no-async

perl -i.bak -p -e "s/\/MDd/\/MT/g" makefile
perl -i.bak -p -e "s/\/MTd/\/MT/g" makefile
perl -i.bak -p -e "s/\/MD/\/MT/g" makefile
perl -i.bak -p -e "s/\/Zl/\/Z7/g" makefile
perl -i.bak -p -e "s/\/Zi/\/Z7/g" makefile
perl -i.bak -p -e "s/\/WX/\/W3/g" makefile

perl -i.bak -p -e "s/\/MDd/\/MT/g" configdata.pm
perl -i.bak -p -e "s/\/MTd/\/MT/g" configdata.pm
perl -i.bak -p -e "s/\/MD/\/MT/g" configdata.pm
perl -i.bak -p -e "s/\/Zl/\/Z7/g" configdata.pm
perl -i.bak -p -e "s/\/Zi/\/Z7/g" configdata.pm
perl -i.bak -p -e "s/\/WX/\/W3/g" configdata.pm

echo #ifndef HEADER_DSO_CONF_H> crypto\include\internal\dso_conf.h
echo #define HEADER_DSO_CONF_H>> crypto\include\internal\dso_conf.h
echo #define DSO_NONE>> crypto\include\internal\dso_conf.h
echo #endif>> crypto\include\internal\dso_conf.h

copy /y crypto\include\internal\dso_conf.h crypto\include\internal\dso_conf.h.in

nmake /f makefile clean
nmake /f makefile

mkdir C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2005\Win32_Release

copy libcrypto.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2005\Win32_Release\libeay32.lib /y
copy libssl.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2005\Win32_Release\ssleay32.lib /y

mkdir C:\git\SE-Build-crosslib_win32\OpenSSL\output\Include\vc2005\
copy C:\git\SE-Build-crosslib_win32\OpenSSL\src\build\vc2005\Win32_Release\include\openssl\* C:\git\SE-Build-crosslib_win32\OpenSSL\output\Include\vc2005\ /y
del C:\git\SE-Build-crosslib_win32\OpenSSL\output\Include\vc2005\__DECC_INCLUDE_EPILOGUE.H
del C:\git\SE-Build-crosslib_win32\OpenSSL\output\Include\vc2005\__DECC_INCLUDE_PROLOGUE.H


