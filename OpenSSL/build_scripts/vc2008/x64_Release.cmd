cd /d C:\git\SE-Build-crosslib_win32\OpenSSL\src\build\vc2008\x64_Release

set CYGWIN=nodosfilewarning
set PATH=C:\Strawberry\perl\bin;C:\ADMIN\nasm-2.11.08;%PATH%

call "c:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" amd64

perl Configure VC-WIN64A no-engine no-shared enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method no-async

perl -i.bak -p -e "s/_WIN32_WINNT \>\= 0x0600/_WIN32_WINNT \>\= 0xFFFF/g" crypto\rand\rand_win.c

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

mkdir C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2008\x64_Release

copy libcrypto.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2008\x64_Release\libeay32.lib /y
copy libssl.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2008\x64_Release\ssleay32.lib /y


