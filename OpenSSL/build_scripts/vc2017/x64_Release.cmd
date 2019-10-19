cd /d C:\git\SE-Build-crosslib_win32\OpenSSL\src\build\vc2017\x64_Release

set CYGWIN=nodosfilewarning
set PATH=C:\Strawberry\perl\bin;C:\ADMIN\nasm-2.11.08;%PATH%

call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

perl Configure VC-WIN64A no-engine no-shared enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method no-async

perl -i.bak -p -e "s/\/MDd/\/MTd/g" makefile
perl -i.bak -p -e "s/\/Zl/\/Z7/g" makefile
perl -i.bak -p -e "s/\/Zi/\/Z7/g" makefile

perl -i.bak -p -e "s/\/MD/\/MT/g" configdata.pm
perl -i.bak -p -e "s/\/Zl/\/Z7/g" configdata.pm
perl -i.bak -p -e "s/\/Zi/\/Z7/g" configdata.pm

nmake /f makefile clean
nmake /f makefile

mkdir C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2017\x64_Release

copy libcrypto.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2017\x64_Release\libeay32.lib /y
copy libssl.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2017\x64_Release\ssleay32.lib /y


