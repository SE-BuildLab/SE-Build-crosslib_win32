cd /d C:\git\SE-Build-crosslib_win32\OpenSSL\src\build\vc2019\Win32_Debug

set CYGWIN=nodosfilewarning
set PATH=C:\Strawberry\perl\bin;C:\ADMIN\nasm-2.11.08;%PATH%

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars32.bat"

perl Configure --debug VC-WIN32 no-engine no-shared enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method no-async

perl -i.bak -p -e "s/\/MDd/\/MTd/g" makefile
perl -i.bak -p -e "s/\/Zl/\/Z7/g" makefile
perl -i.bak -p -e "s/\/Zi/\/Z7/g" makefile

perl -i.bak -p -e "s/\/MD/\/MT/g" configdata.pm
perl -i.bak -p -e "s/\/Zl/\/Z7/g" configdata.pm
perl -i.bak -p -e "s/\/Zi/\/Z7/g" configdata.pm

nmake /f makefile clean
nmake /f makefile

mkdir C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2019\Win32_Debug

copy libcrypto.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2019\Win32_Debug\libeay32.lib /y
copy libssl.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2019\Win32_Debug\ssleay32.lib /y


