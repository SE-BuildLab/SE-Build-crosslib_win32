cd /d C:\git\SE-Build-crosslib_win32\OpenSSL\src\build\vc2008\x64_Debug

set CYGWIN=nodosfilewarning
set PATH=C:\Perl\bin;C:\ADMIN\nasm-2.11.08;%PATH%

call "c:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" amd64

perl Configure VC-WIN64A enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method

call ms\do_win64a

copy /y ms\nt.mak ms\nt_tmp.mak

perl -i.bak -p -e "s/\/MD/\/MTd/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/MT/\/MTd/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/Zl/\/Z7/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/Zi/\/Z7/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/Ox \/O2\ \/Ob2/\/Od/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/advapi32.lib//g" ms\nt_tmp.mak
perl -i.bak -p -e "s/inc32/winx64debug_inc32/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/out32/winx64debug_out32/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/tmp32/winx64debug_tmp32/g" ms\nt_tmp.mak

copy /y ms\nt_tmp.mak ms\winx64debug.mak

nmake /f ms\winx64debug.mak clean
nmake /f ms\winx64debug.mak

mkdir C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2008\x64_Debug

copy winx64debug_out32\libeay32.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2008\x64_Debug\libeay32.lib /y
copy winx64debug_out32\ssleay32.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2008\x64_Debug\ssleay32.lib /y


