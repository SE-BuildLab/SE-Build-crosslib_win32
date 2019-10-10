cd /d C:\git\SE-Build-crosslib_win32\OpenSSL\src\build\vc2019\Win32_Debug

set CYGWIN=nodosfilewarning
set PATH=C:\Perl\bin;C:\ADMIN\nasm-2.11.08;%PATH%

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars32.bat"

perl Configure VC-WIN32 enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method

call ms\do_nasm

copy /y ms\nt.mak ms\nt_tmp.mak

perl -i.bak -p -e "s/\/MD/\/MTd/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/MT/\/MTd/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/Zl/\/Z7/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/Zi/\/Z7/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/Ox \/O2\ \/Ob2/\/Od/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/advapi32.lib//g" ms\nt_tmp.mak
perl -i.bak -p -e "s/inc32/win32debug_inc32/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/out32/win32debug_out32/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/tmp32/win32debug_tmp32/g" ms\nt_tmp.mak

copy /y ms\nt_tmp.mak ms\win32debug.mak

nmake /f ms\win32debug.mak clean
nmake /f ms\win32debug.mak

mkdir C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2019\Win32_Debug

copy win32debug_out32\libeay32.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2019\Win32_Debug\libeay32.lib /y
copy win32debug_out32\ssleay32.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2019\Win32_Debug\ssleay32.lib /y


