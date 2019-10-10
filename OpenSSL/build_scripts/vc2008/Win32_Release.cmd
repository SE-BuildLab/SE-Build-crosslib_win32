cd /d C:\git\SE-Build-crosslib_win32\OpenSSL\src\build\vc2008\Win32_Release

set CYGWIN=nodosfilewarning
set PATH=C:\Perl\bin;C:\ADMIN\nasm-2.11.08;%PATH%

call "c:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" x86

perl Configure VC-WIN32 enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method

call ms\do_nasm

copy /y ms\nt.mak ms\nt_tmp.mak

perl -i.bak -p -e "s/\/MD/\/MT/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/MT/\/MT/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/Zl/\/Z7/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/Zi/\/Z7/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/advapi32.lib//g" ms\nt_tmp.mak
perl -i.bak -p -e "s/inc32/win32release_inc32/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/out32/win32release_out32/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/tmp32/win32release_tmp32/g" ms\nt_tmp.mak

copy /y ms\nt_tmp.mak ms\win32release.mak

nmake /f ms\win32release.mak clean
nmake /f ms\win32release.mak

mkdir C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2008\Win32_Release

copy win32release_out32\libeay32.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2008\Win32_Release\libeay32.lib /y
copy win32release_out32\ssleay32.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2008\Win32_Release\ssleay32.lib /y

mkdir C:\git\SE-Build-crosslib_win32\OpenSSL\output\Include\vc2008\
copy C:\git\SE-Build-crosslib_win32\OpenSSL\src\build\vc2008\Win32_Release\win32release_inc32\openssl\* C:\git\SE-Build-crosslib_win32\OpenSSL\output\Include\vc2008\ /y


