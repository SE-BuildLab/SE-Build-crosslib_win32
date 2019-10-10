cd /d C:\git\SE-Build-crosslib_win32\OpenSSL\src\build\vc2005\x64_Release

set CYGWIN=nodosfilewarning
set PATH=C:\Perl\bin;C:\ADMIN\nasm-2.11.08;%PATH%

call "C:\Program Files (x86)\Microsoft Visual Studio 8\VC\vcvarsall.bat" amd64

perl Configure VC-WIN64A enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method

call ms\do_win64a

copy /y ms\nt.mak ms\nt_tmp.mak

perl -i.bak -p -e "s/\/MD/\/MT/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/MT/\/MT/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/Zl/\/Z7/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/\/Zi/\/Z7/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/advapi32.lib//g" ms\nt_tmp.mak
perl -i.bak -p -e "s/inc32/winx64release_inc32/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/out32/winx64release_out32/g" ms\nt_tmp.mak
perl -i.bak -p -e "s/tmp32/winx64release_tmp32/g" ms\nt_tmp.mak

copy /y ms\nt_tmp.mak ms\winx64release.mak

nmake /f ms\winx64release.mak clean
nmake /f ms\winx64release.mak

mkdir C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2005\x64_Release

copy winx64release_out32\libeay32.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2005\x64_Release\libeay32.lib /y
copy winx64release_out32\ssleay32.lib C:\git\SE-Build-crosslib_win32\OpenSSL\output\Library\vc2005\x64_Release\ssleay32.lib /y


