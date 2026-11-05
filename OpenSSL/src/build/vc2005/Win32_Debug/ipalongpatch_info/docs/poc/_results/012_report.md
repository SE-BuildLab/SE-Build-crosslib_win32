# 012 of 033 — CVE-2025-69419 (PKCS12-friendlyName-UTF8-OOB)

Log file: `20261102_121342_012of033_CVE-2025-69419_PKCS12-friendlyName-UTF8-OOB.log`

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の確認)

crypto/pkcs12/p12_utl.c (pristine 1.1.1w): bmp_to_utf8(str, utf16, len) ends with 'return UTF8_putc(str, len > 4 ? 4 : len, utf32chr)' where len is the number of UTF-16 bytes still to be read, not the output capacity. OPENSSL_uni2utf8() pass 1 calls bmp_to_utf8(NULL, ...) (UTF8_putc with str==NULL ignores len) and allocates asclen (+1 for NUL) bytes (line 202); pass 2 (lines 208-213) calls bmp_to_utf8(asctmp+asclen, uni+i, unilen-i) and does 'asclen += j' without checking j. For the last character unilen-i == 2, so any code point >= U+0800 yields j == -1. With a one-character name asclen becomes -1 and line 217 'asctmp[asclen] = 0' writes one byte before the allocation. PKCS12_get_friendlyname() (p12_attr.c:95) calls this on attacker-controlled attribute data; PKCS12_parse() uses ASN1_STRING_to_UTF8() instead and is not affected. The patch adds 'if (j < 0) { OPENSSL_free(asctmp); return NULL; }' after the pass-2 call (and the equivalent check in a_strex.c do_buf()).

crypto/pkcs12/p12_utl.c (素の 1.1.1w): bmp_to_utf8(str, utf16, len) は最後に 'return UTF8_putc(str, len > 4 ? 4 : len, utf32chr)' を実行するが、この len は残りの UTF-16 入力バイト数であり出力容量ではない。OPENSSL_uni2utf8() の 1 パス目は bmp_to_utf8(NULL, ...) を呼び (str==NULL の UTF8_putc は len を無視する) asclen (+NUL 1 バイト) を確保する (202 行)。2 パス目 (208〜213 行) は bmp_to_utf8(asctmp+asclen, uni+i, unilen-i) を呼び、j を検査せず 'asclen += j' する。最後の文字では unilen-i == 2 なので U+0800 以上のコードポイントは j == -1 となる。1 文字の名前では asclen が -1 になり、217 行の 'asctmp[asclen] = 0' が割り当ての 1 バイト前に書き込む。PKCS12_get_friendlyname() (p12_attr.c:95) は攻撃者制御の属性データに対してこれを呼ぶ。PKCS12_parse() は ASN1_STRING_to_UTF8() を使うため非影響。パッチは 2 パス目の呼び出し直後に 'if (j < 0) { OPENSSL_free(asctmp); return NULL; }' を追加する (a_strex.c の do_buf() にも同等のチェック)。

## PoC design / PoC の設計

good.p12 = unpatched 'openssl pkcs12 -export -name AB -certpbe NONE -passout pass:x' (servercert/serverkey). make_bad.py rewrites the friendlyName BMPString of every bag in the unencrypted SafeContents to the given UTF-16BE bytes (30 42 = U+3042, FF FF = U+FFFF, 30 42 00 41, 00 41 30 42) and recomputes the MAC. poc_friendlyname.c: d2i_PKCS12_fp -> PKCS12_verify_mac -> PKCS12_unpack_authsafes -> PKCS12_unpack_p7data/p7encdata -> PKCS12_get_friendlyname(bag) for each bag, printing the result bytes. run_poc.sh builds it against the four builds and runs the BASE/BASE-ASAN/gdb/valgrind, PATCHED/PATCHED-ASAN and regression steps.

good.p12 = 未修正ビルドの 'openssl pkcs12 -export -name AB -certpbe NONE -passout pass:x' (servercert/serverkey)。make_bad.py は非暗号化 SafeContents 内の全バッグの friendlyName BMPString を指定の UTF-16BE バイト列 (30 42 = U+3042、FF FF = U+FFFF、30 42 00 41、00 41 30 42) に書き換え MAC を再計算する。poc_friendlyname.c: d2i_PKCS12_fp -> PKCS12_verify_mac -> PKCS12_unpack_authsafes -> PKCS12_unpack_p7data/p7encdata -> 各バッグに PKCS12_get_friendlyname(bag) を呼び結果のバイト列を表示する。run_poc.sh が 4 ビルド向けにビルドし、BASE/BASE-ASAN/gdb/valgrind、PATCHED/PATCHED-ASAN、回帰確認の各ステップを実行する。

## Observed behaviour BEFORE the patch (evidence excerpts) / パッチ前の挙動 (証拠抜粋)

BASE-ASAN: 'ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 1 ... #0 OPENSSL_uni2utf8 crypto/pkcs12/p12_utl.c:217 #1 PKCS12_get_friendlyname p12_attr.c:95 ... 0x... is located 1 bytes before 4-byte region ... allocated by ... OPENSSL_uni2utf8 p12_utl.c:202' for both U+3042 and U+FFFF. valgrind on the debug build: 'Invalid write of size 1 at OPENSSL_uni2utf8 (p12_utl.c:217) ... Address ... is 1 bytes before a block of size 4 alloc'd'. gdb: at p12_utl.c:217 asclen = -1, &asctmp[asclen] = asctmp - 1 (uni = {0x30,0x42}, unilen = 2). Without a sanitizer the program does not visibly crash (the byte lands in the glibc chunk header) and returns an empty string.

BASE-ASAN: U+3042、U+FFFF の両方で 'ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 1 ... #0 OPENSSL_uni2utf8 crypto/pkcs12/p12_utl.c:217 #1 PKCS12_get_friendlyname p12_attr.c:95 ... 0x... is located 1 bytes before 4-byte region ... allocated by ... OPENSSL_uni2utf8 p12_utl.c:202'。debug ビルドの valgrind: 'Invalid write of size 1 at OPENSSL_uni2utf8 (p12_utl.c:217) ... Address ... is 1 bytes before a block of size 4 alloc'd'。gdb: p12_utl.c:217 で asclen = -1、&asctmp[asclen] = asctmp - 1 (uni = {0x30,0x42}、unilen = 2)。サニタイザ無しでは目に見えるクラッシュは起きず (当該バイトは glibc のチャンクヘッダに書かれる) 空文字列が返る。

```
==2311==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000001ef at pc ... bp ... sp ...
WRITE of size 1 at 0x5020000001ef thread T0
    #0 0x... in OPENSSL_uni2utf8 ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_utl.c:217
    #1 0x... in PKCS12_get_friendlyname ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_attr.c:95
    #2 0x... in main /home/user/work/poc/012_CVE-2025-69419/poc_friendlyname.c:55
0x5020000001ef is located 1 bytes before 4-byte region [0x5020000001f0,0x5020000001f4)
allocated by thread T0 here:
    #0 malloc
    #1 CRYPTO_malloc ../src_1.1.1w/openssl-1.1.1w/crypto/mem.c:222
    #2 OPENSSL_uni2utf8 ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_utl.c:202
---
Breakpoint 1, OPENSSL_uni2utf8 (uni=0x555555572e20 "0B", unilen=2) at crypto/pkcs12/p12_utl.c:217
217	        asctmp[asclen] = '\0';
$1 = -1
$2 = 0x555555574ff0 ""
$5 = 0x555555574fef ""
---
==2853== Invalid write of size 1
==2853==    at 0x4A4419A: OPENSSL_uni2utf8 (p12_utl.c:217)
==2853==    by 0x4A3FB7C: PKCS12_get_friendlyname (p12_attr.c:95)
==2853==  Address 0x4e19d6f is 1 bytes before a block of size 4 alloc'd
```

## Observed behaviour AFTER the patch / パッチ後の挙動

PATCHED and PATCHED-ASAN: PKCS12_get_friendlyname() returns NULL for the one-character names (bad_u3042.p12, bad_uffff.p12); the program finishes normally with exit 0, ASan reports nothing and valgrind --leak-check=full reports no error and no leak (the buffer is freed on the error path).

PATCHED と PATCHED-ASAN: 1 文字名 (bad_u3042.p12、bad_uffff.p12) に対して PKCS12_get_friendlyname() は NULL を返し、プログラムは exit 0 で正常終了、ASan の報告は無く、valgrind --leak-check=full もエラー・リーク無し (エラー経路でバッファは解放される)。

```
$ ./poc_friendlyname_patched bad_u3042.p12 x
[poc] MAC verification: OK
[poc] safe 0 bag 0 (certBag): PKCS12_get_friendlyname() returned NULL
[poc] safe 1 bag 0 (pkcs8ShroudedKeyBag): PKCS12_get_friendlyname() returned NULL
[poc] finished without crashing
[exit status: 0]
```

## Regression check / 回帰確認

With the patched library the ASCII name 'AB' and the two-character name '<U+3042>A' are decoded correctly ('AB' = 41 42; e3 81 82 41) by PKCS12_get_friendlyname(), on PATCHED and PATCHED-ASAN; 'openssl pkcs12 -info' on good.p12 and on the malformed file works (exit 0); valgrind on good.p12 is clean. Known behaviour (identical to the upstream/Ubuntu fix): a BMPString whose LAST character is >= U+0800 (trailing.p12, 'A<U+3042>') now yields NULL instead of the silently truncated string returned by the unpatched code - a safe failure, not a crash.

修正版ライブラリでは ASCII 名 'AB' と 2 文字名 '<U+3042>A' が PKCS12_get_friendlyname() で正しく得られ ('AB' = 41 42、e3 81 82 41)、PATCHED と PATCHED-ASAN の両方で確認した。good.p12 と不正ファイルに対する 'openssl pkcs12 -info' も動作 (exit 0)、good.p12 の valgrind もクリーン。既知の挙動 (上流/Ubuntu の修正と同一): 末尾の文字が U+0800 以上の BMPString (trailing.p12、'A<U+3042>') は、未修正版が黙って切り詰めた文字列を返していたのに対し NULL を返すようになる — クラッシュではなく安全な失敗。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/012_CVE-2025-69419
BASE=/home/user/work/base/openssl-1.1.1w; SRC=/home/user/work/src_1.1.1w/openssl-1.1.1w
$BASE/util/shlib_wrap.sh $BASE/apps/openssl pkcs12 -export -in $SRC/test/certs/servercert.pem -inkey $SRC/test/certs/serverkey.pem -name AB -passout pass:x -certpbe NONE -out good.p12
python3 -I make_bad.py good.p12 x          # -> bad_u3042.p12, bad_uffff.p12, mixed.p12, trailing.p12 (MAC recomputed)
./build.sh                                # poc_friendlyname_{base,base_asan,patched,patched_asan}
ASAN_OPTIONS=detect_leaks=0 ./poc_friendlyname_base_asan bad_u3042.p12 x    # heap-buffer-overflow WRITE of size 1, 1 byte before a 4-byte region
LD_LIBRARY_PATH=$BASE valgrind -q ./poc_friendlyname_base bad_u3042.p12 x    # Invalid write of size 1
LD_LIBRARY_PATH=$BASE gdb -q -batch -ex 'set breakpoint pending on' -ex 'break p12_utl.c:217' -ex run -ex 'print asclen' -ex bt --args ./poc_friendlyname_base bad_u3042.p12 x
./poc_friendlyname_patched bad_u3042.p12 x        # returns NULL, no crash
./poc_friendlyname_patched good.p12 x ; ./poc_friendlyname_patched mixed.p12 x   # 'AB', '<U+3042>A'
./run_poc.sh                              # everything, with captures in out/
```

## Limitations / notes / 制限事項・注記

The openssl command line tool is not a trigger for this bug (apps/pkcs12.c uses OPENSSL_uni2asc()), so the demonstration uses a C program that calls the public API PKCS12_get_friendlyname(), as named in the advisory. On the non-sanitized build the one-byte underflow corrupts the glibc chunk header without an immediate crash; its presence is proven with ASan, valgrind and gdb. The fix (like upstream/Ubuntu) turns friendly names ending in a >= U+0800 character into a NULL result rather than fixing the capacity computation; this is documented above as a known behaviour, not a regression introduced by the backport.

openssl コマンドラインツールはこのバグの発動経路ではない (apps/pkcs12.c は OPENSSL_uni2asc() を使用) ため、アドバイザリに名前のある公開 API PKCS12_get_friendlyname() を呼ぶ C プログラムで実証した。非サニタイザビルドでは 1 バイトのアンダーフローは glibc のチャンクヘッダを壊すだけで即時クラッシュは起きないため、ASan・valgrind・gdb でその存在を証明した。修正は (上流/Ubuntu と同様) 容量計算を直すのではなく、末尾が U+0800 以上の名前を NULL 結果にするものであり、上記に既知の挙動として記載した (バックポートによる回帰ではない)。
