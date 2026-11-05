# 023 of 033 — CVE-2026-7383 (ASN1-mbstring-ncopy-int-overflow)

Log file: `20261102_123829_023of033_CVE-2026-7383_ASN1-mbstring-ncopy-int-overflow.log`

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の確認)

crypto/asn1/a_mbstr.c (pristine 1.1.1w): line 48 'int outform, outlen = 0;', line 51 'int nchar;', line 174 'outlen = nchar << 1;' (BMP), line 179 'outlen = nchar << 2;' (UNIV), line 189 'if ((p = OPENSSL_malloc(outlen + 1)) == NULL)', line 198 'traverse_string(in, len, inform, cpyfunc, &p);'. nchar comes from the caller's input length (int). For nchar = 2^30 and UniversalString output, nchar << 2 does not fit in an int and evaluates to 0, so a 1-byte buffer is allocated while cpy_univ() (lines 320-329) writes 4 bytes per character. For BMPString output the shift produces a negative value and the allocation fails (no overflow, but *out is left dangling by the error path). The patch adds the INT_MAX/2 and INT_MAX/4 range checks before the shifts (raising ASN1_R_STRING_TOO_LONG and clearing *out), checks the traverse_string() result of the UTF-8 sizing pass, and makes out_utf8() reject UTF8_putc() errors and sums exceeding INT_MAX.

crypto/asn1/a_mbstr.c (素の 1.1.1w): 48 行 'int outform, outlen = 0;'、51 行 'int nchar;'、174 行 'outlen = nchar << 1;' (BMP)、179 行 'outlen = nchar << 2;' (UNIV)、189 行 'if ((p = OPENSSL_malloc(outlen + 1)) == NULL)'、198 行 'traverse_string(in, len, inform, cpyfunc, &p);'。nchar は呼び出し側の入力長 (int) に由来する。nchar = 2^30 で UniversalString 出力の場合、nchar << 2 は int に収まらず 0 と評価され、1 バイトのバッファが確保される一方で cpy_univ() (320〜329 行) は 1 文字あたり 4 バイトを書き込む。BMPString 出力ではシフトが負の値になり確保が失敗する (オーバーフローは無いが、エラー経路で *out が dangling のまま残る)。パッチはシフトの前に INT_MAX/2 と INT_MAX/4 の範囲チェック (ASN1_R_STRING_TOO_LONG を報告し *out をクリア) を追加し、UTF-8 サイズ計算パスの traverse_string() の結果を検査し、out_utf8() で UTF8_putc() のエラーと INT_MAX を超える合計を拒否する。

## PoC design / PoC の設計

poc_mbstr.c: big(len, mask) mmaps len bytes, fills them with 'A', prints nchar and the 64-bit values of nchar << 2 / nchar << 1, calls ASN1_mbstring_ncopy(&out, in, (int)len, MBSTRING_ASC, mask, 0, 0), prints the return value, the OpenSSL error queue and out->type/length on success. Modes: univ (2^30, B_ASN1_UNIVERSALSTRING), bmp (2^30, B_ASN1_BMPSTRING), univmax (INT_MAX/4, UNIVERSALSTRING), small (short ASCII/UTF-8 strings via ASN1_mbstring_copy with several masks). build.sh links it against BASE, BASE-ASAN, PATCHED and PATCHED-ASAN; run_poc.sh runs the modes sequentially (memory 1-2.5 GiB each), with gdb for BASE and valgrind plus the unit tests for PATCHED.

poc_mbstr.c: big(len, mask) は len バイトを mmap して 'A' で埋め、nchar と nchar << 2 / nchar << 1 の 64 ビット値を表示し、ASN1_mbstring_ncopy(&out, in, (int)len, MBSTRING_ASC, mask, 0, 0) を呼び、戻り値、OpenSSL エラーキュー、成功時は out->type/length を表示する。モード: univ (2^30、B_ASN1_UNIVERSALSTRING)、bmp (2^30、B_ASN1_BMPSTRING)、univmax (INT_MAX/4、UNIVERSALSTRING)、small (ASN1_mbstring_copy を複数のマスクで短い ASCII/UTF-8 文字列に適用)。build.sh が BASE、BASE-ASAN、PATCHED、PATCHED-ASAN にリンクし、run_poc.sh が各モードを順番に (メモリ 1〜2.5 GiB ずつ) 実行し、BASE では gdb、PATCHED では valgrind と単体テストも実行する。

## Observed behaviour BEFORE the patch (evidence excerpts) / パッチ前の挙動 (証拠抜粋)

Unpatched 1.1.1w: the UniversalString run dies with SIGSEGV (exit 139). gdb at a_mbstr.c:189: 'ASN1_mbstring_ncopy (out=..., in=... 'A'..., len=1073741824, inform=4097, mask=256, ...)', '$1 = 1073741824' (nchar), '$2 = 0' (outlen), '$4 = 4294967296' ((long)nchar << 2); then 'SIGSEGV in cpy_univ (value=65, ...) at crypto/asn1/a_mbstr.c:324' <- traverse_string (a_mbstr.c:235) <- ASN1_mbstring_ncopy (a_mbstr.c:198). BASE-ASAN: 'ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 1 ... #0 cpy_univ a_mbstr.c:325 #1 traverse_string a_mbstr.c:235 #2 ASN1_mbstring_ncopy a_mbstr.c:198 ... 0x... is located 0 bytes after 1-byte region ... allocated by ... CRYPTO_malloc ... ASN1_mbstring_ncopy a_mbstr.c:189'. The BMPString control returns -1 with 'malloc failure' (ASan: allocation-size-too-big for 0xffffffff80000001 bytes), i.e. the negative size is not exploitable but still a wrong result.

未修正 1.1.1w: UniversalString の実行は SIGSEGV (exit 139) で異常終了。a_mbstr.c:189 の gdb: 'ASN1_mbstring_ncopy (out=..., in=... 'A'..., len=1073741824, inform=4097, mask=256, ...)'、'$1 = 1073741824' (nchar)、'$2 = 0' (outlen)、'$4 = 4294967296' ((long)nchar << 2)。その後 'SIGSEGV in cpy_univ (value=65, ...) at crypto/asn1/a_mbstr.c:324' <- traverse_string (a_mbstr.c:235) <- ASN1_mbstring_ncopy (a_mbstr.c:198)。BASE-ASAN: 'ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 1 ... #0 cpy_univ a_mbstr.c:325 #1 traverse_string a_mbstr.c:235 #2 ASN1_mbstring_ncopy a_mbstr.c:198 ... 0x... is located 0 bytes after 1-byte region ... allocated by ... CRYPTO_malloc ... ASN1_mbstring_ncopy a_mbstr.c:189'。BMPString の対照は 'malloc failure' で -1 を返す (ASan: 0xffffffff80000001 バイトの allocation-size-too-big)、すなわち負のサイズは悪用不可だが誤った結果である。

```
Breakpoint 1, ASN1_mbstring_ncopy (out=0x7fffffffc308, in=0x7fffb7800000 'A' <repeats 200 times>..., len=1073741824, inform=4097, mask=256, minsize=0, maxsize=0) at crypto/asn1/a_mbstr.c:189
189	    if ((p = OPENSSL_malloc(outlen + 1)) == NULL) {
$1 = 1073741824
$2 = 0
$3 = 0
$4 = 4294967296

Program received signal SIGSEGV, Segmentation fault.
cpy_univ (value=65, arg=0x7fffffffc288) at crypto/asn1/a_mbstr.c:324
324	    *q++ = (unsigned char)((value >> 24) & 0xff);
#0  cpy_univ (value=65, arg=0x7fffffffc288) at crypto/asn1/a_mbstr.c:324
#1  traverse_string (p=..., len=1073709235, inform=4097, rfunc=<cpy_univ>, arg=...) at crypto/asn1/a_mbstr.c:235
#2  ASN1_mbstring_ncopy (out=..., in=..., len=1073741824, inform=4097, mask=256, minsize=0, maxsize=0) at crypto/asn1/a_mbstr.c:198
---
==10624==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000011 at pc ... bp ... sp ...
WRITE of size 1 at 0x502000000011 thread T0
    #0 in cpy_univ ../src_1.1.1w/openssl-1.1.1w/crypto/asn1/a_mbstr.c:325
    #1 in traverse_string ../src_1.1.1w/openssl-1.1.1w/crypto/asn1/a_mbstr.c:235
    #2 in ASN1_mbstring_ncopy ../src_1.1.1w/openssl-1.1.1w/crypto/asn1/a_mbstr.c:198
0x502000000011 is located 0 bytes after 1-byte region [0x502000000010,0x502000000011)
allocated by thread T0 here:
    #1 CRYPTO_malloc ../src_1.1.1w/openssl-1.1.1w/crypto/mem.c:222
    #2 ASN1_mbstring_ncopy ../src_1.1.1w/openssl-1.1.1w/crypto/asn1/a_mbstr.c:189
```

## Observed behaviour AFTER the patch / パッチ後の挙動

Patched build (debug and ASan): both 2^30-character runs return -1 with 'asn1 encoding routines:ASN1_mbstring_ncopy:string too long' (a_mbstr.c:213 for UNIV, :200 for BMP), *out is NULL, no crash, no sanitizer report (4/4 runs). The boundary input INT_MAX/4 characters is still converted (type 28, length 2147483644).

修正版 (debug と ASan): 2^30 文字の 2 つの実行はいずれも 'asn1 encoding routines:ASN1_mbstring_ncopy:string too long' (UNIV は a_mbstr.c:213、BMP は :200) で -1 を返し、*out は NULL、クラッシュもサニタイザ報告も無し (4/4 回)。境界入力の INT_MAX/4 文字は引き続き変換される (type 28、length 2147483644)。

```
$ ./poc_mbstr_patched univ 30
[poc] input: 1073741824 (0x40000000) ASCII bytes 'A' -> nchar = 1073741824; nchar << 2 = 0x100000000, nchar << 1 = 0x80000000
[poc] calling ASN1_mbstring_ncopy(&out, in, 1073741824, MBSTRING_ASC, B_ASN1_UNIVERSALSTRING, 0, 0) ...
...:error:0D07A097:asn1 encoding routines:ASN1_mbstring_ncopy:string too long:../openssl-1.1.1w-ipalongpatch_20261102/crypto/asn1/a_mbstr.c:213:
[poc] ASN1_mbstring_ncopy returned -1
[poc] out pointer after failure: (nil) (not freed by the PoC)
[poc] finished without crashing
[exit status: 1]
$ ./poc_mbstr_patched univmax
[poc] ASN1_mbstring_ncopy returned 28
[poc] out->type = 28, out->length = 2147483644
```

## Regression check / 回帰確認

Patched build: short-string conversions ('Hello' and UTF-8 U+3042 'A' to UniversalString, BMPString, UTF8String and the minimal DirectoryString type) produce the same correct encodings as the unpatched build, also under ASan and valgrind (no errors, no leaks); INT_MAX/4 characters are still accepted; the patched build's own asn1_encode_test, asn1_decode_test, asn1_string_table_test, asn1_time_test and asn1_internal_test all pass; 'openssl req -utf8' creates and prints a request subject correctly.

修正版: 短い文字列の変換 ('Hello' と UTF-8 の U+3042 'A' を UniversalString、BMPString、UTF8String、最小 DirectoryString 型へ) は未修正版と同じ正しい符号化を生成し、ASan と valgrind (エラー・リーク無し) 下でも同様。INT_MAX/4 文字は引き続き受理。修正版ビルド自身の asn1_encode_test、asn1_decode_test、asn1_string_table_test、asn1_time_test、asn1_internal_test はすべて合格。'openssl req -utf8' による要求の subject 作成と表示も正しい。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/023_CVE-2026-7383
./build.sh                                 # poc_mbstr_{base,base_asan,patched,patched_asan}
./poc_mbstr_base univ 30                    # unpatched: SIGSEGV (needs ~1 GiB RAM)
LD_LIBRARY_PATH=/home/user/work/base/openssl-1.1.1w gdb -q -batch -ex 'set breakpoint pending on' -ex 'break a_mbstr.c:189' -ex run -ex 'print nchar' -ex 'print outlen' -ex continue -ex bt --args ./poc_mbstr_base univ 30
ASAN_OPTIONS=detect_leaks=0 ./poc_mbstr_base_asan univ 30   # heap-buffer-overflow WRITE in cpy_univ
./poc_mbstr_patched univ 30 ; ./poc_mbstr_patched bmp 30    # 'string too long', -1
./poc_mbstr_patched small ; ./poc_mbstr_patched univmax     # regression (univmax needs ~2.5 GiB RAM)
./run_poc.sh                                # everything (runs the memory-heavy cases one at a time)
```

## Limitations / notes / 制限事項・注記

The overflow is reachable only through direct ASN1_mbstring_copy()/ASN1_mbstring_ncopy() callers (or custom ASN1_STRING_TABLE entries) with inputs of about 2^30 characters, so the demonstration is a C program, not an openssl command. The UTF-8 output overflow (out_utf8 sum) cannot wrap to a small positive value with an int input length (the sum stays below 3*2^30 and the allocation simply fails), so only the UniversalString wrap-to-zero case is demonstrated as a memory-safety failure; the BMPString case is shown as a control (wrong negative size, allocation failure). The unpatched malloc-failure path leaves *out dangling (pre-existing behaviour, not part of this CVE).

このオーバーフローは ASN1_mbstring_copy()/ASN1_mbstring_ncopy() を直接呼ぶ (または独自の ASN1_STRING_TABLE エントリを使う) 呼び出し元に約 2^30 文字の入力を与えた場合にのみ到達するため、実証は openssl コマンドではなく C プログラムで行った。UTF-8 出力のオーバーフロー (out_utf8 の合計) は入力長が int である限り小さな正の値に巻き戻らない (合計は 3*2^30 未満に留まり確保が単に失敗する) ため、メモリ安全性の失敗として実証したのは UniversalString の 0 への巻き戻りのみで、BMPString は対照 (誤った負のサイズ、確保失敗) として示した。未修正の malloc 失敗経路が *out を dangling にするのは既存の挙動であり本 CVE の対象外。
