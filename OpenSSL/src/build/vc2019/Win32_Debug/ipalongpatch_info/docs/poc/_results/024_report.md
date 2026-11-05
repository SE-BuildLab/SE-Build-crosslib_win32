# 024 of 033 — CVE-2026-34180 (ASN1-STRING-set-len-truncation)

Log file: `20261102_123847_024of033_CVE-2026-34180_ASN1-STRING-set-len-truncation.log`

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の確認)

crypto/asn1/tasn_dec.c (pristine 1.1.1w): asn1_d2i_ex_primitive() keeps the content length in 'long len' and calls 'asn1_ex_c2i(pval, cont, len, utype, &free_cont, it)' (line 780); asn1_ex_c2i() is declared with 'int len' (lines 60/793), so 0x80000001 becomes -2147483647. In the string branch (line 906) 'ASN1_STRING_set(stmp, cont, len)' is called; crypto/asn1/asn1_lib.c ASN1_STRING_set() lines 277-280: 'if (len_in < 0) { if (data == NULL) return 0; len = strlen(data); }' - the content is scanned for a NUL past the end of the input. If a NUL is found within INT_MAX-1 bytes the (wrong) data is copied, otherwise the length check fails or the scan faults. The patch makes asn1_ex_c2i() take 'long len', computes 'int ilen = (int)len' and fails with ASN1_R_TOO_LONG whenever len != (long)ilen, in the prim_c2i, OBJECT and string branches, and uses ilen for stmp->length / ASN1_STRING_set().

crypto/asn1/tasn_dec.c (素の 1.1.1w): asn1_d2i_ex_primitive() は内容長を 'long len' に保持し 'asn1_ex_c2i(pval, cont, len, utype, &free_cont, it)' を呼ぶ (780 行) が、asn1_ex_c2i() は 'int len' で宣言されている (60/793 行) ため 0x80000001 は -2147483647 になる。文字列分岐 (906 行) で 'ASN1_STRING_set(stmp, cont, len)' が呼ばれ、crypto/asn1/asn1_lib.c の ASN1_STRING_set() 277〜280 行 'if (len_in < 0) { if (data == NULL) return 0; len = strlen(data); }' により、入力の終端を越えて NUL を走査する。INT_MAX-1 バイト以内に NUL があれば (誤った) データがコピーされ、無ければ長さチェックで失敗するか走査がフォルトする。パッチは asn1_ex_c2i() を 'long len' にし、'int ilen = (int)len' を計算して len != (long)ilen の場合は prim_c2i、OBJECT、文字列の各分岐で ASN1_R_TOO_LONG で失敗させ、stmp->length / ASN1_STRING_set() には ilen を使う。

## PoC design / PoC の設計

poc_c2i.c: header 04 84 80 00 00 01 + 0x80000001 bytes 'A' (total 2147483655 bytes). do_mmap(): mmap(total rounded up to a page + 1 guard page), mprotect(last page, PROT_NONE), place the data so that it ends exactly at the guard page, call d2i_ASN1_OCTET_STRING(NULL, &p, total). do_malloc(): same data in malloc()ed memory. do_small()/do_big(): regression decodes (5-byte OCTET STRING, UTF8String with U+3042, 1 GiB OCTET STRING). build.sh links against the four builds; run_poc.sh runs each mode once per build (sequentially), with gdb on BASE, valgrind on PATCHED and the patched build's asn1_*_test binaries.

poc_c2i.c: ヘッダ 04 84 80 00 00 01 + 0x80000001 バイトの 'A' (合計 2147483655 バイト)。do_mmap(): mmap(ページ切り上げした total + ガードページ 1 枚)、mprotect(最終ページ, PROT_NONE)、データがガードページでちょうど終わるよう配置し、d2i_ASN1_OCTET_STRING(NULL, &p, total) を呼ぶ。do_malloc(): 同じデータを malloc() したメモリに置く。do_small()/do_big(): 回帰用の復号 (5 バイトの OCTET STRING、U+3042 を含む UTF8String、1 GiB の OCTET STRING)。build.sh が 4 ビルドにリンクし、run_poc.sh が各モードをビルドごとに 1 回ずつ (順番に) 実行し、BASE では gdb、PATCHED では valgrind と修正版ビルドの asn1_*_test バイナリも実行する。

## Observed behaviour BEFORE the patch (evidence excerpts) / パッチ前の挙動 (証拠抜粋)

Unpatched 1.1.1w: d2i_ASN1_OCTET_STRING() on the 2^31+1 byte element dies with SIGSEGV (exit 139). gdb: '#0 __strlen_evex ... #1 ASN1_STRING_set (str=..., _data=..., len_in=-2147483647) at crypto/asn1/asn1_lib.c:280  280  len = strlen(data); #2 asn1_ex_c2i (pval=..., cont=... 'A'..., len=-2147483647, utype=4, ...) at crypto/asn1/tasn_dec.c:906 #3 asn1_d2i_ex_primitive (..., inlen=2147483655, ...) at tasn_dec.c:780 ... #7 d2i_ASN1_OCTET_STRING'. BASE-ASAN with the guard page: 'ERROR: AddressSanitizer: SEGV on unknown address 0x7fce9d7ff000 (= the guard page) ... READ ... #0 __strlen_evex #1 strlen (interceptor) #2 ASN1_STRING_set asn1_lib.c:280 #3 asn1_ex_c2i tasn_dec.c:906'. BASE-ASAN with a heap buffer: 'ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 2147483650 ... #0 strlen #1 ASN1_STRING_set asn1_lib.c:280 #2 asn1_ex_c2i tasn_dec.c:906 ... 0x... is located 0 bytes after 2147483655-byte region'.

未修正 1.1.1w: 2^31+1 バイト要素への d2i_ASN1_OCTET_STRING() は SIGSEGV (exit 139) で異常終了。gdb: '#0 __strlen_evex ... #1 ASN1_STRING_set (str=..., _data=..., len_in=-2147483647) at crypto/asn1/asn1_lib.c:280  280  len = strlen(data); #2 asn1_ex_c2i (pval=..., cont=... 'A'..., len=-2147483647, utype=4, ...) at crypto/asn1/tasn_dec.c:906 #3 asn1_d2i_ex_primitive (..., inlen=2147483655, ...) at tasn_dec.c:780 ... #7 d2i_ASN1_OCTET_STRING'。ガードページ付き BASE-ASAN: 'ERROR: AddressSanitizer: SEGV on unknown address 0x7fce9d7ff000 (= ガードページ) ... READ ... #0 __strlen_evex #1 strlen (インターセプタ) #2 ASN1_STRING_set asn1_lib.c:280 #3 asn1_ex_c2i tasn_dec.c:906'。ヒープバッファの BASE-ASAN: 'ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 2147483650 ... #0 strlen #1 ASN1_STRING_set asn1_lib.c:280 #2 asn1_ex_c2i tasn_dec.c:906 ... 0x... is located 0 bytes after 2147483655-byte region'。

```
Program received signal SIGSEGV, Segmentation fault.
__strlen_evex () at ../sysdeps/x86_64/multiarch/strlen-evex-base.S:143
#0  __strlen_evex () at ../sysdeps/x86_64/multiarch/strlen-evex-base.S:143
#1  ASN1_STRING_set (str=0x55555555a2b0, _data=0x7fff777fefff, len_in=-2147483647) at crypto/asn1/asn1_lib.c:280
#2  asn1_ex_c2i (pval=..., cont=0x7fff777fefff 'A' <repeats 200 times>..., len=-2147483647, utype=4, free_cont=..., it=<ASN1_OCTET_STRING_it>) at crypto/asn1/tasn_dec.c:906
#3  asn1_d2i_ex_primitive (pval=..., in=..., inlen=2147483655, it=<ASN1_OCTET_STRING_it>, tag=4, aclass=0, opt=0, ctx=...) at crypto/asn1/tasn_dec.c:780
#4  asn1_item_embed_d2i (...) at crypto/asn1/tasn_dec.c:181
#5  ASN1_item_ex_d2i (...) at crypto/asn1/tasn_dec.c:124
#6  ASN1_item_d2i (...) at crypto/asn1/tasn_dec.c:114
#7  d2i_ASN1_OCTET_STRING (a=0x0, in=..., len=2147483655) at crypto/asn1/tasn_typ.c:28
280	        len = strlen(data);
$1 = -2147483647
---
==15072==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7fceec3fe807 at pc ... bp ... sp ...
READ of size 2147483650 at 0x7fceec3fe807 thread T0
    #0 in strlen ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:391
    #1 in ASN1_STRING_set ../src_1.1.1w/openssl-1.1.1w/crypto/asn1/asn1_lib.c:280
    #2 in asn1_ex_c2i ../src_1.1.1w/openssl-1.1.1w/crypto/asn1/tasn_dec.c:906
    #3 in asn1_d2i_ex_primitive ../src_1.1.1w/openssl-1.1.1w/crypto/asn1/tasn_dec.c:780
0x7fceec3fe807 is located 0 bytes after 2147483655-byte region [0x7fce6c3fe800,0x7fceec3fe807)
```

## Observed behaviour AFTER the patch / パッチ後の挙動

Patched build (debug and ASan): d2i_ASN1_OCTET_STRING() returns NULL with 'asn1 encoding routines:asn1_ex_c2i:too long:crypto/asn1/tasn_dec.c:970' for both the guard-page and the heap buffer variant; no crash, no sanitizer report (3/3 runs).

修正版 (debug と ASan): ガードページ版・ヒープバッファ版の両方で d2i_ASN1_OCTET_STRING() が 'asn1 encoding routines:asn1_ex_c2i:too long:crypto/asn1/tasn_dec.c:970' を出して NULL を返し、クラッシュもサニタイザ報告も無し (3/3 回)。

```
$ ./poc_c2i_patched mmap
[poc] DER header: 04 84 80 00 00 01 (OCTET STRING, content length 0x80000001 = 2147483649 bytes), total 2147483655 bytes
[poc] (int)0x80000001 = -2147483647  <- length seen by asn1_ex_c2i()/ASN1_STRING_set() in the unpatched code
[poc] calling d2i_ASN1_OCTET_STRING(NULL, &p, 2147483655) ...
...:error:0D0CC09B:asn1 encoding routines:asn1_ex_c2i:too long:../openssl-1.1.1w-ipalongpatch_20261102/crypto/asn1/tasn_dec.c:970:
[poc] d2i_ASN1_OCTET_STRING returned NULL
[poc] finished without crashing
[exit status: 1]
```

## Regression check / 回帰確認

Patched build: ordinary OCTET STRING and UTF8String elements decode correctly (also under ASan and valgrind, no errors/leaks), a valid 1 GiB OCTET STRING decodes with length 1073741824, the patched build's asn1_encode_test / asn1_decode_test / asn1_string_table_test / asn1_time_test / asn1_internal_test all pass, and the patched openssl decodes an X.509 certificate, signs and verifies a PKCS#7 message and parses it with asn1parse.

修正版: 通常の OCTET STRING と UTF8String は正しく復号でき (ASan と valgrind 下でもエラー・リーク無し)、正当な 1 GiB の OCTET STRING は length 1073741824 で復号され、修正版ビルドの asn1_encode_test / asn1_decode_test / asn1_string_table_test / asn1_time_test / asn1_internal_test はすべて合格、修正版 openssl による X.509 証明書の復号、PKCS#7 の署名・検証、asn1parse も正常。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/024_CVE-2026-34180
./build.sh                                   # poc_c2i_{base,base_asan,patched,patched_asan}
./poc_c2i_base mmap                           # unpatched: SIGSEGV in strlen (needs ~2 GiB RAM)
LD_LIBRARY_PATH=/home/user/work/base/openssl-1.1.1w gdb -q -batch -ex run -ex bt --args ./poc_c2i_base mmap
ASAN_OPTIONS=detect_leaks=0 ./poc_c2i_base_asan malloc      # heap-buffer-overflow READ of size 2147483650 by strlen
./poc_c2i_patched mmap                        # 'asn1_ex_c2i:too long', returns NULL
./poc_c2i_patched small ; ./poc_c2i_patched big              # regression
./run_poc.sh                                  # everything (memory-heavy cases run one at a time)
```

## Limitations / notes / 制限事項・注記

The issue needs more than 2 GiB of attacker-controlled input to a d2i_* function, so it is demonstrated with a C program and synthetic data rather than an openssl command (the command line tools are not affected, as the advisory states). The 'memory disclosure' variant (a NUL found within INT_MAX-1 bytes beyond the buffer so that foreign memory is copied) was not demonstrated; with this input the scan either faults (shown) or ends with a length that ASN1_STRING_set() rejects.

この問題は d2i_* 関数に 2 GiB 超の攻撃者制御入力が必要なため、openssl コマンドではなく C プログラムと合成データで実証した (アドバイザリどおりコマンドラインツールは非影響)。「メモリ漏えい」の変種 (バッファの先 INT_MAX-1 バイト以内に NUL があり外部メモリがコピーされる) は実証していない。本入力では走査がフォルトする (実証済み) か、ASN1_STRING_set() が拒否する長さで終わる。
