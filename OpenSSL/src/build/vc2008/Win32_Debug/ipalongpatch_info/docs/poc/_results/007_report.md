# 007 / CVE-2024-9143 / GF2m-poly2arr-OOB-memory-access

Log file / ログファイル: `20261102_121100_007of033_CVE-2024-9143_GF2m-poly2arr-OOB-memory-access.log` (in /home/user/work/deliver/ipalongpatch_info/logs/)

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

`BN_GF2m_poly2arr()` (crypto/bn/bn_gf2m.c) only rejected the zero polynomial. `BN_GF2m_mod_arr()` walks the exponent array with `for (k = 1; p[k] != 0; k++)` and computes `n = p[0] - p[k]`, `z[j - n] ^= ...`: for an even polynomial (no constant term) the loop passes the `-1` terminator and uses the memory after the array (in `struct ec_group_st`, the `BIGNUM *a` pointer following `int poly[6]`) as exponents, giving wild indices. A hexanomial exactly fills `poly[6]` without a terminator and the old return value (6) looked like a pentanomial, so `ec_GF2m_simple_group_set_curve()` accepted it and `-1`-terminated consumers (`BN_GF2m_arr2poly` via `BN_GF2m_mod_inv_arr`) over-read. Patch 007 rejects non-odd polynomials and degrees > OPENSSL_ECC_MAX_FIELD_BITS (661) and returns k+1 unambiguously, so the EC check `(i != 5 && i != 3)` rejects all three classes (EC_R_UNSUPPORTED_FIELD) and `BN_GF2m_mod_mul()` fails with BN_R_INVALID_LENGTH.

`BN_GF2m_poly2arr()` (crypto/bn/bn_gf2m.c) はゼロ多項式しか拒否していなかった。`BN_GF2m_mod_arr()` は `for (k = 1; p[k] != 0; k++)` で指数配列を走査し `n = p[0] - p[k]`、`z[j - n] ^= ...` を計算する。偶数多項式 (定数項なし) ではループが `-1` 終端を通過し、配列の後ろのメモリ (`struct ec_group_st` では `int poly[6]` に続く `BIGNUM *a` ポインタ) を指数として使うため異常なインデックスになる。六項式は `poly[6]` を終端なしにちょうど埋め、旧戻り値 (6) は五項式と同じに見えるため `ec_GF2m_simple_group_set_curve()` が受理し、`-1` 終端前提の利用側 (`BN_GF2m_mod_inv_arr` 経由の `BN_GF2m_arr2poly`) が読み過ぎる。パッチ 007 は奇数でない多項式と次数 > OPENSSL_ECC_MAX_FIELD_BITS (661) を拒否し k+1 を一意に返すため、EC 側の検査 `(i != 5 && i != 3)` が 3 種類すべてを拒否し (EC_R_UNSUPPORTED_FIELD)、`BN_GF2m_mod_mul()` は BN_R_INVALID_LENGTH で失敗する。

## PoC design / PoC の設計

`gf2m_poc.c <case>` exercises `EC_GROUP_new_curve_GF2m()`, `EC_POINT_set_compressed_coordinates_GF2m()/EC_POINT_mul()`, `BN_GF2m_mod_mul()` and `BN_GF2m_poly2arr()+BN_GF2m_mod_inv_arr()` with: 0xf2 (even), 0xf3 (hexanomial), x^662+... (degree 662), the even pentanomial x^163+x^7+x^6+x^3+x, the hexanomial x^163+x^7+x^6+x^3+x^2+1, and the benign sect163k1 polynomial. Built against BASE-ASAN / PATCHED-ASAN (ASan reports) and BASE / PATCHED (gdb). `run_poc.sh` runs everything and the regression checks.

`gf2m_poc.c <case>` は 0xf2 (偶数)、0xf3 (六項式)、x^662+... (次数 662)、偶数五項式 x^163+x^7+x^6+x^3+x、六項式 x^163+x^7+x^6+x^3+x^2+1、正常な sect163k1 多項式を用いて `EC_GROUP_new_curve_GF2m()`、`EC_POINT_set_compressed_coordinates_GF2m()/EC_POINT_mul()`、`BN_GF2m_mod_mul()`、`BN_GF2m_poly2arr()+BN_GF2m_mod_inv_arr()` を実行する。BASE-ASAN / PATCHED-ASAN (ASan 報告) と BASE / PATCHED (gdb) 向けにビルドし、`run_poc.sh` が全体と回帰確認を実行する。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
$ ./gf2m_poc_base_asan even_small      -> returned a group (polynomial ACCEPTED, degree 7)
$ ./gf2m_poc_base_asan hexa_small      -> returned a group (polynomial ACCEPTED, degree 7)
$ ./gf2m_poc_base_asan degree          -> returned a group (polynomial ACCEPTED, degree 662)
$ ./gf2m_poc_base_asan even163_curve
==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 8
    #0 BN_GF2m_mod_arr crypto/bn/bn_gf2m.c:336
    #1 ec_GF2m_simple_group_set_curve crypto/ec/ec2_smpl.c:111
    #3 EC_GROUP_new_curve_GF2m crypto/ec/ec_cvt.c:75
 ... is located 16 bytes after 56-byte region ... allocated by bn_wexpand
$ ./gf2m_poc_base_asan even163_mul
==ERROR: AddressSanitizer: SEGV on unknown address ... READ
    #0 BN_GF2m_mod_arr bn_gf2m.c:336  #1 BN_GF2m_mod_mul_arr  #2 BN_GF2m_mod_mul  #3 BN_GF2m_mod_inv
    #4 BN_GF2m_mod_div  #5 ec_GF2m_simple_field_div  #8 EC_POINT_set_compressed_coordinates_GF2m
$ ./gf2m_poc_base_asan modmul_api      -> SEGV in BN_GF2m_mod_arr via BN_GF2m_mod_mul
$ ./gf2m_poc_base_asan hexa_arr_inv
  BN_GF2m_poly2arr(p, arr, 6) returned 6   arr = {163, 7, 6, 3, 2, 0}   (no -1 terminator)
==ERROR: AddressSanitizer: stack-buffer-overflow ... READ of size 4
    #0 BN_GF2m_arr2poly bn_gf2m.c:1157   #1 BN_GF2m_mod_inv_arr bn_gf2m.c:775
$ gdb ... ./gf2m_poc_base even163_curve
Program received signal SIGSEGV   BN_GF2m_mod_arr (...) at crypto/bn/bn_gf2m.c:336
336   z[j - n] ^= (zz >> d0);
k = 6   p[0]@8 = {163, 7, 6, 3, 1, -1, 1431684288, 21845}   n = -22370064
r->top = r->dmax = 7   z = 0x55555555b3e0   &z[j-n] = 0x555560006c90
```

The exponent loop runs past the `-1` terminator and uses the halves of the following `BIGNUM *` pointer (0x5555 5555C4C0) as exponents; the resulting write target is ~179 MB beyond the 7-word buffer.

指数ループが `-1` 終端を通過し、後続の `BIGNUM *` ポインタ (0x5555 5555C4C0) の上下半分を指数として使うため、書き込み先は 7 ワードのバッファから約 179 MB 先になる。

## Observed behaviour AFTER the patch / 修正後の挙動

```
$ ./gf2m_poc_patched_asan even_small|hexa_small|degree|even163_curve|even163_mul|hexa163_inv
  -> returned NULL (polynomial REJECTED)
     error:100C3083:elliptic curve routines:ec_GF2m_simple_group_set_curve:unsupported field
$ ./gf2m_poc_patched_asan modmul_api
  -> BN_GF2m_mod_mul returned 0   error:0308506A:bignum routines:BN_GF2m_mod_mul:invalid length
$ ./gf2m_poc_patched_asan hexa_arr_inv
  BN_GF2m_poly2arr(p, arr, 6) returned 7 -> rejected by the EC-style size check, BN_GF2m_mod_inv_arr() not called
```

No AddressSanitizer report in any patched case.

修正版ではどのケースでも AddressSanitizer の報告は無い。

## Regression check / 回帰確認

valid163 (sect163k1 polynomial) gives identical EC_POINT_mul results on BASE and PATCHED. Patched command line: sect163k1/sect233r1/sect283k1/sect571r1 `ecparam -genkey`, `ec -check`, ECDSA sign + verify ("Verified OK"); explicit-parameter sect233r1 (trinomial) and sect571r1 (pentanomial): `ecparam -check` ok and sign/verify ok. Patched `test/ec_internal_test` (incl. `ok 3 - ec2m_field_sanity`) and `test/ectest` pass. valgrind clean.

valid163 (sect163k1 多項式) の EC_POINT_mul 結果は BASE と PATCHED で同一。修正済みコマンドライン: sect163k1/sect233r1/sect283k1/sect571r1 の `ecparam -genkey`、`ec -check`、ECDSA 署名+検証 ("Verified OK"); 明示パラメータの sect233r1 (三項式) と sect571r1 (五項式): `ecparam -check` ok、署名検証 ok。修正済みビルドの `test/ec_internal_test` (`ok 3 - ec2m_field_sanity` を含む) と `test/ectest` が合格。valgrind 問題なし。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/007_CVE-2024-9143
BA=/home/user/work/base_asan; S=/home/user/work/src_1.1.1w/openssl-1.1.1w
PA=/home/user/work/patched/build-asan; PS=/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102
B=/home/user/work/base/openssl-1.1.1w
gcc -g -O0 -Wall -fsanitize=address -I$BA/include -I$S/include gf2m_poc.c -L$BA -lcrypto -Wl,-rpath,$BA -o gf2m_poc_base_asan
gcc -g -O0 -Wall -fsanitize=address -I$PA/include -I$PS/include gf2m_poc.c -L$PA -lcrypto -Wl,-rpath,$PA -o gf2m_poc_patched_asan
gcc -g -O0 -Wall -I$B/include gf2m_poc.c -L$B -lcrypto -Wl,-rpath,$B -o gf2m_poc_base
export ASAN_OPTIONS=detect_leaks=0
./gf2m_poc_base_asan even163_curve      # heap-buffer-overflow in BN_GF2m_mod_arr
./gf2m_poc_base_asan hexa_arr_inv       # stack-buffer-overflow in BN_GF2m_arr2poly
./gf2m_poc_patched_asan even163_curve   # returned NULL (unsupported field)
gdb -q -batch -ex run -ex bt -ex 'print/d p[0]@8' -ex 'print n' --args ./gf2m_poc_base even163_curve
./run_poc.sh                            # everything, with verdict
```

## Limitations / notes / 制限事項・注記

The inputs cannot be reached through X.509/TLS (per the advisory), so the low-level API is used directly. The wild address depends on heap layout but was detected by ASan (or crashed with SIGSEGV) in every run. The hexanomial over-read is shown with the public `BN_GF2m_mod_inv_arr()`; inside the EC code a hexanomial only leads to erroneous acceptance. The first run_poc.sh run had a script error in one regression step (`ecparam -check` on a key file); fixed and re-run, both outputs kept.

アドバイザリの通り X.509/TLS からは到達できないため低レベル API を直接使用した。異常アドレスはヒープ配置に依存するが、全実行で ASan が検出 (または SIGSEGV) した。六項式の読み過ぎは公開 API `BN_GF2m_mod_inv_arr()` で示した (EC コード内部では誤受理に留まる)。run_poc.sh 初回は回帰の 1 手順 (鍵ファイルへの `ecparam -check`) にスクリプト誤りがあり、修正して再実行、両出力を保持。
