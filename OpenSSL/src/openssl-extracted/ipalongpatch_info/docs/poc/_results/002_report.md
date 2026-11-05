# 002 of 033 — CVE-2024-0727 (PKCS12-NULL-ContentInfo-crash)

Log file: `20261102_120658_002of033_CVE-2024-0727_PKCS12-NULL-ContentInfo-crash.log`

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の確認)

crypto/pkcs7/pk7_asn1.c declares every PKCS#7 content as ASN1_NDEF_EXP_OPT (OPTIONAL), so after d2i a ContentInfo with a valid type OID but no [0] content has p7->d.ptr == NULL. In the pristine 1.1.1w, PKCS12_unpack_authsafes() (p12_add.c:162) passes p12->authsafes->d.data straight to ASN1_item_unpack(), which reads oct->data (asn_pack.c:58); PKCS12_unpack_p7data() (p12_add.c:79) does the same with p7->d.data; PKCS12_unpack_p7encdata() (p12_add.c:138) reads p7->d.encrypted->enc_data; pkcs12_gen_mac() (p12_mutl.c:131) reads p12->authsafes->d.data->length for the HMAC input; newpass_p12() (p12_npas.c:81) reads p7->d.encrypted->enc_data->algorithm. All five are reachable from PKCS12_parse(), PKCS12_verify_mac(), PKCS12_newpass() and the openssl pkcs12 command.

crypto/pkcs7/pk7_asn1.c は PKCS#7 の全 content を ASN1_NDEF_EXP_OPT (OPTIONAL) として宣言しており、type OID は正しいが [0] content の無い ContentInfo を d2i すると p7->d.ptr == NULL になる。素の 1.1.1w では PKCS12_unpack_authsafes() (p12_add.c:162) が p12->authsafes->d.data をそのまま ASN1_item_unpack() に渡し、そこで oct->data (asn_pack.c:58) が読まれる。PKCS12_unpack_p7data() (p12_add.c:79) も p7->d.data で同様、PKCS12_unpack_p7encdata() (p12_add.c:138) は p7->d.encrypted->enc_data を、pkcs12_gen_mac() (p12_mutl.c:131) は HMAC 入力として p12->authsafes->d.data->length を、newpass_p12() (p12_npas.c:81) は p7->d.encrypted->enc_data->algorithm を読む。いずれも PKCS12_parse()、PKCS12_verify_mac()、PKCS12_newpass() および openssl pkcs12 コマンドから到達可能である。

The IPALongPatch 002 (semantic backport of upstream commit d135eeab / Ubuntu CVE-2024-0727.patch) inserts 'if (p7->d.data == NULL) { PKCS12err(..., PKCS12_R_DECODE_ERROR); return NULL; }' style checks in the three p12_add.c functions, a check in pkcs12_gen_mac(), the 'p7->d.encrypted == NULL ||' guard in newpass_p12(), and a p7->d.sign NULL check in SMIME_write_PKCS7().

IPALongPatch 002 (上流コミット d135eeab / Ubuntu CVE-2024-0727.patch の意味的バックポート) は、p12_add.c の 3 関数に 'if (p7->d.data == NULL) { PKCS12err(..., PKCS12_R_DECODE_ERROR); return NULL; }' 型のチェックを、pkcs12_gen_mac() にもチェックを、newpass_p12() に 'p7->d.encrypted == NULL ||' のガードを、SMIME_write_PKCS7() に p7->d.sign の NULL チェックを追加する。

## PoC design / PoC の設計

good.p12 is produced by the unpatched 'openssl pkcs12 -export' (servercert.pem/serverkey.pem, password x). make_bad.py (pure Python 3, python3 -I) parses the DER into a tree, deletes the [0] EXPLICIT content of (a) the outer authSafes ContentInfo, (b) the inner pkcs7-data ContentInfo, or (c) the inner pkcs7-encryptedData ContentInfo, re-encodes all enclosing lengths, and for (b)/(c) recomputes the MAC (PKCS#12 KDF id=3 + HMAC-SHA1, iteration count and salt taken from the file; self-checked by reproducing the stored MAC of good.p12). poc_api.c calls PKCS12_parse(), PKCS12_newpass() or PKCS12_unpack_authsafes()+PKCS12_unpack_p7data()/PKCS12_unpack_p7encdata() on a file. run_poc.sh executes everything against BASE/BASE-ASAN/PATCHED/PATCHED-ASAN, takes gdb backtraces, runs the regression tests and valgrind, and prints the verdict.

good.p12 は未修正の 'openssl pkcs12 -export' (servercert.pem/serverkey.pem、パスワード x) で作成する。make_bad.py (純 Python 3、python3 -I) は DER を木構造に解析し、(a) 外側 authSafes ContentInfo、(b) 内側 pkcs7-data ContentInfo、(c) 内側 pkcs7-encryptedData ContentInfo のいずれかの [0] EXPLICIT content を削除し、上位の長さをすべて再エンコードし、(b)(c) では MAC を再計算する (PKCS#12 KDF id=3 + HMAC-SHA1、反復回数と salt はファイルから取得。good.p12 の格納 MAC を再現できることで自己検証)。poc_api.c はファイルに対して PKCS12_parse()、PKCS12_newpass()、または PKCS12_unpack_authsafes()+PKCS12_unpack_p7data()/PKCS12_unpack_p7encdata() を呼ぶ。run_poc.sh が BASE/BASE-ASAN/PATCHED/PATCHED-ASAN に対する全実行、gdb バックトレース取得、回帰テスト、valgrind を行い判定を表示する。

## Observed behaviour BEFORE the patch (evidence excerpts) / パッチ前の挙動 (証拠抜粋)

Unpatched 1.1.1w: 'openssl pkcs12 -in bad_*.p12 -nodes -passin pass:x [-nomacver]' dies with SIGSEGV (exit 139) for all three variants (6/6 runs). gdb: variant (a) -> ASN1_item_unpack (oct=0x0) <- PKCS12_unpack_authsafes (p12_add.c:162), or, when the MAC is verified, pkcs12_gen_mac (p12_mutl.c:131) reading p12->authsafes->d.data->length; variant (b) -> ASN1_item_unpack (oct=0x0) <- PKCS12_unpack_p7data (p12_add.c:79); variant (c) -> PKCS12_unpack_p7encdata (p12_add.c:138) 'p7->d.encrypted->enc_data->enc_data' with d.encrypted NULL, also reached through PKCS12_newpass -> newpass_p12 (p12_npas.c:80). BASE-ASAN: all 12 CLI/API runs report 'AddressSanitizer: SEGV on unknown address 0x000000000008 ... Hint: address points to the zero page' at the same source lines.

未修正 1.1.1w: 'openssl pkcs12 -in bad_*.p12 -nodes -passin pass:x [-nomacver]' は 3 種すべてで SIGSEGV (exit 139) で異常終了した (6/6 回)。gdb: (a) -> ASN1_item_unpack (oct=0x0) <- PKCS12_unpack_authsafes (p12_add.c:162)、MAC 検証時は pkcs12_gen_mac (p12_mutl.c:131) で p12->authsafes->d.data->length を読んで落ちる。(b) -> ASN1_item_unpack (oct=0x0) <- PKCS12_unpack_p7data (p12_add.c:79)。(c) -> PKCS12_unpack_p7encdata (p12_add.c:138) の 'p7->d.encrypted->enc_data->enc_data' で d.encrypted が NULL、PKCS12_newpass -> newpass_p12 (p12_npas.c:80) 経由でも同じ。BASE-ASAN: CLI/API の 12 回すべてで同じ行に対する 'AddressSanitizer: SEGV on unknown address 0x000000000008 ... Hint: address points to the zero page' が報告された。

```
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7a9c281 in ASN1_item_unpack (oct=0x0, it=0x7ffff7d3d0c0 <PKCS12_AUTHSAFES_it>) at crypto/asn1/asn_pack.c:58
58	    p = oct->data;
#0  ASN1_item_unpack (oct=0x0, ...) at crypto/asn1/asn_pack.c:58
#1  PKCS12_unpack_authsafes (p12=0x55555564ea60) at crypto/pkcs12/p12_add.c:162
#2  dump_certs_keys_p12 (...) at apps/pkcs12.c:606
---
Program received signal SIGSEGV, Segmentation fault.
PKCS12_unpack_p7encdata (p7=0x55555564fd80, pass="x", passlen=-1) at crypto/pkcs12/p12_add.c:138
138	                                   p7->d.encrypted->enc_data->enc_data, 1);
---
==904==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000008 (pc ... T0)
==904==The signal is caused by a READ memory access.
==904==Hint: address points to the zero page.
    #0 in PKCS12_unpack_p7encdata ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_add.c:138
    #1 in newpass_p12 ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_npas.c:80
    #2 in PKCS12_newpass ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_npas.c:49
```

## Observed behaviour AFTER the patch / パッチ後の挙動

Patched build (debug and ASan): every run exits with status 1 and a clean error: 'PKCS12_unpack_authsafes:decode error' (variant a, -nomacver), 'PKCS12_gen_mac:decode error' + 'mac verify failure' (variant a, MAC path / PKCS12_parse), 'PKCS12_unpack_p7data:decode error' (variant b), decode error from PKCS12_unpack_p7encdata (variant c; reported under the PKCS12_unpack_p7data function code as in the upstream fix) and 'PKCS12_newpass:parse error'. No crash, no sanitizer report (27/27 runs).

修正版 (debug と ASan): すべての実行が exit 1 で正常にエラー終了した: 'PKCS12_unpack_authsafes:decode error' ((a) -nomacver)、'PKCS12_gen_mac:decode error' + 'mac verify failure' ((a) MAC 経路 / PKCS12_parse)、'PKCS12_unpack_p7data:decode error' ((b))、PKCS12_unpack_p7encdata からの decode error ((c)、上流修正と同様 PKCS12_unpack_p7data の関数コードで報告)、'PKCS12_newpass:parse error'。クラッシュもサニタイザ報告も無し (27/27 回)。

```
$ openssl pkcs12 -in bad_a_authsafes_nocontent.p12 -nodes -passin pass:x -nomacver -out /dev/null
Error outputting keys and certificates
...:error:23082065:PKCS12 routines:PKCS12_unpack_authsafes:decode error:...crypto/pkcs12/p12_add.c:238:
[exit status: 1]
$ ./poc_api_patched bad_c_inner_encdata_nocontent.p12 newpass x
...:error:23083065:PKCS12 routines:PKCS12_unpack_p7data:decode error:...crypto/pkcs12/p12_add.c:185:
...:error:23080072:PKCS12 routines:PKCS12_newpass:parse error:...crypto/pkcs12/p12_npas.c:50:
[poc_api] PKCS12_newpass returned 0
[poc_api] finished without crashing, result=failure
```

## Regression check / 回帰確認

With the patched build, good.p12 is imported with 'openssl pkcs12 -info' (MAC sha1/2048 iterations, certificate bag and shrouded key bag dumped, exit 0), PKCS12_parse()/PKCS12_newpass()/PKCS12_unpack_* return success, a new PKCS#12 exported by the patched build re-imports correctly, PATCHED-ASAN reports nothing, and valgrind --leak-check=full shows no errors and no leaks for both good.p12 and malformed variant (c).

修正版で good.p12 を 'openssl pkcs12 -info' で取り込み (MAC sha1/2048 反復、証明書バッグと shrouded key bag を出力、exit 0)、PKCS12_parse()/PKCS12_newpass()/PKCS12_unpack_* が成功を返し、修正版でエクスポートした新規 PKCS#12 の再取り込みも成功、PATCHED-ASAN は報告無し、valgrind --leak-check=full は good.p12 と不正ファイル (c) の両方でエラー・リーク無しであった。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/002_CVE-2024-0727
BASE=/home/user/work/base/openssl-1.1.1w; PAT=/home/user/work/patched/build; SRC=/home/user/work/src_1.1.1w/openssl-1.1.1w
# 1. regular file
$BASE/util/shlib_wrap.sh $BASE/apps/openssl pkcs12 -export -in $SRC/test/certs/servercert.pem -inkey $SRC/test/certs/serverkey.pem -name testname -passout pass:x -out good.p12
# 2. malformed variants (a) authSafes without content, (b) inner pkcs7-data without content, (c) inner pkcs7-encryptedData without content
python3 -I make_bad.py good.p12 x
# 3. unpatched build: segmentation fault (exit 139) in each case
$BASE/util/shlib_wrap.sh $BASE/apps/openssl pkcs12 -in bad_a_authsafes_nocontent.p12 -nodes -passin pass:x -nomacver -out /dev/null
$BASE/util/shlib_wrap.sh $BASE/apps/openssl pkcs12 -in bad_b_inner_data_nocontent.p12 -nodes -passin pass:x -out /dev/null
$BASE/util/shlib_wrap.sh $BASE/apps/openssl pkcs12 -in bad_c_inner_encdata_nocontent.p12 -nodes -passin pass:x -out /dev/null
LD_LIBRARY_PATH=$BASE gdb -q -batch -ex run -ex bt --args $BASE/apps/openssl pkcs12 -in bad_c_inner_encdata_nocontent.p12 -nodes -passin pass:x -out /dev/null
# 4. patched build: clean 'decode error', exit 1
$PAT/util/shlib_wrap.sh $PAT/apps/openssl pkcs12 -in bad_c_inner_encdata_nocontent.p12 -nodes -passin pass:x -out /dev/null
# 5. API level (PKCS12_parse / PKCS12_newpass / PKCS12_unpack_*)
./build.sh && ./poc_api_base bad_c_inner_encdata_nocontent.p12 newpass x ; ./poc_api_patched bad_c_inner_encdata_nocontent.p12 newpass x
# 6. everything at once (BASE, BASE-ASAN, PATCHED, PATCHED-ASAN, gdb, regression, valgrind)
./run_poc.sh
```

## Limitations / notes / 制限事項・注記

The SMIME_write_PKCS7() part of the patch (p7->d.sign NULL check) is a write-side hardening that upstream does not consider security relevant; it was not exercised separately. Variant (a) cannot carry a valid MAC (there is no authSafes content to MAC), so the MAC path for (a) crashes inside pkcs12_gen_mac() rather than in the unpack functions; variants (b)/(c) carry a recomputed valid MAC and crash after successful MAC verification. For variant (c) the patched error is reported under the PKCS12_unpack_p7data function code (PKCS12_F_PKCS12_UNPACK_P7DATA), exactly as in the upstream 1.1.1 fix; this is cosmetic.

パッチのうち SMIME_write_PKCS7() の部分 (p7->d.sign の NULL チェック) は書き込み側の堅牢化で上流もセキュリティ上重要とは見ていないため、個別には検証していない。(a) は MAC 対象の authSafes content 自体が無いため正しい MAC を持てず、MAC 経路では unpack 関数ではなく pkcs12_gen_mac() 内でクラッシュする。(b)(c) は再計算した正しい MAC を持ち、MAC 検証成功後にクラッシュする。(c) の修正版エラーは上流 1.1.1 修正と同じく PKCS12_unpack_p7data の関数コード (PKCS12_F_PKCS12_UNPACK_P7DATA) で報告されるが、表示上の問題に過ぎない。
