# 014 of 033 — CVE-2025-69421 (PKCS12-item-decrypt-NULL-deref)

Log file: `20261102_121856_014of033_CVE-2025-69421_PKCS12-item-decrypt-NULL-deref.log`

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の確認)

crypto/pkcs7/pk7_asn1.c: 'ASN1_IMP_OPT(PKCS7_ENC_CONTENT, enc_data, ASN1_OCTET_STRING_NDEF, 0)' - encryptedContent is optional, so d2i leaves enc_data->enc_data NULL when the field is missing. crypto/pkcs12/p12_add.c PKCS12_unpack_p7encdata() (line 135-138) calls PKCS12_item_decrypt_d2i(algorithm, PKCS12_SAFEBAGS, pass, passlen, p7->d.encrypted->enc_data->enc_data, 1) without a NULL check, and crypto/pkcs12/p12_decr.c:91 'PKCS12_pbe_crypt(algor, pass, passlen, oct->data, oct->length, ...)' dereferences the NULL oct. Callers: parse_pk12() (PKCS12_parse), newpass_p12() (PKCS12_newpass), dump_certs_keys_p12() (openssl pkcs12). The patch inserts the oct == NULL check (ERR_R_PASSED_NULL_PARAMETER) at the top of PKCS12_item_decrypt_d2i(), which also protects PKCS8_decrypt() callers.

crypto/pkcs7/pk7_asn1.c: 'ASN1_IMP_OPT(PKCS7_ENC_CONTENT, enc_data, ASN1_OCTET_STRING_NDEF, 0)' — encryptedContent は OPTIONAL であり、欠落時には d2i が enc_data->enc_data を NULL のまま残す。crypto/pkcs12/p12_add.c の PKCS12_unpack_p7encdata() (135〜138 行) は NULL チェック無しに PKCS12_item_decrypt_d2i(algorithm, PKCS12_SAFEBAGS, pass, passlen, p7->d.encrypted->enc_data->enc_data, 1) を呼び、crypto/pkcs12/p12_decr.c:91 の 'PKCS12_pbe_crypt(algor, pass, passlen, oct->data, oct->length, ...)' が NULL の oct を参照する。呼び出し元: parse_pk12() (PKCS12_parse)、newpass_p12() (PKCS12_newpass)、dump_certs_keys_p12() (openssl pkcs12)。パッチは PKCS12_item_decrypt_d2i() の先頭に oct == NULL チェック (ERR_R_PASSED_NULL_PARAMETER) を挿入し、PKCS8_decrypt() 経由の呼び出しも保護する。

## PoC design / PoC の設計

good.p12 from the unpatched 'openssl pkcs12 -export' (defaults: cert bag in pkcs7-encryptedData with RC2-40, key as shrouded key bag, MAC SHA-1/2048). make_bad.py parses the DER, descends into authSafes -> AuthenticatedSafe -> the pkcs7-encryptedData ContentInfo -> EncryptedData -> EncryptedContentInfo, removes the element with tag 0x80 ([0] IMPLICIT encryptedContent), re-encodes and recomputes the MAC (RFC 7292 KDF + HMAC-SHA1). poc_api.c (same program as item 002) calls PKCS12_parse(), PKCS12_newpass() or PKCS12_unpack_authsafes()+PKCS12_unpack_p7data()/PKCS12_unpack_p7encdata(). run_poc.sh runs all steps on the four builds, takes gdb backtraces, performs the regression checks and valgrind runs and prints a verdict.

good.p12 は未修正の 'openssl pkcs12 -export' (既定: 証明書バッグは RC2-40 の pkcs7-encryptedData、鍵は shrouded key bag、MAC は SHA-1/2048) で作成。make_bad.py は DER を解析し authSafes -> AuthenticatedSafe -> pkcs7-encryptedData の ContentInfo -> EncryptedData -> EncryptedContentInfo と降りて、タグ 0x80 の要素 ([0] IMPLICIT encryptedContent) を削除し、再エンコードして MAC を再計算 (RFC 7292 KDF + HMAC-SHA1) する。poc_api.c (項目 002 と同じプログラム) は PKCS12_parse()、PKCS12_newpass()、または PKCS12_unpack_authsafes()+PKCS12_unpack_p7data()/PKCS12_unpack_p7encdata() を呼ぶ。run_poc.sh が 4 ビルドで全ステップを実行し、gdb バックトレース、回帰確認、valgrind を行い判定を出す。

## Observed behaviour BEFORE the patch (evidence excerpts) / パッチ前の挙動 (証拠抜粋)

Unpatched 1.1.1w: 'openssl pkcs12 -in bad_no_encryptedcontent.p12 -nodes -passin pass:x' (MAC verifies) and the PKCS12_parse()/PKCS12_newpass()/PKCS12_unpack_* API runs all die with SIGSEGV (exit 139, 4/4). gdb: 'PKCS12_item_decrypt_d2i (algor=..., it=<PKCS12_SAFEBAGS_it>, pass="x", passlen=-1, oct=0x0, zbuf=1) at crypto/pkcs12/p12_decr.c:91  91  if (!PKCS12_pbe_crypt(algor, pass, passlen, oct->data, oct->length,' called from PKCS12_unpack_p7encdata (p12_add.c:135) <- dump_certs_keys_p12 / parse_pk12 <- PKCS12_parse. BASE-ASAN: 'AddressSanitizer: SEGV on unknown address 0x000000000000 ... READ ... #0 PKCS12_item_decrypt_d2i p12_decr.c:91 #1 PKCS12_unpack_p7encdata p12_add.c:135' in all 4 runs.

未修正 1.1.1w: 'openssl pkcs12 -in bad_no_encryptedcontent.p12 -nodes -passin pass:x' (MAC は検証成功) と PKCS12_parse()/PKCS12_newpass()/PKCS12_unpack_* の API 実行はすべて SIGSEGV (exit 139、4/4) で異常終了。gdb: 'PKCS12_item_decrypt_d2i (algor=..., it=<PKCS12_SAFEBAGS_it>, pass="x", passlen=-1, oct=0x0, zbuf=1) at crypto/pkcs12/p12_decr.c:91  91  if (!PKCS12_pbe_crypt(algor, pass, passlen, oct->data, oct->length,'、呼び出し元は PKCS12_unpack_p7encdata (p12_add.c:135) <- dump_certs_keys_p12 / parse_pk12 <- PKCS12_parse。BASE-ASAN: 4 回すべてで 'AddressSanitizer: SEGV on unknown address 0x000000000000 ... READ ... #0 PKCS12_item_decrypt_d2i p12_decr.c:91 #1 PKCS12_unpack_p7encdata p12_add.c:135'。

```
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7be6b47 in PKCS12_item_decrypt_d2i (algor=0x55555564fde0, it=0x7ffff7d3d080 <PKCS12_SAFEBAGS_it>, pass=0x55555564e6b0 "x", passlen=-1, oct=0x0, zbuf=1) at crypto/pkcs12/p12_decr.c:91
91	    if (!PKCS12_pbe_crypt(algor, pass, passlen, oct->data, oct->length,
#0  PKCS12_item_decrypt_d2i (..., oct=0x0, zbuf=1) at crypto/pkcs12/p12_decr.c:91
#1  PKCS12_unpack_p7encdata (p7=0x55555564fd80, pass="x", passlen=-1) at crypto/pkcs12/p12_add.c:135
#2  dump_certs_keys_p12 (...) at apps/pkcs12.c:620
$1 = (const ASN1_OCTET_STRING *) 0x0
---
==4797==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc ... T0)
==4797==The signal is caused by a READ memory access.
==4797==Hint: address points to the zero page.
    #0 in PKCS12_item_decrypt_d2i ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_decr.c:91
    #1 in PKCS12_unpack_p7encdata ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_add.c:135
    #2 in parse_pk12 ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_kiss.c:147
    #3 in PKCS12_parse ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_kiss.c:82
```

## Observed behaviour AFTER the patch / パッチ後の挙動

Patched build (debug and ASan): every run exits with status 1 and 'PKCS12 routines:PKCS12_item_decrypt_d2i:passed a null parameter:crypto/pkcs12/p12_decr.c:113' (followed by 'PKCS12_parse:parse error' / 'PKCS12_newpass:parse error' for the API); no crash, no sanitizer report (8/8).

修正版 (debug と ASan): すべての実行が exit 1 で 'PKCS12 routines:PKCS12_item_decrypt_d2i:passed a null parameter:crypto/pkcs12/p12_decr.c:113' (API では続けて 'PKCS12_parse:parse error' / 'PKCS12_newpass:parse error') を出し、クラッシュもサニタイザ報告も無し (8/8)。

```
$ openssl pkcs12 -in bad_no_encryptedcontent.p12 -nodes -passin pass:x -out /dev/null
Error outputting keys and certificates
...:error:2306A043:PKCS12 routines:PKCS12_item_decrypt_d2i:passed a null parameter:../openssl-1.1.1w-ipalongpatch_20261102/crypto/pkcs12/p12_decr.c:113:
[exit status: 1]
```

## Regression check / 回帰確認

Patched build: good.p12 imports with -info (exit 0, certificate and key dumped), PKCS12_parse()/PKCS12_newpass()/PKCS12_unpack_* succeed, a file exported by the patched build re-imports, PATCHED-ASAN is silent, a wrong password is still rejected with 'Mac verify error', and valgrind --leak-check=full shows no errors/leaks for the malformed and the benign file.

修正版: good.p12 は -info 付きで取り込める (exit 0、証明書と鍵を出力)、PKCS12_parse()/PKCS12_newpass()/PKCS12_unpack_* は成功、修正版でエクスポートしたファイルの再取り込みも成功、PATCHED-ASAN は無報告、誤パスワードは引き続き 'Mac verify error' で拒否、valgrind --leak-check=full は不正ファイル・正規ファイルともエラー・リーク無し。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/014_CVE-2025-69421
BASE=/home/user/work/base/openssl-1.1.1w; PAT=/home/user/work/patched/build; SRC=/home/user/work/src_1.1.1w/openssl-1.1.1w
$BASE/util/shlib_wrap.sh $BASE/apps/openssl pkcs12 -export -in $SRC/test/certs/servercert.pem -inkey $SRC/test/certs/serverkey.pem -name testname -passout pass:x -out good.p12
python3 -I make_bad.py good.p12 x       # -> bad_no_encryptedcontent.p12 (MAC recomputed)
$BASE/util/shlib_wrap.sh $BASE/apps/openssl pkcs12 -in bad_no_encryptedcontent.p12 -nodes -passin pass:x -out /dev/null   # SIGSEGV
LD_LIBRARY_PATH=$BASE gdb -q -batch -ex run -ex bt --args $BASE/apps/openssl pkcs12 -in bad_no_encryptedcontent.p12 -nodes -passin pass:x -out /dev/null
$PAT/util/shlib_wrap.sh $PAT/apps/openssl pkcs12 -in bad_no_encryptedcontent.p12 -nodes -passin pass:x -out /dev/null     # 'passed a null parameter', exit 1
./build.sh && ./poc_api_base bad_no_encryptedcontent.p12 parse x ; ./poc_api_patched bad_no_encryptedcontent.p12 parse x
./run_poc.sh                             # all builds, gdb, ASan, regression, valgrind
```

## Limitations / notes / 制限事項・注記

Only the PKCS12_unpack_p7encdata() path can produce a NULL oct from a decoded file: the PKCS#8 shrouded key bag path (PKCS8_decrypt()) uses X509_SIG whose digest field is mandatory, so it cannot be exercised with a malformed input; the added check protects it anyway. The malformed file carries a valid recomputed MAC, so no -nomacver is needed.

復号したファイルから NULL の oct を生じさせられるのは PKCS12_unpack_p7encdata() 経路のみである。PKCS#8 shrouded key bag の経路 (PKCS8_decrypt()) は digest フィールドが必須の X509_SIG を使うため不正入力で到達させられないが、追加されたチェックはその経路も保護する。不正ファイルは再計算した正しい MAC を持つため -nomacver は不要。
