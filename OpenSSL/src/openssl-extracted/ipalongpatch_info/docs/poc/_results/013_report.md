# 013 of 033 — CVE-2025-69420 (TS-RESP-verify-ASN1-TYPE-check)

Log file: `20261102_121342_013of033_CVE-2025-69420_TS-RESP-verify-ASN1-TYPE-check.log`

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の確認)

crypto/ts/ts_rsp_verify.c (pristine 1.1.1w) lines 260-281: ess_get_signing_cert() and ess_get_signing_cert_v2() do 'attr = PKCS7_get_signed_attribute(si, NID_...); if (attr == NULL) return NULL; p = attr->value.sequence->data; return d2i_ESS_SIGNING_CERT[_V2](NULL, &p, attr->value.sequence->length);'. The attribute value is decoded as ASN1_ANY (X509_ATTRIBUTE: SET OF ANY); for a BOOLEAN the decoder stores the content byte in the union (value.boolean = 0xff, so value.sequence == (ASN1_STRING *)0xff), for NULL it stores a NULL pointer. ts_check_signing_certs() calls both getters unconditionally from TS_RESP_verify_signature() after ts_verify_cert() and before PKCS7_signatureVerify(), so a valid signature is not required. The patch changes both checks to 'if (attr == NULL || attr->type != V_ASN1_SEQUENCE) return NULL;'.

crypto/ts/ts_rsp_verify.c (素の 1.1.1w) 260〜281 行: ess_get_signing_cert() と ess_get_signing_cert_v2() は 'attr = PKCS7_get_signed_attribute(si, NID_...); if (attr == NULL) return NULL; p = attr->value.sequence->data; return d2i_ESS_SIGNING_CERT[_V2](NULL, &p, attr->value.sequence->length);' を実行する。属性値は ASN1_ANY (X509_ATTRIBUTE: SET OF ANY) として復号され、BOOLEAN ではデコーダが内容バイトを共用体に格納する (value.boolean = 0xff、よって value.sequence == (ASN1_STRING *)0xff)、NULL では NULL ポインタが格納される。ts_check_signing_certs() は TS_RESP_verify_signature() から ts_verify_cert() の後、PKCS7_signatureVerify() の前に両 getter を無条件に呼ぶため、有効な署名は不要である。パッチは両方のチェックを 'if (attr == NULL || attr->type != V_ASN1_SEQUENCE) return NULL;' に変更する。

## PoC design / PoC の設計

tsa/ is rebuilt from scratch by run_poc.sh: CA (req -x509, section ts_ca_dn), TSA cert (req + x509 -req with extensions tsa_cert), query (ts -query -data data.txt -tspolicy tsa_policy1 -cert), replies with tsa_config1 (ESS v2, sha256 cert id) and with the added tsa_config_v1 (ESS v1, sha1 cert id). make_bad.py locates the attribute SEQUENCE {OID signingCertificate(V2), SET {value}} in the DER tree and replaces the value with BOOLEAN TRUE, NULL or INTEGER 1 (bad_v{1,2}_{bool,null,int}.tsr). All verifications use 'openssl ts -config CAtsa.cnf -verify -queryfile req1.tsq -in <file> -CAfile tsaca.pem -untrusted tsa_cert1.pem'.

tsa/ は run_poc.sh が毎回ゼロから構築する: CA (req -x509、セクション ts_ca_dn)、TSA 証明書 (req + x509 -req、拡張 tsa_cert)、要求 (ts -query -data data.txt -tspolicy tsa_policy1 -cert)、tsa_config1 (ESS v2、sha256 証明書 ID) と追加した tsa_config_v1 (ESS v1、sha1 証明書 ID) による応答。make_bad.py は DER 木の中で属性 SEQUENCE {OID signingCertificate(V2), SET {value}} を見つけ、値を BOOLEAN TRUE、NULL、INTEGER 1 に置換する (bad_v{1,2}_{bool,null,int}.tsr)。検証はすべて 'openssl ts -config CAtsa.cnf -verify -queryfile req1.tsq -in <file> -CAfile tsaca.pem -untrusted tsa_cert1.pem' で行う。

## Observed behaviour BEFORE the patch (evidence excerpts) / パッチ前の挙動 (証拠抜粋)

Unpatched 1.1.1w: 'openssl ts -verify' dies with SIGSEGV (exit 139) for the BOOLEAN and NULL variants of both attributes (4/4). gdb: 'ess_get_signing_cert_v2 (si=...) at crypto/ts/ts_rsp_verify.c:279  279  p = attr->value.sequence->data;' with '*attr = {type = 1, value = {ptr = 0xff ..., boolean = 255, ... sequence = 0xff}}', and 'ess_get_signing_cert ... ts_rsp_verify.c:267' with '{type = 5, value = {ptr = 0x0 ...}}'; call chain ts_check_signing_certs <- TS_RESP_verify_signature <- int_ts_RESP_verify_token <- TS_RESP_verify_response <- verify_command (apps/ts.c:846). BASE-ASAN: 'SEGV on unknown address 0x000000000107 ... READ ... #0 ess_get_signing_cert_v2 ts_rsp_verify.c:279' (0x107 = 0xff + offset of the data pointer in ASN1_STRING), and address 0x8 for the NULL variants. The INTEGER control variant does not crash on BASE (ASN1_STRING-compatible) and fails with 'ess signing certificate error' after a failed d2i.

未修正 1.1.1w: 両属性の BOOLEAN および NULL 変種で 'openssl ts -verify' が SIGSEGV (exit 139) で異常終了 (4/4)。gdb: 'ess_get_signing_cert_v2 (si=...) at crypto/ts/ts_rsp_verify.c:279  279  p = attr->value.sequence->data;'、'*attr = {type = 1, value = {ptr = 0xff ..., boolean = 255, ... sequence = 0xff}}'、および 'ess_get_signing_cert ... ts_rsp_verify.c:267' で '{type = 5, value = {ptr = 0x0 ...}}'。呼び出し連鎖は ts_check_signing_certs <- TS_RESP_verify_signature <- int_ts_RESP_verify_token <- TS_RESP_verify_response <- verify_command (apps/ts.c:846)。BASE-ASAN: 'SEGV on unknown address 0x000000000107 ... READ ... #0 ess_get_signing_cert_v2 ts_rsp_verify.c:279' (0x107 = 0xff + ASN1_STRING の data ポインタのオフセット)、NULL 変種ではアドレス 0x8。対照の INTEGER 変種は BASE でもクラッシュせず (ASN1_STRING 互換)、d2i 失敗後に 'ess signing certificate error' となる。

```
Program received signal SIGSEGV, Segmentation fault.
ess_get_signing_cert_v2 (si=0x5555556506a0) at crypto/ts/ts_rsp_verify.c:279
279	    p = attr->value.sequence->data;
#0  ess_get_signing_cert_v2 (si=0x5555556506a0) at crypto/ts/ts_rsp_verify.c:279
#1  ts_check_signing_certs (si=0x5555556506a0, chain=0x555555659830) at crypto/ts/ts_rsp_verify.c:206
#2  TS_RESP_verify_signature (token=..., certs=..., store=..., signer_out=...) at crypto/ts/ts_rsp_verify.c:133
#3  int_ts_RESP_verify_token (...) at crypto/ts/ts_rsp_verify.c:431
#4  TS_RESP_verify_response (...) at crypto/ts/ts_rsp_verify.c:378
#5  verify_command (...) at apps/ts.c:846
$1 = {type = 1, value = {ptr = 0xff <error: Cannot access memory at address 0xff>, boolean = 255, ..., sequence = 0xff, ...}}
---
==4137==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000107 (pc ... T0)
==4137==The signal is caused by a READ memory access.
    #0 in ess_get_signing_cert_v2 ../src_1.1.1w/openssl-1.1.1w/crypto/ts/ts_rsp_verify.c:279
    #1 in ts_check_signing_certs ../src_1.1.1w/openssl-1.1.1w/crypto/ts/ts_rsp_verify.c:206
    #2 in TS_RESP_verify_signature ../src_1.1.1w/openssl-1.1.1w/crypto/ts/ts_rsp_verify.c:133
```

## Observed behaviour AFTER the patch / パッチ後の挙動

Patched build (debug and ASan): all six malformed responses (BOOLEAN, NULL, INTEGER for v1 and v2) are rejected with 'time stamp routines:ts_check_signing_certs:ess signing certificate error', 'Verification: FAILED', exit 1; no crash and no sanitizer report (10/10 runs).

修正版 (debug と ASan): 6 種の不正応答 (v1/v2 の BOOLEAN、NULL、INTEGER) すべてが 'time stamp routines:ts_check_signing_certs:ess signing certificate error'、'Verification: FAILED'、exit 1 で拒否され、クラッシュもサニタイザ報告も無し (10/10 回)。

```
$ openssl ts -config CAtsa.cnf -verify -queryfile req1.tsq -in bad_v2_bool.tsr -CAfile tsaca.pem -untrusted tsa_cert1.pem
Using configuration from CAtsa.cnf
...:error:2F067065:time stamp routines:ts_check_signing_certs:ess signing certificate error:../openssl-1.1.1w-ipalongpatch_20261102/crypto/ts/ts_rsp_verify.c:253:
Verification: FAILED
[exit status: 1]
```

## Regression check / 回帰確認

Patched build: the genuine v2 and v1 responses verify OK with -queryfile and with -data, the extracted token verifies through TS_RESP_verify_token(), a response generated by the patched 'openssl ts -reply' verifies and prints, PATCHED-ASAN is silent, a response checked against a different request is still rejected with 'message imprint mismatch', and valgrind --leak-check=full reports no errors/leaks for the malformed and the genuine response.

修正版: 正規の v2/v1 応答は -queryfile でも -data でも OK、抽出したトークンは TS_RESP_verify_token() 経由で OK、修正版の 'openssl ts -reply' が生成した応答も検証・表示でき、PATCHED-ASAN は無報告、別の要求に対する応答は引き続き 'message imprint mismatch' で拒否、valgrind --leak-check=full は不正応答・正規応答ともエラー・リーク無し。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/013_CVE-2025-69420 && ./run_poc.sh      # rebuilds tsa/ and runs everything; or step by step:
BASE=/home/user/work/base/openssl-1.1.1w; PAT=/home/user/work/patched/build; cd tsa
O="$BASE/util/shlib_wrap.sh $BASE/apps/openssl"
TSDNSECT=ts_ca_dn $O req -config CAtsa.cnf -new -x509 -nodes -out tsaca.pem -keyout tsacakey.pem
TSDNSECT=ts_cert_dn INDEX=1 $O req -config CAtsa.cnf -new -out tsa_req1.pem -keyout tsa_key1.pem
$O x509 -req -in tsa_req1.pem -out tsa_cert1.pem -CA tsaca.pem -CAkey tsacakey.pem -CAcreateserial -extfile CAtsa.cnf -extensions tsa_cert
$O ts -config CAtsa.cnf -query -data data.txt -tspolicy tsa_policy1 -cert -out req1.tsq
$O ts -config CAtsa.cnf -reply -section tsa_config1 -queryfile req1.tsq -out resp_v2.tsr
python3 -I ../make_bad.py resp_v2.tsr bad_v2          # -> bad_v2_bool.tsr, bad_v2_null.tsr, bad_v2_int.tsr
$O ts -config CAtsa.cnf -verify -queryfile req1.tsq -in bad_v2_bool.tsr -CAfile tsaca.pem -untrusted tsa_cert1.pem    # SIGSEGV
LD_LIBRARY_PATH=$BASE gdb -q -batch -ex run -ex bt -ex 'print *attr' --args $BASE/apps/openssl ts -config CAtsa.cnf -verify -queryfile req1.tsq -in bad_v2_bool.tsr -CAfile tsaca.pem -untrusted tsa_cert1.pem
$PAT/util/shlib_wrap.sh $PAT/apps/openssl ts -config CAtsa.cnf -verify -queryfile req1.tsq -in bad_v2_bool.tsr -CAfile tsaca.pem -untrusted tsa_cert1.pem   # ess signing certificate error
$PAT/util/shlib_wrap.sh $PAT/apps/openssl ts -config CAtsa.cnf -verify -queryfile req1.tsq -in resp_v2.tsr -CAfile tsaca.pem -untrusted tsa_cert1.pem       # Verification: OK
```

## Limitations / notes / 制限事項・注記

The TSA key material is generated fresh on every run (so file contents differ between runs; the verification results do not). Only the two ESS getters are patched; the INTEGER control shows that ASN1_STRING-compatible wrong types never crashed, while BOOLEAN/NULL did - the patched build now rejects all non-SEQUENCE types uniformly.

TSA の鍵材料は実行ごとに新規生成される (ファイル内容は毎回異なるが検証結果は変わらない)。修正は 2 つの ESS getter のみ。対照の INTEGER は ASN1_STRING 互換の誤型では元々クラッシュせず、BOOLEAN/NULL ではクラッシュしたことを示す — 修正版は SEQUENCE 以外の型を一律に拒否する。
