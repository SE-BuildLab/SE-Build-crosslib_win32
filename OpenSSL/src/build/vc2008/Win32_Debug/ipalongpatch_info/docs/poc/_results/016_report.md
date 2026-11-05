# 016 of 033 — CVE-2026-22796 (PKCS7-digest-attr-type-confusion)

Log file: `20261102_121857_016of033_CVE-2026-22796_PKCS7-digest-attr-type-confusion.log`

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の確認)

crypto/pkcs7/pk7_doit.c (pristine 1.1.1w): PKCS7_digest_from_attributes() = 'if ((astype = get_attribute(sk, NID_pkcs9_messageDigest)) == NULL) return NULL; return astype->value.octet_string;'. PKCS7_signatureVerify() (lines 1003-1012): 'message_digest = PKCS7_digest_from_attributes(sk); if (!message_digest) { ...UNABLE_TO_FIND_MESSAGE_DIGEST...; goto err; } if ((message_digest->length != (int)md_len) || memcmp(message_digest->data, md_dat, md_len)) ...'. With a BOOLEAN attribute the ANY decoder stores 0xff in the union, so message_digest == (ASN1_OCTET_STRING *)0xff and line 1009 faults; a NULL attribute is caught by the existing NULL check, and ASN1_STRING-compatible wrong types (INTEGER, ...) only cause a digest mismatch. The patch inserts 'if (astype->type != V_ASN1_OCTET_STRING) return NULL;'.

crypto/pkcs7/pk7_doit.c (素の 1.1.1w): PKCS7_digest_from_attributes() = 'if ((astype = get_attribute(sk, NID_pkcs9_messageDigest)) == NULL) return NULL; return astype->value.octet_string;'。PKCS7_signatureVerify() (1003〜1012 行): 'message_digest = PKCS7_digest_from_attributes(sk); if (!message_digest) { ...UNABLE_TO_FIND_MESSAGE_DIGEST...; goto err; } if ((message_digest->length != (int)md_len) || memcmp(message_digest->data, md_dat, md_len)) ...'。BOOLEAN 属性では ANY デコーダが共用体に 0xff を格納するため message_digest == (ASN1_OCTET_STRING *)0xff となり 1009 行でフォルトする。NULL 属性は既存の NULL チェックで捕捉され、ASN1_STRING 互換の誤型 (INTEGER 等) はダイジェスト不一致になるだけ。パッチは 'if (astype->type != V_ASN1_OCTET_STRING) return NULL;' を挿入する。

## PoC design / PoC の設計

good.p7: unpatched 'openssl smime -sign -in test/smcont.txt -signer test/smime-certs/smrsa1.pem -nodetach -outform DER'. make_bad.py locates SEQUENCE {OID messageDigest, SET {OCTET STRING}} in the DER tree and replaces the value with BOOLEAN TRUE / NULL / INTEGER 1; the signature stays untouched (the vulnerable code runs before it is checked). The tampered-content helper flips the first byte of the inner pkcs7-data OCTET STRING. Verification command: 'openssl smime -verify -noverify -inform DER -in <file> -out /dev/null'. run_poc.sh runs all steps on the four builds, including gdb ('print message_digest') and valgrind.

good.p7: 未修正の 'openssl smime -sign -in test/smcont.txt -signer test/smime-certs/smrsa1.pem -nodetach -outform DER'。make_bad.py は DER 木の中で SEQUENCE {OID messageDigest, SET {OCTET STRING}} を見つけ、値を BOOLEAN TRUE / NULL / INTEGER 1 に置換する。署名はそのまま (脆弱コードは署名検証前に実行される)。改ざん用補助は内側 pkcs7-data の OCTET STRING の先頭バイトを反転する。検証コマンド: 'openssl smime -verify -noverify -inform DER -in <file> -out /dev/null'。run_poc.sh が 4 ビルドで gdb ('print message_digest') と valgrind を含む全ステップを実行する。

## Observed behaviour BEFORE the patch (evidence excerpts) / パッチ前の挙動 (証拠抜粋)

Unpatched 1.1.1w: 'openssl smime -verify -noverify -inform DER -in bad_bool.p7' dies with SIGSEGV (exit 139). gdb: 'PKCS7_signatureVerify (bio=..., p7=..., si=..., x509=...) at crypto/pkcs7/pk7_doit.c:1009  1009  if ((message_digest->length != (int)md_len) ||' <- PKCS7_verify (pk7_smime.c:351) <- smime_main (apps/smime.c:552); 'message_digest = (ASN1_OCTET_STRING *) 0xff'. BASE-ASAN: 'ERROR: AddressSanitizer: SEGV on unknown address 0x0000000000ff ... READ ... #0 PKCS7_signatureVerify pk7_doit.c:1009 #1 PKCS7_verify pk7_smime.c:351'. Controls on BASE: bad_null.p7 -> 'unable to find message digest' (exit 4), bad_int.p7 -> 'digest failure' (exit 4), no crash.

未修正 1.1.1w: 'openssl smime -verify -noverify -inform DER -in bad_bool.p7' が SIGSEGV (exit 139) で異常終了。gdb: 'PKCS7_signatureVerify (bio=..., p7=..., si=..., x509=...) at crypto/pkcs7/pk7_doit.c:1009  1009  if ((message_digest->length != (int)md_len) ||' <- PKCS7_verify (pk7_smime.c:351) <- smime_main (apps/smime.c:552)、'message_digest = (ASN1_OCTET_STRING *) 0xff'。BASE-ASAN: 'ERROR: AddressSanitizer: SEGV on unknown address 0x0000000000ff ... READ ... #0 PKCS7_signatureVerify pk7_doit.c:1009 #1 PKCS7_verify pk7_smime.c:351'。BASE での対照: bad_null.p7 -> 'unable to find message digest' (exit 4)、bad_int.p7 -> 'digest failure' (exit 4)、クラッシュ無し。

```
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7bedae8 in PKCS7_signatureVerify (bio=0x55555564fe30, p7=0x5555556500e0, si=0x555555650c00, x509=0x555555650320) at crypto/pkcs7/pk7_doit.c:1009
1009	        if ((message_digest->length != (int)md_len) ||
#0  PKCS7_signatureVerify (...) at crypto/pkcs7/pk7_doit.c:1009
#1  PKCS7_verify (p7=..., certs=0x0, store=..., indata=0x0, out=..., flags=32) at crypto/pkcs7/pk7_smime.c:351
#2  smime_main (argc=0, argv=...) at apps/smime.c:552
$1 = (ASN1_OCTET_STRING *) 0xff
---
==6553==ERROR: AddressSanitizer: SEGV on unknown address 0x0000000000ff (pc ... T0)
==6553==The signal is caused by a READ memory access.
    #0 in PKCS7_signatureVerify ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs7/pk7_doit.c:1009
    #1 in PKCS7_verify ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs7/pk7_smime.c:351
    #2 in smime_main ../src_1.1.1w/openssl-1.1.1w/apps/smime.c:552
```

## Observed behaviour AFTER the patch / パッチ後の挙動

Patched build (debug and ASan): bad_bool.p7, bad_null.p7 and bad_int.p7 all fail with 'PKCS7 routines:PKCS7_signatureVerify:unable to find message digest' + 'PKCS7_verify:signature failure', 'Verification failure', exit 4; no crash, no sanitizer report (5/5 runs).

修正版 (debug と ASan): bad_bool.p7、bad_null.p7、bad_int.p7 はすべて 'PKCS7 routines:PKCS7_signatureVerify:unable to find message digest' + 'PKCS7_verify:signature failure'、'Verification failure'、exit 4 で失敗。クラッシュもサニタイザ報告も無し (5/5 回)。

```
$ openssl smime -verify -noverify -inform DER -in bad_bool.p7 -out /dev/null
Verification failure
...:error:2107106C:PKCS7 routines:PKCS7_signatureVerify:unable to find message digest:../openssl-1.1.1w-ipalongpatch_20261102/crypto/pkcs7/pk7_doit.c:1039:
...:error:21075069:PKCS7 routines:PKCS7_verify:signature failure:../openssl-1.1.1w-ipalongpatch_20261102/crypto/pkcs7/pk7_smime.c:394:
[exit status: 4]
```

## Regression check / 回帰確認

Patched build: good.p7 verifies ('Verification successful', extracted content byte-identical to test/smcont.txt), also with full chain validation against smroot.pem and under ASan; signing and verifying an S/MIME message and a detached DER signature (-content) with the patched build succeed; a message whose content was tampered with is still rejected with 'digest failure'; valgrind --leak-check=full shows no errors/leaks for bad_bool.p7 and good.p7.

修正版: good.p7 は検証成功 ('Verification successful'、抽出内容は test/smcont.txt とバイト一致)、smroot.pem による完全なチェーン検証でも ASan 下でも成功。修正版での S/MIME メッセージと分離 DER 署名 (-content) の署名・検証も成功。内容を改ざんしたメッセージは引き続き 'digest failure' で拒否。valgrind --leak-check=full は bad_bool.p7 と good.p7 でエラー・リーク無し。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/016_CVE-2026-22796
BASE=/home/user/work/base/openssl-1.1.1w; PAT=/home/user/work/patched/build; SRC=/home/user/work/src_1.1.1w/openssl-1.1.1w
$BASE/util/shlib_wrap.sh $BASE/apps/openssl smime -sign -in $SRC/test/smcont.txt -signer $SRC/test/smime-certs/smrsa1.pem -nodetach -outform DER -out good.p7
python3 -I make_bad.py good.p7 bad        # -> bad_bool.p7, bad_null.p7, bad_int.p7, bad_tampered_content.p7
$BASE/util/shlib_wrap.sh $BASE/apps/openssl smime -verify -noverify -inform DER -in bad_bool.p7 -out /dev/null    # SIGSEGV
LD_LIBRARY_PATH=$BASE gdb -q -batch -ex run -ex bt -ex 'print message_digest' --args $BASE/apps/openssl smime -verify -noverify -inform DER -in bad_bool.p7 -out /dev/null
$PAT/util/shlib_wrap.sh $PAT/apps/openssl smime -verify -noverify -inform DER -in bad_bool.p7 -out /dev/null      # unable to find message digest, exit 4
$PAT/util/shlib_wrap.sh $PAT/apps/openssl smime -verify -noverify -inform DER -in good.p7 -out /dev/null          # Verification successful
./run_poc.sh
```

## Limitations / notes / 制限事項・注記

Only the BOOLEAN encoding crashes the unpatched build (NULL is caught by an existing check, ASN1_STRING-based types merely mismatch); the patched check rejects every non-OCTET STRING type. The first run of run_poc.sh had two scripting defects in the regression helper and the verdict counting (not in the PoC itself); they were corrected and the script re-run, as recorded in the log.

未修正ビルドをクラッシュさせるのは BOOLEAN 符号化のみ (NULL は既存チェックで捕捉、ASN1_STRING ベースの型は不一致になるだけ)。修正版のチェックは OCTET STRING 以外の型をすべて拒否する。run_poc.sh の初回実行では回帰用補助と判定カウントに 2 つのスクリプト上の不備があった (PoC 自体ではない)。修正して再実行したことをログに記録した。
