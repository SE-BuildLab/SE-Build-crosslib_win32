# 020 of 033 — CVE-2026-28390 — CMS-KTRI-OAEP-label-NULL-deref

Log file / ログファイル: `/home/user/work/deliver/ipalongpatch_info/logs/20261102_123942_020of033_CVE-2026-28390_CMS-KTRI-OAEP-label-NULL-deref.log`
PoC directory / PoC ディレクトリ: `/home/user/work/poc/020_CVE-2026-28390/` (`run_poc.sh`, `ktri_mutate.py --mode drop-label`, `out/`)
Verdict / 判定: **PASS** (2026/11/02 12:39:42 – 12:50:03 JST, 00:10:21)

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コードで確認)

**EN.** `crypto/rsa/rsa_ameth.c:rsa_cms_decrypt()` (1.1.1w) decodes the RSAES-OAEP-params of a KeyTransRecipientInfo; if `oaep->pSourceFunc` is present it checks `OBJ_obj2nid(plab->algorithm) == NID_pSpecified` and then `plab->parameter->type != V_ASN1_OCTET_STRING` (line 964) without testing `plab->parameter` for NULL. Since the parameters of an `AlgorithmIdentifier` are OPTIONAL, a pSourceFunc encoded as `SEQUENCE { pSpecified }` yields `plab->parameter == NULL` and a crash during `CMS_decrypt_set1_pkey → cms_RecipientInfo_ktri_decrypt → cms_env_asn1_ctrl → rsa_pkey_ctrl → rsa_cms_decrypt`, before the RSA private-key operation. Patch 020 (upstream 4e569eac93059ccf9b36c811ea70ff4695d920e6 / Ubuntu `CVE-2026-28390.patch`) uses `X509_ALGOR_get0(&aoid, &ptype, &parameter, oaep->pSourceFunc)`, fails with `RSA_R_INVALID_LABEL` when `ptype != V_ASN1_OCTET_STRING` (absent → `V_ASN1_UNDEF`), reads the label via `ASN1_STRING_get0_data()/ASN1_STRING_length()` and hands a `OPENSSL_memdup()` copy to `EVP_PKEY_CTX_set0_rsa_oaep_label()`; the IPALongPatch additionally skips the copy for an empty label (`label != NULL && labellen > 0`) so an explicitly encoded empty label is accepted. Confirmed by a comment-stripped diff of the patched tree.

**JA.** `crypto/rsa/rsa_ameth.c` の `rsa_cms_decrypt()` (1.1.1w) は KeyTransRecipientInfo の RSAES-OAEP-params をデコードし、`oaep->pSourceFunc` があれば `OBJ_obj2nid(plab->algorithm) == NID_pSpecified` を確認した後、`plab->parameter` の NULL 検査無しに `plab->parameter->type != V_ASN1_OCTET_STRING` (964 行目) を評価する。`AlgorithmIdentifier` の parameters は OPTIONAL なので、`SEQUENCE { pSpecified }` と符号化された pSourceFunc は `plab->parameter == NULL` となり、`CMS_decrypt_set1_pkey → cms_RecipientInfo_ktri_decrypt → cms_env_asn1_ctrl → rsa_pkey_ctrl → rsa_cms_decrypt` の経路で RSA 秘密鍵演算の前にクラッシュする。パッチ 020 (上流 4e569eac93059ccf9b36c811ea70ff4695d920e6 / Ubuntu `CVE-2026-28390.patch`) は `X509_ALGOR_get0(&aoid, &ptype, &parameter, oaep->pSourceFunc)` を用い、`ptype != V_ASN1_OCTET_STRING` (欠落時は `V_ASN1_UNDEF`) なら `RSA_R_INVALID_LABEL` で失敗し、ラベルを `ASN1_STRING_get0_data()/ASN1_STRING_length()` で読んで `OPENSSL_memdup()` の複製を `EVP_PKEY_CTX_set0_rsa_oaep_label()` に渡す。IPALongPatch はさらに空ラベルでは複製を省く (`label != NULL && labellen > 0`) ため、明示的に符号化された空ラベルも受理される。修正済みツリーのコメント除去 diff で確認。

## PoC design / PoC の設計

**EN.** A legitimate RSA-OAEP message with an explicit label is made with the BASE build: `openssl cms -encrypt -recip test/certs/servercert.pem -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_label:0102 -aes128 -outform DER` (asn1parse: `rsaesOaep { [2] pSourceFunc { pSpecified, OCTET STRING 0102 } }`). `ktri_mutate.py --mode drop-label` (standard-library DER parser/encoder) deletes the OCTET STRING. The result is decrypted with `openssl cms -decrypt -inkey test/certs/serverkey.pem -inform DER` on BASE (plain, with/without `-recip`, gdb), BASE-ASAN, PATCHED and PATCHED-ASAN (with `-debug_decrypt` to see the real error, and in default mode), and PATCHED under valgrind. Variants: NULL-typed label parameter; explicit empty label added to a message encrypted with the default label (`--mode add-empty-psource`).

**JA.** BASE ビルドで明示的ラベル付きの正規 RSA-OAEP メッセージを作成する: `openssl cms -encrypt -recip test/certs/servercert.pem -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_label:0102 -aes128 -outform DER` (asn1parse: `rsaesOaep { [2] pSourceFunc { pSpecified, OCTET STRING 0102 } }`)。`ktri_mutate.py --mode drop-label` (標準ライブラリの DER パーサ/エンコーダ) で OCTET STRING を削除する。結果を `openssl cms -decrypt -inkey test/certs/serverkey.pem -inform DER` で BASE (通常、`-recip` 有/無、gdb)、BASE-ASAN、PATCHED と PATCHED-ASAN (実際のエラーを見るための `-debug_decrypt` 付きとデフォルトモード)、valgrind 下の PATCHED により復号する。変種: NULL 型のラベルパラメータ、デフォルトラベルで暗号化したメッセージへの明示的空ラベルの追加 (`--mode add-empty-psource`)。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠抜粋)

**EN.** BASE: `Segmentation fault` (exit 139), with and without `-recip`. BASE-ASAN:

```
==…==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 ... READ ... address points to the zero page.
    #0 ... in rsa_cms_decrypt ../src_1.1.1w/openssl-1.1.1w/crypto/rsa/rsa_ameth.c:964
    #1 ... in rsa_pkey_ctrl ../src_1.1.1w/openssl-1.1.1w/crypto/rsa/rsa_ameth.c:505
    #2 ... in cms_env_asn1_ctrl ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_env.c:68
    #3 ... in cms_RecipientInfo_ktri_decrypt ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_env.c:395
    #4 ... in CMS_RecipientInfo_decrypt ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_env.c:760
    #5 ... in CMS_decrypt_set1_pkey ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_smime.c:637
```

gdb: `Program received signal SIGSEGV ... rsa_cms_decrypt (ri=...) at crypto/rsa/rsa_ameth.c:964 / 964 if (plab->parameter->type != V_ASN1_OCTET_STRING) {`, `print *plab` → `{algorithm = <nid_objs+…>, parameter = 0x0}`, `OBJ_obj2nid(plab->algorithm)` → 935 (pSpecified), faulting instruction `mov (%rax),%eax`.

**JA.** BASE: `-recip` の有無にかかわらず `Segmentation fault` (終了コード 139)。BASE-ASAN: 上記のとおり `rsa_cms_decrypt` (`rsa_ameth.c:964`) で `SEGV on unknown address 0x000000000000` (READ、zero page)、経路は `rsa_pkey_ctrl` ← `cms_env_asn1_ctrl` ← `cms_RecipientInfo_ktri_decrypt` ← `CMS_RecipientInfo_decrypt` ← `CMS_decrypt_set1_pkey`。gdb: `964 if (plab->parameter->type != V_ASN1_OCTET_STRING) {` で SIGSEGV、`print *plab` → `{algorithm = <nid_objs+…>, parameter = 0x0}`、`OBJ_obj2nid(plab->algorithm)` → 935 (pSpecified)、違反命令 `mov (%rax),%eax`。

## Observed behaviour AFTER the patch / 修正後の挙動

**EN.** PATCHED / PATCHED-ASAN with `-debug_decrypt`: `rsa routines:rsa_cms_decrypt:invalid label:...rsa_ameth.c:1038` / `cms_env_asn1_ctrl:ctrl failure` / `CMS_decrypt_set1_pkey:no matching recipient`, exit 4, no signal, no sanitizer report (leak detection on). Default mode: no crash and no plaintext — OpenSSL's `CMS_decrypt_set1_pkey()` intentionally hides RSA failures for key-transport recipients and continues with a random content key, so the run ends with `EVP_DecryptFinal_ex:bad decrypt` (exit 4) or, with probability ≈1/256, exit 0 with garbage output (one such case occurred in the recorded run: 95 bytes of garbage, `cmp` against the plaintext fails; 70 repetitions all gave `bad decrypt`). valgrind `--leak-check=full` on PATCHED: `ERROR SUMMARY: 0 errors`, no leaks. The NULL-typed variant gives `invalid label` on both builds; the explicitly encoded empty label decrypts correctly on PATCHED-ASAN (and BASE).

**JA.** PATCHED / PATCHED-ASAN (`-debug_decrypt`): `rsa routines:rsa_cms_decrypt:invalid label:...rsa_ameth.c:1038` / `cms_env_asn1_ctrl:ctrl failure` / `CMS_decrypt_set1_pkey:no matching recipient`、終了コード 4、シグナル無し、サニタイザ報告無し (リーク検出有効)。デフォルトモード: クラッシュも平文出力も無い — OpenSSL の `CMS_decrypt_set1_pkey()` は鍵転送受信者の RSA 失敗を意図的に隠しランダムなコンテンツ鍵で続行するため、`EVP_DecryptFinal_ex:bad decrypt` (終了コード 4) で終わるか、約 1/256 の確率で終了コード 0 とごみ出力になる (記録した実行で 1 回発生: 95 バイトのごみ、平文との `cmp` は不一致。70 回の反復では全て `bad decrypt`)。PATCHED の valgrind `--leak-check=full`: `ERROR SUMMARY: 0 errors`、リーク無し。NULL 型の変種は両ビルドで `invalid label`。明示的に符号化された空ラベルは PATCHED-ASAN (および BASE) で正しく復号された。

## Regression check / 回帰確認

**EN.** PATCHED-ASAN (leak detection on): OAEP with label `0102` round trip OK; OAEP without label decrypt OK. PATCHED: OAEP SHA-256 + label `deadbeef` PEM round trip OK; PKCS#1 v1.5 round trip OK. BASE decrypts a PATCHED-produced OAEP message OK. Wrong RSA key (`smrsa1.pem`) rejected cleanly (exit 4). valgrind `--leak-check=full` on PATCHED decrypting the legitimate labelled message: 0 errors, no leaks (the label copy made by the patch is freed), output identical.

**JA.** PATCHED-ASAN (リーク検出有効): ラベル `0102` 付き OAEP のラウンドトリップ OK、ラベル無し OAEP の復号 OK。PATCHED: OAEP SHA-256 + ラベル `deadbeef` の PEM ラウンドトリップ OK、PKCS#1 v1.5 ラウンドトリップ OK。PATCHED で作成した OAEP メッセージを BASE で復号 OK。誤った RSA 鍵 (`smrsa1.pem`) はクリーンに拒否 (終了コード 4)。正規ラベル付きメッセージを復号する PATCHED の valgrind `--leak-check=full`: 0 エラー、リーク無し (パッチが作るラベルの複製は解放される)、出力一致。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```bash
cd /home/user/work/poc/020_CVE-2026-28390
BASE=/home/user/work/base/openssl-1.1.1w; BASE_ASAN=/home/user/work/base_asan; PATCHED=/home/user/work/patched/build
SRC=/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102; CERT=$SRC/test/certs/servercert.pem; KEY=$SRC/test/certs/serverkey.pem
printf 'secret\n' > msg.txt
$BASE/util/shlib_wrap.sh $BASE/apps/openssl cms -encrypt -binary -recip $CERT -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_label:0102 -aes128 -outform DER -in msg.txt -out out/o.der
python3 -I ktri_mutate.py --mode drop-label out/o.der out/o_nolabel.der          # pSourceFunc { pSpecified } without the OCTET STRING
$BASE/util/shlib_wrap.sh $BASE/apps/openssl cms -decrypt -inkey $KEY -inform DER -in out/o_nolabel.der -out /dev/null; echo "exit=$?"      # 139 (SIGSEGV)
ASAN_OPTIONS=detect_leaks=0 $BASE_ASAN/util/shlib_wrap.sh $BASE_ASAN/apps/openssl cms -decrypt -inkey $KEY -inform DER -in out/o_nolabel.der -out /dev/null   # ASan SEGV rsa_ameth.c:964
$PATCHED/util/shlib_wrap.sh $PATCHED/apps/openssl cms -decrypt -debug_decrypt -inkey $KEY -inform DER -in out/o_nolabel.der -out /dev/null; echo "exit=$?"   # 'invalid label', 4
$PATCHED/util/shlib_wrap.sh $PATCHED/apps/openssl cms -decrypt -inkey $KEY -inform DER -in out/o.der | cmp - msg.txt && echo REGRESSION_OK
# or: ./run_poc.sh | tee out/run_poc.output.txt
```

## Limitations / notes / 制限事項・注記

**EN.** (1) In default (non-debug) mode OpenSSL deliberately masks RSA key-transport decryption failures (MMA countermeasure) and decrypts with a random key; the patched build's clean rejection is therefore shown with `-debug_decrypt`, and in default mode by the absence of plaintext (`cmp`), accepting that about 1 run in 256 ends with exit 0 and garbage (observed once). (2) The explicit-empty-label test documents the IPALongPatch's deliberate deviation from the Ubuntu patch (which would reject a zero-length label because `OPENSSL_memdup()` of 0 bytes returns NULL); BASE also accepts it. (3) Only RSA key transport is affected; KARI/PWRI paths are covered by items 019/021/022.

**JA.** (1) デフォルト (非デバッグ) モードでは OpenSSL が RSA 鍵転送の復号失敗を意図的に隠し (MMA 対策) ランダム鍵で復号するため、修正済みビルドのクリーンな拒否は `-debug_decrypt` で示し、デフォルトモードでは平文が出ないこと (`cmp`) で示した。約 256 回に 1 回は終了コード 0 とごみ出力になる (1 回観測)。(2) 明示的空ラベルのテストは、IPALongPatch が Ubuntu パッチから意図的に逸脱している点 (Ubuntu 版は 0 バイトの `OPENSSL_memdup()` が NULL を返すため長さ 0 のラベルを拒否する) を記録するもので、BASE も受理する。(3) 影響は RSA 鍵転送のみで、KARI/PWRI の経路は項目 019/021/022 で扱っている。
