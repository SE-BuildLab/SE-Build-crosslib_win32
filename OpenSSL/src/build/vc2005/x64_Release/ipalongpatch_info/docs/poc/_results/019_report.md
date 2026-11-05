# 019 of 033 — CVE-2026-28389 — CMS-KARI-no-params-NULL-deref

Log file / ログファイル: `/home/user/work/deliver/ipalongpatch_info/logs/20261102_122406_019of033_CVE-2026-28389_CMS-KARI-no-params-NULL-deref.log`
PoC directory / PoC ディレクトリ: `/home/user/work/poc/019_CVE-2026-28389/` (`run_poc.sh`, `kari_mutate.py --mode drop-params`, `out/`)
Verdict / 判定: **PASS** (2026/11/02 12:24:06 – 12:31:09 JST, 00:07:03)

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コードで確認)

**EN.** For a KeyAgreeRecipientInfo the `keyEncryptionAlgorithm` is an `AlgorithmIdentifier` whose OPTIONAL `parameters` normally hold a nested `AlgorithmIdentifier` naming the key-wrap cipher (`id-aes128-wrap`, …). When it is absent, `alg->parameter == NULL`. In 1.1.1w `crypto/ec/ec_ameth.c:ecdh_cms_set_shared_info()` line 761 and `crypto/dh/dh_ameth.c:dh_cms_set_shared_info()` line 703 both execute `if (alg->parameter->type != V_ASN1_SEQUENCE)` without a NULL check (call chain `CMS_decrypt_set1_pkey → cms_kari_set1_pkey → CMS_RecipientInfo_kari_decrypt → cms_env_asn1_ctrl → ec_pkey_ctrl/dh_pkey_ctrl → ecdh_cms_decrypt/dh_cms_decrypt`). Patch 019 (same as upstream 781a1acfa3b447dc7ca5d4a0cc91483666501614 / Ubuntu `CVE-2026-28389.patch`): EC side adds `if (alg == NULL || alg->parameter == NULL) return 0;`; DH side uses `X509_ALGOR_get0(&aoid, &ptype, &parameter, alg)` and tests `ptype != V_ASN1_SEQUENCE` (ptype is `V_ASN1_UNDEF` when absent), reading the data via `ASN1_STRING_get0_data()/ASN1_STRING_length()`. Confirmed by a comment-stripped diff of the patched tree.

**JA.** KeyAgreeRecipientInfo の `keyEncryptionAlgorithm` は `AlgorithmIdentifier` で、その OPTIONAL な `parameters` には通常、鍵ラップ暗号 (`id-aes128-wrap` 等) を示す入れ子の `AlgorithmIdentifier` が入る。欠落すると `alg->parameter == NULL` となる。1.1.1w の `crypto/ec/ec_ameth.c` `ecdh_cms_set_shared_info()` 761 行目と `crypto/dh/dh_ameth.c` `dh_cms_set_shared_info()` 703 行目はいずれも NULL 検査無しに `if (alg->parameter->type != V_ASN1_SEQUENCE)` を実行する (呼び出し経路 `CMS_decrypt_set1_pkey → cms_kari_set1_pkey → CMS_RecipientInfo_kari_decrypt → cms_env_asn1_ctrl → ec_pkey_ctrl/dh_pkey_ctrl → ecdh_cms_decrypt/dh_cms_decrypt`)。パッチ 019 (上流 781a1acfa3b447dc7ca5d4a0cc91483666501614 / Ubuntu `CVE-2026-28389.patch` と同一): EC 側は `if (alg == NULL || alg->parameter == NULL) return 0;` を追加、DH 側は `X509_ALGOR_get0(&aoid, &ptype, &parameter, alg)` で分解して `ptype != V_ASN1_SEQUENCE` を検査 (欠落時 ptype は `V_ASN1_UNDEF`) し、`ASN1_STRING_get0_data()/ASN1_STRING_length()` でデータを読む。修正済みツリーのコメント除去 diff で確認。

## PoC design / PoC の設計

**EN.** Legitimate KARI messages are created with the BASE build for an EC recipient (`test/smime-certs/smec1.pem`, keyEncryptionAlgorithm `dhSinglePass-stdDH-sha1kdf-scheme { id-aes128-wrap }`) and an X9.42 DH recipient (`test/smime-certs/smdh.pem`, `id-smime-alg-ESDH { id-aes128-wrap }`); both files also contain the private key. `kari_mutate.py --mode drop-params` (standard-library DER parser/encoder) deletes the parameters element and re-encodes the lengths. The results are decrypted with `openssl cms -decrypt -recip <pem> -inkey <pem> -inform DER` on BASE (plain, gdb), BASE-ASAN, PATCHED (plain, valgrind) and PATCHED-ASAN. A `--mode null-params` variant (parameters present but NULL) shows the crash is specific to absent parameters.

**JA.** BASE ビルドで EC 受信者 (`test/smime-certs/smec1.pem`、keyEncryptionAlgorithm `dhSinglePass-stdDH-sha1kdf-scheme { id-aes128-wrap }`) と X9.42 DH 受信者 (`test/smime-certs/smdh.pem`、`id-smime-alg-ESDH { id-aes128-wrap }`) 向けの正規 KARI メッセージを作成する (両ファイルは秘密鍵も含む)。`kari_mutate.py --mode drop-params` (標準ライブラリの DER パーサ/エンコーダ) が parameters 要素を削除し長さを再計算する。結果を `openssl cms -decrypt -recip <pem> -inkey <pem> -inform DER` で BASE (通常、gdb)、BASE-ASAN、PATCHED (通常、valgrind)、PATCHED-ASAN により復号する。`--mode null-params` の変種 (parameters が存在するが NULL) により、クラッシュが parameters 欠落に特有であることを示す。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠抜粋)

**EN.** BASE: `Segmentation fault` (exit 139) for both messages. BASE-ASAN (EC):

```
==…==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 ... The signal is caused by a READ memory access. Hint: address points to the zero page.
    #0 ... in ecdh_cms_set_shared_info ../src_1.1.1w/openssl-1.1.1w/crypto/ec/ec_ameth.c:761
    #1 ... in ecdh_cms_decrypt .../crypto/ec/ec_ameth.c:821
    #2 ... in ec_pkey_ctrl .../crypto/ec/ec_ameth.c:518
    #3 ... in cms_env_asn1_ctrl .../crypto/cms/cms_env.c:68
    #4 ... in CMS_RecipientInfo_kari_decrypt .../crypto/cms/cms_kari.c:240
    #5 ... in cms_kari_set1_pkey .../crypto/cms/cms_smime.c:593
    #6 ... in CMS_decrypt_set1_pkey .../crypto/cms/cms_smime.c:624
```

BASE-ASAN (DH): same report with `#0 dh_cms_set_shared_info ../src_1.1.1w/openssl-1.1.1w/crypto/dh/dh_ameth.c:703`, `#1 dh_cms_decrypt dh_ameth.c:770`, `#2 dh_pkey_ctrl dh_ameth.c:497`. gdb (both): `Program received signal SIGSEGV` at `761 if (alg->parameter->type != V_ASN1_SEQUENCE)` / `703 ...`, `print *alg` → `{algorithm = <nid_objs+…>, parameter = 0x0}`, `print alg->parameter` → `(ASN1_TYPE *) 0x0`, faulting instruction `mov (%rax),%eax`.

**JA.** BASE: 両メッセージで `Segmentation fault` (終了コード 139)。BASE-ASAN (EC): 上記のとおり `ecdh_cms_set_shared_info` (`ec_ameth.c:761`) で `SEGV on unknown address 0x000000000000` (READ、zero page)。BASE-ASAN (DH): `#0 dh_cms_set_shared_info ../src_1.1.1w/openssl-1.1.1w/crypto/dh/dh_ameth.c:703`、`#1 dh_cms_decrypt dh_ameth.c:770`、`#2 dh_pkey_ctrl dh_ameth.c:497` で同様の報告。gdb (両方): `761 if (alg->parameter->type != V_ASN1_SEQUENCE)` / `703 ...` で SIGSEGV、`print *alg` → `{algorithm = <nid_objs+…>, parameter = 0x0}`、`print alg->parameter` → `(ASN1_TYPE *) 0x0`、違反命令 `mov (%rax),%eax`。

## Observed behaviour AFTER the patch / 修正後の挙動

**EN.** PATCHED and PATCHED-ASAN (with/without leak detection): `Error decrypting CMS using private key` / `elliptic curve routines:ecdh_cms_decrypt:shared info error:...ec_ameth.c:848` (EC) or `Diffie-Hellman routines:dh_cms_decrypt:shared info error:...dh_ameth.c:861` (DH) / `CMS routines:cms_env_asn1_ctrl:ctrl failure`, exit code 4, no signal, no sanitizer output. valgrind `--leak-check=full` on PATCHED for both files: `ERROR SUMMARY: 0 errors`, `All heap blocks were freed -- no leaks are possible`.

**JA.** PATCHED と PATCHED-ASAN (リーク検出有/無): `Error decrypting CMS using private key` / `elliptic curve routines:ecdh_cms_decrypt:shared info error:...ec_ameth.c:848` (EC) または `Diffie-Hellman routines:dh_cms_decrypt:shared info error:...dh_ameth.c:861` (DH) / `CMS routines:cms_env_asn1_ctrl:ctrl failure`、終了コード 4、シグナル無し、サニタイザ出力無し。両ファイルに対する PATCHED の valgrind `--leak-check=full`: `ERROR SUMMARY: 0 errors`、`All heap blocks were freed -- no leaks are possible`。

## Regression check / 回帰確認

**EN.** PATCHED-ASAN (leak detection on): ECDH `-aes128` DER round trip OK; X9.42 DH `-aes128` DER round trip OK. PATCHED: ECDH `-aes256` PEM round trip OK. BASE decrypts a PATCHED-produced ECDH message OK. Decrypting the EC message with the DH key fails cleanly (no matching recipient, exit 4). valgrind on PATCHED decrypting the legitimate EC message: 0 errors, output identical. The NULL-type variant fails cleanly on both builds (`shared info error`).

**JA.** PATCHED-ASAN (リーク検出有効): ECDH `-aes128` DER ラウンドトリップ OK、X9.42 DH `-aes128` DER ラウンドトリップ OK。PATCHED: ECDH `-aes256` PEM ラウンドトリップ OK。PATCHED で作成した ECDH メッセージを BASE で復号 OK。EC メッセージを DH 鍵で復号するとクリーンに失敗 (no matching recipient、終了コード 4)。正規 EC メッセージを復号する PATCHED の valgrind: 0 エラー、出力一致。NULL 型の変種は両ビルドでクリーンに失敗 (`shared info error`)。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```bash
cd /home/user/work/poc/019_CVE-2026-28389
BASE=/home/user/work/base/openssl-1.1.1w; BASE_ASAN=/home/user/work/base_asan; PATCHED=/home/user/work/patched/build
CERTS=/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/test/smime-certs
printf 'secret\n' > msg.txt
for R in smec1 smdh; do
  $BASE/util/shlib_wrap.sh $BASE/apps/openssl cms -encrypt -binary -recip $CERTS/$R.pem -aes128 -outform DER -in msg.txt -out out/$R.der
  python3 -I kari_mutate.py --mode drop-params out/$R.der out/${R}_noparams.der          # delete keyEncryptionAlgorithm.parameters
  $BASE/util/shlib_wrap.sh $BASE/apps/openssl cms -decrypt -recip $CERTS/$R.pem -inkey $CERTS/$R.pem -inform DER -in out/${R}_noparams.der -out /dev/null; echo "BASE exit=$?"      # 139
  ASAN_OPTIONS=detect_leaks=0 $BASE_ASAN/util/shlib_wrap.sh $BASE_ASAN/apps/openssl cms -decrypt -recip $CERTS/$R.pem -inkey $CERTS/$R.pem -inform DER -in out/${R}_noparams.der -out /dev/null   # ASan SEGV
  $PATCHED/util/shlib_wrap.sh $PATCHED/apps/openssl cms -decrypt -recip $CERTS/$R.pem -inkey $CERTS/$R.pem -inform DER -in out/${R}_noparams.der -out /dev/null; echo "PATCHED exit=$?"   # 'shared info error', 4
  $PATCHED/util/shlib_wrap.sh $PATCHED/apps/openssl cms -decrypt -recip $CERTS/$R.pem -inkey $CERTS/$R.pem -inform DER -in out/$R.der | cmp - msg.txt && echo "$R REGRESSION_OK"
done
# or: ./run_poc.sh | tee out/run_poc.output.txt
```

## Limitations / notes / 制限事項・注記

**EN.** Both affected functions (EC and X9.42 DH) were exercised; the DH side was possible because the 1.1.1 test suite ships `test/smime-certs/smdh.pem` (DH certificate + key), so no code-only argument was needed. The X9.42 DH recipient needs `EVP_PKEY_DHX` keys; plain PKCS#3 DH keys do not support CMS in 1.1.1 and are out of scope. The `-encrypt` side always writes the parameters, so the new failure branch is only reachable with crafted input, as intended.

**JA.** 影響を受ける両関数 (EC と X9.42 DH) を実際に実行した。DH 側は 1.1.1 のテストスイートが `test/smime-certs/smdh.pem` (DH 証明書 + 鍵) を同梱しているため可能で、コード説明だけで補う必要は無かった。X9.42 DH 受信者には `EVP_PKEY_DHX` 鍵が必要で、1.1.1 では素の PKCS#3 DH 鍵は CMS をサポートしないため対象外。`-encrypt` 側は常に parameters を出力するため、新しい失敗分岐は意図どおり細工した入力でのみ到達する。
