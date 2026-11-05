# 021 of 033 — CVE-2026-42766 — CMS-PWRI-no-KDF-alg-NULL-deref

Log file / ログファイル: `/home/user/work/deliver/ipalongpatch_info/logs/20261102_121449_021of033_CVE-2026-42766_CMS-PWRI-no-KDF-alg-NULL-deref.log`
PoC directory / PoC ディレクトリ: `/home/user/work/poc/021_CVE-2026-42766/` (`run_poc.sh`, `pwri_mutate.py --mode drop-kdf`, `out/`)
Verdict / 判定: **PASS** (2026/11/02 12:14:49 – 12:17:50 JST, 00:03:01)

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コードで確認)

**EN.** `PasswordRecipientInfo.keyDerivationAlgorithm` is declared `ASN1_IMP_OPT(..., 0)` in `crypto/cms/cms_asn1.c`, so a DER message without the `[0]` element decodes with `pwri->keyDerivationAlgorithm == NULL`. In `crypto/cms/cms_pwri.c:cms_RecipientInfo_pwri_crypt()` (1.1.1w) the code sets `algtmp = pwri->keyDerivationAlgorithm;` and immediately calls `EVP_PBE_CipherInit(algtmp->algorithm, ..., algtmp->parameter, kekctx, en_de)` at line 339 without a NULL check (only `keyEncryptionAlgorithm` was checked earlier). Patch 021 adds `if (algtmp == NULL) { CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER); goto err; }`, identical in effect to upstream commit df32fc58bd726eecf88ac67b22fef0c8ff5eeef8 / Ubuntu `CVE-2026-42766.patch` (confirmed by a comment-stripped diff of the patched tree).

**JA.** `PasswordRecipientInfo.keyDerivationAlgorithm` は `crypto/cms/cms_asn1.c` で `ASN1_IMP_OPT(..., 0)` と宣言されているため、`[0]` 要素の無い DER メッセージは `pwri->keyDerivationAlgorithm == NULL` のままデコードされる。`crypto/cms/cms_pwri.c` の `cms_RecipientInfo_pwri_crypt()` (1.1.1w) は `algtmp = pwri->keyDerivationAlgorithm;` とした直後、NULL 検査無しに 339 行目で `EVP_PBE_CipherInit(algtmp->algorithm, ..., algtmp->parameter, kekctx, en_de)` を呼ぶ (先に検査されるのは `keyEncryptionAlgorithm` のみ)。パッチ 021 は `if (algtmp == NULL) { CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER); goto err; }` を追加しており、上流コミット df32fc58bd726eecf88ac67b22fef0c8ff5eeef8 / Ubuntu の `CVE-2026-42766.patch` と実質同一である (修正済みツリーのコメント除去 diff で確認)。

## PoC design / PoC の設計

**EN.** Create a legitimate PWRI message (`openssl cms -encrypt -pwri_password PoC-passw0rd -aes128 -outform DER`), then `pwri_mutate.py --mode drop-kdf` (standard-library DER parser/encoder) removes the `[0] keyDerivationAlgorithm` element from the `cont [3]` PasswordRecipientInfo and re-encodes the lengths (`asn1parse` of the result shows only version, keyEncryptionAlgorithm and encryptedKey). The file is decrypted with `openssl cms -decrypt -pwri_password ... -inform DER` on BASE (plain + gdb), BASE-ASAN, PATCHED (plain + valgrind) and PATCHED-ASAN. No secret is needed; the password is never used before the crash.

**JA.** 正規の PWRI メッセージを作成し (`openssl cms -encrypt -pwri_password PoC-passw0rd -aes128 -outform DER`)、`pwri_mutate.py --mode drop-kdf` (標準ライブラリの DER パーサ/エンコーダ) で `cont [3]` PasswordRecipientInfo から `[0] keyDerivationAlgorithm` 要素を削除し長さを再計算する (結果の `asn1parse` には version、keyEncryptionAlgorithm、encryptedKey のみが現れる)。このファイルを `openssl cms -decrypt -pwri_password ... -inform DER` で BASE (通常 + gdb)、BASE-ASAN、PATCHED (通常 + valgrind)、PATCHED-ASAN により復号する。秘密情報は不要で、パスワードはクラッシュ前には使われない。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠抜粋)

**EN.** BASE: `Segmentation fault` (exit code 139). BASE-ASAN:

```
==2860==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000008 (pc ... T0)
==2860==The signal is caused by a READ memory access.
==2860==Hint: address points to the zero page.
    #0 ... in cms_RecipientInfo_pwri_crypt ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_pwri.c:339
    #1 ... in CMS_RecipientInfo_decrypt ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_env.c:766
    #2 ... in CMS_decrypt_set1_password ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_smime.c:721
    #3 ... in cms_main ../src_1.1.1w/openssl-1.1.1w/apps/cms.c:993
```

gdb (BASE debug build): `Program received signal SIGSEGV ... cms_RecipientInfo_pwri_crypt (...) at crypto/cms/cms_pwri.c:339 / 339 if (EVP_PBE_CipherInit(algtmp->algorithm,` ; `print algtmp` → `(X509_ALGOR *) 0x0`; `print pwri->keyDerivationAlgorithm` → `(X509_ALGOR *) 0x0`; `print *pwri->keyEncryptionAlgorithm` → valid `{algorithm = ..., parameter = ...}`; faulting instruction `mov 0x8(%rax),%rdx` (load of `algtmp->parameter` through the NULL pointer).

**JA.** BASE: `Segmentation fault` (終了コード 139)。BASE-ASAN: 上記のとおり `cms_RecipientInfo_pwri_crypt` (`cms_pwri.c:339`) で `SEGV on unknown address 0x000000000008` (READ、"address points to the zero page")。gdb (BASE デバッグビルド): `cms_pwri.c:339` の `if (EVP_PBE_CipherInit(algtmp->algorithm,` で SIGSEGV、`print algtmp` → `(X509_ALGOR *) 0x0`、`print pwri->keyDerivationAlgorithm` → `(X509_ALGOR *) 0x0`、`print *pwri->keyEncryptionAlgorithm` は正常な構造体、違反命令は `mov 0x8(%rax),%rdx` (NULL ポインタ経由の `algtmp->parameter` の読み出し)。

## Observed behaviour AFTER the patch / 修正後の挙動

**EN.** PATCHED and PATCHED-ASAN (with and without leak detection) print `Error decrypting CMS using password` / `CMS routines:cms_RecipientInfo_pwri_crypt:invalid key encryption parameter:...cms_pwri.c:414` / `CMS_decrypt_set1_password:no matching recipient` and exit with code 4 (no signal). valgrind `--leak-check=full` on PATCHED: `ERROR SUMMARY: 0 errors`, `All heap blocks were freed -- no leaks are possible`.

**JA.** PATCHED と PATCHED-ASAN (リーク検出有り/無し) は `Error decrypting CMS using password` / `CMS routines:cms_RecipientInfo_pwri_crypt:invalid key encryption parameter:...cms_pwri.c:414` / `CMS_decrypt_set1_password:no matching recipient` を表示して終了コード 4 で終了する (シグナル無し)。PATCHED の valgrind `--leak-check=full`: `ERROR SUMMARY: 0 errors`、`All heap blocks were freed -- no leaks are possible`。

## Regression check / 回帰確認

**EN.** PATCHED-ASAN (leak detection on): PWRI `-aes128` DER encrypt → decrypt, output identical (exit 0). PATCHED: `-des3` PEM round trip OK. BASE decrypts a PATCHED-produced message OK. Wrong password rejected with `unwrap failure` (exit 4). valgrind on PATCHED decrypting the legitimate message: 0 errors, output identical.

**JA.** PATCHED-ASAN (リーク検出有効): PWRI `-aes128` DER の暗号化→復号で出力一致 (終了コード 0)。PATCHED: `-des3` PEM ラウンドトリップ OK。PATCHED で作成したメッセージを BASE で復号 OK。誤ったパスワードは `unwrap failure` (終了コード 4) で拒否。正規メッセージを復号する PATCHED の valgrind: 0 エラー、出力一致。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```bash
cd /home/user/work/poc/021_CVE-2026-42766
BASE=/home/user/work/base/openssl-1.1.1w; BASE_ASAN=/home/user/work/base_asan; PATCHED=/home/user/work/patched/build
printf 'secret\n' > msg.txt
$BASE/util/shlib_wrap.sh $BASE/apps/openssl cms -encrypt -binary -pwri_password PoC-passw0rd -aes128 -outform DER -in msg.txt -out out/pwri_ok.der
python3 -I pwri_mutate.py --mode drop-kdf out/pwri_ok.der out/pwri_nokdf.der      # delete [0] keyDerivationAlgorithm
$BASE/util/shlib_wrap.sh $BASE/apps/openssl cms -decrypt -pwri_password PoC-passw0rd -inform DER -in out/pwri_nokdf.der -out /dev/null; echo "exit=$?"   # 139 (SIGSEGV)
ASAN_OPTIONS=detect_leaks=0 $BASE_ASAN/util/shlib_wrap.sh $BASE_ASAN/apps/openssl cms -decrypt -pwri_password PoC-passw0rd -inform DER -in out/pwri_nokdf.der -out /dev/null   # ASan SEGV at cms_pwri.c:339
$PATCHED/util/shlib_wrap.sh $PATCHED/apps/openssl cms -decrypt -pwri_password PoC-passw0rd -inform DER -in out/pwri_nokdf.der -out /dev/null; echo "exit=$?"   # 'invalid key encryption parameter', exit 4
$PATCHED/util/shlib_wrap.sh $PATCHED/apps/openssl cms -decrypt -pwri_password PoC-passw0rd -inform DER -in out/pwri_ok.der | cmp - msg.txt && echo REGRESSION_OK
# or: ./run_poc.sh | tee out/run_poc.output.txt
```

## Limitations / notes / 制限事項・注記

**EN.** The first run of `run_poc.sh` reproduced the crash but its automatic verdict said FAIL because the gdb-output grep expected `algtmp = (X509_ALGOR *) 0x0` while gdb prints `$1 = (X509_ALGOR *) 0x0`; only the evaluation pattern was fixed (first output kept as `out/run_poc.output.attempt1.txt`, excerpt in the log). The encryption side (`-encrypt`) always emits the KDF field, so the regression check cannot exercise the new error branch with legitimate input; it is exercised by the malicious input only, as intended.

**JA.** `run_poc.sh` の初回実行でもクラッシュは再現したが、自動判定が gdb 出力に `algtmp = (X509_ALGOR *) 0x0` を期待していた (gdb は `$1 = (X509_ALGOR *) 0x0` と出力) ため FAIL と表示された。判定パターンのみ修正した (初回出力は `out/run_poc.output.attempt1.txt` として保存、ログに抜粋あり)。暗号化側 (`-encrypt`) は常に KDF フィールドを出力するため、正規入力で新しいエラー分岐を通すことはできない。この分岐は意図どおり悪意ある入力のみで検証している。
