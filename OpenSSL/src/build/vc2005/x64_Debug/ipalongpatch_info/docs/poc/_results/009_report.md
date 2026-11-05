# 009 of 033 — CVE-2025-9230 — CMS-PWRI-KEK-unwrap-OOB-rw

Log file / ログファイル: `/home/user/work/deliver/ipalongpatch_info/logs/20261102_120333_009of033_CVE-2025-9230_CMS-PWRI-KEK-unwrap-OOB-rw.log`
PoC directory / PoC ディレクトリ: `/home/user/work/poc/009_CVE-2025-9230/` (`run_poc.sh`, `pwri_mutate.py`, `out/`)
Verdict / 判定: **PASS** (2026/11/02 12:03:33 – 12:11:54 JST, 00:08:21)

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コードで確認)

**EN.** `crypto/cms/cms_pwri.c:kek_unwrap_key()` implements the RFC 3211 key unwrap for CMS PasswordRecipientInfo (PWRI). After the two-pass CBC decryption the heap buffer `tmp` (allocated with `inlen` = length of the message's `encryptedKey`) holds `[len byte tmp[0]][3 check bytes][key][padding]`. The 1.1.1w check `if (inlen < (size_t)(tmp[0] - 4))` accepts any `tmp[0] <= inlen + 4`, but the key only fits if `tmp[0] <= inlen - 4`. `memcpy(out, tmp + 4, tmp[0])` then reads up to 8 bytes past `tmp` and writes up to 4 bytes past `out` (= `key`, allocated with `encryptedKey->length` bytes at `cms_pwri.c:363`). Patch 009 changes the test to `if (inlen < 4 + (size_t)tmp[0])`, identical to upstream commit eb7ca9504a1b9ba7ed50140fc5b81e1e5e9adf59 / Ubuntu `CVE-2025-9230.patch` (verified with a comment-stripped diff of the patched tree).

**JA.** `crypto/cms/cms_pwri.c` の `kek_unwrap_key()` は CMS PasswordRecipientInfo (PWRI) 用の RFC 3211 鍵アンラップである。2 回の CBC 復号後、ヒープバッファ `tmp` (メッセージの `encryptedKey` 長 `inlen` で確保) には `[鍵長バイト tmp[0]][チェックバイト 3 個][鍵][パディング]` が入る。1.1.1w の検査 `if (inlen < (size_t)(tmp[0] - 4))` は `tmp[0] <= inlen + 4` を全て受け入れるが、鍵が収まるのは `tmp[0] <= inlen - 4` の場合のみである。続く `memcpy(out, tmp + 4, tmp[0])` は `tmp` を最大 8 バイト越えて読み、`out` (= `key`、`cms_pwri.c:363` で `encryptedKey->length` バイト確保) を最大 4 バイト越えて書く。パッチ 009 は検査を `if (inlen < 4 + (size_t)tmp[0])` に変更しており、上流コミット eb7ca9504a1b9ba7ed50140fc5b81e1e5e9adf59 / Ubuntu の `CVE-2025-9230.patch` と同一である (修正済みツリーのコメント除去 diff で確認)。

## PoC design / PoC の設計

**EN.** A legitimate PWRI message is created with `openssl cms -encrypt -pwri_password PoC-passw0rd -aes128 -outform DER` (KEK cipher aes-128-cbc + IV, PBKDF2-HMAC-SHA1 with 8-byte salt and 2048 iterations, `encryptedKey` = 32 bytes, so `inlen` = 32). `pwri_mutate.py` (standard library only) parses the DER, derives the KEK with `hashlib.pbkdf2_hmac`, builds a 32-byte key block with length byte 36 (= `inlen + 4`, the maximum the buggy check accepts) and valid check bytes, wraps it with a Python re-implementation of the RFC 3211 wrap (two chained AES-CBC passes done with `openssl enc` of the BASE build) and replaces only the `encryptedKey` OCTET STRING. The wrap implementation is validated first by unwrapping the real CEK and re-wrapping it with fresh padding (`pwri_rewrap.der`), which OpenSSL decrypts correctly. The malicious file is then decrypted with BASE-ASAN, BASE+valgrind, BASE+gdb, PATCHED-ASAN, PATCHED+valgrind.

**JA.** 正規の PWRI メッセージを `openssl cms -encrypt -pwri_password PoC-passw0rd -aes128 -outform DER` で作成する (KEK 暗号は aes-128-cbc + IV、PBKDF2-HMAC-SHA1 (8 バイト salt、2048 回)、`encryptedKey` は 32 バイトで `inlen` = 32)。`pwri_mutate.py` (標準ライブラリのみ) が DER を解析し、`hashlib.pbkdf2_hmac` で KEK を導出し、鍵長バイト 36 (= `inlen + 4`、バグのある検査が受け入れる最大値) と正しいチェックバイトを持つ 32 バイトの鍵ブロックを作り、RFC 3211 ラップ (連鎖した AES-CBC 2 回。AES は BASE ビルドの `openssl enc`) の Python 再実装でラップし、`encryptedKey` OCTET STRING のみを置換する。ラップ実装は、本物の CEK をアンラップして新しいパディングで再ラップしたもの (`pwri_rewrap.der`) を OpenSSL が正しく復号できることで先に検証している。悪意あるファイルを BASE-ASAN、BASE+valgrind、BASE+gdb、PATCHED-ASAN、PATCHED+valgrind で復号する。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠抜粋)

**EN.** BASE-ASAN (`openssl cms -decrypt -pwri_password ... -in pwri_evil.der`):

```
==32303==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5030000279f0 ...
READ of size 36 at 0x5030000279f0 thread T0
    #0 ... in memcpy
    #1 ... in kek_unwrap_key ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_pwri.c:223
    #2 ... in cms_RecipientInfo_pwri_crypt ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_pwri.c:369
    #3 ... in CMS_RecipientInfo_decrypt ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_env.c:766
    #4 ... in CMS_decrypt_set1_password ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_smime.c:721
0x5030000279f0 is located 0 bytes after 32-byte region [0x5030000279d0,0x5030000279f0)
allocated by thread T0 here: ... kek_unwrap_key .../crypto/cms/cms_pwri.c:191
```

valgrind on the BASE debug build shows both directions: `Invalid read of size 2 ... kek_unwrap_key (cms_pwri.c:223) ... Address ... is 2 bytes after a block of size 32 alloc'd ... kek_unwrap_key (cms_pwri.c:191)` and `Invalid write of size 2 ... kek_unwrap_key (cms_pwri.c:223) ... Address ... is 0 bytes after a block of size 32 alloc'd ... cms_RecipientInfo_pwri_crypt (cms_pwri.c:363)` (12 errors from 5 contexts; the later `OPENSSL_cleanse` errors come from the corrupted key length 36 being used to clear the 32-byte key). gdb at `cms_pwri.c:223`: `inlen=32, tmp[0]=36, *outlen=36`, `old check: inlen < tmp[0]-4 -> 32 < 32 -> ACCEPT (bug)`, `new check: inlen < 4+tmp[0] -> 32 < 40 -> reject`. A boundary case with length byte 32 (read OOB by 4 bytes, write in bounds) was also reproduced (READ of size 32).

**JA.** BASE-ASAN では上記のとおり `kek_unwrap_key` (`cms_pwri.c:223`) の memcpy で、`cms_pwri.c:191` で確保された 32 バイト領域の直後に対する 36 バイトの READ (heap-buffer-overflow) が報告された。BASE デバッグビルドの valgrind では読み書き両方向が確認できた: `Invalid read of size 2 ... kek_unwrap_key (cms_pwri.c:223) ... 2 bytes after a block of size 32` (tmp) および `Invalid write of size 2 ... kek_unwrap_key (cms_pwri.c:223) ... 0 bytes after a block of size 32 alloc'd ... cms_RecipientInfo_pwri_crypt (cms_pwri.c:363)` (鍵バッファ)。合計 12 エラー/5 コンテキスト (後続の `OPENSSL_cleanse` のエラーは、破壊された鍵長 36 で 32 バイトの鍵を消去するために生じたもの)。gdb (`cms_pwri.c:223`) では `inlen=32, tmp[0]=36, *outlen=36`、旧検査 `32 < 32 -> ACCEPT (bug)`、新検査 `32 < 40 -> reject` を表示した。鍵長バイト 32 の境界ケース (読み出しのみ 4 バイト超過) も再現した (READ of size 32)。

## Observed behaviour AFTER the patch / 修正後の挙動

**EN.** PATCHED-ASAN and PATCHED (also under valgrind `--leak-check=full`) reject `pwri_evil.der` and `pwri_evil32.der` with `CMS routines:cms_RecipientInfo_pwri_crypt:unwrap failure:...cms_pwri.c:452` / `CMS_decrypt_set1_password:no matching recipient` (exit code 4); no AddressSanitizer report, valgrind `ERROR SUMMARY: 0 errors`, `All heap blocks were freed -- no leaks are possible`. The in-bounds boundary value (length byte 28 = `inlen - 4`) is still accepted by the unwrap in the patched build (then fails later in content decryption because a 28-byte key is not a valid AES-128 key), showing the new check is not stricter than necessary.

**JA.** PATCHED-ASAN と PATCHED (valgrind `--leak-check=full` 下でも) は `pwri_evil.der` と `pwri_evil32.der` を `CMS routines:cms_RecipientInfo_pwri_crypt:unwrap failure:...cms_pwri.c:452` / `CMS_decrypt_set1_password:no matching recipient` (終了コード 4) で拒否した。AddressSanitizer の報告は無く、valgrind は `ERROR SUMMARY: 0 errors`、`All heap blocks were freed -- no leaks are possible`。境界内の値 (鍵長バイト 28 = `inlen - 4`) は修正後もアンラップを通過する (その後 28 バイト鍵は AES-128 の鍵として不正なためコンテンツ復号で失敗) ので、新しい検査が必要以上に厳しくなっていないことも確認できた。

## Regression check / 回帰確認

**EN.** With the patched builds: PWRI encrypt (`-aes128`, DER) → decrypt round trip under PATCHED-ASAN with leak detection enabled (exit 0, output identical to the input); `-aes256` PEM round trip with PATCHED (OK); a message encrypted by PATCHED decrypted by BASE (OK); the re-wrapped message `pwri_rewrap.der` decrypted by PATCHED-ASAN (OK); wrong password rejected cleanly (`unwrap failure`, exit 4); valgrind `--leak-check=full` on PATCHED decrypting the legitimate message: `0 errors`, output identical.

**JA.** 修正済みビルドで: PWRI 暗号化 (`-aes128`, DER) → 復号のラウンドトリップをリーク検出有効の PATCHED-ASAN で実施 (終了コード 0、出力は入力と一致)。`-aes256` PEM のラウンドトリップ (PATCHED、OK)。PATCHED で暗号化したものを BASE で復号 (OK)。再ラップしたメッセージ `pwri_rewrap.der` を PATCHED-ASAN で復号 (OK)。誤ったパスワードはクリーンに拒否 (`unwrap failure`、終了コード 4)。正規メッセージを復号する PATCHED の valgrind `--leak-check=full`: `0 errors`、出力一致。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```bash
cd /home/user/work/poc/009_CVE-2025-9230
BASE=/home/user/work/base/openssl-1.1.1w; BASE_ASAN=/home/user/work/base_asan
PATCHED=/home/user/work/patched/build;   PATCHED_ASAN=/home/user/work/patched/build-asan
printf 'secret\n' > msg.txt
# 1. legitimate PWRI message (AES-128-CBC KEK, PBKDF2)
$BASE/util/shlib_wrap.sh $BASE/apps/openssl cms -encrypt -binary -pwri_password PoC-passw0rd -aes128 -outform DER -in msg.txt -out out/pwri_ok.der
# 2. craft: length byte 36 for a 32-byte encryptedKey (needs the password to derive the KEK)
python3 -I pwri_mutate.py --mode evil --password PoC-passw0rd --openssl "$BASE/util/shlib_wrap.sh $BASE/apps/openssl" out/pwri_ok.der out/pwri_evil.der
# 3. unpatched: ASan heap-buffer-overflow READ in kek_unwrap_key (cms_pwri.c:223)
ASAN_OPTIONS=detect_leaks=0 $BASE_ASAN/util/shlib_wrap.sh $BASE_ASAN/apps/openssl cms -decrypt -pwri_password PoC-passw0rd -inform DER -in out/pwri_evil.der -out /dev/null
#    unpatched: valgrind shows invalid read (tmp) and invalid write (key buffer)
LD_LIBRARY_PATH=$BASE valgrind $BASE/apps/openssl cms -decrypt -pwri_password PoC-passw0rd -inform DER -in out/pwri_evil.der -out /dev/null
# 4. patched: clean "unwrap failure"
ASAN_OPTIONS=detect_leaks=0 $PATCHED_ASAN/util/shlib_wrap.sh $PATCHED_ASAN/apps/openssl cms -decrypt -pwri_password PoC-passw0rd -inform DER -in out/pwri_evil.der -out /dev/null
# 5. regression: round trip with the patched build
$PATCHED/util/shlib_wrap.sh $PATCHED/apps/openssl cms -encrypt -binary -pwri_password PoC-passw0rd -aes128 -outform DER -in msg.txt -out out/p.der
$PATCHED/util/shlib_wrap.sh $PATCHED/apps/openssl cms -decrypt -pwri_password PoC-passw0rd -inform DER -in out/p.der | cmp - msg.txt && echo ROUNDTRIP_OK
# or simply: ./run_poc.sh | tee out/run_poc.output.txt
```

## Limitations / notes / 制限事項・注記

**EN.** (1) The PoC assumes the attacker knows the PWRI password (needed to derive the KEK so that the check bytes validate); this matches the advisory's assessment that exploitation probability is low. (2) ASan aborts at the first error, so the ASan report shows only the READ; the WRITE past the key buffer is shown by valgrind (the memcpy interceptor checks the source first). (3) In a non-instrumented build the 4-byte write stays within glibc's chunk slack for a 32-byte allocation, so no visible crash occurs there; the memory corruption is proven by ASan/valgrind. (4) The `openssl enc` of the BASE build is used only as an AES-CBC primitive by the PoC script; it is unrelated to the vulnerable code path.

**JA.** (1) 本 PoC は攻撃者が PWRI のパスワードを知っていることを前提とする (チェックバイトを通すための KEK 導出に必要)。これはアドバイザリの「悪用確率は低い」という評価と整合する。(2) ASan は最初のエラーで停止するため、ASan レポートには READ のみが現れる。鍵バッファを越える WRITE は valgrind で示した (memcpy インターセプタは転送元を先に検査する)。(3) 計装なしのビルドでは 4 バイトの書き込みは 32 バイト確保の glibc チャンクの余白内に収まるため目に見えるクラッシュは起きない。メモリ破壊は ASan/valgrind で証明した。(4) BASE ビルドの `openssl enc` は PoC スクリプトが AES-CBC プリミティブとして使うだけで、脆弱なコードパスとは無関係である。
