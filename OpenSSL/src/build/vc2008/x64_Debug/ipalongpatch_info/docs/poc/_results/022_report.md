# 022 of 033 — CVE-2026-9076 — CMS-PWRI-checkbyte-OOB-read

Log file / ログファイル: `/home/user/work/deliver/ipalongpatch_info/logs/20261102_121750_022of033_CVE-2026-9076_CMS-PWRI-checkbyte-OOB-read.log`
PoC directory / PoC ディレクトリ: `/home/user/work/poc/022_CVE-2026-9076/` (`run_poc.sh`, `pwri_mutate.py --mode stream`, `out/`)
Verdict / 判定: **PASS** (2026/11/02 12:17:50 – 12:24:06 JST, 00:06:16)

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コードで確認)

**EN.** In `crypto/cms/cms_pwri.c:kek_unwrap_key()` (1.1.1w) the only size guards are `inlen < 2 * blocklen` and `inlen % blocklen`, with `blocklen = EVP_CIPHER_CTX_block_size(ctx)` of the KEK cipher that the message itself names inside `keyEncryptionAlgorithm.parameters`. The decrypted buffer `tmp` is `OPENSSL_malloc(inlen)` and the RFC 3211 check-byte test at line 214 reads `tmp[1..6]`, i.e. needs 7 bytes. With a stream-mode cipher (EVP block size 1) `inlen = 2` passes both guards and `tmp[4..6]` are read past a 2-byte heap allocation, before any password-dependent check. In 1.1.1 the usable stream-mode ciphers are those with `EVP_CIPH_FLAG_DEFAULT_ASN1` and an IV (AES-OFB/CFB128); RC4 has no ASN.1 parameter support and is rejected earlier by `EVP_CIPHER_asn1_to_param()`. Patch 022 adds `if (blocklen < 4) return 0;`, makes `blocklen` an `int` and rejects `inlen > INT_MAX`, identical to upstream commit 01e0d2a0aa8f095686f381ae8c589af28617fa94 / Ubuntu `CVE-2026-9076.patch` (confirmed by diff of the patched tree).

**JA.** `crypto/cms/cms_pwri.c` の `kek_unwrap_key()` (1.1.1w) のサイズ検査は `inlen < 2 * blocklen` と `inlen % blocklen` のみで、`blocklen` はメッセージ自身が `keyEncryptionAlgorithm.parameters` 内で指定する KEK 暗号の `EVP_CIPHER_CTX_block_size(ctx)` である。復号バッファ `tmp` は `OPENSSL_malloc(inlen)` で、214 行目の RFC 3211 チェックバイト検査は `tmp[1..6]` を読む (7 バイト必要)。ストリームモードの暗号 (EVP ブロック長 1) では `inlen = 2` が両検査を通過し、パスワード依存の検査の前に `tmp[4..6]` が 2 バイトのヒープ領域を越えて読まれる。1.1.1 で利用可能なストリームモード暗号は `EVP_CIPH_FLAG_DEFAULT_ASN1` と IV を持つもの (AES-OFB/CFB128) で、RC4 は ASN.1 パラメータ非対応のため `EVP_CIPHER_asn1_to_param()` で先に拒否される。パッチ 022 は `if (blocklen < 4) return 0;` を追加し、`blocklen` を `int` にして `inlen > INT_MAX` も拒否する。上流コミット 01e0d2a0aa8f095686f381ae8c589af28617fa94 / Ubuntu `CVE-2026-9076.patch` と同一 (修正済みツリーの diff で確認)。

## PoC design / PoC の設計

**EN.** Starting from a legitimate PWRI message (`openssl cms -encrypt -pwri_password PoC-passw0rd -aes128 -outform DER`), `pwri_mutate.py --mode stream --cipher-oid <oid> [--keep-iv] --enckey-len 2` replaces the inner KEK AlgorithmIdentifier (`aes-128-cbc` + IV) by the given cipher OID and shrinks `encryptedKey` to the 2 bytes `11 12`. Trial 1 uses RC4 (`1.2.840.113549.3.4`, no parameters) as suggested; trial 2 uses AES-128-OFB (`2.16.840.1.101.3.4.1.3`) keeping the 16-byte IV, and AES-128-CFB (`…4.1.4`) as a variant. The files are decrypted with BASE-ASAN (correct and wrong password), BASE under valgrind and gdb (break at `cms_pwri.c:214`), PATCHED-ASAN (±leak detection), PATCHED and PATCHED under valgrind. Regression: PWRI round trips with AES-128 (block 16) and 3DES (block 8) KEKs on the patched builds.

**JA.** 正規の PWRI メッセージ (`openssl cms -encrypt -pwri_password PoC-passw0rd -aes128 -outform DER`) を起点に、`pwri_mutate.py --mode stream --cipher-oid <oid> [--keep-iv] --enckey-len 2` で内側の KEK AlgorithmIdentifier (`aes-128-cbc` + IV) を指定 OID の暗号に置き換え、`encryptedKey` を 2 バイト `11 12` に縮める。試行 1 は示唆どおり RC4 (`1.2.840.113549.3.4`、パラメータ無し)、試行 2 は AES-128-OFB (`2.16.840.1.101.3.4.1.3`、16 バイト IV 維持)、変種として AES-128-CFB (`…4.1.4`)。BASE-ASAN (正しい/誤ったパスワード)、valgrind と gdb (`cms_pwri.c:214` でブレーク) 下の BASE、PATCHED-ASAN (リーク検出±)、PATCHED、valgrind 下の PATCHED で復号する。回帰: 修正済みビルドで AES-128 (ブロック 16) と 3DES (ブロック 8) の KEK による PWRI ラウンドトリップ。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠抜粋)

**EN.** Trial 1 (RC4) stops in both builds before the bug: `EVP_CIPHER_asn1_to_param:cipher parameter error` / `cms_RecipientInfo_pwri_crypt:cipher parameter initialisation error:...cms_pwri.c:330`. Trial 2 (AES-128-OFB), BASE-ASAN:

```
==…==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000314 ...
READ of size 1 at 0x502000000314 thread T0
    #0 ... in kek_unwrap_key ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_pwri.c:214
    #1 ... in cms_RecipientInfo_pwri_crypt ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_pwri.c:369
    #2 ... in CMS_RecipientInfo_decrypt ../src_1.1.1w/openssl-1.1.1w/crypto/cms/cms_env.c:766
0x502000000314 is located 2 bytes after 2-byte region [0x502000000310,0x502000000312)
allocated by thread T0 here: ... kek_unwrap_key .../crypto/cms/cms_pwri.c:191
```

The same report appears with a wrong password (`attacker-does-not-know-the-password`) and with the AES-128-CFB variant. valgrind (BASE debug build): `Invalid read of size 1 at kek_unwrap_key (cms_pwri.c:214) ... Address ... is 2 bytes after a block of size 2 alloc'd ... kek_unwrap_key (cms_pwri.c:191)` (5 errors). gdb at `cms_pwri.c:214`: `blocklen=1 inlen=2 -> tmp = OPENSSL_malloc(2)`, `old guard: inlen < 2*blocklen -> 2 < 2 -> pass ; new guard: blocklen < 4 -> reject`, `EVP_CIPHER_CTX_block_size(ctx) = 1`, cipher NID 420 (`NID_aes_128_ofb128`).

**JA.** 試行 1 (RC4) は両ビルドともバグの前で停止する: `EVP_CIPHER_asn1_to_param:cipher parameter error` / `cms_RecipientInfo_pwri_crypt:cipher parameter initialisation error:...cms_pwri.c:330`。試行 2 (AES-128-OFB) の BASE-ASAN では上記のとおり `kek_unwrap_key` (`cms_pwri.c:214`) で、`cms_pwri.c:191` で確保された 2 バイト領域の 2 バイト後ろに対する `READ of size 1` の heap-buffer-overflow が報告された。誤ったパスワード (`attacker-does-not-know-the-password`) でも、AES-128-CFB 変種でも同じ報告。valgrind (BASE デバッグビルド): `Invalid read of size 1 at kek_unwrap_key (cms_pwri.c:214) ... 2 bytes after a block of size 2 alloc'd ... kek_unwrap_key (cms_pwri.c:191)` (5 エラー)。gdb (`cms_pwri.c:214`): `blocklen=1 inlen=2 -> tmp = OPENSSL_malloc(2)`、旧検査 `2 < 2 -> pass`、新検査 `blocklen < 4 -> reject`、`EVP_CIPHER_CTX_block_size(ctx) = 1`、暗号 NID 420 (`NID_aes_128_ofb128`)。

## Observed behaviour AFTER the patch / 修正後の挙動

**EN.** PATCHED-ASAN (with and without leak detection) and PATCHED reject the AES-128-OFB and AES-128-CFB messages with `cms_RecipientInfo_pwri_crypt:unwrap failure:...cms_pwri.c:452` (exit 4; `kek_unwrap_key()` returns 0 at the new `blocklen < 4` guard before allocating or decrypting anything), no sanitizer output; valgrind `--leak-check=full`: `ERROR SUMMARY: 0 errors`, `All heap blocks were freed`. The RC4 file is rejected as before (`cipher parameter initialisation error`).

**JA.** PATCHED-ASAN (リーク検出有/無) と PATCHED は AES-128-OFB と AES-128-CFB のメッセージを `cms_RecipientInfo_pwri_crypt:unwrap failure:...cms_pwri.c:452` (終了コード 4。`kek_unwrap_key()` は新しい `blocklen < 4` 検査で、確保も復号もせずに 0 を返す) で拒否し、サニタイザ出力は無い。valgrind `--leak-check=full`: `ERROR SUMMARY: 0 errors`、`All heap blocks were freed`。RC4 ファイルは従来どおり拒否 (`cipher parameter initialisation error`)。

## Regression check / 回帰確認

**EN.** PATCHED-ASAN (leak detection on): `-aes128` PWRI DER round trip OK (identical output); `-des3` PWRI (KEK `des-ede3-cbc`, block size 8, shown with `asn1parse`) encrypted by PATCHED and decrypted by PATCHED-ASAN OK; PATCHED-produced message decrypted by BASE OK; wrong password rejected (`unwrap failure`); valgrind on PATCHED decrypting the legitimate message: 0 errors, output identical.

**JA.** PATCHED-ASAN (リーク検出有効): `-aes128` PWRI DER ラウンドトリップ OK (出力一致)。`-des3` PWRI (KEK `des-ede3-cbc`、ブロック長 8、`asn1parse` で表示) を PATCHED で暗号化し PATCHED-ASAN で復号 OK。PATCHED で作成したメッセージを BASE で復号 OK。誤ったパスワードは拒否 (`unwrap failure`)。正規メッセージを復号する PATCHED の valgrind: 0 エラー、出力一致。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```bash
cd /home/user/work/poc/022_CVE-2026-9076
BASE=/home/user/work/base/openssl-1.1.1w; BASE_ASAN=/home/user/work/base_asan; PATCHED=/home/user/work/patched/build
printf 'secret\n' > msg.txt
$BASE/util/shlib_wrap.sh $BASE/apps/openssl cms -encrypt -binary -pwri_password PoC-passw0rd -aes128 -outform DER -in msg.txt -out out/pwri_ok.der
# KEK cipher -> aes-128-ofb (block size 1), keep IV, encryptedKey -> 2 bytes
python3 -I pwri_mutate.py --mode stream --cipher-oid 2.16.840.1.101.3.4.1.3 --keep-iv --enckey-len 2 out/pwri_ok.der out/pwri_ofb.der
# unpatched: ASan heap-buffer-overflow READ of size 1 in kek_unwrap_key (cms_pwri.c:214); any password works
ASAN_OPTIONS=detect_leaks=0 $BASE_ASAN/util/shlib_wrap.sh $BASE_ASAN/apps/openssl cms -decrypt -pwri_password anything -inform DER -in out/pwri_ofb.der -out /dev/null
LD_LIBRARY_PATH=$BASE valgrind $BASE/apps/openssl cms -decrypt -pwri_password anything -inform DER -in out/pwri_ofb.der -out /dev/null
# patched: clean 'unwrap failure'
$PATCHED/util/shlib_wrap.sh $PATCHED/apps/openssl cms -decrypt -pwri_password anything -inform DER -in out/pwri_ofb.der -out /dev/null; echo "exit=$?"
# regression
$PATCHED/util/shlib_wrap.sh $PATCHED/apps/openssl cms -decrypt -pwri_password PoC-passw0rd -inform DER -in out/pwri_ok.der | cmp - msg.txt && echo REGRESSION_OK
# or: ./run_poc.sh | tee out/run_poc.output.txt
```

## Limitations / notes / 制限事項・注記

**EN.** (1) The RC4 variant from the task hint cannot reach `kek_unwrap_key()` in 1.1.1 (RC4 lacks ASN.1 parameter support, `EVP_CIPHER_asn1_to_param()` fails first); the demonstration therefore uses AES-128-OFB/CFB, which are stream-mode (block size 1) ciphers accepted by the parameter decoder — this is documented in the log as trial 1/trial 2. (2) The over-read is 1-byte reads at offsets 2..4 past a 2-byte heap block; in a non-instrumented build it does not crash (the bytes are inside the malloc chunk slack), the advisory itself notes a crash needs a page boundary. ASan/valgrind prove the read. (3) Three runs of `run_poc.sh` were made; the first two differed only in a comment typo (NID 419 vs 420) and a misplaced `asn1parse -strparse` in the regression section; evidence identical (outputs kept as `out/run_poc.output.attempt1.txt`, `attempt2.txt`).

**JA.** (1) タスクのヒントにある RC4 の変種は 1.1.1 では `kek_unwrap_key()` に到達できない (RC4 は ASN.1 パラメータ非対応で `EVP_CIPHER_asn1_to_param()` が先に失敗)。そのため実証にはパラメータデコーダに受理されるストリームモード (ブロック長 1) 暗号 AES-128-OFB/CFB を用いた。ログには試行 1/試行 2 として記録。(2) 読み越しは 2 バイトのヒープブロックの 2〜4 バイト後ろへの 1 バイト読み出しで、計装なしビルドではクラッシュしない (malloc チャンクの余白内)。アドバイザリ自身もクラッシュにはページ境界が必要と述べている。ASan/valgrind で読み出しを証明した。(3) `run_poc.sh` は 3 回実行し、最初の 2 回はコメントの誤記 (NID 419 と 420) と回帰セクションの `asn1parse -strparse` の指定ミスのみが異なる。証拠は同一 (出力は `out/run_poc.output.attempt1.txt`、`attempt2.txt` として保存)。
