# 028 of 033 — CVE-2026-63072 — CMS-AESWRAPPAD-unwrap-OOB-write

Log file / ログファイル: `/home/user/work/deliver/ipalongpatch_info/logs/20261102_123339_028of033_CVE-2026-63072_CMS-AESWRAPPAD-unwrap-OOB-write.log`
PoC directory / PoC ディレクトリ: `/home/user/work/poc/028_CVE-2026-63072/` (`run_poc.sh`, `kari_mutate.py --mode wrap-pad`, `out/`)
Verdict / 判定: **PASS** (2026/11/02 12:33:39 – 12:39:42 JST, 00:06:03)

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コードで確認)

**EN.** `crypto/cms/cms_kari.c:cms_kek_cipher()` (1.1.1w) asks the key-wrap cipher for the output length with `EVP_CipherUpdate(kari->ctx, NULL, &outlen, in, inlen)`; `aes_wrap_cipher()` (`crypto/evp/e_aes.c`) answers `inlen - 8` for decryption, and the buffer is allocated with `OPENSSL_malloc(outlen)` (line 208). The key-wrap OID comes from the message and both `id-aesNNN-wrap` and `id-aesNNN-wrap-pad` are accepted (`EVP_CIPHER_mode() == EVP_CIPH_WRAP_MODE`). For the padded variant `CRYPTO_128_unwrap_pad()` (`crypto/modes/wrap128.c`) executes `OPENSSL_cleanse(out, inlen)` on each RFC 5649 integrity-failure path (lines 289/301/315/325) — `inlen` bytes into an `inlen - 8` byte buffer. Flipping one OID byte of a legitimate message changes the KEK (the KDF SharedInfo contains the AlgorithmIdentifier) and selects the padded unwrap, whose AIV check cannot pass, so the overflow is deterministic. Patch 028 allocates `outsize = max(outlen, inlen)` (upstream bfa46dc3638d57197deb27a2c368a14e8a7ea7c7 / Ubuntu `CVE-2026-63072-2.patch`) and adds the upstream regression test `test_kari_wrap_pad_unwrap_overflow()` to `test/cmsapitest.c` (confirmed by diff of the patched tree).

**JA.** `crypto/cms/cms_kari.c` の `cms_kek_cipher()` (1.1.1w) は `EVP_CipherUpdate(kari->ctx, NULL, &outlen, in, inlen)` で鍵ラップ暗号に出力長を問い合わせる。`aes_wrap_cipher()` (`crypto/evp/e_aes.c`) は復号時 `inlen - 8` を返し、バッファは `OPENSSL_malloc(outlen)` (208 行目) で確保される。鍵ラップ OID はメッセージ由来で、`id-aesNNN-wrap` と `id-aesNNN-wrap-pad` の両方が受理される (`EVP_CIPHER_mode() == EVP_CIPH_WRAP_MODE`)。パディング付き変種では `CRYPTO_128_unwrap_pad()` (`crypto/modes/wrap128.c`) が RFC 5649 の各完全性失敗経路 (289/301/315/325 行目) で `OPENSSL_cleanse(out, inlen)` を実行する — `inlen - 8` バイトのバッファに `inlen` バイト。正規メッセージの OID 1 バイトを変えると KEK が変わり (KDF の SharedInfo に AlgorithmIdentifier が含まれる)、AIV 検査が通らないパディング付きアンラップが選ばれるため、オーバーフローは決定的である。パッチ 028 は `outsize = max(outlen, inlen)` を確保し (上流 bfa46dc3638d57197deb27a2c368a14e8a7ea7c7 / Ubuntu `CVE-2026-63072-2.patch`)、上流の回帰テスト `test_kari_wrap_pad_unwrap_overflow()` を `test/cmsapitest.c` に追加している (修正済みツリーの diff で確認)。

## PoC design / PoC の設計

**EN.** Following the upstream regression test with the CLI: encrypt to `test/smime-certs/smec1.pem` with `-aes256` (key wrap `id-aes256-wrap`, 40-byte encryptedKey); `kari_mutate.py --mode wrap-pad` rewrites the last OID byte 0x2d → 0x30 (`id-aes256-wrap-pad`); `cmp -l` shows the single changed byte. Decrypt with `openssl cms -decrypt -recip smec1.pem -inkey smec1.pem -inform DER` on BASE (plain, valgrind, gdb with breakpoints at `cms_kari.c:208` and `wrap128.c:301`), BASE-ASAN, PATCHED (plain, valgrind, gdb at `cms_kari.c:263`) and PATCHED-ASAN; repeat with an AES-128 message (24-byte encryptedKey → 16-byte buffer); run the patched `test/cmsapitest` (3 arguments) normally, under ASan and under valgrind; regression round trips.

**JA.** 上流回帰テストの手順を CLI で追う: `test/smime-certs/smec1.pem` 宛に `-aes256` で暗号化 (鍵ラップ `id-aes256-wrap`、encryptedKey 40 バイト)、`kari_mutate.py --mode wrap-pad` で OID 最終バイトを 0x2d → 0x30 (`id-aes256-wrap-pad`) に書き換え、`cmp -l` で 1 バイトのみの差を示す。`openssl cms -decrypt -recip smec1.pem -inkey smec1.pem -inform DER` で BASE (通常、valgrind、`cms_kari.c:208` と `wrap128.c:301` にブレークポイントを置いた gdb)、BASE-ASAN、PATCHED (通常、valgrind、`cms_kari.c:263` の gdb)、PATCHED-ASAN により復号。AES-128 メッセージ (encryptedKey 24 バイト → 16 バイトバッファ) でも繰り返す。修正済み `test/cmsapitest` (3 引数) を通常、ASan、valgrind で実行。回帰ラウンドトリップ。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠抜粋)

**EN.** valgrind on BASE (`kari256_pad.der`):

```
==…== Invalid write of size 8
==…==    at 0x…: OPENSSL_cleanse (x86_64cpuid.s:234)
==…==    by 0x…: CRYPTO_128_unwrap_pad (wrap128.c:301)
==…==    by 0x…: aes_wrap_cipher (e_aes.c:3852)
==…==    by 0x…: EVP_DecryptUpdate (evp_enc.c:500)
==…==    by 0x…: EVP_CipherUpdate (evp_enc.c:216)
==…==    by 0x…: cms_kek_cipher (cms_kari.c:211)
==…==    by 0x…: CMS_RecipientInfo_kari_decrypt (cms_kari.c:243)
==…==    by 0x…: cms_kari_set1_pkey (cms_smime.c:593)
==…==    by 0x…: CMS_decrypt_set1_pkey (cms_smime.c:624)
==…==  Address 0x… is 0 bytes after a block of size 32 alloc'd
==…==    by 0x…: CRYPTO_malloc (mem.c:222)
==…==    by 0x…: cms_kek_cipher (cms_kari.c:208)
```

gdb: at `cms_kari.c:208` `inlen=40 (encryptedKey), outlen=32 (length query) -> out = OPENSSL_malloc(32)`, `EVP_CIPHER_CTX_nid(kari->ctx) = 903` (`NID_id_aes256_wrap_pad`); at `wrap128.c:301` `OPENSSL_cleanse(out=…, inlen=40) on a 32-byte buffer: 8 bytes past the end`, AIV bytes ≠ `A6 59 59 A6`. AES-128 variant: `Invalid write of size 8 … 0 bytes after a block of size 16`. Plain BASE run: only `Error decrypting CMS using private key` (exit 4) — the 8 bytes fall into glibc's chunk slack, so there is no visible crash. BASE-ASAN prints no report because `OPENSSL_cleanse()` is hand-written assembly (`crypto/x86_64cpuid.s` is part of the ASan build) and is not instrumented; this matches the upstream test's remark that valgrind flags the overflow.

**JA.** BASE の valgrind (`kari256_pad.der`): 上記のとおり `OPENSSL_cleanse (x86_64cpuid.s:234)` ← `CRYPTO_128_unwrap_pad (wrap128.c:301)` ← `aes_wrap_cipher` ← `EVP_DecryptUpdate` ← `cms_kek_cipher (cms_kari.c:211)` での `Invalid write of size 8`、アドレスは `cms_kek_cipher (cms_kari.c:208)` で確保された 32 バイトブロックの 0 バイト後。gdb: `cms_kari.c:208` で `inlen=40, outlen=32 -> out = OPENSSL_malloc(32)`、`EVP_CIPHER_CTX_nid(kari->ctx) = 903` (`NID_id_aes256_wrap_pad`)、`wrap128.c:301` で `OPENSSL_cleanse(out, inlen=40)` が 32 バイトバッファの 8 バイト先まで書く、AIV は `A6 59 59 A6` ではない。AES-128 変種: `Invalid write of size 8 … 0 bytes after a block of size 16`。BASE の通常実行は `Error decrypting CMS using private key` (終了コード 4) のみ — 8 バイトは glibc チャンクの余白に収まり、目に見えるクラッシュは無い。BASE-ASAN は `OPENSSL_cleanse()` が計装されない手書きアセンブリ (`crypto/x86_64cpuid.s` が ASan ビルドにも含まれる) のため報告しない。上流テストの「valgrind で検出される」との注記と一致する。

## Observed behaviour AFTER the patch / 修正後の挙動

**EN.** PATCHED / PATCHED-ASAN (leak detection on): `Error decrypting CMS using private key`, exit 4, no sanitizer output. valgrind `--leak-check=full` on PATCHED for both the AES-256 and the AES-128 crafted message: `ERROR SUMMARY: 0 errors`, `All heap blocks were freed -- no leaks are possible`. gdb at the patched `cms_kari.c:263`: `inlen=40, outlen=32 -> outsize=40 -> out = OPENSSL_malloc(40)`. The patched `test/cmsapitest servercert.pem serverkey.pem smec1.pem` prints `ok 1 - test_encrypt_decrypt`, `ok 2 - test_kari_wrap_pad_unwrap_overflow` (debug build, ASan build with leak detection, and under valgrind with 0 errors).

**JA.** PATCHED / PATCHED-ASAN (リーク検出有効): `Error decrypting CMS using private key`、終了コード 4、サニタイザ出力無し。AES-256 と AES-128 の細工メッセージ両方に対する PATCHED の valgrind `--leak-check=full`: `ERROR SUMMARY: 0 errors`、`All heap blocks were freed -- no leaks are possible`。修正済み `cms_kari.c:263` の gdb: `inlen=40, outlen=32 -> outsize=40 -> out = OPENSSL_malloc(40)`。修正済み `test/cmsapitest servercert.pem serverkey.pem smec1.pem` は `ok 1 - test_encrypt_decrypt`、`ok 2 - test_kari_wrap_pad_unwrap_overflow` を出力 (デバッグビルド、リーク検出付き ASan ビルド、valgrind 下で 0 エラー)。

## Regression check / 回帰確認

**EN.** PATCHED-ASAN (leak detection on): ECDH `-aes256` DER round trip OK (identical output); PATCHED: `-aes128` PEM round trip OK; BASE decrypts a PATCHED-produced message OK; valgrind on PATCHED decrypting the legitimate AES-256 message: 0 errors, output identical; patched cmsapitest `test_encrypt_decrypt` OK.

**JA.** PATCHED-ASAN (リーク検出有効): ECDH `-aes256` DER ラウンドトリップ OK (出力一致)。PATCHED: `-aes128` PEM ラウンドトリップ OK。PATCHED で作成したメッセージを BASE で復号 OK。正規 AES-256 メッセージを復号する PATCHED の valgrind: 0 エラー、出力一致。修正済み cmsapitest の `test_encrypt_decrypt` OK。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```bash
cd /home/user/work/poc/028_CVE-2026-63072
BASE=/home/user/work/base/openssl-1.1.1w; PATCHED=/home/user/work/patched/build
SRC=/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102; EC=$SRC/test/smime-certs/smec1.pem
printf 'secret\n' > msg.txt
$BASE/util/shlib_wrap.sh $BASE/apps/openssl cms -encrypt -binary -recip $EC -aes256 -outform DER -in msg.txt -out out/k.der
python3 -I kari_mutate.py --mode wrap-pad out/k.der out/k_pad.der          # id-aes256-wrap -> id-aes256-wrap-pad (one byte)
# unpatched: valgrind shows 'Invalid write of size 8' in OPENSSL_cleanse <- CRYPTO_128_unwrap_pad, after a 32-byte block from cms_kek_cipher
LD_LIBRARY_PATH=$BASE valgrind $BASE/apps/openssl cms -decrypt -recip $EC -inkey $EC -inform DER -in out/k_pad.der -out /dev/null
# patched: same clean error, valgrind 0 errors
LD_LIBRARY_PATH=$PATCHED valgrind --leak-check=full $PATCHED/apps/openssl cms -decrypt -recip $EC -inkey $EC -inform DER -in out/k_pad.der -out /dev/null
# patched regression test added by the patch
(cd $PATCHED && ./util/shlib_wrap.sh ./test/cmsapitest $SRC/test/certs/servercert.pem $SRC/test/certs/serverkey.pem $EC)
# regression
$PATCHED/util/shlib_wrap.sh $PATCHED/apps/openssl cms -decrypt -recip $EC -inkey $EC -inform DER -in out/k.der | cmp - msg.txt && echo REGRESSION_OK
# or: ./run_poc.sh | tee out/run_poc.output.txt
```

## Limitations / notes / 制限事項・注記

**EN.** (1) AddressSanitizer cannot observe this particular write because the overflowing store is performed by the assembly implementation of `OPENSSL_cleanse()`; the memory-safety evidence therefore comes from valgrind (both AES-256 and AES-128 variants) plus gdb values, exactly as the upstream test comment anticipates. (2) In a non-instrumented process the 8 bytes stay inside glibc's allocation slack for 16/32-byte blocks, so no crash is visible; a 24-byte buffer (3DES content → AES-192 wrap) would corrupt the next chunk header, but 1.1.1 uses `id-smime-alg-CMS3DESwrap` for 3DES content, so that variant is not applicable. (3) The first run of `run_poc.sh` had a wrong NID in a comment (914 instead of 903); only the comment was corrected (first output kept as `out/run_poc.output.attempt1.txt`).

**JA.** (1) オーバーフローする書き込みはアセンブリ実装の `OPENSSL_cleanse()` が行うため AddressSanitizer はこの書き込みを観測できない。メモリ安全性の証拠は valgrind (AES-256 と AES-128 の両変種) と gdb の値による。上流テストのコメントが想定するとおりである。(2) 計装なしのプロセスでは 8 バイトは 16/32 バイトブロックの glibc 余白内に収まるためクラッシュは見えない。24 バイトバッファ (3DES コンテンツ → AES-192 ラップ) なら次チャンクのヘッダを壊すが、1.1.1 は 3DES コンテンツに `id-smime-alg-CMS3DESwrap` を使うためその変種は適用できない。(3) `run_poc.sh` の初回実行ではコメント中の NID が誤っていた (903 ではなく 914)。コメントのみ修正した (初回出力は `out/run_poc.output.attempt1.txt` として保存)。
