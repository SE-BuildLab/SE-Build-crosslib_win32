# 011 / CVE-2025-69418 / OCB-AESNI-tail-bytes-unencrypted

Log file / ログファイル: `20261102_122439_011of033_CVE-2025-69418_OCB-AESNI-tail-bytes-unencrypted.log` (in /home/user/work/deliver/ipalongpatch_info/logs/)

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

In `CRYPTO_ocb128_encrypt()/_decrypt()` (crypto/modes/ocb128.c) the hardware stream path (`ctx->stream != NULL`, AES-NI `aesni_ocb_encrypt`) processes all full blocks in one call but, unlike the portable loop, does not advance `in`/`out`. The trailing partial block is then handled by `ocb_block_xor(in, pad.c, last_len, out)` (line 403 / 495) on the *first* `last_len` bytes: the real tail is never encrypted nor included in the checksum, and the first bytes of the ciphertext are overwritten. EVP (`aes_ocb_cipher`) is unaffected because it passes the tail in a separate call with `num_blocks == 0`. Patch 011 adds `in += num_blocks * 16; out += num_blocks * 16;` after the stream call in both functions.

`CRYPTO_ocb128_encrypt()/_decrypt()` (crypto/modes/ocb128.c) のハードウェア stream 経路 (`ctx->stream != NULL`、AES-NI の `aesni_ocb_encrypt`) は全フルブロックを 1 回で処理するが、移植版ループと異なり `in`/`out` を進めない。末尾の部分ブロックは `ocb_block_xor(in, pad.c, last_len, out)` (403 / 495 行目) により「先頭の」`last_len` バイトに対して処理され、本来の末尾は暗号化もチェックサム投入もされず、暗号文の先頭バイトが上書きされる。EVP (`aes_ocb_cipher`) は末尾を `num_blocks == 0` の別呼び出しで渡すため非影響。パッチ 011 は両関数の stream 呼び出し後に `in += num_blocks * 16; out += num_blocks * 16;` を追加する。

## PoC design / PoC の設計

`ocb_poc.c` is linked statically against libcrypto.a to call the internal `aesni_*` functions and build an OCB context exactly like `aes_ocb_init_key()`. It compares EVP_aes_128_ocb, the low-level generic path (AES_encrypt, stream = NULL) and the low-level AES-NI stream path on the OpenSSL known-answer vector (40 bytes = 2 blocks + 8), a 37-byte message and a 32-byte control, with a single `CRYPTO_ocb128_encrypt()` call; it prints differing byte positions, in-place output (cleartext tail?), the tag of a tail-modified message (authenticated?) and the decryption/tag check of the correct ciphertext. gdb shows `in - pt` / `out - ct` at the tail-processing line.

`ocb_poc.c` は libcrypto.a に静的リンクして内部の `aesni_*` 関数を呼び、`aes_ocb_init_key()` と同じ OCB コンテキストを構築する。OpenSSL の既知解ベクタ (40 バイト = 2 ブロック + 8)、37 バイト、32 バイトの対照について、EVP_aes_128_ocb、低レベル汎用経路 (AES_encrypt、stream = NULL)、低レベル AES-NI stream 経路を 1 回の `CRYPTO_ocb128_encrypt()` で比較し、異なるバイト位置、in-place 出力 (末尾が平文か)、末尾を変えたメッセージのタグ (認証されるか)、正しい暗号文の復号/タグ検証を表示する。gdb で末尾処理行での `in - pt` / `out - ct` を示す。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
=== message length 40 bytes = 2 full blocks + 8 trailing bytes ===
EVP ciphertext  BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A657149D53773463CB68C65778B058A635   tag 659C623211DEEA0DE30D2C381879F4C8
EVP vs known-answer test vector:  MATCH
--- low-level GENERIC (AES_encrypt, stream=NULL): ciphertext == EVP: yes, tag == EVP: yes
--- low-level AESNI (aesni_encrypt + aesni_ocb_encrypt stream)
  ciphertext (separate out buffer) 48E6775890788615031C144DA0B26122CEAAB9B05DF771A657149D53773463CB0000000000000000
  tag                              3101B19F14A7C154A8FCE589C402DDDD
  differing ciphertext byte positions: 0 1 2 3 4 5 6 7 32 33 34 35 36 37 38 39
  ciphertext (in-place)            F6429D2219C3F102031C144DA0B26122CEAAB9B05DF771A657149D53773463CB2021222324252627
  !! the last 8 bytes of the in-place 'ciphertext' are the PLAINTEXT tail (unencrypted)
  tag over a message whose tail bytes differ: IDENTICAL tag -> tail bytes are NOT authenticated
  decrypt(EVP ciphertext)          F6429D2219C3F10208090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F0000000000000000
  decrypted == plaintext: NO, tag verification (CRYPTO_ocb128_finish): FAILED
(37-byte message: same with positions 0-4 / 32-36; 32-byte block-aligned control: correct)
$ gdb ... 'break ocb128.c:403 if ctx->stream != 0 && num_blocks != 0' ./ocb_poc_base
num_blocks = 2   last_len = 8   ptlen = 40   in - pt = 0   out - ct = 0
```

## Observed behaviour AFTER the patch / 修正後の挙動

```
--- low-level AESNI (aesni_encrypt + aesni_ocb_encrypt stream)
  ciphertext == EVP: yes, tag == EVP: yes      (40 and 37 bytes)
  in-place tail bytes differ from the plaintext (encrypted)
  tag over a message whose tail bytes differ: different tag (tail authenticated)
  decrypted == plaintext: yes, tag verification (CRYPTO_ocb128_finish): OK
RESULT: all low-level OCB implementations agree with EVP (no CVE-2025-69418 symptom)
$ gdb ... 'break ocb128.c:459 if ctx->stream != 0 && num_blocks != 0' ./ocb_poc_patched
num_blocks = 2   last_len = 8   ptlen = 40   in - pt = 32   out - ct = 32
```

## Regression check / 回帰確認

Patched `test/evp_test test/recipes/30-test_evp_data/evpciph.txt` (contains the AES-OCB known-answer vectors, run through EVP and thus through the patched AES-NI stream path): `ok 1 - run_file_tests`. EVP results identical on BASE/PATCHED and equal to the published vector; generic path unchanged; valgrind clean.

修正済み `test/evp_test test/recipes/30-test_evp_data/evpciph.txt` (AES-OCB の既知解ベクタを含み、EVP 経由で修正済み AES-NI stream 経路を通る): `ok 1 - run_file_tests`。EVP の結果は BASE/PATCHED で同一かつ公開ベクタと一致; 汎用経路は不変; valgrind 問題なし。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/011_CVE-2025-69418
B=/home/user/work/base/openssl-1.1.1w; P=/home/user/work/patched/build
PS=/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102
gcc -g -O0 -Wall -I$B/include ocb_poc.c $B/libcrypto.a -ldl -pthread -o ocb_poc_base
gcc -g -O0 -Wall -I$P/include -I$PS/include ocb_poc.c $P/libcrypto.a -ldl -pthread -o ocb_poc_patched
./ocb_poc_base      # AESNI path: differing bytes 0-7 and 32-39, plaintext tail, identical tag, exit 1
./ocb_poc_patched   # all implementations agree with EVP, exit 0
gdb -q -batch -ex 'break ocb128.c:403 if ctx->stream != 0 && num_blocks != 0' -ex run -ex 'set $in0 = in' -ex up -ex 'print (long)($in0 - pt)' -ex kill ./ocb_poc_base
./run_poc.sh        # everything, with verdict
```

## Limitations / notes / 制限事項・注記

Only reachable via the low-level API with a hardware stream function (static linking to internal aesni_* symbols is required to demonstrate it; EVP and TLS are unaffected, confirmed for EVP). Deterministic results (published test vector). Only AES-128 exercised (fix is key-size independent). First run_poc.sh run had the gdb breakpoint stop in the EVP path first; condition tightened, both outputs kept.

ハードウェア stream 関数付きの低レベル API からのみ到達可能 (実証には内部 aesni_* シンボルへの静的リンクが必要; EVP と TLS は非影響で、EVP については確認済み)。結果は決定的 (公開テストベクタ)。AES-128 のみ試験 (修正は鍵長非依存)。run_poc.sh 初回は gdb ブレークポイントが先に EVP 経路で停止; 条件を絞り込み、両出力を保持。
