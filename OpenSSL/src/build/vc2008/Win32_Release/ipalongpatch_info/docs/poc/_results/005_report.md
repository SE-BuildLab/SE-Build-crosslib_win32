# 005/033 CVE-2024-4741 — SSL-free-buffers-use-after-free

Log file / ログファイル: `20261102_122048_005of033_CVE-2024-4741_SSL-free-buffers-use-after-free.log` (in /home/user/work/deliver/ipalongpatch_info/logs/). Verification 2026/11/02 12:20:48–2026/11/02 12:27:37 (JST), verdict **PASS**.

ログファイル: `20261102_122048_005of033_CVE-2024-4741_SSL-free-buffers-use-after-free.log` (/home/user/work/deliver/ipalongpatch_info/logs/ 配下)。検証 2026/11/02 12:20:48〜2026/11/02 12:27:37 (JST)、判定 **PASS**。

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

CVE-2024-4741 (OpenSSL advisory 2024-05-28, Low): SSL_free_buffers() in ssl/ssl_lib.c only checked RECORD_LAYER_read_pending() (rbuf.left != 0, i.e. raw bytes not yet consumed) and RECORD_LAYER_write_pending(). It did not notice two states in which the read buffer is still in use: (1) the 5 byte record header has been read and parsed (rlayer.rstate == SSL_ST_READ_BODY, rlayer.packet points into rbuf, packet_length == 5) but the record body has not arrived yet (rbuf.left == 0); (2) a whole record was received and decrypted in place but the application has read only part of the plaintext (rrec[0].length > 0, rrec[0].data points into rbuf). In both states the unpatched function returned 1 and RECORD_LAYER_release() -> ssl3_release_read_buffer() freed rbuf.buf. The next SSL_read() then (1) allocates a new buffer in ssl3_read_n() but keeps using the stale rlayer.packet pointer: ssl3_get_record() sets rr->input = packet + 5 inside the freed block and decrypts/MACs from there, or (2) memcpy()s the remaining plaintext out of the freed block (rec_layer_s3.c:1430) - a heap use-after-free read.

CVE-2024-4741 (OpenSSL アドバイザリ 2024-05-28、Low): ssl/ssl_lib.c の SSL_free_buffers() は RECORD_LAYER_read_pending() (rbuf.left != 0、すなわち未消費の生バイトがある) と RECORD_LAYER_write_pending() しか検査していなかった。読みバッファが使用中である次の 2 状態を見落としていた: (1) 5 バイトのレコードヘッダを読み取り・解析済み (rlayer.rstate == SSL_ST_READ_BODY、rlayer.packet は rbuf 内を指し、packet_length == 5) だがレコード本体が未着 (rbuf.left == 0); (2) レコード全体を受信してその場で復号したが、アプリケーションが平文の一部しか読んでいない (rrec[0].length > 0、rrec[0].data は rbuf 内を指す)。どちらの状態でも未修正の関数は 1 を返し、RECORD_LAYER_release() → ssl3_release_read_buffer() が rbuf.buf を解放する。次の SSL_read() は (1) ssl3_read_n() で新バッファを確保するが古い rlayer.packet ポインタを使い続け、ssl3_get_record() が rr->input = packet + 5 (解放済みブロック内) を設定してそこから復号/MAC 検証する、または (2) 残りの平文を解放済みブロックから memcpy() する (rec_layer_s3.c:1430) — ヒープ use-after-free 読み出し。

## PoC design / PoC の設計

poc_4741.c builds a TLS client/server pair connected through memory BIOs (tlshelp.h), completes the handshake (TLS 1.2 with AES128-SHA, i.e. CBC+HMAC, and TLS 1.3 with AES-256-GCM are both tested), lets the server SSL_write() a 67 byte message and takes the raw record out of the client's read BIO so that it can be fed back in pieces. Scenario 1: write only the 5 byte header, SSL_read() (-> SSL_ERROR_WANT_READ), then SSL_free_buffers() - unpatched returns 1 (buffer freed), patched 0; then the body is fed and SSL_read() is called again (unpatched: UAF read during decryption/MAC, visible as 'decryption failed or bad record mac' without sanitizer, as heap-use-after-free under ASan and 'Invalid read ... free'd' under valgrind; patched: the 67 bytes arrive intact). Scenario 2: feed the whole record, SSL_read() 1 byte (SSL_pending()=66), SSL_free_buffers() - unpatched 1 / patched 0 - then read the rest (unpatched: memcpy from freed memory, ASan heap-use-after-free in ssl3_read_bytes rec_layer_s3.c:1430; patched: intact). Scenario 0 (regression): read everything, SSL_free_buffers() must return 1 in both builds, and three further message exchanges in both directions (with SSL_free_buffers() after each) must work. run_poc.sh runs all scenarios for BASE, BASE-ASAN, PATCHED, PATCHED-ASAN, valgrind on BASE (scenarios 1,2) and PATCHED (1,2,0 with --leak-check=full), and the upstream test/sslbuffertest binary of the BASE, PATCHED and PATCHED-ASAN builds.

poc_4741.c はメモリ BIO で接続した TLS クライアント/サーバ対 (tlshelp.h) を作り、ハンドシェイク完了後 (TLS 1.2 の AES128-SHA = CBC+HMAC と、TLS 1.3 の AES-256-GCM の両方を試験)、サーバから 67 バイトのメッセージを SSL_write() し、クライアントの読み BIO から生レコードを取り出して小分けに戻せるようにする。シナリオ 1: 5 バイトのヘッダだけ書き込み SSL_read() (→ SSL_ERROR_WANT_READ)、続いて SSL_free_buffers() — 未修正は 1 (バッファ解放)、修正版は 0; その後本体を与えて再度 SSL_read() (未修正: 復号/MAC 時の UAF 読み出し。サニタイザ無しでは 'decryption failed or bad record mac'、ASan では heap-use-after-free、valgrind では 'Invalid read ... free'd' として観測; 修正版: 67 バイトが無傷で届く)。シナリオ 2: レコード全体を与え SSL_read() で 1 バイトだけ読む (SSL_pending()=66)、SSL_free_buffers() — 未修正 1 / 修正版 0 — 続いて残りを読む (未修正: 解放済みメモリからの memcpy、ASan で ssl3_read_bytes rec_layer_s3.c:1430 の heap-use-after-free; 修正版: 無傷)。シナリオ 0 (回帰): 全部読み切った状態では両ビルドで SSL_free_buffers() が 1 を返し、その後双方向に 3 往復のメッセージ交換 (各回 SSL_free_buffers() 付き) が成功すること。run_poc.sh は BASE, BASE-ASAN, PATCHED, PATCHED-ASAN の全シナリオ、BASE (シナリオ 1,2) と PATCHED (1,2,0、--leak-check=full) の valgrind、BASE/PATCHED/PATCHED-ASAN ビルドの上流 test/sslbuffertest を実行する。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
  SSL_read()=-1 SSL_get_error()=2 (SSL_ERROR_WANT_READ, body not yet available)
step 2: SSL_free_buffers(client) while the record body is still outstanding
  SSL_free_buffers()=1 -> VULNERABLE: read buffer freed while a partially received record is being processed
  SSL_read()=-1 SSL_get_error()=1; error queue: decryption failed or bad record mac
RESULT scenario 1 TLS1.3: VULNERABLE
step 2: SSL_free_buffers(client) while 66 decrypted bytes are still unread
  SSL_free_buffers()=1 -> VULNERABLE: read buffer freed while it still holds unread plaintext
  SSL_read()=66, data intact but copied out of FREED memory (stale heap content)
RESULT scenario 2 TLS1.3: VULNERABLE

==6022==ERROR: AddressSanitizer: heap-use-after-free on address 0x52900000524c at pc 0x7f49b44fb42e bp 0x7ffcf317d380 sp 0x7ffcf317cb28
READ of size 16 at 0x52900000524c thread T0
    #1 0x7f49b3f5b1d5 in aes_gcm_ctrl ../src_1.1.1w/openssl-1.1.1w/crypto/evp/e_aes.c:2881
    #2 0x7f49b3f8b421 in EVP_CIPHER_CTX_ctrl ../src_1.1.1w/openssl-1.1.1w/crypto/evp/evp_enc.c:667
    #3 0x7f49b4b8a147 in tls13_enc ../src_1.1.1w/openssl-1.1.1w/ssl/record/ssl3_record_tls13.c:151
    #4 0x7f49b4b7fe4b in ssl3_get_record ../src_1.1.1w/openssl-1.1.1w/ssl/record/ssl3_record.c:529
    #5 0x7f49b4b7927d in ssl3_read_bytes ../src_1.1.1w/openssl-1.1.1w/ssl/record/rec_layer_s3.c:1320
freed by thread T0 here:
    #1 0x7f49b3fbc715 in CRYPTO_free ../src_1.1.1w/openssl-1.1.1w/crypto/mem.c:312
    #2 0x7f49b4b7c5df in ssl3_release_read_buffer ../src_1.1.1w/openssl-1.1.1w/ssl/record/ssl3_buffer.c:180
    #3 0x7f49b4b7187f in RECORD_LAYER_release ../src_1.1.1w/openssl-1.1.1w/ssl/record/rec_layer_s3.c:72
    #4 0x7f49b4bcb7c4 in SSL_free_buffers ../src_1.1.1w/openssl-1.1.1w/ssl/ssl_lib.c:5250
    #5 0x5562f69d8a50 in main /home/user/work/poc/005_CVE-2024-4741/poc_4741.c:87
    #1 0x7f49b3fbc4b4 in CRYPTO_malloc ../src_1.1.1w/openssl-1.1.1w/crypto/mem.c:222
    #2 0x7f49b4b7bf7d in ssl3_setup_read_buffer ../src_1.1.1w/openssl-1.1.1w/ssl/record/ssl3_buffer.c:63
    #3 0x7f49b4b7c420 in ssl3_setup_buffers ../src_1.1.1w/openssl-1.1.1w/ssl/record/ssl3_buffer.c:147
    #4 0x7f49b4c0177b in state_machine ../src_1.1.1w/openssl-1.1.1w/ssl/statem/statem.c:392
    #5 0x7f49b4c00e47 in ossl_statem_connect ../src_1.1.1w/openssl-1.1.1w/ssl/statem/statem.c:250
    ... SSL_free_buffers -> RECORD_LAYER_release -> ssl3_release_read_buffer -> CRYPTO_free

==6025==ERROR: AddressSanitizer: heap-use-after-free on address 0x529000005209 at pc 0x7f145f8fb42e bp 0x7ffe04257a50 sp 0x7ffe042571f8
READ of size 66 at 0x529000005209 thread T0
    #0 0x7f145f8fb42d in memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115
    #1 0x7f145ff6dcd5 in ssl3_read_bytes ../src_1.1.1w/openssl-1.1.1w/ssl/record/rec_layer_s3.c:1430
    #0 0x7f145f8fc4d8 in free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:52
    #1 0x7f145f3bc715 in CRYPTO_free ../src_1.1.1w/openssl-1.1.1w/crypto/mem.c:312
    #0 0x7f145f8fd9c7 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x7f145f3bc4b4 in CRYPTO_malloc ../src_1.1.1w/openssl-1.1.1w/crypto/mem.c:222

==6074==  Address 0x4f113ec is 76 bytes inside a block of size 16,712 free'd
==6074==  Address 0x4f113f0 is 80 bytes inside a block of size 16,712 free'd
==6074== Invalid read of size 16
==6074==  Address 0x4f113d8 is 56 bytes inside a block of size 16,712 free'd
... (21 more lines omitted) ...
```

Unpatched: SSL_free_buffers() returns 1 while a record is half received or half read; the next SSL_read() fails with a bogus 'decryption failed or bad record mac' (scenario 1) or copies the rest of the plaintext out of freed memory (scenario 2). ASan: heap-use-after-free READ in memcpy called from tls13_enc/tls1_mac (scenario 1) and ssl3_read_bytes rec_layer_s3.c:1430 (scenario 2), block freed by SSL_free_buffers(). valgrind: 32 / 16 invalid-read errors inside the freed 16,712 byte read buffer.

未修正: レコードの受信途中・読み出し途中でも SSL_free_buffers() が 1 を返す。次の SSL_read() は偽の 'decryption failed or bad record mac' で失敗 (シナリオ 1) するか、残りの平文を解放済みメモリからコピーする (シナリオ 2)。ASan: tls13_enc/tls1_mac から呼ばれた memcpy (シナリオ 1)、ssl3_read_bytes rec_layer_s3.c:1430 (シナリオ 2) での heap-use-after-free READ、解放元は SSL_free_buffers()。valgrind: 解放済み 16,712 バイト読みバッファ内への不正読み出しエラー 32 / 16 件。

## Observed behaviour AFTER the patch / 修正後の挙動

```
  SSL_read()=-1 SSL_get_error()=2 (SSL_ERROR_WANT_READ, body not yet available)
step 2: SSL_free_buffers(client) while the record body is still outstanding
  SSL_free_buffers()=0 -> FIXED: refused (RECORD_LAYER_data_present)
  SSL_read()=67, data INTACT (matches what the server sent)
RESULT scenario 1 TLS1.3: OK
step 2: SSL_free_buffers(client) while 66 decrypted bytes are still unread
  SSL_free_buffers()=0 -> FIXED: refused (RECORD_LAYER_data_present)
  SSL_read()=66, data INTACT
RESULT scenario 2 TLS1.3: OK
==6082== All heap blocks were freed -- no leaks are possible
==6082== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

Patched: SSL_free_buffers() returns 0 in both states (RECORD_LAYER_data_present()), the data is then read intact, no ASan report, valgrind 0 errors and no leaks.

修正版: 両状態で SSL_free_buffers() が 0 を返し (RECORD_LAYER_data_present())、その後データは無傷で読める。ASan 報告無し、valgrind エラー 0・リーク無し。

## Regression check / 回帰確認

```
step 2: SSL_free_buffers(client) with nothing pending (must succeed)
  SSL_free_buffers()=1 -> buffers released as expected
  round 0: 'server->client message 0' and 'client->server message 0' exchanged OK
  SSL_free_buffers()=1 (nothing pending)
  round 1: 'server->client message 1' and 'client->server message 1' exchanged OK
  SSL_free_buffers()=1 (nothing pending)
  round 2: 'server->client message 2' and 'client->server message 2' exchanged OK
  SSL_free_buffers()=1 (nothing pending)
RESULT scenario 0 TLS1.3: OK
+ /home/user/work/base/openssl-1.1.1w/util/shlib_wrap.sh /home/user/work/base/openssl-1.1.1w/test/sslbuffertest /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/servercert.pem /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/serverkey.pem
ok 1 - test_func
+ /home/user/work/patched/build/util/shlib_wrap.sh /home/user/work/patched/build/test/sslbuffertest /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/servercert.pem /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/serverkey.pem
ok 1 - test_func
+ /home/user/work/patched/build-asan/util/shlib_wrap.sh /home/user/work/patched/build-asan/test/sslbuffertest /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/servercert.pem /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/serverkey.pem
ok 1 - test_func
```

With nothing pending SSL_free_buffers() still returns 1 and traffic continues (scenario 0, all builds, TLS 1.2 and 1.3); upstream test/sslbuffertest passes on BASE, PATCHED and PATCHED-ASAN.

保留データが無い場合は SSL_free_buffers() が引き続き 1 を返し通信も継続 (シナリオ 0、全ビルド、TLS 1.2/1.3)。上流 test/sslbuffertest は BASE, PATCHED, PATCHED-ASAN で合格。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/005_CVE-2024-4741
./run_poc.sh                                  # everything, prints VERDICT
./poc_4741_base 1 13; ./poc_4741_base 2 13        # unpatched: SSL_free_buffers()=1, bogus failure / stale data
./poc_4741_baseasan 1 13; ./poc_4741_baseasan 2 13  # unpatched ASan: heap-use-after-free
./poc_4741_patched 1 13; ./poc_4741_patched 2 13  # patched: SSL_free_buffers()=0, data intact
./poc_4741_patched 0 13                           # regression: free with nothing pending + further traffic
valgrind ./poc_4741_base 2 13                     # Invalid read ... block ... free'd by SSL_free_buffers
```

Build example (BASE-ASAN): gcc -g -O0 -fsanitize=address -I/home/user/work/base_asan/include -I/home/user/work/src_1.1.1w/openssl-1.1.1w/include poc_4741.c -L/home/user/work/base_asan -lssl -lcrypto -Wl,-rpath,/home/user/work/base_asan -o poc_4741_baseasan

ビルド例 (BASE-ASAN): gcc -g -O0 -fsanitize=address -I/home/user/work/base_asan/include -I/home/user/work/src_1.1.1w/openssl-1.1.1w/include poc_4741.c -L/home/user/work/base_asan -lssl -lcrypto -Wl,-rpath,/home/user/work/base_asan -o poc_4741_baseasan

## Limitations / notes / 制約・注記

Only applications that call SSL_free_buffers() directly are affected; the PoC calls it at the two moments identified by the advisory. In scenario 2 the stale plaintext happens to be intact without a sanitizer (glibc keeps the freed 16 KB block content), so the data-level symptom is only visible with ASan/valgrind; scenario 1 shows a functional symptom (bogus decryption failure) even without tools.

SSL_free_buffers() を直接呼ぶアプリケーションのみ影響する。PoC はアドバイザリが示す 2 つのタイミングで呼び出す。シナリオ 2 ではサニタイザ無しだと古い平文が偶然無傷で残る (glibc が解放済み 16 KB ブロックの内容を保持) ため、データ面の症状は ASan/valgrind でのみ見える。シナリオ 1 はツール無しでも機能的症状 (偽の復号失敗) が出る。

