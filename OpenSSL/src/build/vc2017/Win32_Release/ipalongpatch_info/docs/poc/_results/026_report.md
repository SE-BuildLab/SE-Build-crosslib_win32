# 026/033 HollowByte — LP2161371-TLS-init-buf-mem-DoS

Log file / ログファイル: `20261102_123308_026of033_HollowByte_LP2161371-TLS-init-buf-mem-DoS.log` (in /home/user/work/deliver/ipalongpatch_info/logs/). Verification 2026/11/02 12:33:08–2026/11/02 13:10:57 (JST), verdict **PASS**.

ログファイル: `20261102_123308_026of033_HollowByte_LP2161371-TLS-init-buf-mem-DoS.log` (/home/user/work/deliver/ipalongpatch_info/logs/ 配下)。検証 2026/11/02 12:33:08〜2026/11/02 13:10:57 (JST)、判定 **PASS**。

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

'HollowByte' (no CVE; Ubuntu LP: #2161371; upstream PR #30792-#30794 'Grow the init_buf incrementally as we receive data', OpenSSL 3.0.21 etc.): every TLS handshake message starts with a 4 byte header (1 byte type, 24 bit length). In 1.1.1w, as soon as the header has been read, read_state_machine() (ssl/statem/statem.c:610) calls grow_init_buf(s, message_size + 4) -> BUF_MEM_grow_clean(), which immediately (re)allocates the handshake buffer for the whole announced length - up to CLIENT_HELLO_MAX_LENGTH = 131396 bytes for a ClientHello - before any body byte has arrived (BUF_MEM_grow_clean even over-allocates by 4/3: a claimed 131072 bytes become a 174772 byte allocation). An unauthenticated peer therefore makes the server allocate ~170 KiB per connection by sending 9 bytes (TLS record header + handshake header) and then nothing; with many such idle connections this exhausts memory (denial of service, worsened by glibc heap fragmentation as described by the reporter).

「HollowByte」(CVE 無し; Ubuntu LP: #2161371; 上流 PR #30792〜#30794 'Grow the init_buf incrementally as we receive data'、OpenSSL 3.0.21 等): TLS ハンドシェイクメッセージはすべて 4 バイトのヘッダ (型 1 バイト、長さ 24 ビット) で始まる。1.1.1w では、ヘッダを読んだ直後に read_state_machine() (ssl/statem/statem.c:610) が grow_init_buf(s, message_size + 4) → BUF_MEM_grow_clean() を呼び、本体が 1 バイトも届く前に申告長全体 — ClientHello なら最大 CLIENT_HELLO_MAX_LENGTH = 131396 バイト — のハンドシェイクバッファを即座に (再) 確保する (BUF_MEM_grow_clean はさらに 4/3 倍に過剰確保する: 申告 131072 バイトが 174772 バイトの確保になる)。そのため認証されていない相手が 9 バイト (TLS レコードヘッダ + ハンドシェイクヘッダ) だけ送って何も送らないことで、サーバに接続あたり約 170 KiB を確保させられる; そのような放置接続を多数作るとメモリが枯渇する (DoS; 報告者が述べるとおり glibc のヒープ断片化で悪化する)。

## PoC design / PoC の設計

hb_client.py (python3 -I) opens N TCP connections to 127.0.0.1 and sends on each exactly 9 bytes: 16 03 01 00 04 (record header, length 4) + 01 02 00 00 (ClientHello header claiming 131072 bytes), then keeps the connections open. hb_server.c is a non-blocking TLS server that accepts N connections, calls SSL_accept() once per connection (P1: fixed per-connection cost, no data yet), then calls SSL_accept() again when the 9 bytes arrive (P2) and reports heap in use (mallinfo2 uordblks+hblkhd), VmRSS and VmData at each point; the P2-P1 difference divided by N is the memory the 9 byte header costs per connection: expected ~150 KiB unpatched and ~0 patched (the initial 16 KiB init_buf, allocated as 21849 bytes by BUF_MEM_grow, already covers the first 16388 byte chunk). N = 200 for the debug builds, 100 for the ASan builds (RSS only; mallinfo2 is meaningless under ASan). Second, deterministic structural evidence on the stock 'openssl s_server' of each build under gdb: 'break BUF_MEM_grow_clean if len >= 16000' (set after 'break main' so the shared library symbol is resolved; stdin kept open because s_server quits on stdin EOF) prints the requested length and the backtrace for one HollowByte connection: unpatched 131076 from read_state_machine()/grow_init_buf(), patched 16388 from tls_get_message_body(). Regression (regress.sh): normal TLS 1.2 and 1.3 handshakes plus a 25 certificate chain (20112 bytes DER; Certificate message 21758/21811 bytes, i.e. spanning several records) received by the patched client from patched and unpatched servers, and by the unpatched client from the patched server; HTTP 200 must be obtained via s_server -www.

hb_client.py (python3 -I) は 127.0.0.1 に N 本の TCP 接続を開き、それぞれに正確に 9 バイト: 16 03 01 00 04 (レコードヘッダ、長さ 4) + 01 02 00 00 (131072 バイトを申告する ClientHello ヘッダ) を送って接続を開いたまま保持する。hb_server.c は非ブロッキングの TLS サーバで、N 接続を accept し、接続ごとに SSL_accept() を 1 回呼び (P1: データ未着時の固定コスト)、9 バイトが届いたら再度 SSL_accept() を呼ぶ (P2)。各時点でヒープ使用量 (mallinfo2 uordblks+hblkhd)、VmRSS、VmData を報告し、P2−P1 を N で割った値が 9 バイトのヘッダが接続あたりに課すメモリ: 期待値は未修正で約 150 KiB、修正版で約 0 (BUF_MEM_grow が 21849 バイトで確保した初期 16 KiB の init_buf が最初の 16388 バイトチャンクを既に賄う)。デバッグビルドは N = 200、ASan ビルドは 100 (RSS のみ; ASan 下では mallinfo2 は無意味)。第二に、各ビルドの標準 'openssl s_server' に gdb を付けた決定的な構造的証拠: 'break BUF_MEM_grow_clean if len >= 16000' ('break main' 後に設定して共有ライブラリのシンボルを解決; s_server は stdin EOF で終了するため stdin を維持) が HollowByte 接続 1 本に対する要求長とバックトレースを表示: 未修正は read_state_machine()/grow_init_buf() からの 131076、修正版は tls_get_message_body() からの 16388。回帰 (regress.sh): 通常の TLS 1.2/1.3 ハンドシェイクと、25 証明書のチェーン (DER 20112 バイト; Certificate メッセージ 21758/21811 バイトで複数レコードにまたがる) を修正版クライアントが修正版/未修正サーバから、未修正クライアントが修正版サーバから受信し、s_server -www で HTTP 200 を得ること。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
P1 all connections accepted, SSL_accept() called, no data yet: heap_in_use=  14654672 bytes  VmRSS=  14260 kB  VmData=  14536 kB
   per-connection fixed cost: 72428 bytes
P2 every connection delivered its 9 byte header, SSL_accept() -> WANT_READ: heap_in_use=  45509072 bytes  VmRSS=  40936 kB  VmData=  48936 kB
   heap growth caused by the 9 byte headers: 30854400 bytes total = 154272 bytes per connection
RESULT: per-connection growth after the header = 154272 bytes (VULNERABLE: init_buf pre-allocated to the claimed size)
HIT 1: BUF_MEM_grow_clean(str->max=21848, len=131076) -> allocation will be (len+3)/3*4 = 174772 bytes
#0  BUF_MEM_grow_clean (str=0x5555556e1770, len=131076) at crypto/buffer/buffer.c:115
#1  0x00007ffff7f67aee in grow_init_buf (s=0x55555570cb00, size=131076) at ssl/statem/statem.c:501
#2  0x00007ffff7f67d9b in read_state_machine (s=0x55555570cb00) at ssl/statem/statem.c:610
```

Unpatched: 9 bytes per connection cost 154,272 bytes of heap each (200 connections: +30.9 MB heap, VmRSS 14.5 -> 41.2 MB); gdb shows BUF_MEM_grow_clean(len=131076) -> 174,772 byte allocation from read_state_machine() right after the header.

未修正: 接続あたり 9 バイトで各 154,272 バイトのヒープを消費 (200 接続: ヒープ +30.9 MB、VmRSS 14.5 → 41.2 MB); gdb はヘッダ直後に read_state_machine() から BUF_MEM_grow_clean(len=131076) → 174,772 バイト確保を示す。

## Observed behaviour AFTER the patch / 修正後の挙動

```
P1 all connections accepted, SSL_accept() called, no data yet: heap_in_use=  14654800 bytes  VmRSS=  14232 kB  VmData=  14536 kB
   per-connection fixed cost: 72428 bytes
P2 every connection delivered its 9 byte header, SSL_accept() -> WANT_READ: heap_in_use=  14654800 bytes  VmRSS=  14240 kB  VmData=  14536 kB
   heap growth caused by the 9 byte headers: 0 bytes total = 0 bytes per connection
RESULT: per-connection growth after the header = 0 bytes (OK: buffer grows only with received data)
HIT 1: BUF_MEM_grow_clean(str->max=21848, len=16388) -> allocation will be (len+3)/3*4 = 21852 bytes
#0  BUF_MEM_grow_clean (str=0x5555556e17e0, len=16388) at ../openssl-1.1.1w-ipalongpatch_20261102/crypto/buffer/buffer.c:115
#1  0x00007ffff7f778b2 in grow_init_buf (s=0x55555570cb70, size=16388) at ../openssl-1.1.1w-ipalongpatch_20261102/ssl/statem/statem_lib.c:1285
#2  0x00007ffff7f779b0 in tls_get_message_body (s=0x55555570cb70, len=0x7fffffffb658) at ../openssl-1.1.1w-ipalongpatch_20261102/ssl/statem/statem_lib.c:1364
```

Patched: 0 bytes of growth per connection (RSS/VmData unchanged); the only grow request is 16388 bytes from tls_get_message_body(), satisfied by the existing buffer.

修正版: 接続あたり増加 0 バイト (RSS/VmData 不変); 拡張要求は tls_get_message_body() からの 16388 バイトのみで既存バッファで賄われる。

## Regression check / 回帰確認

```
chain file: 25 certificates, 20112 bytes of DER in total (> 16384 => Certificate message spans several records)
(a) normal handshakes, patched server + patched client
[tls12_small] New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384; HTTP 200: 1; Certificate handshake message: 819 bytes
[tls13_small] New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384; HTTP 200: 1; Certificate handshake message: 822 bytes
(b) big chain: patched client receiving a Certificate message > 16 KiB (multi-record)
[tls12_bigchain_pp] New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384; HTTP 200: 1; Certificate handshake message: 21758 bytes
21758
[tls13_bigchain_pp] New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384; HTTP 200: 1; Certificate handshake message: 21811 bytes
21811
[tls12_bigchain_bp] New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384; HTTP 200: 1; Certificate handshake message: 21758 bytes
21758
(c) big chain: patched server, unpatched client (interoperability)
[tls13_bigchain_pb] New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384; HTTP 200: 1; Certificate handshake message: 21811 bytes
21811
Certificate message sizes seen by the clients (TLS1.2 p/p, TLS1.3 p/p, TLS1.2 base-server/patched-client, TLS1.3 patched-server/base-client): 21758 21811 21758 21811 bytes
REGRESSION: PASS
```

Normal TLS 1.2/1.3 handshakes and multi-record Certificate messages (21.7 KB) work with the patched client/server in all combinations; the patched tree's test suite (test_ssl_new etc.) was reported passing by the build step.

通常の TLS 1.2/1.3 ハンドシェイクと複数レコードにまたがる Certificate メッセージ (21.7 KB) は修正版クライアント/サーバの全組み合わせで動作; 修正版ツリーのテストスイート (test_ssl_new 等) はビルド工程で合格済みと報告されている。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/026_HollowByte
./run_poc.sh                                 # everything, prints VERDICT
# manual measurement (terminal 1 / terminal 2):
./hb_server_base 14026 200 /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/servercert.pem /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/serverkey.pem
python3 -I hb_client.py 127.0.0.1 14026 200 131072 4 2        # -> RESULT: per-connection growth after the header = 154272 bytes (base) / 0 (hb_server_patched)
# gdb on the stock server:
sleep 40 | LD_LIBRARY_PATH=/home/user/work/base/openssl-1.1.1w timeout 30 gdb -batch -x gdb_bufgrow.cmd --args /home/user/work/base/openssl-1.1.1w/apps/openssl s_server -accept 14126 -cert <cert> -key <key> &
python3 -I hb_client.py 127.0.0.1 14126 1 131072 3 1          # -> HIT 1: BUF_MEM_grow_clean(..., len=131076) (base) / len=16388 (patched)
./regress.sh /home/user/work/patched/build /home/user/work/base/openssl-1.1.1w 14226
```

Build example (BASE): gcc -g -O0 -I/home/user/work/base/openssl-1.1.1w/include hb_server.c -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o hb_server_base

ビルド例 (BASE): gcc -g -O0 -I/home/user/work/base/openssl-1.1.1w/include hb_server.c -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o hb_server_base

## Limitations / notes / 制約・注記

No CVE exists for this issue; the effect per connection is bounded (~170 KiB) and the DoS needs many idle connections, as the OpenSSL blog explains. The PoC measures the server-side effect precisely in-process (mallinfo2) and with the stock s_server under gdb; the glibc fragmentation/RSS-retention aspect described by the reporter was not reproduced. DTLS is not covered by the fix (as upstream).

本件に CVE は無い; 接続あたりの影響は有界 (約 170 KiB) で、OpenSSL ブログの説明どおり DoS には多数の放置接続が必要。PoC はサーバ側の影響をプロセス内 (mallinfo2) と標準 s_server + gdb で正確に計測した; 報告者が述べる glibc の断片化/RSS 高止まりの側面は再現していない。修正は DTLS を対象としない (上流同様)。

