# 027/033 CVE-2026-54874 — DTLS-future-epoch-buffer-memDoS

Log file / ログファイル: `20261102_124251_027of033_CVE-2026-54874_DTLS-future-epoch-buffer-memDoS.log` (in /home/user/work/deliver/ipalongpatch_info/logs/). Verification 2026/11/02 12:42:51–2026/11/02 13:06:05 (JST), verdict **PASS**.

ログファイル: `20261102_124251_027of033_CVE-2026-54874_DTLS-future-epoch-buffer-memDoS.log` (/home/user/work/deliver/ipalongpatch_info/logs/ 配下)。検証 2026/11/02 12:42:51〜2026/11/02 13:06:05 (JST)、判定 **PASS**。

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

CVE-2026-54874 (OpenSSL advisory 2026-08-25, Low; CWE-405): while a DTLS handshake is in progress, a record whose epoch is the next epoch (r_epoch + 1, content type handshake or alert) cannot be processed yet, so dtls1_get_record() (ssl/record/ssl3_record.c) calls dtls1_buffer_record() to queue it in unprocessed_rcds. In 1.1.1w dtls1_buffer_record() (ssl/record/rec_layer_d1.c) does not copy the record: it takes ownership of the whole live read buffer (rdata->rbuf = s->rlayer.rbuf, 16720 bytes here) together with s->rlayer.packet, zeroes the record layer's buffer and calls ssl3_setup_buffers() to allocate a fresh ~16.7 KiB read buffer. Up to 100 records are queued per connection. A peer therefore makes the server retain about 100 x 16.9 KiB = 1.7 MB with 100 forged 29 byte datagrams (amplification of several hundred times), which is a memory denial of service.

CVE-2026-54874 (OpenSSL アドバイザリ 2026-08-25、Low; CWE-405): DTLS ハンドシェイク中に次エポック (r_epoch + 1、内容種別 handshake または alert) のレコードを受信するとまだ処理できないため、dtls1_get_record() (ssl/record/ssl3_record.c) が dtls1_buffer_record() を呼んで unprocessed_rcds に待ち行列化する。1.1.1w の dtls1_buffer_record() (ssl/record/rec_layer_d1.c) はレコードをコピーせず、使用中の読みバッファ全体 (rdata->rbuf = s->rlayer.rbuf、ここでは 16720 バイト) を s->rlayer.packet とともに奪い取り、レコード層のバッファをゼロ化して ssl3_setup_buffers() で新たに約 16.7 KiB の読みバッファを確保する。接続あたり最大 100 レコードが待ち行列化される。よって相手は 29 バイトの偽造データグラム 100 個でサーバに約 100 × 16.9 KiB = 1.7 MB を保持させられる (数百倍の増幅) — メモリ DoS。

## PoC design / PoC の設計

dtls_client.py (python3 -I) sends a hand-built DTLS 1.2 ClientHello over UDP to 127.0.0.1, drains the server's first flight (ServerHello ... ServerHelloDone, 7 datagrams) so that the server is in the middle of the handshake, then sends 120 forged records: content type 22, version 0xfefd, epoch 1, increasing sequence numbers, 16 payload bytes (29 bytes each, 3480 bytes in total). dtls_server.c is a minimal DTLS 1.2 server (DTLS_server_method, non-blocking UDP socket, BIO_new_dgram) that drives SSL_accept() and reports heap in use via mallinfo2() plus VmRSS/VmData: M0 right after the ClientHello has been processed, M1 after the forged records have been received (3 s of silence). Expected: unpatched ~1.7 MB growth (100 queued records x (16720 byte read buffer + bookkeeping)), patched a few KB (16 copies of 29 bytes + bookkeeping). The same is cross-checked on the stock 'openssl s_server -dtls1_2' of each build under gdb: breakpoints on dtls1_buffer_record (prints packet_length, rbuf.len and the queue size) and on ssl3_setup_read_buffer (counts fresh read buffer allocations): unpatched must allocate one new read buffer per queued record (100), patched none. ASan builds are run for memory-safety sanity (RSS only - mallinfo2 is meaningless under ASan) and the patched/unpatched servers are run under valgrind --leak-check=full. Regression: real DTLS 1.2 handshakes with application data between s_client and s_server (patched/patched, patched server/unpatched client, unpatched server/patched client).

dtls_client.py (python3 -I) は手組みの DTLS 1.2 ClientHello を UDP で 127.0.0.1 に送り、サーバの最初のフライト (ServerHello 〜 ServerHelloDone、7 データグラム) を読み捨ててサーバをハンドシェイク途中の状態にし、続いて偽造レコード 120 個を送る: 内容種別 22、バージョン 0xfefd、エポック 1、増加するシーケンス番号、ペイロード 16 バイト (各 29 バイト、合計 3480 バイト)。dtls_server.c は最小の DTLS 1.2 サーバ (DTLS_server_method、非ブロッキング UDP ソケット、BIO_new_dgram) で、SSL_accept() を駆動しつつ mallinfo2() によるヒープ使用量と VmRSS/VmData を報告する: M0 は ClientHello 処理直後、M1 は偽造レコード受信後 (3 秒間無通信)。期待値: 未修正は約 1.7 MB 増 (待ち行列 100 レコード × (16720 バイトの読みバッファ + 管理情報))、修正版は数 KB (29 バイトのコピー 16 個 + 管理情報)。同じことを各ビルドの標準 'openssl s_server -dtls1_2' にgdb を付けて相互確認する: dtls1_buffer_record (packet_length、rbuf.len、待ち行列サイズを表示) と ssl3_setup_read_buffer (新規読みバッファ確保回数を計数) にブレークポイント: 未修正は待ち行列化レコードごとに新しい読みバッファを確保 (100 回)、修正版は 0 回のはず。ASan ビルドはメモリ安全性の健全性確認 (RSS のみ — ASan 下では mallinfo2 は無意味) に使い、修正版/未修正版サーバを valgrind --leak-check=full でも実行する。回帰: s_client と s_server の実 DTLS 1.2 ハンドシェイクとアプリケーションデータ送受信 (修正版/修正版、修正版サーバ/未修正クライアント、未修正サーバ/修正版クライアント)。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
[client] sent DTLS ClientHello (113 bytes)
[client] received 7 datagram(s), 1441 bytes from the server (handshake in progress on the server)
[client] sent 120 forged epoch-1 records of 29 bytes each (3480 bytes on the wire)
M0 after ClientHello (handshake in progress):              heap_in_use=   249856 bytes  VmRSS=  5688 kB  VmData=   400 kB
M1 after receiving the forged next-epoch records:          heap_in_use=  1940656 bytes  VmRSS=  6116 kB  VmData=  2128 kB
   heap growth caused by the forged records: 1690800 bytes
RESULT: heap growth = 1690800 bytes (VULNERABLE: ~16.7 KiB read buffer retained per buffered record)
ssl3_setup_read_buffer hit #1: a new ~16.7 KiB read buffer is allocated
dtls1_buffer_record hit #1: incoming record packet_length=29 bytes, live read buffer rbuf.len=16720 bytes, queue size before=0
ssl3_setup_read_buffer hit #2: a new ~16.7 KiB read buffer is allocated
dtls1_buffer_record hit #2: incoming record packet_length=29 bytes, live read buffer rbuf.len=16720 bytes, queue size before=1
ssl3_setup_read_buffer hit #100: a new ~16.7 KiB read buffer is allocated
dtls1_buffer_record hit #100: incoming record packet_length=29 bytes, live read buffer rbuf.len=16720 bytes, queue size before=99
ssl3_setup_read_buffer hit #101: a new ~16.7 KiB read buffer is allocated
dtls1_buffer_record hit #101: incoming record packet_length=29 bytes, live read buffer rbuf.len=16720 bytes, queue size before=100
(gdb totals: 120 dtls1_buffer_record hits, 101 ssl3_setup_read_buffer hits)
```

Unpatched: 3,480 bytes of forged next-epoch records (120 x 29 bytes) make the server heap grow by 1,690,800 bytes (100 queued records x 16,908 bytes), VmData 400 -> 2128 kB; gdb on s_server shows a fresh 16.7 KiB read buffer allocated for every queued record (101 ssl3_setup_read_buffer calls) until the queue holds 100 records.

未修正: 偽造次エポックレコード 3,480 バイト (120 × 29 バイト) でサーバのヒープが 1,690,800 バイト増加 (待ち行列 100 レコード × 16,908 バイト)、VmData 400 → 2128 kB; s_server の gdb では待ち行列化レコードごとに新しい 16.7 KiB 読みバッファが確保され (ssl3_setup_read_buffer 101 回)、待ち行列は 100 レコードまで増える。

## Observed behaviour AFTER the patch / 修正後の挙動

```
M0 after ClientHello (handshake in progress):              heap_in_use=   249984 bytes  VmRSS=  5700 kB  VmData=   400 kB
M1 after receiving the forged next-epoch records:          heap_in_use=   252592 bytes  VmRSS=  5700 kB  VmData=   400 kB
   heap growth caused by the forged records: 2608 bytes
RESULT: heap growth = 2608 bytes (OK: only the record bytes are retained)
ssl3_setup_read_buffer hit #1: a new ~16.7 KiB read buffer is allocated
dtls1_buffer_record hit #1: incoming record packet_length=29 bytes, live read buffer rbuf.len=16720 bytes, queue size before=0
dtls1_buffer_record hit #2: incoming record packet_length=29 bytes, live read buffer rbuf.len=16720 bytes, queue size before=1
dtls1_buffer_record hit #16: incoming record packet_length=29 bytes, live read buffer rbuf.len=16720 bytes, queue size before=15
dtls1_buffer_record hit #17: incoming record packet_length=29 bytes, live read buffer rbuf.len=16720 bytes, queue size before=16
dtls1_buffer_record hit #120: incoming record packet_length=29 bytes, live read buffer rbuf.len=16720 bytes, queue size before=16
(gdb totals: 120 dtls1_buffer_record hits, 1 ssl3_setup_read_buffer hit)
==21699== All heap blocks were freed -- no leaks are possible
==21699== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

Patched: the same traffic grows the heap by 2,608 bytes only (16 record copies, queue capped at 16), no new read buffers are allocated, VmData unchanged; ASan clean, valgrind 0 errors / no leaks.

修正版: 同じトラフィックでヒープ増加は 2,608 バイトのみ (レコード複製 16 個、待ち行列上限 16)、新規読みバッファ確保無し、VmData 不変; ASan クリーン、valgrind エラー 0・リーク無し。

## Regression check / 回帰確認

```
[patched_server_patched_client] client: New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384 / Protocol  : DTLSv1.2; server received the application data: 1
[patched_server_base_client] client: New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384 / Protocol  : DTLSv1.2; server received the application data: 1
[base_server_patched_client] client: New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384 / Protocol  : DTLSv1.2; server received the application data: 1
REGRESSION: PASS
```

DTLS 1.2 s_client/s_server handshakes with application data succeed in all three build combinations (Protocol: DTLSv1.2, data received by the server).

DTLS 1.2 の s_client/s_server ハンドシェイクとアプリケーションデータ送受信は 3 つのビルド組み合わせすべてで成功 (Protocol: DTLSv1.2、サーバがデータを受信)。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/027_CVE-2026-54874
./run_poc.sh                                   # everything, prints VERDICT
# manual: terminal 1
./dtls_server_base 14027 /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/servercert.pem /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/serverkey.pem
# terminal 2
python3 -I dtls_client.py 127.0.0.1 14027 120 16 1   # -> server prints RESULT: heap growth = 1690800 bytes (BASE) / 2608 bytes (dtls_server_patched)
# stock s_server under gdb (BASE):
sleep 40 | LD_LIBRARY_PATH=/home/user/work/base/openssl-1.1.1w timeout 30 gdb -batch -x gdb_dtls.cmd --args /home/user/work/base/openssl-1.1.1w/apps/openssl s_server -dtls1_2 -accept 14127 -cert <cert> -key <key> &
python3 -I dtls_client.py 127.0.0.1 14127 120 16 1   # count 'ssl3_setup_read_buffer hit' lines: 101 (BASE) vs 1 (PATCHED)
```

Build example (BASE): gcc -g -O0 -I/home/user/work/base/openssl-1.1.1w/include dtls_server.c -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o dtls_server_base

ビルド例 (BASE): gcc -g -O0 -I/home/user/work/base/openssl-1.1.1w/include dtls_server.c -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o dtls_server_base

## Limitations / notes / 制約・注記

The heap figure is measured in-process with mallinfo2() (precise); RSS grows less because the stolen buffers are mostly untouched. The amplification here is ~486x (1,690,800 / 3,480) with 29 byte records; the advisory quotes ~1200x for minimal records. The per-connection effect is bounded (100 records), so many connections would be needed for a real DoS - as the advisory states (Low).

ヒープ量はプロセス内の mallinfo2() で計測 (正確)。RSS の増加は奪われたバッファの大半が未使用のため小さい。ここでの増幅率は 29 バイトレコードで約 486 倍 (1,690,800 / 3,480); アドバイザリは最小レコードで約 1200 倍としている。接続あたりの影響は有界 (100 レコード) なので実際の DoS には多数の接続が必要 — アドバイザリの記載 (Low) どおり。

