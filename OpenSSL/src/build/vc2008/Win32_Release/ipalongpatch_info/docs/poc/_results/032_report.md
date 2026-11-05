# 032/033 CVE-2026-84782 — DTLS-retransmit-stale-init-off

Log file / ログファイル: `20261102_130106_032of033_CVE-2026-84782_DTLS-retransmit-stale-init-off.log` (in /home/user/work/deliver/ipalongpatch_info/logs/). Verification 2026/11/02 13:01:06–2026/11/02 13:22:21 (JST), verdict **PASS**.

ログファイル: `20261102_130106_032of033_CVE-2026-84782_DTLS-retransmit-stale-init-off.log` (/home/user/work/deliver/ipalongpatch_info/logs/ 配下)。検証 2026/11/02 13:01:06〜2026/11/02 13:22:21 (JST)、判定 **PASS**。

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

CVE-2026-84782 (OpenSSL advisory 2026-09-29, High): DTLS handshake messages are written from s->init_buf by dtls1_do_write() (ssl/statem/statem_dtls.c), which keeps the position in s->init_off/s->init_num and - because the handshake output goes through a buffering BIO that is flushed per datagram - can return SSL_ERROR_WANT_WRITE in the middle of a message when the transport cannot take the next datagram, leaving the write parked with init_off > 0. If the retransmission timer fires in that state, dtls1_handle_timeout() (ssl/d1_lib.c) calls dtls1_retransmit_buffered_messages() -> dtls1_retransmit_message(), which copies the queued message to the start of init_buf and sets init_num, but in 1.1.1w leaves init_off untouched. dtls1_do_write() therefore writes the retransmission starting at the stale offset: the fragment headers it generates claim offset 0 but the bytes are taken from further into the buffer and, towards the end, from beyond the end of the message (stale init_buf memory - heap content disclosure to the peer as plaintext handshake data; a crash if the read reaches unmapped memory). It also overwrites init_off/init_num/w_msg_hdr that the parked write still needs, so the next SSL_connect()/SSL_accept() fails: in a debug build the ossl_assert() at statem_dtls.c:128 aborts the process, in a release build the handshake fails (SSL_ERROR_SYSCALL).

CVE-2026-84782 (OpenSSL アドバイザリ 2026-09-29、High): DTLS のハンドシェイクメッセージは dtls1_do_write() (ssl/statem/statem_dtls.c) が s->init_buf から書き出し、位置を s->init_off/s->init_num に保持する。ハンドシェイク出力はデータグラム単位でフラッシュされるバッファリング BIO を通るため、トランスポートが次のデータグラムを受け取れないとメッセージの途中で SSL_ERROR_WANT_WRITE を返し、init_off > 0 のまま書き込みが中断 (パーク) される。その状態で再送タイマが発火すると dtls1_handle_timeout() (ssl/d1_lib.c) が dtls1_retransmit_buffered_messages() → dtls1_retransmit_message() を呼び、待ち行列のメッセージを init_buf の先頭へコピーして init_num を設定するが、1.1.1w では init_off をそのままにする。そのため dtls1_do_write() は古いオフセットから再送を書き出す: 生成するフラグメントヘッダはオフセット 0 を主張するが、バイト列はバッファのより先の位置から、末尾付近ではメッセージの終端を越えた領域 (init_buf の古いメモリ — 平文のハンドシェイクデータとして相手へヒープ内容が漏えい; 未マップ領域に達すればクラッシュ) から取られる。さらにパーク中の書き込みが必要とする init_off/init_num/w_msg_hdr を上書きするため、次の SSL_connect()/SSL_accept() は失敗する: デバッグビルドでは statem_dtls.c:128 の ossl_assert() がプロセスを abort させ、リリースビルドではハンドシェイク失敗 (SSL_ERROR_SYSCALL) となる。

## PoC design / PoC の設計

(1) The patched tree's test/dtlstest.c (unmodified copy, sha256 verified) and test/ssltestlib.c are compiled against each library with that build's libtestutil.a: BASE and BASE-ASAN must fail the two new tests (the fragment-limited BIO counts write calls made by DTLSv1_handle_timeout() while the write is parked), PATCHED and PATCHED-ASAN must pass all 7 tests. (2) dtls_retransmit_dump.c (own program on the same testutil/ssltestlib basis) reproduces both scenarios - client: ClientHello of 894 bytes with a 750 byte ALPN list, MTU 256, the BIO lets 1 datagram out; server: ServerHello + Certificate, the BIO lets 2 datagrams out - records every datagram that reaches the BIO, fires the timer three times, and parses each datagram (DTLS record header, handshake fragment header: type, msg_len, msg_seq, frag_off, frag_len) comparing timer-written fragments with the bytes of the same message written in the initial call and flagging all-zero fragment bodies (init_buf memory beyond the message). Finally it calls the handshake function again. Expected unpatched: datagrams written during the timeouts, a retransmitted fragment labelled frag_off 0 whose bytes differ from the original (client: ALPN padding instead of version/random; server: a 'ServerHello' record containing Certificate bytes), zero bytes from beyond the message, and an abort (ossl_assert statem_dtls.c:128, exit 134) on the resumed call. Expected patched: zero datagrams during the timeouts, DTLSv1_handle_timeout() = 0, and the resumed call completes the flight with correctly continued fragments (frag_off 231 ...) and SSL_ERROR_WANT_READ. (3) valgrind on the dump program (patched: leak check; unpatched: any invalid access) and ASan builds. Regression: the 5 pre-existing dtlstest tests and the patched dump runs (normal retransmission/resumption behaviour).

(1) 修正版ツリーの test/dtlstest.c (無変更のコピー、sha256 で確認) と test/ssltestlib.c を各ライブラリとそのビルドの libtestutil.a でコンパイルする: BASE と BASE-ASAN は新規 2 テストに失敗 (フラグメント制限 BIO が、書き込みパーク中に DTLSv1_handle_timeout() が行った書き込み回数を数える) し、PATCHED と PATCHED-ASAN は 7 テストすべてに合格すること。(2) dtls_retransmit_dump.c (同じ testutil/ssltestlib 基盤上の自作プログラム) は両シナリオ — クライアント: 750 バイトの ALPN リストを持つ 894 バイトの ClientHello、MTU 256、BIO はデータグラム 1 個のみ通過; サーバ: ServerHello + Certificate、BIO はデータグラム 2 個通過 — を再現し、BIO に届いた全データグラムを記録、タイマを 3 回発火させ、各データグラムを解析 (DTLS レコードヘッダ、ハンドシェイクフラグメントヘッダ: type、msg_len、msg_seq、frag_off、frag_len) してタイマによるフラグメントを初回呼び出しで書かれた同一メッセージのバイト列と比較し、全ゼロのフラグメント本体 (メッセージを越えた init_buf メモリ) を検出する。最後にハンドシェイク関数を再度呼ぶ。期待値 — 未修正: タイムアウト中にデータグラムが書かれ、frag_off 0 とラベルされた再送フラグメントのバイト列が元と異なる (クライアント: version/random の代わりに ALPN パディング; サーバ: Certificate のバイトを含む 'ServerHello' レコード)、メッセージ外からのゼロバイト、再開呼び出しでの abort (ossl_assert statem_dtls.c:128、終了コード 134)。修正版: タイムアウト中のデータグラム 0、DTLSv1_handle_timeout() = 0、再開呼び出しが正しく続きのフラグメント (frag_off 231 ...) でフライトを完了し SSL_ERROR_WANT_READ。(3) dump プログラムの valgrind (修正版: リーク検査; 未修正: 不正アクセスの有無) と ASan ビルド。回帰: 既存の 5 つの dtlstest テストと修正版の dump 実行 (通常の再送/再開動作)。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
# ERROR: (int) 'fb->write_calls == write_calls_before' failed @ dtlstest_patched.c:697
# [7] compared to [2]
not ok 6 - test_dtls_client_retransmit
# ERROR: (int) 'fb->write_calls == write_calls_before' failed @ dtlstest_patched.c:783
# [9] compared to [3]
not ok 7 - test_dtls_server_retransmit

step 1: SSL_connect() = -1, SSL_get_error = 3 (SSL_ERROR_WANT_WRITE); 1 datagram(s) written before the BIO blocked -> write parked mid-message
step 2.1: timer expired, DTLSv1_handle_timeout() = 1, BIO write calls during the timeout: 5
step 2.2: timer expired, DTLSv1_handle_timeout() = 1, BIO write calls during the timeout: 4
step 2.3: timer expired, DTLSv1_handle_timeout() = 1, BIO write calls during the timeout: 4
  datagram #1 (phase 0 = initial call), 256 bytes:
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 0 frag_len 231
  datagram #2 (phase 1 = TIMER), 256 bytes:
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 231 frag_len 231
  datagram #3 (phase 1 = TIMER), 256 bytes:
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 0 frag_len 231
      -> compared with the 231 reference bytes of ClientHello msg_seq 0 written in the initial call: 149 differ (CORRUPTED - bytes come from a stale buffer offset)
  datagram #4 (phase 1 = TIMER), 256 bytes:
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 231 frag_len 231
  datagram #5 (phase 1 = TIMER), 256 bytes:
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 462 frag_len 231
      -> all 231 body bytes are zero: this is not message content but init_buf memory beyond the end of the message
  datagram #6 (phase 1 = TIMER), 226 bytes:
    record 1: type 22 epoch 0 len 213 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 693 frag_len 201
      -> all 201 body bytes are zero: this is not message content but init_buf memory beyond the end of the message
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 0 frag_len 231
      -> compared with the 231 reference bytes of ClientHello msg_seq 0 written in the initial call: 0 differ (identical)
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 231 frag_len 231
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 462 frag_len 231
    record 1: type 22 epoch 0 len 213 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 693 frag_len 201
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 0 frag_len 231
      -> compared with the 231 reference bytes of ClientHello msg_seq 0 written in the initial call: 0 differ (identical)
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 231 frag_len 231
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 462 frag_len 231
    record 1: type 22 epoch 0 len 213 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 693 frag_len 201
SUMMARY client: datagrams written by the retransmission timer while the write was parked: 13 (the first one is the flush of the datagram parked in the buffering BIO, the rest is the retransmission); corrupted retransmitted fragments: 1; zero bytes sent from init_buf beyond the end of a message: 432
... (4 more lines omitted) ...
```

Unpatched: the two new tests fail (write calls during the timeout: 7 vs 2 / 9 vs 3). Dump: the first timer retransmission is built from the stale init_off - the 'frag_off 0' ClientHello fragment carries ALPN padding instead of version/random (149/231 bytes differ), two fragments carry 432 zero bytes from beyond the message, and the server-side 'ServerHello' record carries 57 bytes of Certificate data; the resumed handshake call aborts on the dtls1_do_write() assertion (exit 134).

未修正: 新規 2 テストが失敗 (タイムアウト中の書き込み回数 7 対 2 / 9 対 3)。ダンプ: 最初のタイマ再送が古い init_off から構築され — 'frag_off 0' の ClientHello フラグメントが version/random の代わりに ALPN パディングを運び (231 バイト中 149 が相違)、2 つのフラグメントがメッセージ外からの 432 バイトのゼロを運び、サーバ側の 'ServerHello' レコードは Certificate のデータ 57 バイトを運ぶ; 再開したハンドシェイク呼び出しは dtls1_do_write() のアサーションで abort (終了コード 134)。

## Observed behaviour AFTER the patch / 修正後の挙動

```
ok 6 - test_dtls_client_retransmit
ok 7 - test_dtls_server_retransmit
step 1: SSL_connect() = -1, SSL_get_error = 3 (SSL_ERROR_WANT_WRITE); 1 datagram(s) written before the BIO blocked -> write parked mid-message
step 2.1: timer expired, DTLSv1_handle_timeout() = 0, BIO write calls during the timeout: 0
step 2.2: timer expired, DTLSv1_handle_timeout() = 0, BIO write calls during the timeout: 0
step 2.3: timer expired, DTLSv1_handle_timeout() = 0, BIO write calls during the timeout: 0
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 0 frag_len 231
SUMMARY client: datagrams written by the retransmission timer while the write was parked: 0 (the first one is the flush of the datagram parked in the buffering BIO, the rest is the retransmission); corrupted retransmitted fragments: 0; zero bytes sent from init_buf beyond the end of a message: 0
RESULT client: OK
step 3: calling the resumed SSL_connect() (unpatched: the parked write's init_off/init_num were clobbered by the retransmission -> dtls1_do_write() assertion statem_dtls.c:128 fails: abort() in this debug build, SSL_ERROR_SYSCALL in a release build)
step 3: resumed SSL_connect() = -1, SSL_get_error = 2 (SSL_ERROR_WANT_READ: flight completed, waiting for the peer)
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 0 frag_len 231
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 231 frag_len 231
    record 1: type 22 epoch 0 len 243 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 462 frag_len 231
    record 1: type 22 epoch 0 len 213 | handshake ClientHello(1) msg_len 894 msg_seq 0 frag_off 693 frag_len 201
==24233== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

Patched: both new tests pass on PATCHED and PATCHED-ASAN; DTLSv1_handle_timeout() writes nothing while the write is parked and the resumed call completes the flight with contiguous fragments (SSL_ERROR_WANT_READ); valgrind 0 errors, no leaks.

修正版: 新規 2 テストは PATCHED と PATCHED-ASAN で合格; 書き込みパーク中は DTLSv1_handle_timeout() が何も書かず、再開呼び出しが連続したフラグメントでフライトを完了 (SSL_ERROR_WANT_READ); valgrind エラー 0、リーク無し。

## Regression check / 回帰確認

```
ok 1 - test_dtls_unprocessed
ok 2 - test_dtls_drop_records
ok 3 - test_cookie
ok 4 - test_dtls_duplicate_records
ok 5 - test_swap_app_data
ok 6 - test_dtls_client_retransmit
ok 7 - test_dtls_server_retransmit
    record 1: type 22 epoch 0 len 243 | handshake Certificate(11) msg_len 815 msg_seq 1 frag_off 149 frag_len 231
step 3: resumed SSL_accept() = -1, SSL_get_error = 2 (SSL_ERROR_WANT_READ: flight completed, waiting for the peer)
    record 1: type 22 epoch 0 len 243 | handshake Certificate(11) msg_len 815 msg_seq 1 frag_off 149 frag_len 231
    record 1: type 22 epoch 0 len 243 | handshake Certificate(11) msg_len 815 msg_seq 1 frag_off 380 frag_len 231
    record 1: type 22 epoch 0 len 216 | handshake Certificate(11) msg_len 815 msg_seq 1 frag_off 611 frag_len 204
```

Pre-existing DTLS tests pass on all builds; resumption of a parked flight works on the patched library (client and server); DTLS 1.2 s_client/s_server handshakes verified in item 027.

既存の DTLS テストは全ビルドで合格; 修正版ライブラリでパークしたフライトの再開が動作 (クライアント・サーバ); DTLS 1.2 の s_client/s_server ハンドシェイクは項目 027 で確認。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/032_CVE-2026-84782
./run_poc.sh                                              # builds + runs everything, prints VERDICT
./dtlstest_base    /home/user/work/src_1.1.1w/openssl-1.1.1w/apps/server.pem /home/user/work/src_1.1.1w/openssl-1.1.1w/apps/server.pem   # not ok 6, not ok 7
./dtlstest_patched /home/user/work/src_1.1.1w/openssl-1.1.1w/apps/server.pem /home/user/work/src_1.1.1w/openssl-1.1.1w/apps/server.pem   # ok 1..7
./dump_base    <server.pem> <server.pem> client      # corrupted retransmission + abort (exit 134); 'server' for the server side
./dump_patched <server.pem> <server.pem> client      # no writes during timeouts, flight resumed (exit 0)
```

Build example (BASE): gcc -g -O0 -I/home/user/work/base/openssl-1.1.1w/include -I/home/user/work/base/openssl-1.1.1w -I/home/user/work/base/openssl-1.1.1w/test dtlstest_patched.c ssltestlib.c /home/user/work/base/openssl-1.1.1w/test/libtestutil.a -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o dtlstest_base

ビルド例 (BASE): gcc -g -O0 -I/home/user/work/base/openssl-1.1.1w/include -I/home/user/work/base/openssl-1.1.1w -I/home/user/work/base/openssl-1.1.1w/test dtlstest_patched.c ssltestlib.c /home/user/work/base/openssl-1.1.1w/test/libtestutil.a -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o dtlstest_base

## Limitations / notes / 制約・注記

In this reproduction the bytes read from beyond the message are zeros because init_buf (16 KiB, zero-filled by BUF_MEM_grow) was freshly allocated for the first flight; in a long-lived connection or with larger messages the same read returns stale heap content (the advisory's disclosure) and, if the stale offset reaches past the allocation, a crash. No ASan/valgrind memory error is produced here because the reads stay inside the 16 KiB buffer; the abort comes from OpenSSL's own ossl_assert() in the debug build (a release build fails the handshake instead).

本再現ではメッセージ外から読まれたバイトはゼロである (init_buf (16 KiB、BUF_MEM_grow によりゼロ埋め) が最初のフライト用に新規確保されたため); 長寿命の接続やより大きなメッセージでは同じ読み出しが古いヒープ内容を返し (アドバイザリの漏えい)、古いオフセットが確保領域を越えればクラッシュする。読み出しが 16 KiB バッファ内に留まるため ASan/valgrind のメモリエラーは出ない; abort はデバッグビルドにおける OpenSSL 自身の ossl_assert() による (リリースビルドでは代わりにハンドシェイクが失敗する)。

