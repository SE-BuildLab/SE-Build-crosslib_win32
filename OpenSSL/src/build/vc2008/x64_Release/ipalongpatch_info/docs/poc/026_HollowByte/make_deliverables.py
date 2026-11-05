#!/usr/bin/env python3
import sys; sys.path.insert(0, "/home/user/work/poc/026_HollowByte")
from mkdeliv import Deliv
D = "/home/user/work/poc/026_HollowByte"
d = Deliv("026", "HollowByte", "LP2161371-TLS-init-buf-mem-DoS", D)
S = ["Vulnerability mechanism (as observed in the code)", "PoC design",
     "Observed behaviour BEFORE the patch (evidence excerpts)", "Observed behaviour AFTER the patch",
     "Regression check", "How to reproduce manually (step-by-step commands a human can run)", "Limitations / notes"]
d.H("1. Vulnerability description / 脆弱性の説明")
mech_en = ("'HollowByte' (no CVE; Ubuntu LP: #2161371; upstream PR #30792-#30794 'Grow the init_buf incrementally as we receive data', OpenSSL 3.0.21 etc.): every "
 "TLS handshake message starts with a 4 byte header (1 byte type, 24 bit length). In 1.1.1w, as soon as the header has been read, read_state_machine() "
 "(ssl/statem/statem.c:610) calls grow_init_buf(s, message_size + 4) -> BUF_MEM_grow_clean(), which immediately (re)allocates the handshake buffer for the "
 "whole announced length - up to CLIENT_HELLO_MAX_LENGTH = 131396 bytes for a ClientHello - before any body byte has arrived (BUF_MEM_grow_clean even "
 "over-allocates by 4/3: a claimed 131072 bytes become a 174772 byte allocation). An unauthenticated peer therefore makes the server allocate ~170 KiB per "
 "connection by sending 9 bytes (TLS record header + handshake header) and then nothing; with many such idle connections this exhausts memory "
 "(denial of service, worsened by glibc heap fragmentation as described by the reporter).")
mech_ja = ("「HollowByte」(CVE 無し; Ubuntu LP: #2161371; 上流 PR #30792〜#30794 'Grow the init_buf incrementally as we receive data'、OpenSSL 3.0.21 等): TLS ハンドシェイク"
 "メッセージはすべて 4 バイトのヘッダ (型 1 バイト、長さ 24 ビット) で始まる。1.1.1w では、ヘッダを読んだ直後に read_state_machine() (ssl/statem/statem.c:610) が "
 "grow_init_buf(s, message_size + 4) → BUF_MEM_grow_clean() を呼び、本体が 1 バイトも届く前に申告長全体 — ClientHello なら最大 CLIENT_HELLO_MAX_LENGTH = 131396 バイト — の"
 "ハンドシェイクバッファを即座に (再) 確保する (BUF_MEM_grow_clean はさらに 4/3 倍に過剰確保する: 申告 131072 バイトが 174772 バイトの確保になる)。"
 "そのため認証されていない相手が 9 バイト (TLS レコードヘッダ + ハンドシェイクヘッダ) だけ送って何も送らないことで、サーバに接続あたり約 170 KiB を確保させられる; "
 "そのような放置接続を多数作るとメモリが枯渇する (DoS; 報告者が述べるとおり glibc のヒープ断片化で悪化する)。")
d.P(mech_en, mech_ja)
d.P("IPALongPatch 026 (backport of upstream c5785a5e35882079faf49015c0ea0bb1b9a24ecf / Ubuntu lp2161371.patch) removes the up-front growth from "
    "read_state_machine() and moves grow_init_buf() into tls_get_message_body() (ssl/statem/statem_lib.c), where the buffer is grown by at most "
    "SSL3_RT_MAX_PLAIN_LENGTH (16384) bytes per chunk just before each chunk of the body is read, so memory follows the data actually received. (DTLS is "
    "unchanged, as upstream.)",
    "IPALongPatch 026 (上流 c5785a5e35882079faf49015c0ea0bb1b9a24ecf / Ubuntu lp2161371.patch のバックポート) は read_state_machine() からの事前拡張を取り除き、"
    "grow_init_buf() を tls_get_message_body() (ssl/statem/statem_lib.c) へ移して、本体の各チャンクを読む直前に最大 SSL3_RT_MAX_PLAIN_LENGTH (16384) バイト単位で"
    "拡張するようにした。これによりメモリは実際に受信したデータ量に従う (上流同様 DTLS は変更なし)。")
d.H("2. PoC strategy / PoC の方針")
poc_en = ("hb_client.py (python3 -I) opens N TCP connections to 127.0.0.1 and sends on each exactly 9 bytes: 16 03 01 00 04 (record header, length 4) + "
 "01 02 00 00 (ClientHello header claiming 131072 bytes), then keeps the connections open. hb_server.c is a non-blocking TLS server that accepts N connections, "
 "calls SSL_accept() once per connection (P1: fixed per-connection cost, no data yet), then calls SSL_accept() again when the 9 bytes arrive (P2) and reports "
 "heap in use (mallinfo2 uordblks+hblkhd), VmRSS and VmData at each point; the P2-P1 difference divided by N is the memory the 9 byte header costs per "
 "connection: expected ~150 KiB unpatched and ~0 patched (the initial 16 KiB init_buf, allocated as 21849 bytes by BUF_MEM_grow, already covers the first "
 "16388 byte chunk). N = 200 for the debug builds, 100 for the ASan builds (RSS only; mallinfo2 is meaningless under ASan). Second, deterministic structural "
 "evidence on the stock 'openssl s_server' of each build under gdb: 'break BUF_MEM_grow_clean if len >= 16000' (set after 'break main' so the shared library "
 "symbol is resolved; stdin kept open because s_server quits on stdin EOF) prints the requested length and the backtrace for one HollowByte connection: "
 "unpatched 131076 from read_state_machine()/grow_init_buf(), patched 16388 from tls_get_message_body(). Regression (regress.sh): normal TLS 1.2 and 1.3 "
 "handshakes plus a 25 certificate chain (20112 bytes DER; Certificate message 21758/21811 bytes, i.e. spanning several records) received by the patched "
 "client from patched and unpatched servers, and by the unpatched client from the patched server; HTTP 200 must be obtained via s_server -www.")
poc_ja = ("hb_client.py (python3 -I) は 127.0.0.1 に N 本の TCP 接続を開き、それぞれに正確に 9 バイト: 16 03 01 00 04 (レコードヘッダ、長さ 4) + 01 02 00 00 "
 "(131072 バイトを申告する ClientHello ヘッダ) を送って接続を開いたまま保持する。hb_server.c は非ブロッキングの TLS サーバで、N 接続を accept し、接続ごとに SSL_accept() を "
 "1 回呼び (P1: データ未着時の固定コスト)、9 バイトが届いたら再度 SSL_accept() を呼ぶ (P2)。各時点でヒープ使用量 (mallinfo2 uordblks+hblkhd)、VmRSS、VmData を報告し、"
 "P2−P1 を N で割った値が 9 バイトのヘッダが接続あたりに課すメモリ: 期待値は未修正で約 150 KiB、修正版で約 0 (BUF_MEM_grow が 21849 バイトで確保した初期 16 KiB の init_buf が"
 "最初の 16388 バイトチャンクを既に賄う)。デバッグビルドは N = 200、ASan ビルドは 100 (RSS のみ; ASan 下では mallinfo2 は無意味)。第二に、各ビルドの標準 'openssl s_server' に "
 "gdb を付けた決定的な構造的証拠: 'break BUF_MEM_grow_clean if len >= 16000' ('break main' 後に設定して共有ライブラリのシンボルを解決; s_server は stdin EOF で終了するため "
 "stdin を維持) が HollowByte 接続 1 本に対する要求長とバックトレースを表示: 未修正は read_state_machine()/grow_init_buf() からの 131076、修正版は tls_get_message_body() からの 16388。"
 "回帰 (regress.sh): 通常の TLS 1.2/1.3 ハンドシェイクと、25 証明書のチェーン (DER 20112 バイト; Certificate メッセージ 21758/21811 バイトで複数レコードにまたがる) を"
 "修正版クライアントが修正版/未修正サーバから、未修正クライアントが修正版サーバから受信し、s_server -www で HTTP 200 を得ること。")
d.P(poc_en, poc_ja)
d.H("3. Commands executed and raw output / 実行コマンドと生出力")
d.P("Complete console output of the final run_poc.sh run (earlier runs: section 7):", "最終的な run_poc.sh 実行の全コンソール出力 (以前の実行は第 7 節):")
d.CMD("run_poc.sh console output", "cd /home/user/work/poc/026_HollowByte && ./run_poc.sh", d.rd("run_poc_output.txt"))
d.H("4. Evidence on the UNPATCHED build / 未修正ビルドでの証拠")
d.P("BASE measurement: 200 connections x 9 bytes make the heap grow by 30,854,400 bytes = 154,272 bytes per connection (the 16 KiB init_buf is replaced by a "
    "174,772 byte one); VmData 14.5 MB -> 48.9 MB, VmRSS 14.5 MB -> 41.2 MB.",
    "BASE 測定: 200 接続 × 9 バイトでヒープが 30,854,400 バイト = 接続あたり 154,272 バイト増加 (16 KiB の init_buf が 174,772 バイトのものに置き換わる); "
    "VmData 14.5 MB → 48.9 MB、VmRSS 14.5 MB → 41.2 MB。")
d.CMD("BASE measurement", "./hb_server_base 14026 200 CERT KEY & python3 -I hb_client.py 127.0.0.1 14026 200 131072 4 2", d.rd("client_base.txt") + "\n" + d.rd("measure_base.txt"))
d.P("gdb on the unpatched s_server: the first BUF_MEM_grow_clean() with len >= 16000 after the 9 byte header is len=131076 (claimed 131072 + 4) -> 174,772 byte "
    "allocation, called from grow_init_buf() <- read_state_machine() (statem.c:610), i.e. before any body byte exists.",
    "未修正 s_server の gdb: 9 バイトのヘッダ後、len >= 16000 の最初の BUF_MEM_grow_clean() は len=131076 (申告 131072 + 4) → 174,772 バイトの確保で、"
    "grow_init_buf() ← read_state_machine() (statem.c:610) から呼ばれる、すなわち本体が 1 バイトも無い時点。")
d.CMD("gdb BASE s_server", "sleep 40 | LD_LIBRARY_PATH=BASE timeout 30 gdb -batch -x gdb_bufgrow.cmd --args BASE/apps/openssl s_server -accept 14126 -cert CERT -key KEY", d.rd("gdb_base.txt", grep=r"^HIT|^#[0-5] |Breakpoint 2"))
d.CMD("BASE-ASAN measurement (100 connections; RSS 26.6 MB -> 43.4 MB; no ASan report)", "./hb_server_baseasan 14026 100 ...", d.rd("measure_baseasan.txt"))
d.H("5. Evidence on the PATCHED build / 修正ビルドでの証拠")
d.P("PATCHED measurement: the same 200 x 9 bytes cause 0 bytes of heap growth (P1 == P2), VmRSS/VmData unchanged. gdb: the only large grow request is len=16388 "
    "(one 16384 byte chunk + 4) from tls_get_message_body() (statem_lib.c:1364) and it does not even reallocate (str->max is already 21848). PATCHED-ASAN: RSS 26.7 -> 27.1 MB, no report.",
    "PATCHED 測定: 同じ 200 × 9 バイトでヒープ増加は 0 バイト (P1 == P2)、VmRSS/VmData 不変。gdb: 大きな拡張要求は tls_get_message_body() (statem_lib.c:1364) からの len=16388 "
    "(16384 バイトのチャンク 1 つ + 4) のみで、再確保すら起きない (str->max は既に 21848)。PATCHED-ASAN: RSS 26.7 → 27.1 MB、報告無し。")
d.CMD("PATCHED measurement", "./hb_server_patched 14026 200 CERT KEY & python3 -I hb_client.py 127.0.0.1 14026 200 131072 4 2", d.rd("measure_patched.txt"))
d.CMD("gdb PATCHED s_server", "sleep 40 | LD_LIBRARY_PATH=PATCHED timeout 30 gdb -batch -x gdb_bufgrow.cmd --args PATCHED/apps/openssl s_server -accept 14126 -cert CERT -key KEY", d.rd("gdb_patched.txt", grep=r"^HIT|^#[0-5] "))
d.CMD("PATCHED-ASAN measurement", "./hb_server_patchasan 14026 100 ...", d.rd("measure_patchasan.txt"))
d.H("6. Regression check / 回帰確認")
d.P("regress.sh output: TLS 1.2/1.3 handshakes with HTTP 200, and the 21,758 / 21,811 byte Certificate messages (bigger than one record) are received correctly by the "
    "patched client (incremental init_buf growth across records) from both servers, and by the unpatched client from the patched server.",
    "regress.sh の出力: TLS 1.2/1.3 ハンドシェイクで HTTP 200、さらに 21,758 / 21,811 バイトの Certificate メッセージ (1 レコードより大きい) を修正版クライアントが両サーバから "
    "(レコードをまたぐ init_buf の逐次拡張)、未修正クライアントが修正版サーバから正しく受信。")
d.CMD("regression", "./regress.sh PATCHED BASE 14226", d.rd("regress.txt"))
d.CMD("regression detail: s_client -msg lines for the Certificate message (TLS1.3 big chain)", "grep Certificate out/regress_client_tls13_bigchain_pp.txt", d.rd("regress_client_tls13_bigchain_pp.txt", grep=r"Handshake \[length [0-9a-f]+\], (Certificate|ServerHello|Finished)|^New,|HTTP/1.0 200"))
d.H("7. Trial and error / 試行錯誤の記録")
d.P("Runs 1-2 of run_poc.sh failed for tooling reasons: an unconditional breakpoint on BUF_MEM_grow_clean was hit while s_server parsed the PEM key, so the two "
    "handled hits were not the init_buf growth; the regression script used awk strtonum (not available in mawk); a conditional breakpoint set before the shared "
    "library was loaded stayed 'pending' and never fired; and s_server exited because gdb's stdin reached EOF. Run 3 passed with a crude 15 s wait (the 'ss' tool is "
    "not installed, so the port check could not work). Run 4 failed only for the patched gdb case because the /proc/net/tcp check matched a TIME_WAIT socket and the "
    "client connected before the server listened. Run 5 (recorded above) waits for a LISTEN (state 0A) entry and keeps stdin open with 'sleep 40 |'. The "
    "measurement results (154,272 vs 0 bytes per connection) were identical in every run.",
    "run_poc.sh の 1〜2 回目はツール上の理由で失敗: BUF_MEM_grow_clean への無条件ブレークポイントが s_server の PEM 鍵解析中にヒットし、処理した 2 ヒットは init_buf 拡張ではなかった; "
    "回帰スクリプトが awk strtonum (mawk に無い) を使っていた; 共有ライブラリのロード前に設定した条件付きブレークポイントが 'pending' のまま発火しなかった; gdb の stdin が EOF になり "
    "s_server が終了した。3 回目は粗い 15 秒待ち ('ss' コマンドが無くポート確認が機能しなかった) で合格。4 回目は /proc/net/tcp の確認が TIME_WAIT ソケットに一致しサーバの listen 前に"
    "クライアントが接続したため修正版の gdb のみ失敗。5 回目 (上記記録) は LISTEN (状態 0A) エントリを待ち、'sleep 40 |' で stdin を維持。測定結果 (接続あたり 154,272 対 0 バイト) は毎回同一。")
d.RP(S[0], mech_en, mech_ja); d.RP(S[1], poc_en, poc_ja)
d.RC(S[2], d.rd("measure_base.txt", grep=r"^P1|^P2|per-connection|heap growth|^RESULT") + "\n" + d.rd("gdb_base.txt", grep=r"^HIT 1|^#[0-2] "))
d.RP(S[2], "Unpatched: 9 bytes per connection cost 154,272 bytes of heap each (200 connections: +30.9 MB heap, VmRSS 14.5 -> 41.2 MB); gdb shows BUF_MEM_grow_clean(len=131076) -> 174,772 byte allocation from read_state_machine() right after the header.",
     "未修正: 接続あたり 9 バイトで各 154,272 バイトのヒープを消費 (200 接続: ヒープ +30.9 MB、VmRSS 14.5 → 41.2 MB); gdb はヘッダ直後に read_state_machine() から BUF_MEM_grow_clean(len=131076) → 174,772 バイト確保を示す。")
d.RC(S[3], d.rd("measure_patched.txt", grep=r"^P1|^P2|per-connection|heap growth|^RESULT") + "\n" + d.rd("gdb_patched.txt", grep=r"^HIT 1|^#[0-2] "))
d.RP(S[3], "Patched: 0 bytes of growth per connection (RSS/VmData unchanged); the only grow request is 16388 bytes from tls_get_message_body(), satisfied by the existing buffer.",
     "修正版: 接続あたり増加 0 バイト (RSS/VmData 不変); 拡張要求は tls_get_message_body() からの 16388 バイトのみで既存バッファで賄われる。")
d.RC(S[4], d.rd("regress.txt"))
d.RP(S[4], "Normal TLS 1.2/1.3 handshakes and multi-record Certificate messages (21.7 KB) work with the patched client/server in all combinations; the patched tree's test suite (test_ssl_new etc.) was reported passing by the build step.",
     "通常の TLS 1.2/1.3 ハンドシェイクと複数レコードにまたがる Certificate メッセージ (21.7 KB) は修正版クライアント/サーバの全組み合わせで動作; 修正版ツリーのテストスイート (test_ssl_new 等) はビルド工程で合格済みと報告されている。")
d.RC(S[5], "cd /home/user/work/poc/026_HollowByte\n./run_poc.sh                                 # everything, prints VERDICT\n# manual measurement (terminal 1 / terminal 2):\n"
     "./hb_server_base 14026 200 /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/servercert.pem /home/user/work/src_1.1.1w/openssl-1.1.1w/test/certs/serverkey.pem\n"
     "python3 -I hb_client.py 127.0.0.1 14026 200 131072 4 2        # -> RESULT: per-connection growth after the header = 154272 bytes (base) / 0 (hb_server_patched)\n"
     "# gdb on the stock server:\nsleep 40 | LD_LIBRARY_PATH=/home/user/work/base/openssl-1.1.1w timeout 30 gdb -batch -x gdb_bufgrow.cmd --args /home/user/work/base/openssl-1.1.1w/apps/openssl s_server -accept 14126 -cert <cert> -key <key> &\n"
     "python3 -I hb_client.py 127.0.0.1 14126 1 131072 3 1          # -> HIT 1: BUF_MEM_grow_clean(..., len=131076) (base) / len=16388 (patched)\n./regress.sh /home/user/work/patched/build /home/user/work/base/openssl-1.1.1w 14226")
d.RP(S[5], "Build example (BASE): gcc -g -O0 -I/home/user/work/base/openssl-1.1.1w/include hb_server.c -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o hb_server_base",
     "ビルド例 (BASE): gcc -g -O0 -I/home/user/work/base/openssl-1.1.1w/include hb_server.c -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o hb_server_base")
d.RP(S[6], "No CVE exists for this issue; the effect per connection is bounded (~170 KiB) and the DoS needs many idle connections, as the OpenSSL blog explains. The PoC "
     "measures the server-side effect precisely in-process (mallinfo2) and with the stock s_server under gdb; the glibc fragmentation/RSS-retention aspect described by "
     "the reporter was not reproduced. DTLS is not covered by the fix (as upstream).",
     "本件に CVE は無い; 接続あたりの影響は有界 (約 170 KiB) で、OpenSSL ブログの説明どおり DoS には多数の放置接続が必要。PoC はサーバ側の影響をプロセス内 (mallinfo2) と標準 s_server + gdb で"
     "正確に計測した; 報告者が述べる glibc の断片化/RSS 高止まりの側面は再現していない。修正は DTLS を対象としない (上流同様)。")
d.finish("PASS",
 "Unpatched 1.1.1w allocates the whole announced handshake message (claimed 131072 bytes -> BUF_MEM_grow_clean(131076) -> 174,772 byte buffer) as soon as the 4 byte header arrives: 200 idle 9-byte connections cost 154,272 bytes of heap each (+30.9 MB). Patched grows init_buf in 16 KiB chunks only as data arrives (0 bytes growth for the same traffic; gdb shows len=16388 from tls_get_message_body()), and normal handshakes including 21.7 KB multi-record Certificate messages still work.",
 "未修正 1.1.1w は 4 バイトのヘッダが届いた時点で申告されたハンドシェイクメッセージ全体を確保する (申告 131072 バイト → BUF_MEM_grow_clean(131076) → 174,772 バイトのバッファ): 9 バイトの放置接続 200 本で各 154,272 バイトのヒープ (+30.9 MB)。修正版はデータ到着に応じて init_buf を 16 KiB 単位で拡張するだけ (同じトラフィックで増加 0 バイト; gdb は tls_get_message_body() からの len=16388 を示す) で、21.7 KB の複数レコード Certificate メッセージを含む通常のハンドシェイクも正常。判定: 合格 (PASS)。",
 {"before_en": "200 connections sending only a 9-byte record+handshake header claiming a 131072-byte ClientHello: heap +154,272 bytes per connection (+30.9 MB total, VmRSS 14.5->41.2 MB); gdb on s_server: BUF_MEM_grow_clean(len=131076) -> 174,772-byte allocation from read_state_machine()/grow_init_buf() before any body byte.",
  "before_ja": "131072 バイトの ClientHello を申告する 9 バイトのレコード+ハンドシェイクヘッダだけを送る 200 接続: 接続あたりヒープ +154,272 バイト (合計 +30.9 MB、VmRSS 14.5→41.2 MB); s_server の gdb: 本体未着のまま read_state_machine()/grow_init_buf() から BUF_MEM_grow_clean(len=131076) → 174,772 バイト確保。",
  "after_en": "Patched: 0 bytes of heap growth per connection for the same traffic (VmRSS/VmData unchanged); gdb: only BUF_MEM_grow_clean(len=16388) from tls_get_message_body(), satisfied by the existing 21848-byte buffer; ASan builds clean.",
  "after_ja": "修正版: 同じトラフィックで接続あたりヒープ増加 0 バイト (VmRSS/VmData 不変); gdb: tls_get_message_body() からの BUF_MEM_grow_clean(len=16388) のみで既存の 21848 バイトバッファで賄われる; ASan ビルドもクリーン。",
  "method_en": "Python client sends 9-byte 'HollowByte' headers on N idle TCP connections; C server measures mallinfo2/VmRSS/VmData before and after the header is processed; stock openssl s_server of each build run under gdb with a conditional breakpoint on BUF_MEM_grow_clean; s_client/s_server regression including a 25-certificate chain.",
  "method_ja": "Python クライアントが N 本の放置 TCP 接続に 9 バイトの 'HollowByte' ヘッダを送信; C サーバがヘッダ処理前後の mallinfo2/VmRSS/VmData を計測; 各ビルドの標準 openssl s_server を BUF_MEM_grow_clean への条件付きブレークポイント付き gdb で実行; 25 証明書チェーンを含む s_client/s_server 回帰。",
  "regression_en": "TLS 1.2/1.3 handshakes with HTTP 200 and 21,758/21,811-byte Certificate messages spanning several records are received correctly by the patched client from patched and unpatched servers (and by the unpatched client from the patched server).",
  "regression_ja": "TLS 1.2/1.3 ハンドシェイクで HTTP 200 を取得し、複数レコードにまたがる 21,758/21,811 バイトの Certificate メッセージを修正版クライアントが修正版/未修正サーバから (未修正クライアントも修正版サーバから) 正しく受信。",
  "tools": ["python3 -I (TCP client)", "gcc", "mallinfo2/proc status", "gdb", "AddressSanitizer", "openssl s_server/s_client -msg", "bash"],
  "poc_files": [D + "/hb_client.py", D + "/hb_server.c", D + "/gdb_bufgrow.cmd", D + "/run_poc.sh", D + "/regress.sh", D + "/make_deliverables.py", D + "/mkdeliv.py", D + "/out/"],
  "limitations_en": "Per-connection effect is bounded (~170 KiB); no CVE assigned. The glibc fragmentation / RSS retention described by the reporter was not reproduced; the PoC quantifies the per-connection allocation precisely instead. DTLS is out of scope of the fix.",
  "limitations_ja": "接続あたりの影響は有界 (約 170 KiB) で CVE は未割り当て。報告者が述べる glibc 断片化/RSS 高止まりは再現せず、PoC は接続あたりの確保量を正確に定量化した。DTLS は修正の対象外。"})
