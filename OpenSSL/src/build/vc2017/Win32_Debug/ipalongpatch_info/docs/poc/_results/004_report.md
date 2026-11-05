# 004/033 CVE-2024-2511 — TLS13-session-cache-unbounded

Log file / ログファイル: `20261102_121141_004of033_CVE-2024-2511_TLS13-session-cache-unbounded.log` (in /home/user/work/deliver/ipalongpatch_info/logs/). Verification 2026/11/02 12:11:41–2026/11/02 12:20:28 (JST), verdict **PASS**.

ログファイル: `20261102_121141_004of033_CVE-2024-2511_TLS13-session-cache-unbounded.log` (/home/user/work/deliver/ipalongpatch_info/logs/ 配下)。検証 2026/11/02 12:11:41〜2026/11/02 12:20:28 (JST)、判定 **PASS**。

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

ssl/statem/statem_srvr.c tls_construct_new_session_ticket(): for a resumed TLSv1.3 handshake the server creates the session for the new (stateful, SSL_OP_NO_TICKET) ticket with ssl_session_dup(s->session, 0), gives it a fresh id and calls ssl_update_cache() -> SSL_CTX_add_session(). In 1.1.1w ssl_session_dup() copies the not_resumable flag, ssl_update_cache() only checks session_id_length==0, and tls_construct_server_hello() sets s->session->session_id_length = 0 whenever s->session->not_resumable is set - also for a session that lives in the cache. ssl/ssl_sess.c remove_session_lock() ignores sessions with session_id_length==0, and SSL_CTX_add_session() breaks out of its eviction loop when remove_session_lock(tail) fails, so the cache can no longer shrink. The flag gets set on a shared session when any connection holding it sends a fatal alert (ssl3_send_alert() -> SSL_CTX_remove_session()) or when the session is removed/timed out.

ssl/statem/statem_srvr.c の tls_construct_new_session_ticket(): 再開された TLSv1.3 ハンドシェイクでは、新しい (SSL_OP_NO_TICKET によるステートフル) チケット用セッションを ssl_session_dup(s->session, 0) で作り、新しい ID を付けて ssl_update_cache() → SSL_CTX_add_session() を呼ぶ。1.1.1w では ssl_session_dup() が not_resumable フラグをコピーし、ssl_update_cache() は session_id_length==0 しか検査せず、tls_construct_server_hello() は s->session->not_resumable なら s->session->session_id_length = 0 にする (キャッシュ内のセッションでも)。ssl/ssl_sess.c の remove_session_lock() は session_id_length==0 のセッションを無視し、SSL_CTX_add_session() は remove_session_lock(tail) が失敗すると追い出しループを抜けるため、キャッシュは縮小できなくなる。共有セッションのフラグは、それを保持するコネクションが致命的アラートを送る(ssl3_send_alert() → SSL_CTX_remove_session()) か、セッションが除去/タイムアウトしたときに立つ。

## PoC design / PoC の設計

poc_2511_dup.c (static link against libssl.a, includes ssl/ssl_local.h) calls the internal ssl_session_dup() on a not_resumable session. poc_2511.c builds TLSv1.3 memory-BIO connections in one process (helpers: tlshelp.h): Y (full handshake, cached session S) -> X (resumes S; an info callback at TLS_ST_SR_CLNT_HELLO injects a bogus record into Y so that Y's fatal alert marks S not_resumable while X holds it) -> Z (resumes S' = X's ticket copy) -> 20 more full handshakes with cache size 5. It prints SSL_CTX_sess_number(), SSL_CTX_sess_cache_full() and every cached session's session_id_length / SSL_SESSION_is_resumable(). run_poc.sh builds and runs everything for BASE, BASE-ASAN, PATCHED, PATCHED-ASAN and runs valgrind on the patched binary; regress_cli.sh checks s_server/s_client resumption.

poc_2511_dup.c (libssl.a を静的リンクし ssl/ssl_local.h をインクルード) は not_resumable なセッションに対して内部関数 ssl_session_dup() を呼ぶ。poc_2511.c は 1 プロセス内にメモリ BIO の TLSv1.3 接続を作る (ヘルパ: tlshelp.h): Y (フルハンドシェイク、キャッシュ済みセッション S) → X (S を再開; TLS_ST_SR_CLNT_HELLO での info コールバックが Y に不正レコードを注入し、X が S を保持している間に Y の致命的アラートで S を not_resumable 化) → Z (X のチケット用複製 S' を再開) → さらに 20 回のフルハンドシェイク (キャッシュ上限 5)。SSL_CTX_sess_number()、SSL_CTX_sess_cache_full()、各キャッシュセッションの session_id_length / SSL_SESSION_is_resumable() を表示する。run_poc.sh が BASE, BASE-ASAN, PATCHED, PATCHED-ASAN のビルド・実行と修正版バイナリの valgrind を行い、regress_cli.sh が s_server/s_client の再開を確認する。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
src->not_resumable            = 1
ssl_session_dup(src,1)->not_resumable  = 1  (internal copy used for the new ticket/session)
SSL_SESSION_dup(src)->not_resumable    = 1  (public API, expected to keep the flag)
VULNERABLE: internal duplicate inherits not_resumable=1 -> would be cached as not_resumable

  [after Z] SSL_CTX_sess_number=2 (cache size limit 5), sess_cache_full=0
    cached session 0x55c73b15d0c0: session_id_length=0 SSL_SESSION_is_resumable=0
  [final] SSL_CTX_sess_number=22 (cache size limit 5), sess_cache_full=0
    cached session 0x55c73b15d0c0: session_id_length=0 SSL_SESSION_is_resumable=0
RESULT: cache count before fill=2, max during fill=22, final=22, limit=5
VULNERABLE: session cache grew beyond its configured size (unremovable not_resumable session with session_id_length 0)
```

Unpatched: the internal duplicate inherits not_resumable=1; after Z the cached session has session_id_length=0; the cache count rises to 22 with a limit of 5 and sess_cache_full stays 0 (no eviction possible). Identical result with the BASE-ASAN build (no ASan report, as expected for a logic bug).

未修正: 内部複製が not_resumable=1 を継承し、Z の後にキャッシュ内セッションが session_id_length=0 になる。件数は上限 5 に対し 22 まで増え、sess_cache_full は 0 のまま (追い出し不能)。BASE-ASAN ビルドでも同一結果 (ロジックバグなので ASan 報告は無し、想定どおり)。

## Observed behaviour AFTER the patch / 修正後の挙動

```
src->not_resumable            = 1
ssl_session_dup(src,1)->not_resumable  = 0  (internal copy used for the new ticket/session)
SSL_SESSION_dup(src)->not_resumable    = 1  (public API, expected to keep the flag)
FIXED: internal duplicate is resumable (not_resumable cleared)

  [after Z] SSL_CTX_sess_number=2 (cache size limit 5), sess_cache_full=0
  [final] SSL_CTX_sess_number=5 (cache size limit 5), sess_cache_full=17
RESULT: cache count before fill=2, max during fill=5, final=5, limit=5
NOT VULNERABLE: session cache stayed within its configured size
```

Patched: ssl_session_dup() returns a resumable copy, no cached entry ever has session_id_length=0, the count never exceeds 5 and 17 evictions are counted. Same with PATCHED-ASAN; valgrind --leak-check=full: 0 errors, all heap blocks freed.

修正版: ssl_session_dup() は再開可能な複製を返し、キャッシュ内に session_id_length=0 のエントリは現れず、件数は 5 を超えず 17 回の追い出しが計上される。PATCHED-ASAN も同様。valgrind --leak-check=full: エラー 0、ヒープブロックはすべて解放済み。

## Regression check / 回帰確認

In the patched run X and Z are resumed (reused=1) and all 20 full handshakes complete with correct LRU eviction. regress_cli.sh: patched 'openssl s_server -tls1_3 -no_ticket' + 's_client -sess_out/-sess_in' on 127.0.0.1:14004 -> 'Reused, TLSv1.3' and 'HTTP/1.0 200 ok' on both resumed connections.

修正版の実行で X と Z は再開 (reused=1)、20 回のフルハンドシェイクも正しい LRU 追い出しとともに完了。regress_cli.sh: 修正版 'openssl s_server -tls1_3 -no_ticket' + 's_client -sess_out/-sess_in' (127.0.0.1:14004) → 再開 2 回とも 'Reused, TLSv1.3' と 'HTTP/1.0 200 ok'。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/004_CVE-2024-2511
./run_poc.sh                       # builds + runs BASE/BASE-ASAN/PATCHED/PATCHED-ASAN + valgrind, prints VERDICT
./poc_2511_base | grep -E 'session_id_length=0|RESULT|VULNERABLE'    # unpatched: count 22 > limit 5
./poc_2511_patched | grep -E 'RESULT|VULNERABLE'                     # patched: count 5 = limit 5
./poc_2511_dup_base; ./poc_2511_dup_patched                          # internal ssl_session_dup(): 1 vs 0
./regress_cli.sh /home/user/work/patched/build                       # s_server -no_ticket / s_client resumption on port 14004
```

Manual build example (BASE): gcc -g -O0 -I/home/user/work/base/openssl-1.1.1w/include poc_2511.c -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o poc_2511_base

手動ビルド例 (BASE): gcc -g -O0 -I/home/user/work/base/openssl-1.1.1w/include poc_2511.c -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o poc_2511_base

## Limitations / notes / 制約・注記

The advisory describes a multi-thread race; the PoC serialises it in one thread by using the SSL info callback as a deterministic 'scheduler' (the not_resumable marking is produced by the library itself: fatal alert -> ssl3_send_alert() -> SSL_CTX_remove_session()). The first PoC version freed connections without SSL_shutdown(), which removes sessions from the cache and masked the bug; this is kept in the log as trial-and-error history. Memory growth is shown as the session count (each entry ~ hundreds of bytes); it is unbounded in the number of connections.

アドバイザリはマルチスレッドの競合として記述しているが、PoC は SSL info コールバックを決定的な「スケジューラ」として使い単一スレッドで直列化した (not_resumable 化はライブラリ自身が行う: 致命的アラート → ssl3_send_alert() → SSL_CTX_remove_session())。PoC 初版は SSL_shutdown() 無しで接続を解放しており、それがセッションをキャッシュから除去してバグを隠していた (試行錯誤の記録としてログに残した)。メモリ増大はセッション件数で示している (1 エントリ数百バイト); 接続数に対して無制限に増える。

