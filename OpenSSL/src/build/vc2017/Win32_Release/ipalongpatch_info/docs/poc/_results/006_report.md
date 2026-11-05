# 006/033 CVE-2024-5535 — SSL-select-next-proto-overread

Log file / ログファイル: `20261102_122754_006of033_CVE-2024-5535_SSL-select-next-proto-overread.log` (in /home/user/work/deliver/ipalongpatch_info/logs/). Verification 2026/11/02 12:27:54–2026/11/02 12:37:30 (JST), verdict **PASS**.

ログファイル: `20261102_122754_006of033_CVE-2024-5535_SSL-select-next-proto-overread.log` (/home/user/work/deliver/ipalongpatch_info/logs/ 配下)。検証 2026/11/02 12:27:54〜2026/11/02 12:37:30 (JST)、判定 **PASS**。

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

CVE-2024-5535 (OpenSSL advisory 2024-06-27, Low): SSL_select_next_proto(out, outlen, server, server_len, client, client_len) in ssl/ssl_lib.c walks the two length-prefixed protocol lists without any bounds checks. When no server protocol is found in the client list - which is always the case for client_len == 0 - the unpatched 1.1.1w code falls through to 'result = client; *out = result + 1; *outlen = result[0];' (ssl_lib.c:2792-2793). With an empty client list this reads one byte outside the supplied buffer (the length) and returns a pointer to the memory that follows it. The caller typically copies and sends those bytes: the NPN client code (ssl/statem/extensions_clnt.c tls_parse_stoc_npn) memcpy()s *outlen bytes from *out into s->ext.npn and sends them in the NextProtocol handshake message, so up to 255 bytes of process memory are disclosed to the peer; if the byte after the list is unmapped the process crashes.

CVE-2024-5535 (OpenSSL アドバイザリ 2024-06-27、Low): ssl/ssl_lib.c の SSL_select_next_proto(out, outlen, server, server_len, client, client_len) は長さプレフィックス付きの 2 つのプロトコルリストを境界検査なしに走査する。サーバ側プロトコルがクライアントリストに見つからない場合 — client_len == 0 では常にそうなる — 未修正 1.1.1w は 'result = client; *out = result + 1; *outlen = result[0];' (ssl_lib.c:2792-2793) に落ちる。空のクライアントリストでは、与えられたバッファの外側の 1 バイトを長さとして読み、その直後のメモリを指すポインタを返す。呼び出し側は通常そのバイト列をコピーして送信する: NPN クライアントコード (ssl/statem/extensions_clnt.c の tls_parse_stoc_npn) は *out から *outlen バイトを s->ext.npn へ memcpy() し NextProtocol ハンドシェイクメッセージで送るため、最大 255 バイトのプロセスメモリが相手に漏えいする。リスト直後のバイトが未マップならプロセスはクラッシュする。

## PoC design / PoC の設計

poc_5535.c has seven modes. unit: 9 protocol-list vectors (matches, server preference, no overlap, empty server list, EMPTY CLIENT LIST, single empty entry, trailing garbage, empty server entry) compared with the fixed semantics - the unpatched build must deviate exactly on the empty-client cases by returning out = client+1. oob: client = malloc(0), client_len = 0 -> the unpatched library reads client[0] (valgrind 'Invalid read ... 0 bytes after a block of size 0'; note ASan rounds malloc(0) up to 1 byte, so ASan cannot see this particular read). crash: the empty list is placed at the first byte of a PROT_NONE page -> the unpatched library dereferences it and dies with SIGSEGV (gdb shows the faulting statement). leak: a 65 byte application buffer whose first byte is 0x40 ('@' = 64) followed by a 64 byte secret; passing it with client_len = 0 makes the unpatched function return the secret as the 'selected protocol'. npn: a real TLS 1.2 connection over memory BIOs in which the server advertises NPN protocols and the client's SSL_CTX_set_next_proto_select_cb callback calls SSL_select_next_proto() with that empty list (the programming error described by the advisory); the server prints SSL_get0_next_proto_negotiated() - unpatched: the 64 secret bytes were transmitted. npn255: same with a 1 byte heap buffer containing 0xff -> unpatched copies 255 bytes past the buffer (ASan heap-buffer-overflow READ of size 255 in tls_parse_stoc_npn) and sends them. alpn (regression): the server ALPN callback uses SSL_select_next_proto() the standard way; case A overlap (client h2,http/1.1 vs server preference http/1.1,h2 -> http/1.1 negotiated on both sides), case B no overlap (client 'foo' -> OPENSSL_NPN_NO_OVERLAP with the first client protocol returned, server answers NOACK, handshake completes without ALPN). run_poc.sh builds and runs all modes on BASE, BASE-ASAN, PATCHED, PATCHED-ASAN, runs gdb on the BASE crash mode, valgrind on BASE (oob, npn255) and PATCHED (all modes, --leak-check=full).

poc_5535.c には 7 つのモードがある。unit: 9 個のプロトコルリストベクタ (一致、サーバ優先、重複なし、空サーバリスト、空クライアントリスト、単一の空エントリ、末尾ゴミ、空のサーバエントリ) を修正後の仕様と比較する — 未修正ビルドは空クライアントの場合だけ out = client+1 を返して逸脱するはず。oob: client = malloc(0)、client_len = 0 → 未修正ライブラリが client[0] を読む (valgrind 'Invalid read ... 0 bytes after a block of size 0'; ASan は malloc(0) を1 バイトに丸めるためこの読み出しは ASan では検出できない)。crash: 空リストを PROT_NONE ページの先頭バイトに置く → 未修正ライブラリがそれを参照して SIGSEGV で死ぬ (gdb で該当文を表示)。leak: 先頭バイトが 0x40 ('@' = 64) でその後に 64 バイトの秘密が続く 65 バイトのアプリケーションバッファを client_len = 0 で渡す → 未修正関数は秘密を「選択されたプロトコル」として返す。npn: メモリ BIO 上の実 TLS 1.2 接続で、サーバが NPN プロトコルを広告し、クライアントの SSL_CTX_set_next_proto_select_cb コールバックがその空リストで SSL_select_next_proto() を呼ぶ (アドバイザリの言うプログラミングミス); サーバが SSL_get0_next_proto_negotiated() を表示 — 未修正: 64 バイトの秘密が送信されている。npn255: 0xff を含む 1 バイトのヒープバッファで同様 → 未修正はバッファの先 255 バイトをコピー (ASan: tls_parse_stoc_npn で heap-buffer-overflow READ of size 255) して送信。alpn (回帰): サーバの ALPN コールバックが SSL_select_next_proto() を標準的に使う; ケース A 重複あり (クライアント h2,http/1.1 対 サーバ優先 http/1.1,h2 → 双方で http/1.1)、ケース B 重複なし (クライアント 'foo' → OPENSSL_NPN_NO_OVERLAP と先頭クライアントプロトコル、サーバは NOACK を返し ALPN 無しでハンドシェイク完了)。run_poc.sh は BASE, BASE-ASAN, PATCHED, PATCHED-ASAN で全モードを実行し、BASE の crash モードに gdb、BASE (oob, npn255) と PATCHED (全モード、--leak-check=full) に valgrind をかける。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
  [FAIL] EMPTY CLIENT LIST (CVE case)       ret=OPENSSL_NPN_NO_OVERLAP outlen=0 out=""  <- out = client+1 (points PAST the buffer)
  [FAIL] client list = single empty entry   ret=OPENSSL_NPN_NO_OVERLAP outlen=0 out=""  <- out = client+1 (points inside the buffer)
RESULT unit: VULNERABLE (old behaviour) - 2 of 9 vectors deviate from the fixed semantics
  selected protocol: len=64 ptr=0x5562566ab2b1 data="SECRET-api-key=sk_live_51H8xQ2eZvKYlo2C9d0uVt1wP; session=0xdead"
  -> the 64 bytes following the empty list (the secret) are returned as the 'selected protocol'
RESULT leak: VULNERABLE
  [client npn cb] SSL_select_next_proto(client_len=0) -> OPENSSL_NPN_NO_OVERLAP, out=0x55ede017a2b1 (=client+1), outlen=64
  [server] SSL_get0_next_proto_negotiated: len=64 ptr=0x55ede01ca700 data="SECRET-api-key=sk_live_51H8xQ2eZvKYlo2C9d0uVt1wP; session=0xdead"
RESULT npn: VULNERABLE
Program received signal SIGSEGV, Segmentation fault.
2793	    *outlen = result[0];
#0  0x00007ffff7f4a1c2 in SSL_select_next_proto (out=0x7fffffffc328, outlen=0x7fffffffc323 "", server=0x555555558b78 <server> "\bhttp/1.1", server_len=9, client=0x7ffff7efe000 "", client_len=0) at ssl/ssl_lib.c:2793
==8715==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000011 at pc 0x7f8999afb42e bp 0x7ffe0137e470 sp 0x7ffe0137dc18
READ of size 255 at 0x502000000011 thread T0
    #1 0x7f899991f775 in tls_parse_stoc_npn ../src_1.1.1w/openssl-1.1.1w/ssl/statem/extensions_clnt.c:1621
0x502000000011 is located 0 bytes after 1-byte region [0x502000000010,0x502000000011)
    #1 0x7f89993bc4b4 in CRYPTO_malloc ../src_1.1.1w/openssl-1.1.1w/crypto/mem.c:222
==8798== Invalid read of size 1
==8798==  Address 0x4e8c080 is 0 bytes after a block of size 0 alloc'd
```

Unpatched: with client_len=0 the function returns out=client+1/outlen=client[0]; the adjacent 64 byte secret is returned and, through the NPN callback, transmitted to the server; a 1 byte buffer leaks 255 bytes (ASan heap-buffer-overflow READ of size 255 in tls_parse_stoc_npn); an empty list at a page boundary crashes the process (SIGSEGV at ssl_lib.c:2793); valgrind: invalid read 0 bytes after a 0 byte block.

未修正: client_len=0 で out=client+1 / outlen=client[0] を返し、隣接する 64 バイトの秘密が返却され NPN コールバック経由でサーバへ送信される; 1 バイトバッファでは 255 バイト漏えい (ASan: tls_parse_stoc_npn で heap-buffer-overflow READ of size 255); ページ境界の空リストではプロセスがクラッシュ (ssl_lib.c:2793 で SIGSEGV); valgrind: 0 バイトブロック直後の不正読み出し。

## Observed behaviour AFTER the patch / 修正後の挙動

```
  [ok  ] EMPTY CLIENT LIST (CVE case)       ret=OPENSSL_NPN_NO_OVERLAP outlen=0 out=NULL
  [ok  ] client list = single empty entry   ret=OPENSSL_NPN_NO_OVERLAP outlen=0 out=NULL
RESULT unit: OK - 0 of 9 vectors deviate from the fixed semantics
  returned: ret=OPENSSL_NPN_NO_OVERLAP out=(nil) outlen=0 (no memory outside the list was touched)
RESULT crash: OK
  selected protocol: len=0 ptr=(nil) data=""
RESULT leak: OK
140345228192640:error:14246044:SSL routines:tls_parse_stoc_npn:internal error:../openssl-1.1.1w-ipalongpatch_20261102/ssl/statem/extensions_clnt.c:1616:
  [client npn cb] SSL_select_next_proto(client_len=0) -> OPENSSL_NPN_NO_OVERLAP, out=(nil) (=client+0), outlen=0
  handshake FAILED (see errors above)
RESULT npn: OK (no memory disclosed)
```

Patched: *out=NULL, *outlen=0, OPENSSL_NPN_NO_OVERLAP for empty/invalid client lists, no out-of-bounds access (crash mode survives, valgrind/ASan clean); the NPN connection with an empty list aborts with 'internal error' instead of disclosing memory.

修正版: 空/不正なクライアントリストでは *out=NULL、*outlen=0、OPENSSL_NPN_NO_OVERLAP を返し境界外アクセス無し (crash モードも生存、valgrind/ASan クリーン); 空リストでの NPN 接続はメモリを漏らす代わりに 'internal error' で中止される。

## Regression check / 回帰確認

```
  case A: client offers h2,http/1.1; server preference http/1.1,h2
  [server alpn cb] SSL_select_next_proto -> OPENSSL_NPN_NEGOTIATED, selected len=8 ptr=0x56419a129919 data="http/1.1"
  handshake completed (TLSv1.3); server sees ALPN len=8 ptr=0x5641a9f6d370 data="http/1.1"
  expected "http/1.1" -> ok
  case B: client offers foo only (no overlap) -> server answers NOACK, connection without ALPN
  [server alpn cb] SSL_select_next_proto -> OPENSSL_NPN_NO_OVERLAP, selected len=3 ptr=0x5641a9f45471 data="foo"
  handshake completed (TLSv1.3); server sees ALPN len=0 ptr=(nil) data=""
  expected "" -> ok
RESULT alpn: OK
```

ALPN overlap -> http/1.1 negotiated on both sides; no overlap -> NO_OVERLAP + first client protocol, server NOACK, handshake completes without ALPN; identical on BASE, BASE-ASAN, PATCHED, PATCHED-ASAN. Valid-list unit vectors unchanged.

ALPN 重複あり → 双方で http/1.1; 重複なし → NO_OVERLAP + 先頭クライアントプロトコル、サーバ NOACK、ALPN 無しでハンドシェイク完了; BASE, BASE-ASAN, PATCHED, PATCHED-ASAN で同一。有効リストの unit ベクタも不変。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/006_CVE-2024-5535
./run_poc.sh                       # everything, prints VERDICT
./poc_5535_base leak; ./poc_5535_patched leak      # secret returned vs NULL
./poc_5535_base npn; ./poc_5535_patched npn        # secret sent over TLS vs handshake aborted
./poc_5535_base crash                              # SIGSEGV (exit 139); ./poc_5535_patched crash -> RESULT crash: OK
./poc_5535_baseasan npn255                         # ASan heap-buffer-overflow READ of size 255
valgrind ./poc_5535_base oob                       # Invalid read of size 1 at SSL_select_next_proto (ssl_lib.c:2793)
./poc_5535_patched alpn                            # regression
```

Build example (PATCHED): gcc -g -O0 -I/home/user/work/patched/build/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/include poc_5535.c -L/home/user/work/patched/build -lssl -lcrypto -Wl,-rpath,/home/user/work/patched/build -o poc_5535_patched

ビルド例 (PATCHED): gcc -g -O0 -I/home/user/work/patched/build/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/include poc_5535.c -L/home/user/work/patched/build -lssl -lcrypto -Wl,-rpath,/home/user/work/patched/build -o poc_5535_patched

## Limitations / notes / 制約・注記

The empty client list is an application-side programming error (the advisory's precondition); the PoC supplies it deliberately. ASan cannot observe the 1 byte overread of malloc(0) (it allocates 1 byte), hence valgrind and the PROT_NONE crash mode are used for that case. With the fix, an NPN client that still passes an empty list fails the handshake with 'internal error' (OPENSSL_malloc(0) == NULL in tls_parse_stoc_npn), which is the safe outcome.

空のクライアントリストはアプリ側のプログラミングミス (アドバイザリの前提条件) であり、PoC は意図的にそれを与える。ASan は malloc(0) の 1 バイト読み越しを観測できない (1 バイト確保する) ため、その場合は valgrind と PROT_NONE の crash モードを用いた。修正後も空リストを渡す NPN クライアントは 'internal error' (tls_parse_stoc_npn で OPENSSL_malloc(0) == NULL) でハンドシェイクに失敗するが、これは安全側の結果である。

