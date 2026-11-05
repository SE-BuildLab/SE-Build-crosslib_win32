# 017 / CVE-2026-28387 / DANE-match-cert-wrong-free-UAF

Log file / ログファイル: `20261102_124214_017of033_CVE-2026-28387_DANE-match-cert-wrong-free-UAF.log` (in /home/user/work/deliver/ipalongpatch_info/logs/)

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

`dane_match()` (crypto/x509/x509_vfy.c) remembers the certificate that matched a TLSA record in `dane->mcert` (`X509_up_ref`). A PKIX-TA(0)/PKIX-EE(1) match is provisional, so `dane_match()` runs again for the issuers (`check_dane_issuer()` from `build_chain()`); when a DANE-TA(2) record then matches, the old match is replaced with `OPENSSL_free(dane->mcert); dane->mcert = cert; X509_up_ref(cert);` (line 2764). OPENSSL_free() frees the X509 struct without touching its reference count or members while `ctx->chain`, the peer chain and the application still reference it -> use-after-free and later double free. Patch 017 changes the call to `X509_free(dane->mcert)`.

`dane_match()` (crypto/x509/x509_vfy.c) は TLSA レコードにマッチした証明書を `dane->mcert` に記憶する (`X509_up_ref`)。PKIX-TA(0)/PKIX-EE(1) のマッチは暫定的で、発行者に対して `dane_match()` が再度走り (`build_chain()` からの `check_dane_issuer()`)、そこで DANE-TA(2) レコードがマッチすると `OPENSSL_free(dane->mcert); dane->mcert = cert; X509_up_ref(cert);` (2764 行目) で旧マッチが置き換えられる。OPENSSL_free() は参照カウントもメンバも触らずに X509 構造体を解放するが、`ctx->chain`・ピアチェーン・アプリケーションは依然それを参照している → use-after-free、後に二重解放。パッチ 017 はこの呼び出しを `X509_free(dane->mcert)` に変更する。

## PoC design / PoC の設計

`dane_uaf.c` builds a DANE client context (SSL_CTX_dane_enable / SSL_dane_enable / SSL_dane_tlsa_add) and runs `X509_verify_cert()` with `X509_STORE_CTX_set0_dane()` on the chain [ee-cert, ca-cert] with root-cert as trust anchor (test/certs of 1.1.1w), like test/danetest.c. Trigger: TLSA "1 0 0 ee-cert" (PKIX-EE) + "2 0 0 ca-cert" (DANE-TA); variant: "0 0 0 ca-cert" + "2 0 0 root-cert" with the root in the peer chain and TRUSTED_FIRST cleared. Built for BASE-ASAN/PATCHED-ASAN (ASan), BASE/PATCHED (gdb, valgrind). The same records are used in a real `openssl s_server`/`s_client -dane_tlsa_domain -dane_tlsa_rrdata` handshake with the ASan builds.

`dane_uaf.c` は DANE クライアントの文脈 (SSL_CTX_dane_enable / SSL_dane_enable / SSL_dane_tlsa_add) を構築し、test/danetest.c と同様に root-cert をトラストアンカーとしてチェーン [ee-cert, ca-cert] (1.1.1w の test/certs) に対し `X509_STORE_CTX_set0_dane()` 付きの `X509_verify_cert()` を実行する。トリガ: TLSA "1 0 0 ee-cert" (PKIX-EE) + "2 0 0 ca-cert" (DANE-TA); 変種: "0 0 0 ca-cert" + "2 0 0 root-cert" (root をピアチェーンに含め TRUSTED_FIRST を解除)。BASE-ASAN/PATCHED-ASAN (ASan)、BASE/PATCHED (gdb、valgrind) 向けにビルド。同じレコードを ASan ビルドの実際の `openssl s_server`/`s_client -dane_tlsa_domain -dane_tlsa_rrdata` ハンドシェイクにも使用する。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
$ ./dane_uaf_base_asan root-cert.pem ee-cert.pem ca-cert.pem "1 0 0 ee-cert.pem" "2 0 0 ca-cert.pem"
==ERROR: AddressSanitizer: heap-use-after-free ... READ of size 4
    #0 check_chain_extensions crypto/x509/x509_vfy.c:489
    #1 verify_chain x509_vfy.c:218   #2 dane_verify x509_vfy.c:2919   #3 X509_verify_cert x509_vfy.c:301
0x... is located 224 bytes inside of 352-byte region   (the X509 object of ee-cert.pem)
freed by thread T0 here:
    #1 CRYPTO_free   #2 dane_match x509_vfy.c:2764   #3 check_dane_issuer x509_vfy.c:2792   #4 build_chain x509_vfy.c:3266
$ gdb ... 'break x509_vfy.c:2764 if dane->mcert != 0' ./dane_uaf_base ...
Breakpoint 1, dane_match (ctx=..., cert=<ca-cert>, depth=1) at crypto/x509/x509_vfy.c:2764
2764   OPENSSL_free(dane->mcert);
dane->mtlsa = {usage = 2, selector = 0, mtype = 0, dlen = 752}   dane->mcert->references = 4
dane->mcert->cert_info.validity.notBefore->data = "160115081949Z"   (a live ee-cert object)
$ valgrind ./dane_uaf_base ... -> many "Invalid read ... inside a block of size 352 free'd ... by dane_match (x509_vfy.c:2764)"
$ openssl(BASE-ASAN) s_client -connect 127.0.0.1:14433 -CAfile root-cert.pem -dane_tlsa_domain server.example \
      -dane_tlsa_rrdata "1 0 0 <ee DER hex>" -dane_tlsa_rrdata "2 0 0 <ca DER hex>"
==ERROR: AddressSanitizer: heap-use-after-free ... check_chain_extensions <- ... <- X509_verify_cert
    <- ssl_verify_cert_chain ssl/ssl_cert.c:427 <- tls_process_server_certificate ssl/statem/statem_clnt.c:1903
```

## Observed behaviour AFTER the patch / 修正後の挙動

```
$ ./dane_uaf_patched_asan root-cert.pem ee-cert.pem ca-cert.pem "1 0 0 ee-cert.pem" "2 0 0 ca-cert.pem"
X509_verify_cert() -> 1, error 0 (ok), chain depth 2
DANE authority: matched TLSA record usage=2 selector=0 mtype=0 at chain depth 1
  matched certificate (dane->mcert): /CN=CA
RESULT: verification SUCCEEDED, process finished normally          (no ASan report; valgrind clean)
$ openssl(PATCHED-ASAN) s_client ... (same TLSA records)
Verification: OK / Verified peername: server.example
DANE TLSA 2 0 0 ...6ecdde5a9bcd89f9a687cffe matched TA certificate at depth 1
Verify return code: 0 (ok)
```

## Regression check / 回帰確認

PATCHED-ASAN: DANE-EE(3) "3 1 1" and "3 0 2" succeed (depth 0); DANE-TA(2) "2 1 1" matches at depth 1; PKIX-EE(1) "1 1 1" alone verifies via the PKIX chain; a corrupted record fails with error 65 "No matching DANE TLSA records"; the previously crashing PKIX-EE+DANE-TA and PKIX-TA+DANE-TA combinations verify correctly. Patched `test/danetest example.com test/danetest.pem test/danetest.in`: `ok 1 - run_tlsatest`.

PATCHED-ASAN: DANE-EE(3) "3 1 1"・"3 0 2" は成功 (深さ 0); DANE-TA(2) "2 1 1" は深さ 1 でマッチ; PKIX-EE(1) "1 1 1" 単独は PKIX チェーンで検証; 破損レコードはエラー 65 "No matching DANE TLSA records" で失敗; 従来クラッシュした PKIX-EE+DANE-TA と PKIX-TA+DANE-TA の組み合わせも正しく検証。修正済み `test/danetest example.com test/danetest.pem test/danetest.in`: `ok 1 - run_tlsatest`。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/017_CVE-2026-28387
BA=/home/user/work/base_asan; S=/home/user/work/src_1.1.1w/openssl-1.1.1w
PA=/home/user/work/patched/build-asan; PS=/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102
gcc -g -O0 -Wall -fsanitize=address -I$BA/include -I$S/include dane_uaf.c -L$BA -lssl -lcrypto -Wl,-rpath,$BA -o dane_uaf_base_asan
gcc -g -O0 -Wall -fsanitize=address -I$PA/include -I$PS/include dane_uaf.c -L$PA -lssl -lcrypto -Wl,-rpath,$PA -o dane_uaf_patched_asan
export ASAN_OPTIONS=detect_leaks=0
./dane_uaf_base_asan root-cert.pem ee-cert.pem ca-cert.pem "1 0 0 ee-cert.pem" "2 0 0 ca-cert.pem"     # heap-use-after-free
./dane_uaf_patched_asan root-cert.pem ee-cert.pem ca-cert.pem "1 0 0 ee-cert.pem" "2 0 0 ca-cert.pem"  # verification SUCCEEDED
# real handshake (BASE-ASAN apps):
B=/home/user/work/base/openssl-1.1.1w
EEHEX=$($B/util/shlib_wrap.sh $B/apps/openssl x509 -in ee-cert.pem -outform DER | od -An -tx1 -v | tr -d ' \n')
CAHEX=$($B/util/shlib_wrap.sh $B/apps/openssl x509 -in ca-cert.pem -outform DER | od -An -tx1 -v | tr -d ' \n')
$BA/util/shlib_wrap.sh $BA/apps/openssl s_server -accept 14433 -cert ee-cert.pem -key ee-key.pem -cert_chain ca-cert.pem -naccept 1 -quiet &
$BA/util/shlib_wrap.sh $BA/apps/openssl s_client -connect 127.0.0.1:14433 -CAfile root-cert.pem -dane_tlsa_domain server.example \
    -dane_tlsa_rrdata "1 0 0 $EEHEX" -dane_tlsa_rrdata "2 0 0 $CAHEX" < /dev/null
./run_poc.sh    # everything, with verdict
```

## Limitations / notes / 制限事項・注記

The plain (non-ASan) build does not crash within the short PoC (freed memory not reused; the leaked reference keeps the final X509_free from double-freeing); ASan/valgrind and the real s_client handshake provide the deterministic evidence. Only the advisory's trigger combinations (PKIX-TA/PKIX-EE with DANE-TA) were exercised. The first two run_poc.sh runs had script-side check issues (case-sensitive grep, unconditional gdb breakpoint); results were identical in all runs and all outputs are kept.

素の (非 ASan) ビルドは短い PoC 内ではクラッシュしない (解放メモリが再利用されず、漏れた参照により最後の X509_free が二重解放に至らない); 決定的な証拠は ASan/valgrind と実際の s_client ハンドシェイク。試したトリガはアドバイザリの組み合わせ (PKIX-TA/PKIX-EE と DANE-TA) のみ。run_poc.sh の最初の 2 回はスクリプト側チェックの問題 (大文字小文字を区別する grep、無条件 gdb ブレークポイント) があったが、結果は全回同一で全出力を保持している。
