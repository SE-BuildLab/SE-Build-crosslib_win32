# 018 / CVE-2026-28388 / DeltaCRL-no-CRLNumber-NULL-deref

Log file / ログファイル: `20261102_124759_018of033_CVE-2026-28388_DeltaCRL-no-CRLNumber-NULL-deref.log` (in /home/user/work/deliver/ipalongpatch_info/logs/)

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

With X509_V_FLAG_USE_DELTAS and a certificate carrying a Freshest CRL extension, `get_delta_sk()` calls `check_delta_base(delta, base)` for every supplied CRL. After checking Delta CRL Indicator, base CRL Number, issuer, AKID, IDP and base number, the unpatched code evaluates `ASN1_INTEGER_cmp(delta->crl_number, base->crl_number) > 0` (x509_vfy.c:1139). A delta CRL without a CRL Number extension has `crl_number == NULL`, and `ASN1_INTEGER_cmp()` dereferences it (`neg = x->type & V_ASN1_NEG;`, a_int.c:27) -> SIGSEGV. Patch 018 adds `if (delta->crl_number == NULL) return 0;`.

X509_V_FLAG_USE_DELTAS と Freshest CRL 拡張付きの証明書の下で、`get_delta_sk()` は与えられた各 CRL に `check_delta_base(delta, base)` を呼ぶ。Delta CRL Indicator、ベース CRL Number、発行者、AKID、IDP、ベース番号を確認した後、未修正コードは `ASN1_INTEGER_cmp(delta->crl_number, base->crl_number) > 0` (x509_vfy.c:1139) を評価する。CRL Number 拡張の無い差分 CRL では `crl_number == NULL` で、`ASN1_INTEGER_cmp()` がそれを参照 (`neg = x->type & V_ASN1_NEG;`、a_int.c:27) → SIGSEGV。パッチ 018 は `if (delta->crl_number == NULL) return 0;` を追加する。

## PoC design / PoC の設計

Attacker input = the upstream test data shipped with the patch (test/certs/cve-2026-28388-{ca,crls,leaf}.pem: base CRL with CRL Number 1, delta CRL with Delta CRL Indicator but no CRL Number, leaf with Freshest CRL). `openssl verify -attime 1739527200 -CAfile ca -crl_check -use_deltas -CRLfile crls leaf` is run with BASE (crash), BASE-ASAN, gdb, PATCHED, PATCHED-ASAN and valgrind. `regress_crl.sh` builds a CA with proper base and delta CRLs (CRL Numbers 1 and 2) to show that CRL checking and delta application still work.

攻撃者入力 = パッチ同梱の上流テストデータ (test/certs/cve-2026-28388-{ca,crls,leaf}.pem: CRL Number 1 のベース CRL、Delta CRL Indicator はあるが CRL Number の無い差分 CRL、Freshest CRL 付きリーフ)。`openssl verify -attime 1739527200 -CAfile ca -crl_check -use_deltas -CRLfile crls leaf` を BASE (クラッシュ)、BASE-ASAN、gdb、PATCHED、PATCHED-ASAN、valgrind で実行。`regress_crl.sh` は正しいベース/差分 CRL (CRL Number 1 と 2) を持つ CA を構築し、CRL 検査と差分適用が引き続き動作することを示す。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
$ openssl(BASE) verify -attime 1739527200 -CAfile cve-2026-28388-ca.pem -crl_check -use_deltas -CRLfile cve-2026-28388-crls.pem cve-2026-28388-leaf.pem
Segmentation fault      [exit status: 139]
$ openssl(BASE-ASAN) verify ... (same)
==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000004 ... READ ... address points to the zero page
    #0 ASN1_INTEGER_cmp crypto/asn1/a_int.c:27
    #1 check_delta_base crypto/x509/x509_vfy.c:1139
    #2 get_delta_sk x509_vfy.c:1160   #3 get_crl_sk x509_vfy.c:1068   #4 get_crl_delta x509_vfy.c:1483
    #5 check_cert   #6 check_revocation   #7 verify_chain   #8 X509_verify_cert   #9 check apps/verify.c:237
$ LD_LIBRARY_PATH=$B gdb ... --args $B/apps/openssl verify ... (same)
Program received signal SIGSEGV   ASN1_INTEGER_cmp (x=0x0, y=0x5555...) at crypto/asn1/a_int.c:27
27    neg = x->type & V_ASN1_NEG;
#1 check_delta_base (delta=..., base=...) at crypto/x509/x509_vfy.c:1139
1139  if (ASN1_INTEGER_cmp(delta->crl_number, base->crl_number) > 0)
delta->crl_number = (ASN1_INTEGER *) 0x0     base->crl_number = 1     *delta->base_crl_number = 1
```

## Observed behaviour AFTER the patch / 修正後の挙動

```
$ openssl(PATCHED) verify -attime 1739527200 ... (same)
CN = Test Leaf
error 11 at 0 depth lookup: CRL is not yet valid
CN = Test CA
error 9 at 1 depth lookup: certificate is not yet valid
error cve-2026-28388-leaf.pem: verification failed     [exit status: 2]
(without -attime: "CRL has expired"; PATCHED-ASAN: no ASan report; valgrind: clean)
```

## Regression check / 回帰確認

PATCHED `regress_crl.sh`: base CRL (CRL Number 1) -> leaf1 OK, leaf2 OK; `-use_deltas` with base + well-formed delta CRL (CRL Number 2, Delta CRL Indicator 1, leaf2 revoked) -> leaf1 OK, leaf2 "certificate revoked"; without `-use_deltas` the delta is ignored (leaf2 OK); `-crl_check_all` OK. BASE gives identical results. Patched `verify_extra_test`: ok 1-7.

PATCHED の `regress_crl.sh`: ベース CRL (CRL Number 1) → leaf1 OK、leaf2 OK; ベース + 正しい差分 CRL (CRL Number 2、Delta CRL Indicator 1、leaf2 失効) で `-use_deltas` → leaf1 OK、leaf2 "certificate revoked"; `-use_deltas` 無しでは差分は無視 (leaf2 OK); `-crl_check_all` OK。BASE も同一結果。修正済み `verify_extra_test`: ok 1〜7。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/018_CVE-2026-28388
B=/home/user/work/base/openssl-1.1.1w; BA=/home/user/work/base_asan; P=/home/user/work/patched/build
ARGS="verify -attime 1739527200 -CAfile cve-2026-28388-ca.pem -crl_check -use_deltas -CRLfile cve-2026-28388-crls.pem cve-2026-28388-leaf.pem"
$B/util/shlib_wrap.sh $B/apps/openssl $ARGS                       # Segmentation fault
ASAN_OPTIONS=detect_leaks=0 $BA/util/shlib_wrap.sh $BA/apps/openssl $ARGS   # ASan SEGV in ASN1_INTEGER_cmp <- check_delta_base
LD_LIBRARY_PATH=$B gdb -q -batch -ex run -ex bt -ex 'frame 1' -ex 'print delta->crl_number' --args $B/apps/openssl $ARGS
$P/util/shlib_wrap.sh $P/apps/openssl $ARGS                       # "CRL is not yet valid", exit 2
./regress_crl.sh $P patched                                       # regression scenario
./run_poc.sh                                                      # everything, with verdict
```

## Limitations / notes / 制限事項・注記

Command line tool used; the crash is inside libcrypto's X509_verify_cert() (any application with X509_V_FLAG_USE_DELTAS is affected). Upstream test data used as input; -attime fixes the patched outcome. The regression delta CRL uses the generic ASN1 extension syntax because `openssl ca` has no delta-CRL option. The first run_poc.sh run invoked verify_extra_test with wrong arguments (fixed, re-run, both outputs kept).

コマンドラインツールを使用; クラッシュは libcrypto の X509_verify_cert() 内 (X509_V_FLAG_USE_DELTAS を使う全アプリケーションが影響)。入力は上流テストデータ; -attime で修正版の結果を固定。回帰用差分 CRL は `openssl ca` に差分 CRL オプションが無いため汎用 ASN1 拡張構文を使用。run_poc.sh 初回は verify_extra_test の引数が誤り (修正・再実行、両出力を保持)。
