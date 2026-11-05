# 030 / CVE-2026-54872 / EC-ladder-scalar-timing-leak

Log file / ログファイル: `20261102_122354_030of033_CVE-2026-54872_EC-ladder-scalar-timing-leak.log` (in /home/user/work/deliver/ipalongpatch_info/logs/)

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

In unpatched 1.1.1w, `ec_scalar_mul_ladder()` (crypto/ec/ec_mult.c) pads the secret scalar before the Montgomery ladder with `BN_copy(k, scalar)`, `BN_add(lambda, k, cardinality)` and `BN_add(k, lambda, cardinality)` (lines 215, 233, 238). `BN_copy()` preserves the minimal top of the scalar and `BN_add()`/`BN_uadd()` process `max(a->top, b->top)` words with value-dependent carry handling, so the work of the two additions depends on the scalar's magnitude: `k->top` is the word count of the nonce and `lambda->top` is 6 or 7 words on brainpoolP384r1 depending on whether `scalar + n` carried into a seventh word (about 18 % of random nonces, since n ≈ 0.55·2^384). Patch 030 adds `bn_set_top_fixed()` (constant-time zero-extension using the new `value_barrier_bn()` barrier, new error code `BN_F_BN_SET_TOP_FIXED`) and pins `k` to `group_top` words and `lambda` to `group_top + 1` words before the respective additions (patched lines 328 and 345).

未修正 1.1.1w の `ec_scalar_mul_ladder()` (crypto/ec/ec_mult.c) は Montgomery ラダーの前に秘密スカラーを `BN_copy(k, scalar)`、`BN_add(lambda, k, cardinality)`、`BN_add(k, lambda, cardinality)` (215、233、238 行) でパディングする。`BN_copy()` はスカラーの最小 top を保ち、`BN_add()`/`BN_uadd()` は `max(a->top, b->top)` ワードを値依存の桁上がり処理で扱うため、2 回の加算の処理量はスカラーの大きさに依存する: `k->top` はノンスのワード数、`lambda->top` は brainpoolP384r1 で `scalar + n` が 7 ワード目に桁上がりしたかにより 6 または 7 (n ≒ 0.55·2^384 なのでランダムノンスの約 18 %)。パッチ 030 は `bn_set_top_fixed()` (新設の `value_barrier_bn()` バリアを用いた定数時間ゼロ拡張、新エラーコード `BN_F_BN_SET_TOP_FIXED`) を追加し、それぞれの加算の前に `k` を `group_top` ワード、`lambda` を `group_top + 1` ワードに固定する (パッチ版 328 行と 345 行)。

## PoC design / PoC の設計

`poc_ladder.c` (statically linked against each build's libcrypto.a) multiplies the brainpoolP384r1 generator by chosen scalars (`once` mode: 1, 1024, n-1, random 64-bit, random full-size), times `EC_POINT_mul(k*G)` for 1-word vs 6-word scalars (`timing N REPS`, interleaved, min of REPS) and runs ECDSA/ECDH regression (`regress N`) on brainpoolP384r1 and secp256k1. `run_poc.sh` drives gdb with printf breakpoints at the two `BN_add()` calls (and at `bn_set_top_fixed()` in the patched tree), the timing, the C and CLI regression checks, cross-build checks and valgrind, and prints a verdict.

`poc_ladder.c` (各ビルドの libcrypto.a に静的リンク) は brainpoolP384r1 の生成元に選んだスカラーを掛け (`once` モード: 1、1024、n-1、ランダム 64 ビット、ランダムフルサイズ)、1 ワード対 6 ワードスカラーで `EC_POINT_mul(k*G)` の時間を計測し (`timing N REPS`、交互、REPS 回の最小値)、brainpoolP384r1 と secp256k1 で ECDSA/ECDH 回帰 (`regress N`) を実行する。`run_poc.sh` は 2 つの `BN_add()` 呼び出し (パッチ版では `bn_set_top_fixed()` にも) に printf ブレークポイントを置いた gdb、タイミング、C と CLI の回帰確認、ビルド間確認、valgrind を駆動し、判定を表示する。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
gdb[BASE] at BN_add(lambda, k, cardinality): k->top=1 (words) k->flags=0x4 | cardinality->top=6 group_top=6 cardinality_bits=384   <- scalar 1
gdb[BASE] at BN_add(k, lambda, cardinality): lambda->top=6 (words) lambda->flags=0x4
gdb[BASE] at BN_add(lambda, k, cardinality): k->top=6 (words) k->flags=0x4 | cardinality->top=6 group_top=6 cardinality_bits=384   <- scalar n-1
gdb[BASE] at BN_add(k, lambda, cardinality): lambda->top=7 (words) lambda->flags=0x4
  distinct k->top values seen at BN_add(lambda,k,cardinality): k->top=1 k->top=6
  distinct lambda->top values seen at BN_add(k,lambda,cardinality): lambda->top=6 lambda->top=7
    class S (1-word scalar)        n=2000 min=1046627 q1=1095222 median=1114931 q3=1208638 ... ns
    class F (6-word scalar)        n=2000 min=1052018 q1=1094383 median=1114108 q3=1217197 ... ns
    median S - median F = 823 ns (0.0739 % of median F)      [first run: -121 ns]
```

The operand tops at both padding additions take two different values depending on the scalar, i.e. the amount of BIGNUM work depends on the secret. The timing difference is within noise, as expected for a leak of a few word operations per ~1.1 ms ladder.

2 回のパディング加算におけるオペランドの top がスカラーに応じて 2 種類の値をとる、すなわち BIGNUM の処理量が秘密に依存する。タイミング差はノイズの範囲内で、約 1.1 ms のラダーあたり数ワード演算分の漏えいとして予想どおりである。

## Observed behaviour AFTER the patch / 修正後の挙動

```
gdb[PATCHED] before bn_set_top_fixed(k, group_top): k->top=1 (value dependent copy of the scalar)   <- scalar 1
gdb[PATCHED] at BN_add(lambda, k, cardinality): k->top=6 (words) k->flags=0x4 | cardinality->top=6 group_top=6 cardinality_bits=384
gdb[PATCHED] at BN_add(k, lambda, cardinality): lambda->top=7 (words) lambda->flags=0x4
gdb[PATCHED] before bn_set_top_fixed(k, group_top): k->top=6 (value dependent copy of the scalar)   <- scalar n-1
gdb[PATCHED] at BN_add(lambda, k, cardinality): k->top=6 (words) ...
gdb[PATCHED] at BN_add(k, lambda, cardinality): lambda->top=7 (words) ...
  distinct k->top values seen at BN_add(lambda,k,cardinality): k->top=6
  distinct lambda->top values seen at BN_add(k,lambda,cardinality): lambda->top=7
    median S - median F = -416 ns (-0.0373 % of median F)    [first run: +1557 ns]; medians 1.115 ms (unpatched 1.114 ms)
```

Both additions now process 6 and 7 words for every scalar; the ladder is not measurably slower.

2 回の加算はすべてのスカラーで 6 ワードと 7 ワードを処理するようになり、ラダーに計測可能な遅延は無い。

## Regression check / 回帰確認

ECDSA sign/verify (100 messages, tampered rejected) and ECDH agreement on brainpoolP384r1 and secp256k1 via the C API on both builds; CLI `ecparam -genkey`, `dgst -sha384 -sign/-verify` ("Verified OK"), `pkeyutl -derive` (secrets agree) on both curves and builds; cross-build: BASE signatures verify with PATCHED and vice versa (x4), PATCHED `pkeyutl -derive` with BASE keys reproduces the BASE secret; valgrind on the patched PoC: 0 errors, 0 bytes definitely/indirectly lost. The full `make test` of the patched tree had passed before (2658 tests).

両ビルドで C API による brainpoolP384r1 と secp256k1 の ECDSA 署名/検証 (100 メッセージ、改変拒否) と ECDH 鍵合意; 両曲線・両ビルドで CLI `ecparam -genkey`、`dgst -sha384 -sign/-verify` ("Verified OK")、`pkeyutl -derive` (秘密一致); ビルド間: BASE の署名を PATCHED が検証し逆も成功 (x4)、BASE の鍵による PATCHED の `pkeyutl -derive` が BASE の秘密を再現; パッチ版 PoC への valgrind: 0 errors、definitely/indirectly lost 0 bytes。パッチ版ツリーの完全な `make test` は事前に合格 (2658 テスト)。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```bash
cd /home/user/work/poc/030_CVE-2026-54872
# 1. build the PoC against the unpatched and the patched build (static link, debug symbols)
gcc -g -O0 -Wall -I/home/user/work/base/openssl-1.1.1w/include -I/home/user/work/src_1.1.1w/openssl-1.1.1w/include -I/home/user/work/src_1.1.1w/openssl-1.1.1w poc_ladder.c /home/user/work/base/openssl-1.1.1w/libcrypto.a -ldl -pthread -o poc_ladder_base
gcc -g -O0 -Wall -I/home/user/work/patched/build/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102 poc_ladder.c /home/user/work/patched/build/libcrypto.a -ldl -pthread -o poc_ladder_patched
# 2. structural check with gdb (unpatched: lines 233/238 of crypto/ec/ec_mult.c)
gdb -batch -ex 'break ec_mult.c:233' -ex 'commands 1\nsilent\nprintf "k->top=%d\\n", k->top\ncontinue\nend' -ex 'break ec_mult.c:238' -ex 'commands 2\nsilent\nprintf "lambda->top=%d\\n", lambda->top\ncontinue\nend' -ex 'run once 1 big rand64 randfull' ./poc_ladder_base
#    (or simply run the whole demonstration, which generates the gdb command files itself)
./run_poc.sh | tee raw_run_poc.txt     # TIMING_N=2000 TIMING_REPS=3 by default; prints VERDICT: PASS
# 3. individual modes
./poc_ladder_base timing 2000 3 ; ./poc_ladder_patched timing 2000 3
./poc_ladder_base regress 100  ; ./poc_ladder_patched regress 100
```

## Limitations / notes / 制約・注記

- The timing measurement is informative only (deltas of a few hundred ns on ~1.1 ms that change sign between runs on this shared 4-vCPU VM); the demonstration is the structural gdb evidence. The 1-word scalars are artificial; the lambda->top dependency affects about 18 % of real random nonces on brainpoolP384r1.
- The comment inherited verbatim from the upstream/Ubuntu patch mentions `ossl_bn_priv_rand_range_fixed_top()`, which exists only in OpenSSL 3.x; in 1.1.1w the ECDSA nonce from `BN_priv_rand_range()` has a minimal top, so the `BN_copy()` length inside the ladder still depends on the nonce at word granularity (probability ~2^-64 per word) -- a residual outside the scope of this CVE fix.
- The verification subagent was terminated before writing the formal log; the orchestrator assembled the log from the unaltered raw captures. The first run's valgrind leak (5 bytes) was in the PoC itself (BN_bn2dec string) and was fixed before the final run; both runs are in the log.

- タイミング計測は参考情報 (約 1.1 ms に対し数百 ns の差で、この共有 4 vCPU VM では実行毎に符号が変わる)。実証は gdb による構造的証拠である。1 ワードスカラーは人工的だが、lambda->top の依存は brainpoolP384r1 の実際のランダムノンスの約 18 % に影響する。
- 上流/Ubuntu パッチから原文どおり継承したコメントは OpenSSL 3.x にしか存在しない `ossl_bn_priv_rand_range_fixed_top()` に言及している。1.1.1w では `BN_priv_rand_range()` による ECDSA ノンスは最小 top を持つため、ラダー内の `BN_copy()` の長さはワード単位でノンスに依存したまま (1 ワードあたり約 2^-64 の確率) であり、本 CVE 修正の範囲外の残余である。
- 検証サブエージェントは正式ログを書く前に停止したため、統括セッションが改変なしの生出力からログを組み立てた。初回実行の valgrind リーク (5 バイト) は PoC 自身 (BN_bn2dec の文字列) のもので最終実行前に修正済み。両実行をログに収録。
