# 031 / CVE-2026-77696 / SM2-sig-gen-timing-side-channel

Log file / ログファイル: `20261102_123554_031of033_CVE-2026-77696_SM2-sig-gen-timing-side-channel.log` (in /home/user/work/deliver/ipalongpatch_info/logs/)

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

In unpatched 1.1.1w, `sm2_sig_gen()` (crypto/sm2/sm2_sign.c:230-259) computes r = (e + x1) mod n, tests `r + k == n` with `BN_add(rk, r, k)` / `BN_cmp(rk, order)`, and computes s = (1 + dA)^-1 (k - r dA) mod n with `BN_mod_mul(tmp, dA, r, order, ctx)`, `BN_sub(tmp, k, tmp)` and `BN_mod_mul(s, s, tmp, order, ctx)`. `BN_mod_mul()` reduces through `BN_nnmod()` -> `BN_div()` (variable time), `BN_sub()` sets a sign when k < r dA mod n so that `BN_nnmod()` must add the modulus back (an extra `BN_add()` only for negative intermediates), `BN_cmp()` branches on the top of r + k, and k is passed to `EC_POINT_mul()` with a minimal top. Patch 031 (port of upstream 10040fa0) pins k with `bn_set_top_fixed()` and `BN_FLG_CONSTTIME`, replaces the comparison by `CRYPTO_memcmp(k, n - r)` over a fixed width, and computes s with `bn_to_mont_fixed_top` / `bn_mul_mont_fixed_top` / `bn_mod_sub_fixed_top` / `bn_to_mont_fixed_top` / `BN_mod_mul_montgomery` (patched lines 342-389), mirroring the ECDSA code.

未修正 1.1.1w の `sm2_sig_gen()` (crypto/sm2/sm2_sign.c:230〜259) は r = (e + x1) mod n を計算し、`r + k == n` を `BN_add(rk, r, k)` / `BN_cmp(rk, order)` で判定し、s = (1 + dA)^-1 (k - r dA) mod n を `BN_mod_mul(tmp, dA, r, order, ctx)`、`BN_sub(tmp, k, tmp)`、`BN_mod_mul(s, s, tmp, order, ctx)` で計算する。`BN_mod_mul()` は `BN_nnmod()` -> `BN_div()` (可変時間) で剰余を取り、`BN_sub()` は k < r dA mod n のとき符号を立てるので `BN_nnmod()` が法を足し戻す (負の中間値のときだけ余分な `BN_add()`)、`BN_cmp()` は r + k の top で分岐し、k は最小 top のまま `EC_POINT_mul()` に渡される。パッチ 031 (上流 10040fa0 の移植) は k を `bn_set_top_fixed()` と `BN_FLG_CONSTTIME` で固定し、比較を固定幅の `CRYPTO_memcmp(k, n - r)` に置き換え、s を `bn_to_mont_fixed_top` / `bn_mul_mont_fixed_top` / `bn_mod_sub_fixed_top` / `bn_to_mont_fixed_top` / `BN_mod_mul_montgomery` (パッチ版 342〜389 行) で ECDSA コードと同様に計算する。

## PoC design / PoC の設計

`poc_sm2.c` (statically linked against each build's libcrypto.a) signs with `EVP_DigestSign` (SM3, distid `1234567812345678`). `sm2_calls.py` is a gdb Python script that places internal breakpoints on 16 BIGNUM primitives and records, for every hit whose call chain reaches `sm2_sig_gen()`, the chain and the source line (`gdb -batch -x sm2_calls.py --args ./poc_sm2_<build> sign 2`). `arith N REPS` isolates the s computation and times the unpatched sequence (seq1) and the patched fixed-top Montgomery sequence (seq2) on identical inputs for one-word vs full-size nonces, checking that the results agree. `timing N`, `regress N`, `keygen`/`signfile`/`verifyfile` (cross-build) complete the picture; `run_rest.sh` runs the cross-build, valgrind and `make test TESTS='test_internal_sm2 test_evp'` checks.

`poc_sm2.c` (各ビルドの libcrypto.a に静的リンク) は `EVP_DigestSign` (SM3、distid `1234567812345678`) で署名する。`sm2_calls.py` は gdb の Python スクリプトで、16 個の BIGNUM プリミティブに内部ブレークポイントを置き、呼び出し連鎖が `sm2_sig_gen()` に到達するヒットについて連鎖とソース行を記録する (`gdb -batch -x sm2_calls.py --args ./poc_sm2_<build> sign 2`)。`arith N REPS` は s 計算を単離し、同一入力に対して未パッチの演算列 (seq1) とパッチ版の fixed-top Montgomery 演算列 (seq2) を 1 ワード対フルサイズのノンスで計測し、結果の一致を確認する。`timing N`、`regress N`、`keygen`/`signfile`/`verifyfile` (ビルド間) がこれを補完し、`run_rest.sh` がビルド間確認、valgrind、`make test TESTS='test_internal_sm2 test_evp'` を実行する。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
     2  BN_cmp <- sm2_sig_gen:252
     2  BN_div <- BN_nnmod <- BN_mod_mul <- sm2_sig_gen:257
     2  BN_sub <- sm2_sig_gen:258
     1  BN_add <- BN_nnmod <- BN_mod_mul <- sm2_sig_gen:259      <- executed for only one of the two signatures (negative k - r*dA)
     2  BN_div <- BN_nnmod <- BN_mod_mul <- sm2_sig_gen:259
variable-time BN_mod_mul() called directly from sm2_sig_gen(): YES
BN_cmp() called directly from sm2_sig_gen(): YES
BN_div() reached via BN_mod_mul() from sm2_sig_gen(): YES
fixed-top Montgomery primitives called directly from sm2_sig_gen(): no
  seq1 (unpatched arithmetic, generic BN_mod_mul/BN_sub):
    class S (1-word k)             n=2000 ... median=954 ... sd=112 ns
    class F (4-word k)             n=2000 ... median=940 ... sd=109 ns
    median S - median F = 14 ns (1.5 % of median F)          [PATCHED binary: 936 vs 916 ns, +20 ns]
```

The signature arithmetic on the secrets goes through variable-time division and sign-dependent branches, and its cost depends on the nonce class.

秘密値に対する署名算術は可変時間の除算と符号依存の分岐を通り、そのコストはノンスのクラスに依存する。

## Observed behaviour AFTER the patch / 修正後の挙動

```
     2  bn_set_top_fixed <- sm2_sig_gen:342
     2  BN_sub <- sm2_sig_gen:359                 (public operands: n - r)
     2  bn_set_top_fixed <- sm2_sig_gen:360
     2  CRYPTO_memcmp <- sm2_sig_gen:365
     2  bn_to_mont_fixed_top <- sm2_sig_gen:385
     2  bn_mul_mont_fixed_top <- sm2_sig_gen:386
     2  bn_mod_sub_fixed_top <- sm2_sig_gen:387
     2  bn_to_mont_fixed_top <- sm2_sig_gen:388
     2  BN_mod_mul_montgomery <- sm2_sig_gen:389
variable-time BN_mod_mul() called directly from sm2_sig_gen(): no
BN_cmp() called directly from sm2_sig_gen(): no
BN_div() reached via BN_mod_mul() from sm2_sig_gen(): no
fixed-top Montgomery primitives called directly from sm2_sig_gen(): YES
  seq2 (patched arithmetic, fixed-top Montgomery):
    class S (1-word k)             n=2000 ... median=272 ... sd=23 ns
    class F (4-word k)             n=2000 ... median=271 ... sd=25 ns
    median S - median F = 1 ns (0.4 % of median F)           [PATCHED binary: 273 vs 273 ns, 0 ns]
  seq1 result == seq2 result for all samples: yes (0 mismatches)
```

The same primitive sequence is executed for every signature, its cost does not depend on the nonce class, and it produces the same s as the old arithmetic (and is ~3.4x faster).

すべての署名で同じプリミティブ列が実行され、そのコストはノンスのクラスに依存せず、旧算術と同じ s を生成する (しかも約 3.4 倍高速)。

## Regression check / 回帰確認

`regress 50` on both builds: 50/50 verified, 50/50 tampered rejected; `sign 2`: 2/2. Cross-build: signature of the unpatched build verified by the patched build and vice versa ("Verified OK" x2); tampered message and wrong key rejected ("VERIFICATION FAILURE" x2). valgrind on the patched PoC (`regress 3`, `arith 20 2`): 0 errors, no leaks. Patched tree `make test TESTS='test_internal_sm2 test_evp'`: PASS (11 tests; the known-answer SM2 signature of the standard is reproduced). The full `make test` (2658 tests) had passed earlier. The 1.1.1 command-line tool cannot sign with SM2 on either build (pre-existing limitation).

両ビルドで `regress 50`: 50/50 検証成功、改変 50/50 拒否; `sign 2`: 2/2。ビルド間: 未パッチ版の署名をパッチ版が検証、逆も成功 ("Verified OK" x2); 改変メッセージと誤った鍵は拒否 ("VERIFICATION FAILURE" x2)。パッチ版 PoC への valgrind (`regress 3`、`arith 20 2`): 0 errors、リーク無し。パッチ版ツリーの `make test TESTS='test_internal_sm2 test_evp'`: PASS (11 テスト; 規格の既知解答 SM2 署名を再現)。完全な `make test` (2658 テスト) は事前に合格。1.1.1 のコマンドラインツールはどちらのビルドでも SM2 で署名できない (元からある制約)。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```bash
cd /home/user/work/poc/031_CVE-2026-77696
gcc -g -O0 -Wall -I/home/user/work/base/openssl-1.1.1w/include -I/home/user/work/src_1.1.1w/openssl-1.1.1w/include -I/home/user/work/src_1.1.1w/openssl-1.1.1w poc_sm2.c /home/user/work/base/openssl-1.1.1w/libcrypto.a -ldl -pthread -lm -o poc_sm2_base
gcc -g -O0 -Wall -I/home/user/work/patched/build/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102 poc_sm2.c /home/user/work/patched/build/libcrypto.a -ldl -pthread -lm -o poc_sm2_patched
# structural evidence: which BIGNUM primitives sm2_sig_gen() calls
gdb -batch -x sm2_calls.py --args ./poc_sm2_base sign 2      # BN_mod_mul/BN_div/BN_sub/BN_cmp: YES
gdb -batch -x sm2_calls.py --args ./poc_sm2_patched sign 2   # none of them; fixed-top primitives + CRYPTO_memcmp
# component timing of the s computation (both sequences inside each binary)
./poc_sm2_base arith 2000 5 ; ./poc_sm2_patched arith 2000 5
# regression, cross-build, valgrind, test recipes
./poc_sm2_base regress 50 ; ./poc_sm2_patched regress 50
./run_rest.sh
```

## Limitations / notes / 制約・注記

- Whole-signature timings cannot be split by nonce class (the nonce is internal) and were taken under heavy, varying load; they are informative only. The class dependence of the old arithmetic was measured in isolation (+14/+20 ns, about 5 standard errors of the median) with artificially small one-word nonces; the gdb trace is the primary, deterministic evidence.
- `bn_set_top_fixed()` does not exist in the unpatched library and is emulated by `pin_top()` in the PoC for the seq2 measurement.
- No CLI-level check is possible: the 1.1.1 `openssl` tool cannot produce SM2 signatures (`dgst`: 'invalid digest type'; `pkeyutl` has no `-rawin`). A first test recipe run used the wrong name `test_sm2_internal` (NOTESTS) and was corrected to `test_internal_sm2`.
- The verification subagent was terminated before the regression checks and the formal log; the orchestrator completed the checks (raw_rest.txt, run_rest.sh) and assembled the log from the unaltered captures.

- 署名全体のタイミングはノンスのクラスで分けられず (ノンスは内部生成)、負荷が大きく変動する状況で取得したため参考情報である。旧算術のクラス依存は人工的に小さい 1 ワードノンスで単離計測した (+14/+20 ns、中央値の標準誤差の約 5 倍)。主たる決定的証拠は gdb トレースである。
- `bn_set_top_fixed()` は未パッチ版ライブラリに存在しないため、seq2 計測では PoC 内の `pin_top()` で模倣した。
- CLI レベルの確認は不可能: 1.1.1 の `openssl` ツールは SM2 署名を生成できない (`dgst`: 'invalid digest type'; `pkeyutl` に `-rawin` 無し)。テストレシピの初回実行は誤った名前 `test_sm2_internal` (NOTESTS) で、`test_internal_sm2` に修正した。
- 検証サブエージェントは回帰確認と正式ログの前に停止したため、統括セッションが確認を完了し (raw_rest.txt、run_rest.sh)、改変なしの出力からログを組み立てた。
