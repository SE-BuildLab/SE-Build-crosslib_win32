# 008 / CVE-2024-13176 / Minerva-ECDSA-timing-side-chan

Log file / ログファイル: `20261102_121206_008of033_CVE-2024-13176_Minerva-ECDSA-timing-side-chan.log` (in /home/user/work/deliver/ipalongpatch_info/logs/)

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

In unpatched 1.1.1w, `ecdsa_sign_setup()` (crypto/ec/ecdsa_ossl.c) computes kinv = k^-1 mod n through `ec_group_do_inverse_ord()` -> `ec_field_inverse_mod_ord()` (crypto/ec/ec_lib.c), which uses `BN_mod_exp_mont(r, x, n-2, n)`. `BN_mod_exp_mont()` normalises its result with `bn_correct_top()`, so when the most significant word of kinv is zero its top shrinks from the order's word count (9 for P-521) to 8. The signing step `BN_mod_mul_montgomery(s, s, ckinv, group->mont_data, ctx)` only takes the assembler fast path (`bn_mul_mont`) when both operands have exactly `mont->N.top` words; a shrunken kinv falls back to `bn_mul_fixed_top()` + `bn_from_montgomery_word()`, about 300 ns slower. For P-521 (order 521 bits, top word has 9 significant bits) this happens for ~1/512 of the nonces and tells an attacker that k^-1 < 2^512. Patch 008 (port of upstream 07272b05) splits the exponentiation into `bn_mod_exp_mont_fixed_top()` (result left fixed-top) plus the normalising public wrapper, and `ec_field_inverse_mod_ord()` uses the fixed-top variant, so kinv always has the order's word count.

未修正 1.1.1w の `ecdsa_sign_setup()` (crypto/ec/ecdsa_ossl.c) は kinv = k^-1 mod n を `ec_group_do_inverse_ord()` -> `ec_field_inverse_mod_ord()` (crypto/ec/ec_lib.c) で計算し、ここでは `BN_mod_exp_mont(r, x, n-2, n)` が使われる。`BN_mod_exp_mont()` は結果を `bn_correct_top()` で正規化するため、kinv の最上位ワードがゼロのとき top は位数のワード数 (P-521 で 9) から 8 に縮む。署名ステップ `BN_mod_mul_montgomery(s, s, ckinv, group->mont_data, ctx)` は両オペランドがちょうど `mont->N.top` ワードのときだけアセンブラの高速経路 (`bn_mul_mont`) を取り、縮んだ kinv は約 300 ns 遅い `bn_mul_fixed_top()` + `bn_from_montgomery_word()` に落ちる。P-521 (位数 521 ビット、最上位ワードの有効ビットは 9) ではノンスの約 1/512 でこれが起こり、攻撃者に k^-1 < 2^512 を教える。パッチ 008 (上流 07272b05 の移植) はべき乗を `bn_mod_exp_mont_fixed_top()` (結果を fixed-top のまま返す) と正規化する公開ラッパに分け、`ec_field_inverse_mod_ord()` が fixed-top 版を使うので kinv は常に位数のワード数を持つ。

## PoC design / PoC の設計

`poc_ecdsa_top.c` is linked statically against each build's libcrypto.a to reach the internal functions. Modes: `inv N` (histogram of `bn_get_top()` of x^-1 mod n for N random x on P-521, correctness checked), `setup N` (top of kinv returned by the real `ECDSA_sign_setup()`), `timing N REPS` (nonces chosen so that k^-1 < 2^512 [class A] or >= 2^512 [class B]; kinv obtained from the real inversion; `ECDSA_do_sign_ex()` and the isolated `BN_mod_mul_montgomery()` timed interleaved, min of REPS, quartiles), `regress N`. `run_poc.sh` adds gdb (conditional breakpoint after the exponentiation in `ec_field_inverse_mod_ord()`), CLI sign/verify, cross-build verification and valgrind, and prints a verdict.

`poc_ecdsa_top.c` は内部関数へ到達するため各ビルドの libcrypto.a に静的リンクする。モード: `inv N` (P-521 のランダム x N 個に対する x^-1 mod n の `bn_get_top()` ヒストグラム、正しさも確認)、`setup N` (実際の `ECDSA_sign_setup()` が返す kinv の top)、`timing N REPS` (k^-1 < 2^512 [クラス A] または >= 2^512 [クラス B] となるノンスを選択; kinv は実際の逆元計算から取得; `ECDSA_do_sign_ex()` と単独の `BN_mod_mul_montgomery()` を交互に計測、REPS 回の最小値、四分位)、`regress N`。`run_poc.sh` は gdb (`ec_field_inverse_mod_ord()` のべき乗直後の条件付きブレークポイント)、CLI 署名/検証、ビルド間相互検証、valgrind を加え、判定を表示する。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
  histogram of bn_get_top(r) over ALL results:  top=8: 212  top=9: 99788
  inverses with zero top word (value < 2^512): 212 of 100000 = 0.212% (expected ~1/512 = 0.195%)
  => VALUE-DEPENDENT TOP: the top shrinks when the top word is zero (unpatched behaviour, CVE-2024-13176)
gdb[BASE] result with ZERO top word: r->top=8  r->d[8]=0x0000000000000000  r->d[7]=0xb8270df578d5aa96  r->flags=0x1
  gdb hits with zero top word: 14; of which r->top=8: 14, r->top=9: 0
    class A (kinv top word zero)       n=3000 min=1690 q1=1751 median=1819 q3=1938 ... ns   [ECDSA_do_sign_ex]
    class B (kinv top word nonzero)    n=3000 ... q1=1140 median=1185 q3=1268 ... ns
    median A - median B = 634 ns
    class A ... median=463 ns / class B ... median=172 ns   [isolated BN_mod_mul_montgomery]: median A - median B = 291 ns
```

The top of the inverted nonce depends on its value and the signing step is measurably slower for those nonces (+634 ns per signature, +291 ns in the Montgomery multiplication, matching the advisory's ~300 ns).

逆元化したノンスの top は値に依存し、そのノンスでは署名ステップが計測可能に遅い (署名あたり +634 ns、Montgomery 乗算で +291 ns、アドバイザリの約 300 ns と一致)。

## Observed behaviour AFTER the patch / 修正後の挙動

```
  histogram of bn_get_top(r) over ALL results:  top=9: 100000
  inverses with zero top word (value < 2^512): 194 of 100000 = 0.194% (expected ~1/512 = 0.195%)
  => FIXED TOP: top stays at the order's word count even when the top word is zero (patched behaviour)
gdb[PATCHED] result with ZERO top word: r->top=9  r->d[8]=0x0000000000000000  r->d[7]=0xe09962435a4dcb37  r->flags=0x1
  gdb hits with zero top word: 13; of which r->top=8: 0, r->top=9: 13
    median A - median B = 12 ns   [ECDSA_do_sign_ex]      median A - median B = 0 ns   [BN_mod_mul_montgomery]
```

The top is fixed at 9 words and the timing difference disappears; the class-B (normal) time is unchanged.

top は 9 ワードに固定され、タイミング差は消失する。クラス B (通常) の時間は不変。

## Regression check / 回帰確認

ECDSA_do_sign/ECDSA_do_verify (200 messages each on P-521 and P-256, tampered digests rejected) on both builds; CLI `ecparam -genkey` + `dgst -sha256 -sign/-verify` for prime256v1 and secp521r1 ("Verified OK"); cross-build verification "Verified OK" x4; valgrind --leak-check=full on the patched PoC: 0 errors, 0 bytes definitely lost; the patched tree's full `make test` had passed.

両ビルドで ECDSA_do_sign/ECDSA_do_verify (P-521 と P-256 で各 200 メッセージ、改変ダイジェスト拒否); CLI `ecparam -genkey` + `dgst -sha256 -sign/-verify` (prime256v1、secp521r1) は "Verified OK"; ビルド間相互検証 "Verified OK" x4; パッチ版 PoC への valgrind --leak-check=full: 0 errors、definitely lost 0 bytes; パッチ版ツリーの完全な `make test` は合格済み。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```bash
cd /home/user/work/poc/008_CVE-2024-13176
gcc -g -O0 -Wall -I/home/user/work/base/openssl-1.1.1w/include -I/home/user/work/src_1.1.1w/openssl-1.1.1w/include -I/home/user/work/src_1.1.1w/openssl-1.1.1w poc_ecdsa_top.c /home/user/work/base/openssl-1.1.1w/libcrypto.a -ldl -pthread -o poc_ecdsa_top_base
gcc -g -O0 -Wall -I/home/user/work/patched/build/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102 poc_ecdsa_top.c /home/user/work/patched/build/libcrypto.a -ldl -pthread -o poc_ecdsa_top_patched
./poc_ecdsa_top_base inv 100000 ; ./poc_ecdsa_top_patched inv 100000      # top histogram: top=8 appears only for the unpatched build
./poc_ecdsa_top_base setup 3000 ; ./poc_ecdsa_top_patched setup 3000      # the real ECDSA_sign_setup()
./poc_ecdsa_top_base timing 3000 7 ; ./poc_ecdsa_top_patched timing 3000 7  # +~600/+~300 ns before, ~0 after
./run_poc.sh | tee raw_run_poc.txt   # full demonstration incl. gdb, CLI, cross-build, valgrind; prints VERDICT: PASS
```

## Limitations / notes / 制約・注記

- Timing classes are selected artificially to obtain enough zero-top-word samples; the natural frequency (~0.2 % on P-521) is shown by the inv/setup modes. Measured on a shared 4-vCPU VM; quartile ranges of the two classes do not overlap for the unpatched build.
- The first timing version compared kinv with the top-sensitive `BN_cmp()` and mis-reported mismatches for the fixed-top kinv; it was replaced by `BN_bn2binpad()`/`memcmp()` and re-run (both runs are in the log).
- For the fixed-top kinv `BN_num_bits()` reports 512 because it looks at the zero top word; the numeric value is identical (signatures verify, value comparison 0 mismatches).

- タイミングのクラスは最上位ワードゼロのサンプルを十分得るため人工的に選択; 自然な頻度 (P-521 で約 0.2 %) は inv/setup モードで示した。共有 4 vCPU VM での計測; 未パッチ版では両クラスの四分位範囲は重ならない。
- 最初の timing 版は top に敏感な `BN_cmp()` で kinv を比較し、fixed-top の kinv について不一致を誤報告した。`BN_bn2binpad()`/`memcmp()` に置き換えて再実行 (両実行をログに収録)。
- fixed-top の kinv では `BN_num_bits()` がゼロの最上位ワードを見て 512 を報告するが、数値は同一 (署名は検証成功、値比較の不一致 0)。
