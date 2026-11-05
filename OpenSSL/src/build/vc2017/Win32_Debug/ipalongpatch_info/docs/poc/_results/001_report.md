# 001 / CVE-2023-5678 / DH-large-Q-excessive-time-DoS

Log file / ログファイル: `20261102_120524_001of033_CVE-2023-5678_DH-large-Q-excessive-time-DoS.log` (in /home/user/work/deliver/ipalongpatch_info/logs/)

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

In unpatched 1.1.1w, `generate_key()` (crypto/dh/dh_key.c) checks only `BN_num_bits(dh->p) > OPENSSL_DH_MAX_MODULUS_BITS` (10000); when `dh->q` is set it draws the private key with `BN_priv_rand_range(priv_key, dh->q)` and computes `g^priv mod p`, so the cost is linear in the bit length of q. `DH_check_pub_key()` (crypto/dh/dh_check.c) unconditionally computes `pub_key^q mod p` when q is set, with no size limit on p or q, and `compute_key()` calls it. Patch 001 adds `DH_R_Q_TOO_LARGE` checks (q > OPENSSL_DH_MAX_MODULUS_BITS) to generate_key()/compute_key(), and to DH_check_pub_key() a `DH_R_MODULUS_TOO_LARGE` error for p > OPENSSL_DH_CHECK_MAX_MODULUS_BITS (32768) plus an immediate `DH_CHECK_INVALID_Q_VALUE` result for q > p.

未修正 1.1.1w の `generate_key()` (crypto/dh/dh_key.c) は `BN_num_bits(dh->p) > OPENSSL_DH_MAX_MODULUS_BITS` (10000) しか確認せず、`dh->q` があると `BN_priv_rand_range(priv_key, dh->q)` で秘密鍵を作り `g^priv mod p` を計算するため、コストは q のビット長に比例する。`DH_check_pub_key()` (crypto/dh/dh_check.c) は q があれば p/q のサイズ制限なしに無条件で `pub_key^q mod p` を計算し、`compute_key()` もこれを呼ぶ。パッチ 001 は generate_key()/compute_key() に `DH_R_Q_TOO_LARGE` 検査 (q > OPENSSL_DH_MAX_MODULUS_BITS) を、DH_check_pub_key() に p > OPENSSL_DH_CHECK_MAX_MODULUS_BITS (32768) での `DH_R_MODULUS_TOO_LARGE` エラーと q > p での即時 `DH_CHECK_INVALID_Q_VALUE` 結果を追加する。

## PoC design / PoC の設計

`dh_large_q.c` builds DH parameters with `DH_set0_pqg()` (p = RFC 3526 2048/8192-bit prime, g = 2, q = 2^(N-1)+1 with N up to 2^26; or p = 2^39999+1 for the 40000-bit modulus case) and times `DH_generate_key()`, `DH_check_pub_key()` and `DH_compute_key()` under a 60-second SIGALRM watchdog (exit 124 on timeout). The same X9.42 parameters are written to PEM for `openssl genpkey -paramfile` under `timeout 60`. `run_poc.sh` runs all of this against BASE and PATCHED and performs the regression checks.

`dh_large_q.c` は `DH_set0_pqg()` で DH パラメータ (p = RFC 3526 の 2048/8192 ビット素数、g = 2、q = 2^(N-1)+1、N は最大 2^26; 40000 ビット法の場合は p = 2^39999+1) を作り、60 秒の SIGALRM 番犬 (タイムアウト時は終了コード 124) の下で `DH_generate_key()`、`DH_check_pub_key()`、`DH_compute_key()` の時間を計測する。同じ X9.42 パラメータを PEM に書き出し、`timeout 60` 下で `openssl genpkey -paramfile` も試す。`run_poc.sh` がこれらを BASE と PATCHED に対して実行し、回帰確認も行う。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
$ ./dh_large_q_base genkey 16384 60     -> DH_generate_key() returned 1 after 0.020 s
$ ./dh_large_q_base genkey 262144 60    -> DH_generate_key() returned 1 after 0.297 s
$ ./dh_large_q_base genkey 1048576 60   -> DH_generate_key() returned 1 after 1.269 s
$ ./dh_large_q_base genkey 4194304 60   -> DH_generate_key() returned 1 after 4.850 s
$ env PBITS=8192 ./dh_large_q_base genkey 4194304 60
TIMEOUT: DH_generate_key() did not return within 60 seconds (still computing) -> aborting (exit 124)
$ ./dh_large_q_base checkq 4194304 60   -> DH_check_pub_key() returned 1 after 3.879 s
$ ./dh_large_q_base compute 4194304 60  -> DH_compute_key() returned -1 after 3.840 s
$ ./dh_large_q_base checkq 67108864 60
TIMEOUT: DH_check_pub_key() did not return within 60 seconds (still computing) -> aborting (exit 124)
$ ./dh_large_q_base checkp 40000 120    -> DH_check_pub_key() returned 1 after 38.468 s
$ timeout 60 openssl(BASE) genpkey -paramfile hugeq_dhx_params.pem -out base_key.pem
real 1m0.003s  user 0m59.490s   [exit status 124 = killed after 60 s]
```

Time grows linearly with the size of q (about 1.2 us per bit for a 2048-bit p) and cubically with the size of p; large inputs do not finish within the 60-second watchdog.

所要時間は q のサイズに線形 (2048 ビット p で約 1.2 マイクロ秒/ビット)、p のサイズに三乗で増大し、大きな入力では 60 秒の番犬内に終了しない。

## Observed behaviour AFTER the patch / 修正後の挙動

```
$ ./dh_large_q_patched genkey 1048576 60
DH_generate_key() returned 0 after 0.001 s
  error:05067082:Diffie-Hellman routines:generate_key:q too large
$ ./dh_large_q_patched compute 4194304 60
DH_compute_key() returned -1 after 0.001 s   error:05066082:...:compute_key:q too large
$ ./dh_large_q_patched checkq 67108864 60
DH_check_pub_key() returned 1 after 0.000 s  check flags = 0x24 PUBKEY_INVALID DH_CHECK_INVALID_Q_VALUE(0x20)
$ ./dh_large_q_patched checkp 40000 60
DH_check_pub_key() returned 0 after 0.001 s  check flags = 0x104 PUBKEY_INVALID DH_MODULUS_TOO_LARGE(0x100)
  error:0507E067:Diffie-Hellman routines:DH_check:modulus too large
$ timeout 60 openssl(PATCHED) genpkey -paramfile hugeq_dhx_params.pem
error:05067082:Diffie-Hellman routines:generate_key:q too large:.../crypto/dh/dh_key.c:139   real 0m0.022s
```

All oversized inputs are rejected in about a millisecond.

過大な入力はすべて約 1 ミリ秒で拒否される。

## Regression check / 回帰確認

Benign 2048-bit parameters with q = (p-1)/2: `DH_check()` codes 0x0, `DH_check_pub_key()` flags 0x0 for both parties, 256-byte shared secrets MATCH (same on BASE). Command line (PATCHED): PKCS#3 1024-bit and X9.42 (`dh_paramgen_type:1`, 1024/160) parameter generation, key generation and `pkeyutl -derive` in both directions give identical secrets. `test/dhtest` of the patched build: ok 1-3. valgrind --leak-check=full on the benign path: clean.

q = (p-1)/2 の正常な 2048 ビットパラメータ: `DH_check()` codes 0x0、双方の `DH_check_pub_key()` フラグ 0x0、256 バイトの共有秘密が一致 (BASE でも同じ)。コマンドライン (PATCHED): PKCS#3 1024 ビットと X9.42 (`dh_paramgen_type:1`、1024/160) のパラメータ生成・鍵生成・双方向 `pkeyutl -derive` で同一の秘密が得られる。修正済みビルドの `test/dhtest`: ok 1〜3。正常系の valgrind --leak-check=full: 問題なし。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/001_CVE-2023-5678
B=/home/user/work/base/openssl-1.1.1w; P=/home/user/work/patched/build
PS=/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102
gcc -g -O0 -Wall -I$B/include dh_large_q.c -L$B -lcrypto -Wl,-rpath,$B -o dh_large_q_base
gcc -g -O0 -Wall -I$P/include -I$PS/include dh_large_q.c -L$P -lcrypto -Wl,-rpath,$P -o dh_large_q_patched
./dh_large_q_base genkey 4194304 60            # ~5 s on BASE
env PBITS=8192 ./dh_large_q_base genkey 4194304 60   # TIMEOUT after 60 s on BASE
./dh_large_q_base checkp 40000 120             # ~40 s on BASE
./dh_large_q_patched genkey 4194304 60         # immediate "q too large"
./dh_large_q_patched checkp 40000 60           # immediate "modulus too large"
env PBITS=8192 ./dh_large_q_patched writeparams 4194304 hugeq.pem
timeout 60 $B/util/shlib_wrap.sh $B/apps/openssl genpkey -paramfile hugeq.pem -out k.pem   # exit 124
timeout 60 $P/util/shlib_wrap.sh $P/apps/openssl genpkey -paramfile hugeq.pem -out k.pem   # "q too large"
./dh_large_q_patched regress 0 60              # regression: REGRESSION RESULT: OK
./run_poc.sh                                   # everything, with verdict
```

## Limitations / notes / 制限事項・注記

Timing on a shared 4-vCPU VM varies by 10-20 % between runs, but the linear scaling and the watchdog results are deterministic. SSL/TLS is not affected per the advisory and was not tested. The first run of run_poc.sh mis-reported FAIL because of a stderr-capture bug in the script's own checks (the measurements were identical); the fixed script was re-run and both outputs are kept in the log.

共有 4 vCPU VM 上の時間計測は実行毎に 10〜20 % 変動するが、線形スケーリングと番犬の結果は決定的である。アドバイザリにより SSL/TLS は非影響で、未試験。run_poc.sh の初回実行はスクリプト自身のチェックの stderr 捕捉バグにより FAIL と誤報告した (計測値は同一); 修正後に再実行し、両方の出力をログに残した。
