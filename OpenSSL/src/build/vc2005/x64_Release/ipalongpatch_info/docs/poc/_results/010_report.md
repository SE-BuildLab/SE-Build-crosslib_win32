# 010 / CVE-2025-68160 / BIO-f-linebuffer-heap-overflow

Log file / ログファイル: `20261102_121611_010of033_CVE-2025-68160_BIO-f-linebuffer-heap-overflow.log` (in /home/user/work/deliver/ipalongpatch_info/logs/)

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の観察)

`linebuffer_write()` (crypto/bio/bf_lbuf.c) passes a newline-free chunk larger than its 10240-byte `obuf` straight to the next BIO. If that BIO accepts only part of it (short write), the unpatched tail of the function does `if (inl > 0) { memcpy(&(ctx->obuf[ctx->obuf_len]), in, inl); ctx->obuf_len += inl; }` (line 198) without checking `inl <= obuf_size - obuf_len`, writing the whole remainder past the end of the heap buffer. Patch 010 replaces this with a loop that copies at most the free space and flushes `obuf` to the next BIO when it is full.

`linebuffer_write()` (crypto/bio/bf_lbuf.c) は 10240 バイトの `obuf` より大きい改行無しのデータ片を次段 BIO にそのまま渡す。次段が一部しか受け付けない (short write) と、未修正の関数末尾は `inl <= obuf_size - obuf_len` を確認せずに `if (inl > 0) { memcpy(&(ctx->obuf[ctx->obuf_len]), in, inl); ctx->obuf_len += inl; }` (198 行目) を実行し、残り全部をヒープバッファの末尾を越えて書き込む。パッチ 010 はこれを、空き容量分だけコピーし満杯なら `obuf` を次段へフラッシュするループに置き換える。

## PoC design / PoC の設計

`lbuf_poc.c`: a custom sink BIO (BIO_meth_new) accepting at most N bytes per write and recording everything; `BIO_f_linebuffer()` pushed on top; one `BIO_write()` of 40000 newline-free bytes, then `BIO_flush()`; the sink content is compared with the input. Cases 40000/1, 40000/10000, control 12000/4000, 100000/3. Regression mode writes lines/partial lines and checks the line-buffering semantics. Built for BASE-ASAN, PATCHED-ASAN, BASE (gdb/valgrind) and PATCHED.

`lbuf_poc.c`: 1 回の write で最大 N バイトだけ受け付け全内容を記録する独自シンク BIO (BIO_meth_new) の上に `BIO_f_linebuffer()` を push し、改行無し 40000 バイトを 1 回 `BIO_write()` して `BIO_flush()`、シンク内容を入力と比較する。ケース 40000/1、40000/10000、対照 12000/4000、100000/3。回帰モードは行・途中行を書き込み行バッファリングの意味を確認する。BASE-ASAN、PATCHED-ASAN、BASE (gdb/valgrind)、PATCHED 向けにビルド。

## Observed behaviour BEFORE the patch (evidence excerpts) / 修正前の挙動 (証拠の抜粋)

```
$ ./lbuf_poc_base_asan overflow 40000 1
==ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 39999
    #0 memcpy
    #1 linebuffer_write crypto/bio/bf_lbuf.c:198
    #2 bwrite_conv  #3 bio_write_intern  #4 BIO_write
0x... is located 0 bytes after 10240-byte region ... allocated by linebuffer_new bf_lbuf.c:66
$ ./lbuf_poc_base_asan overflow 40000 10000   -> WRITE of size 30000 (same region)
$ ./lbuf_poc_base_asan overflow 12000 4000    -> no error (8000-byte remainder fits)
$ ./lbuf_poc_base overflow 40000 1            -> Segmentation fault (exit 139) in realloc during BIO_flush
$ gdb ... break bf_lbuf.c:198
198   memcpy(&(ctx->obuf[ctx->obuf_len]), in, inl);
inl = 39999   ctx->obuf_len = 0   ctx->obuf_size = 10240   num = 1
$ valgrind ./lbuf_poc_base overflow 40000 1
Invalid write of size 1 ... by linebuffer_write (bf_lbuf.c:198) ... 0 bytes after a block of size 10,240
```

## Observed behaviour AFTER the patch / 修正後の挙動

```
$ ./lbuf_poc_patched_asan overflow 40000 1
  BIO_write returned 40000 / BIO_flush returned 1
  after flush: sink received 40000 bytes in 40000 write calls; content == input (OK)
  RESULT: all data delivered intact            (no ASan report; same for 40000/10000, 12000/4000, 100000/3)
$ valgrind --leak-check=full ./lbuf_poc_patched overflow 40000 1   -> clean, all data delivered
```

## Regression check / 回帰確認

Writes "hello ", "world\n", "second line\nthird", " line\n", "tail-without-newline" -> sink grows by 0, 12, 12, 11, 0 bytes; before flush the sink holds exactly the 35 bytes up to the last newline; after `BIO_flush()` all 55 bytes equal the input. Identical on BASE and PATCHED for sink chunk sizes 1, 7, 1000000. valgrind clean; patched `test/bio_memleak_test` ok 1-7.

"hello "、"world\n"、"second line\nthird"、" line\n"、"tail-without-newline" の書き込みでシンクは 0、12、12、11、0 バイトずつ増え、flush 前は最後の改行までの 35 バイトちょうど、`BIO_flush()` 後は 55 バイト全部が入力と一致。chunk 1、7、1000000 で BASE と PATCHED が同一。valgrind 問題なし; 修正済み `test/bio_memleak_test` ok 1〜7。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/010_CVE-2025-68160
BA=/home/user/work/base_asan; S=/home/user/work/src_1.1.1w/openssl-1.1.1w
PA=/home/user/work/patched/build-asan; PS=/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102
B=/home/user/work/base/openssl-1.1.1w
gcc -g -O0 -Wall -D_GNU_SOURCE -fsanitize=address -I$BA/include -I$S/include lbuf_poc.c -L$BA -lcrypto -Wl,-rpath,$BA -o lbuf_poc_base_asan
gcc -g -O0 -Wall -D_GNU_SOURCE -fsanitize=address -I$PA/include -I$PS/include lbuf_poc.c -L$PA -lcrypto -Wl,-rpath,$PA -o lbuf_poc_patched_asan
gcc -g -O0 -Wall -D_GNU_SOURCE -I$B/include lbuf_poc.c -L$B -lcrypto -Wl,-rpath,$B -o lbuf_poc_base
ASAN_OPTIONS=detect_leaks=0 ./lbuf_poc_base_asan overflow 40000 1      # heap-buffer-overflow WRITE of size 39999
ASAN_OPTIONS=detect_leaks=0 ./lbuf_poc_patched_asan overflow 40000 1   # all data delivered intact
gdb -q -batch -ex 'set breakpoint pending on' -ex 'break bf_lbuf.c:198' -ex run -ex 'print inl' -ex 'print ctx->obuf_size' --args ./lbuf_poc_base overflow 40000 1
./lbuf_poc_patched_asan regress 7                                      # line buffering behaves correctly
./run_poc.sh                                                           # everything, with verdict
```

## Limitations / notes / 制限事項・注記

BIO_f_linebuffer() is only used by applications that push it explicitly (not in the TLS path), so a custom short-writing sink BIO models the trigger. Crash location in the plain build depends on heap layout; ASan/valgrind give deterministic evidence. In 1.1.1w the buffer is 10240 bytes (not 4096 as the task hint said). The first run_poc.sh run had two script-side check bugs (gdb pending breakpoint, diff filter); fixed and re-run, both outputs kept in the log.

BIO_f_linebuffer() は明示的に push するアプリケーションのみが使う (TLS 経路では未使用) ため、short write する独自シンク BIO でトリガを模倣した。素のビルドのクラッシュ位置はヒープ配置依存で、決定的な証拠は ASan/valgrind。1.1.1w のバッファは 10240 バイト (課題ヒントの 4096 ではない)。run_poc.sh 初回はスクリプト側チェックの不具合 2 件 (gdb の pending ブレークポイント、diff のフィルタ); 修正して再実行し両出力をログに保持。
