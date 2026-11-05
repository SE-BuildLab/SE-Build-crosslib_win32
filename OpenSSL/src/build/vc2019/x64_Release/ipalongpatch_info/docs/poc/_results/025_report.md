# 025 of 033 — CVE-2026-45447 (PKCS7-verify-use-after-free)

Log file: `20261102_123854_025of033_CVE-2026-45447_PKCS7-verify-use-after-free.log`

Verdict / 判定: **PASS**

## Vulnerability mechanism (as observed in the code) / 脆弱性のメカニズム (コード上の確認)

crypto/pkcs7/pk7_doit.c PKCS7_dataInit(): 'for (i = 0; i < sk_X509_ALGOR_num(md_sk); i++) PKCS7_bio_add_digest(&out, ...)' creates the digest filters; with an empty digestAlgorithms SET out stays NULL and the function ends with 'if (out) BIO_push(out, bio); else out = bio; return out;' i.e. it returns the caller's BIO. crypto/pkcs7/pk7_smime.c PKCS7_verify() (1.1.1w): tmpin = indata for non-memory BIOs (a memory BIO with data is copied into a temporary BIO - the 'performance optimization'), p7bio = PKCS7_dataInit(p7, tmpin) == indata, and at 'err:' 'if (tmpin == indata) { if (indata) BIO_pop(p7bio); } BIO_free_all(p7bio);' frees indata (BIO_pop on a lone BIO does nothing). The caller (apps/smime.c:610 BIO_free(indata), or any application) then uses freed memory. The patch removes tmpin and the optimization (upstream 30adf6d2) and frees only the BIOs above indata (upstream 16aaeaab); it also adds the upstream regression test file and 80-test_cms.t case.

crypto/pkcs7/pk7_doit.c の PKCS7_dataInit(): 'for (i = 0; i < sk_X509_ALGOR_num(md_sk); i++) PKCS7_bio_add_digest(&out, ...)' がダイジェストフィルタを作るが、digestAlgorithms が空の SET だと out は NULL のままで、関数末尾の 'if (out) BIO_push(out, bio); else out = bio; return out;' により呼び出し側の BIO を返す。crypto/pkcs7/pk7_smime.c の PKCS7_verify() (1.1.1w): メモリ BIO 以外では tmpin = indata (データのあるメモリ BIO は一時 BIO にコピーされる —「性能最適化」)、p7bio = PKCS7_dataInit(p7, tmpin) == indata となり、'err:' の 'if (tmpin == indata) { if (indata) BIO_pop(p7bio); } BIO_free_all(p7bio);' が indata を解放する (単独 BIO への BIO_pop は何もしない)。呼び出し側 (apps/smime.c:610 の BIO_free(indata)、または任意のアプリ) は解放済みメモリを使う。パッチは tmpin と最適化を削除 (上流 30adf6d2) し、indata より上の BIO だけを解放する (上流 16aaeaab)。上流の回帰テストファイルと 80-test_cms.t のテストケースも追加する。

## PoC design / PoC の設計

good_detached.p7s: unpatched 'openssl smime -sign -in content.txt -signer smrsa1.pem -outform DER' (detached, SHA-256). make_bad.py parses the ContentInfo, checks the signedData OID, takes SignedData = [0].children[0], asserts children[1] is the SET and empties it. Triggers: 'openssl smime -verify -noverify -inform DER -in bad_detached.p7s -content content.txt -out /dev/null' and poc_verify.c (file BIO -> PKCS7_verify(PKCS7_NOVERIFY) -> BIO_reset/BIO_read -> BIO_free). run_poc.sh runs them on BASE (plus gdb, valgrind), BASE-ASAN, PATCHED, PATCHED-ASAN (plus valgrind), runs the upstream .eml test file on all builds, and performs the regression checks.

good_detached.p7s: 未修正の 'openssl smime -sign -in content.txt -signer smrsa1.pem -outform DER' (分離、SHA-256)。make_bad.py は ContentInfo を解析し signedData OID を確認、SignedData = [0].children[0] を取り、children[1] が SET であることを確認して空にする。発動経路: 'openssl smime -verify -noverify -inform DER -in bad_detached.p7s -content content.txt -out /dev/null' と poc_verify.c (ファイル BIO -> PKCS7_verify(PKCS7_NOVERIFY) -> BIO_reset/BIO_read -> BIO_free)。run_poc.sh はこれらを BASE (gdb、valgrind 付き)、BASE-ASAN、PATCHED、PATCHED-ASAN (valgrind 付き) で実行し、上流の .eml テストファイルを全ビルドで実行し、回帰確認を行う。

## Observed behaviour BEFORE the patch (evidence excerpts) / パッチ前の挙動 (証拠抜粋)

Unpatched 1.1.1w: 'openssl smime -verify ... -content content.txt' prints 'Verification failure' and then aborts with 'crypto/bio/bio_lib.c:123: OpenSSL internal error: refcount error' (exit 134) in the final BIO_free(indata); gdb: SIGABRT <- OPENSSL_die <- BIO_free (bio_lib.c:123) <- smime_main (apps/smime.c:610). valgrind: 'Invalid read of size 8 at BIO_free (bio_lib.c:117) by smime_main (smime.c:610) ... Address is 112 bytes inside a block of size 120 free'd at ... BIO_free (bio_lib.c:138) by BIO_free_all (bio_lib.c:691) by PKCS7_verify (pk7_smime.c:367) ... Block was alloc'd at ... BIO_new_file (bss_file.c:81) by smime_main (smime.c:464)'. The API PoC segfaults when it re-uses its BIO after PKCS7_verify() returned 0. BASE-ASAN: 'ERROR: AddressSanitizer: heap-use-after-free ... READ of size 8 ... #0 BIO_free bio_lib.c:117 #1 smime_main smime.c:610 ... freed by ... BIO_free_all ... PKCS7_verify pk7_smime.c:367 ... previously allocated by ... BIO_new_file bss_file.c:81' and, for the API PoC, in BIO_ctrl (BIO_reset) at poc_verify.c:36.

未修正 1.1.1w: 'openssl smime -verify ... -content content.txt' は 'Verification failure' を出した後、最後の BIO_free(indata) で 'crypto/bio/bio_lib.c:123: OpenSSL internal error: refcount error' により abort (exit 134)。gdb: SIGABRT <- OPENSSL_die <- BIO_free (bio_lib.c:123) <- smime_main (apps/smime.c:610)。valgrind: 'Invalid read of size 8 at BIO_free (bio_lib.c:117) by smime_main (smime.c:610) ... Address is 112 bytes inside a block of size 120 free'd at ... BIO_free (bio_lib.c:138) by BIO_free_all (bio_lib.c:691) by PKCS7_verify (pk7_smime.c:367) ... Block was alloc'd at ... BIO_new_file (bss_file.c:81) by smime_main (smime.c:464)'。API PoC は PKCS7_verify() が 0 を返した後に自身の BIO を再利用した時点で SEGV。BASE-ASAN: 'ERROR: AddressSanitizer: heap-use-after-free ... READ of size 8 ... #0 BIO_free bio_lib.c:117 #1 smime_main smime.c:610 ... freed by ... BIO_free_all ... PKCS7_verify pk7_smime.c:367 ... previously allocated by ... BIO_new_file bss_file.c:81'、API PoC では poc_verify.c:36 の BIO_ctrl (BIO_reset) で報告。

```
$ openssl smime -verify -noverify -inform DER -in bad_detached.p7s -content content.txt -out /dev/null
Verification failure
...:error:2107106C:PKCS7 routines:PKCS7_signatureVerify:unable to find message digest:crypto/pkcs7/pk7_doit.c:967:
...:error:21075069:PKCS7 routines:PKCS7_verify:signature failure:crypto/pkcs7/pk7_smime.c:353:
crypto/bio/bio_lib.c:123: OpenSSL internal error: refcount error
[exit status: 134]
---
==9628==ERROR: AddressSanitizer: heap-use-after-free on address 0x50c0000005f0 at pc ... bp ... sp ...
READ of size 8 at 0x50c0000005f0 thread T0
    #0 in BIO_free ../src_1.1.1w/openssl-1.1.1w/crypto/bio/bio_lib.c:117
    #1 in smime_main ../src_1.1.1w/openssl-1.1.1w/apps/smime.c:610
0x50c0000005f0 is located 112 bytes inside of 120-byte region [0x50c000000580,0x50c0000005f8)
freed by thread T0 here:
    #0 free
    #1 CRYPTO_free ../src_1.1.1w/openssl-1.1.1w/crypto/mem.c:312
    #2 BIO_free ../src_1.1.1w/openssl-1.1.1w/crypto/bio/bio_lib.c:138
    #3 BIO_free_all ../src_1.1.1w/openssl-1.1.1w/crypto/bio/bio_lib.c:691
    #4 PKCS7_verify ../src_1.1.1w/openssl-1.1.1w/crypto/pkcs7/pk7_smime.c:367
    #5 smime_main ../src_1.1.1w/openssl-1.1.1w/apps/smime.c:552
previously allocated by thread T0 here:
    ...
    #3 BIO_new ../src_1.1.1w/openssl-1.1.1w/crypto/bio/bio_lib.c:73
    #4 BIO_new_file ../src_1.1.1w/openssl-1.1.1w/crypto/bio/bss_file.c:81
    #5 smime_main ../src_1.1.1w/openssl-1.1.1w/apps/smime.c:464
```

## Observed behaviour AFTER the patch / パッチ後の挙動

Patched build (debug and ASan): 'openssl smime -verify ... -content' prints 'Verification failure' ('unable to find message digest' / 'signature failure') and exits with status 4 without any abort; the API PoC gets PKCS7_verify() == 0, then re-reads 63 bytes from its own BIO and frees it normally; ASan reports nothing and valgrind --leak-check=full reports no errors and no leaks (4/4 clean runs). The upstream .eml test file also exits 4 on PATCHED and PATCHED-ASAN (and, as expected for 1.1.1w, already failed cleanly on BASE because of the memory-BIO copy).

修正版 (debug と ASan): 'openssl smime -verify ... -content' は 'Verification failure' ('unable to find message digest' / 'signature failure') を出して exit 4 で終了し abort しない。API PoC は PKCS7_verify() == 0 の後、自身の BIO から 63 バイトを再読込して通常どおり解放できる。ASan の報告は無く、valgrind --leak-check=full もエラー・リーク無し (4/4 回クリーン)。上流の .eml テストファイルも PATCHED と PATCHED-ASAN で exit 4 (1.1.1w では予想どおり、メモリ BIO コピーのため BASE でも既に正常に失敗していた)。

```
$ ./poc_verify_patched bad_detached.p7s content.txt
[poc] content BIO 0x55e652c12480 (file BIO), calling PKCS7_verify(p7, NULL, store, indata, NULL, PKCS7_NOVERIFY) ...
...:error:2107106C:PKCS7 routines:PKCS7_signatureVerify:unable to find message digest:...pk7_doit.c:1001:
...:error:21075069:PKCS7 routines:PKCS7_verify:signature failure:...pk7_smime.c:394:
[poc] PKCS7_verify returned 0
[poc] application re-uses its BIO: BIO_reset + BIO_read ...
[poc] read 63 bytes: "Somewhat longer test..."
[poc] application frees its BIO: BIO_free(indata)
[poc] finished without crashing (PKCS7_verify result was 0)
[exit status: 1]
```

## Regression check / 回帰確認

Patched build: the genuine detached signature verifies with -content (file BIO) and through the API (PKCS7_verify returns 1, BIO re-used and freed, also under ASan); S/MIME sign + verify with -CAfile (memory-BIO content path, whose optimization was removed) succeeds with identical content; opaque signature and -text mode verify; a wrong content file is still rejected with 'digest failure'; valgrind --leak-check=full is clean for the detached and the S/MIME verification.

修正版: 正規の分離署名は -content (ファイル BIO) でも API 経由でも検証できる (PKCS7_verify が 1、BIO の再利用と解放、ASan 下も)。-CAfile 付きの S/MIME 署名 + 検証 (最適化が削除されたメモリ BIO 内容経路) は内容一致で成功。opaque 署名と -text モードも検証可。誤った内容ファイルは引き続き 'digest failure' で拒否。valgrind --leak-check=full は分離署名検証と S/MIME 検証でクリーン。

## How to reproduce manually (step-by-step commands a human can run) / 手動再現手順

```
cd /home/user/work/poc/025_CVE-2026-45447
BASE=/home/user/work/base/openssl-1.1.1w; PAT=/home/user/work/patched/build; SRC=/home/user/work/src_1.1.1w/openssl-1.1.1w
cp $SRC/test/smcont.txt content.txt
$BASE/util/shlib_wrap.sh $BASE/apps/openssl smime -sign -in content.txt -signer $SRC/test/smime-certs/smrsa1.pem -outform DER -out good_detached.p7s
python3 -I make_bad.py good_detached.p7s bad_detached.p7s     # digestAlgorithms -> empty SET
$BASE/util/shlib_wrap.sh $BASE/apps/openssl smime -verify -noverify -inform DER -in bad_detached.p7s -content content.txt -out /dev/null   # refcount error / abort
LD_LIBRARY_PATH=$BASE valgrind -q $BASE/apps/openssl smime -verify -noverify -inform DER -in bad_detached.p7s -content content.txt -out /dev/null   # Invalid read of freed BIO
ASAN_OPTIONS=detect_leaks=0 /home/user/work/base_asan/util/shlib_wrap.sh /home/user/work/base_asan/apps/openssl smime -verify -noverify -inform DER -in bad_detached.p7s -content content.txt -out /dev/null   # heap-use-after-free
./build.sh && ./poc_verify_base_asan bad_detached.p7s content.txt      # heap-use-after-free in BIO_ctrl
$PAT/util/shlib_wrap.sh $PAT/apps/openssl smime -verify -noverify -inform DER -in bad_detached.p7s -content content.txt -out /dev/null   # Verification failure, exit 4
./poc_verify_patched bad_detached.p7s content.txt ; ./poc_verify_patched good_detached.p7s content.txt
./run_poc.sh
```

## Limitations / notes / 制限事項・注記

On 1.1.1w the memory-BIO path (S/MIME content read by SMIME_read_PKCS7, including the upstream test file pkcs7-empty-digest-set.eml) is not exploitable because of the 1.1.1w memory-BIO copy; the demonstration therefore uses a file BIO (-content / BIO_new_file), which is exactly what the 1.1.1w code path exposes. The crash symptom on the non-sanitized debug build is an OPENSSL_die('refcount error') abort because the debug build has refcount assertions; release builds would show silent memory corruption or a double free instead.

1.1.1w ではメモリ BIO 経路 (SMIME_read_PKCS7 が読む S/MIME 内容、上流のテストファイル pkcs7-empty-digest-set.eml を含む) は 1.1.1w のメモリ BIO コピーのため悪用できない。そのため実証はファイル BIO (-content / BIO_new_file) を使った。これは 1.1.1w のコード経路がまさに露出しているものである。非サニタイザの debug ビルドでのクラッシュ症状は、debug ビルドが refcount アサーションを持つための OPENSSL_die('refcount error') abort であり、リリースビルドでは静かなメモリ破壊や double free になる。
