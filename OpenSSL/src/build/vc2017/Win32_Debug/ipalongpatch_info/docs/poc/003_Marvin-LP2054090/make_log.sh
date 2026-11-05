#!/bin/bash
# Assembles the formal evidence log for item 003 from the narrative files and the raw captures.
# UTF-8 with BOM, LF line endings.
D=/home/user/work/poc/003_Marvin-LP2054090
START=$(cat $D/START_JST.txt); END=$(cat $D/END_JST.txt)
fmt() { echo "${1:0:4}/${1:4:2}/${1:6:2} ${1:9:2}:${1:11:2}:${1:13:2}"; }
secs() { date -u -d "${1:0:4}-${1:4:2}-${1:6:2} ${1:9:2}:${1:11:2}:${1:13:2}" +%s; }
DUR=$(( $(secs $END) - $(secs $START) ))
DURS=$(printf '%02d:%02d:%02d' $((DUR/3600)) $((DUR%3600/60)) $((DUR%60)))
LOG=/home/user/work/deliver/ipalongpatch_info/logs/${START}_003of033_Marvin-LP2054090_Marvin-RSA-PKCS1-implicit-reject.log
mkdir -p "$(dirname "$LOG")"
{
printf '\xEF\xBB\xBF'
cat /home/user/work/poc/ENV_HEADER.txt
echo
echo "Verification start: $(fmt $START) (JST)"
echo
echo "Item 003 of 033: Marvin-LP2054090 / Marvin-RSA-PKCS1-implicit-reject"
echo "Patch file: /home/user/work/deliver/ipalongpatch_info/patch_files_for_each_cve/openssl-1.1.1w_ipalongpatch_003of033_Marvin-LP2054090_Marvin-RSA-PKCS1-implicit-reject.patch"
echo "Ubuntu reference: /home/user/work/debian_esm6/debian/patches/openssl-1.1.1-pkcs1-implicit-rejection.patch (USN-6663-1, LP: #2054090)"
echo "PoC directory: $D"
echo
cat $D/log_narrative_c.txt
echo
echo "=== d. Commands executed and raw output / 実行したコマンドと生の出力 ==="
echo
echo "[EN] Builds: BASE = /home/user/work/base/openssl-1.1.1w (unpatched 1.1.1w, debug), PATCHED = /home/user/work/patched/build (patched, debug). Tools: util/shlib_wrap.sh + apps/openssl of each build, test/evp_test of each build, gcc 13.3.0, valgrind 3.22.0, python3 -I."
echo "[JA] ビルド: BASE = /home/user/work/base/openssl-1.1.1w (未パッチ 1.1.1w、デバッグ)、PATCHED = /home/user/work/patched/build (パッチ版、デバッグ)。ツール: 各ビルドの util/shlib_wrap.sh + apps/openssl、各ビルドの test/evp_test、gcc 13.3.0、valgrind 3.22.0、python3 -I。"
echo
echo "--- d-1. Test input generation: $D/gen_inputs.sh (+ make_blocks.py) ---"
echo "\$ cat gen_inputs.sh"
cat $D/gen_inputs.sh
echo
echo "\$ ./gen_inputs.sh"
cat $D/raw_gen_inputs.txt
echo
echo "--- d-2. C PoC $D/poc_rsa.c, compiled for each build ---"
echo "\$ gcc -g -O0 -Wall -I/home/user/work/base/openssl-1.1.1w/include poc_rsa.c -L/home/user/work/base/openssl-1.1.1w -lssl -lcrypto -Wl,-rpath,/home/user/work/base/openssl-1.1.1w -o poc_rsa_base"
echo "\$ gcc -g -O0 -Wall -I/home/user/work/patched/build/include -I/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102/include poc_rsa.c -L/home/user/work/patched/build -lssl -lcrypto -Wl,-rpath,/home/user/work/patched/build -o poc_rsa_patched"
echo "(exact behaviour of each API call is printed by the program; see d-5)"
echo
echo "--- d-3. First attempt of run_poc.sh (kept as history) / run_poc.sh の初回試行 (履歴) ---"
echo "[EN] Problems found and fixed afterwards: 'xxd' is not installed (hex dump replaced by od), 'openssl req -x509' needs -config <build>/apps/openssl.cnf in this environment (the certificate was therefore missing and the CMS/PKCS#7/TLS checks could not run), and the TLS success check was too permissive. Excerpt:"
echo "[JA] 判明し後で修正した問題: 'xxd' が未インストール (od による hex ダンプに置換)、この環境では 'openssl req -x509' に -config <build>/apps/openssl.cnf が必要 (証明書が作られず CMS/PKCS#7/TLS の確認が実行できなかった)、TLS 成功判定が緩すぎた。抜粋:"
grep -n "xxd: command not found\|unable to load certificate\|s_client exit\|TLS handshake" $D/raw_run_poc_attempt1.txt | head -12
echo
echo "--- d-4. Second attempt (kept as history) / 2 回目の試行 (履歴) ---"
echo "[EN] CMS/PKCS#7 decrypted output differed from the input at the last byte because 'cms/smime -encrypt' without -binary converts the text to canonical CRLF form; -binary was added, and 'cms -decrypt -debug_decrypt' with the wrong key was added to exercise the key-transport error path. Excerpt:"
echo "[JA] -binary 無しの 'cms/smime -encrypt' はテキストを正規化 CRLF 形式に変換するため、CMS/PKCS#7 の復号出力が入力と最終バイトで不一致になった。-binary を追加し、鍵転送のエラー経路を確認するため誤った鍵での 'cms -decrypt -debug_decrypt' を追加した。抜粋:"
grep -n "differ\|plaintext matches" $D/raw_run_poc_attempt2.txt | head -8
echo
echo "--- d-5. Final run: \$ TIMING_N=5000 ./run_poc.sh  (complete raw output, $D/raw_run_poc.txt) ---"
echo "\$ cat run_poc.sh"
cat $D/run_poc.sh
echo
echo "\$ TIMING_N=5000 ./run_poc.sh"
cat $D/raw_run_poc.txt
echo
echo "--- d-6. valgrind on the patched decryption path (complete, $D/raw_valgrind_patched.txt) ---"
echo "\$ valgrind --leak-check=full ./poc_rsa_patched inputs/rsa2048.pem inputs/ct_good.bin inputs/ct_bad_flip.bin inputs/ct_bad_type1.bin"
cat $D/raw_valgrind_patched.txt
echo
cat $D/log_narrative_efg.txt
echo
echo "--- key excerpts (BASE) / 主要な抜粋 (BASE) ---"
sed -n '/##### \[BASE\] (a) CLI: pkeyutl -decrypt, corrupted/,/##### \[BASE\] (a) CLI: pkeyutl -decrypt, ciphertext whose/p' $D/raw_run_poc.txt | grep -v "^#####.*whose"
grep "Completed 1499 tests" $D/raw_run_poc.txt | head -1
grep -A3 "^Ciphertext file: .*ct_bad_flip" $D/raw_poc_c_base.txt | head -4
echo
echo "--- key excerpts (PATCHED) / 主要な抜粋 (PATCHED) ---"
sed -n '/##### \[PATCHED\] (a) CLI: pkeyutl -decrypt, corrupted/,/##### \[PATCHED\] (a) CLI: pkeyutl -decrypt, ciphertext whose/p' $D/raw_run_poc.txt | grep -v "^#####.*whose"
grep "Completed 1499 tests" $D/raw_run_poc.txt | tail -1
grep -A3 "^Ciphertext file: .*ct_bad_flip" $D/raw_poc_c_patched.txt | head -4
echo
echo "Verification end: $(fmt $END) (JST)"
echo "Duration: $DURS"
echo
echo "Verdict: PASS"
echo "[EN] The unpatched build exposes the PKCS#1 v1.5 padding oracle through its API (error return, no output, 33 failing OpenSSL 3.2 vectors); the patched build implements implicit rejection exactly like OpenSSL 3.2 (deterministic synthetic messages, all 3.2 vectors pass, opt-out controls work), and CMS/PKCS#7/TLS RSA usage shows no regression (CMS/PKCS#7 deliberately keep the explicit error). Timing differences were not observable in either build on this VM; the removed oracle is the API-level one."
echo "[JA] 未パッチ版は PKCS#1 v1.5 のパディングオラクルを API を通じて露出している (エラー戻り・出力無し・OpenSSL 3.2 ベクタ 33 件が不合格)。パッチ版は OpenSSL 3.2 と同一の implicit rejection を実装しており (決定的な合成メッセージ、3.2 ベクタ全件合格、無効化オプションも動作)、CMS/PKCS#7/TLS の RSA 利用に回帰は無い (CMS/PKCS#7 は意図的に明示的エラーを維持)。タイミング差はこの VM ではいずれのビルドでも観測されなかった。除去されたオラクルは API レベルのものである。"
} | sed 's/\r//g' > "$LOG"
echo "written: $LOG ($(wc -c < "$LOG") bytes)"
head -c 3 "$LOG" | od -A n -t x1
file "$LOG"
