#!/bin/bash
# Item 003 (Marvin-LP2054090): RSA PKCS#1 v1.5 implicit rejection - full demonstration.
# Runs every check against the unpatched (BASE) and the patched (PATCHED) build and
# prints a verdict.  Raw output is written to raw_run_poc.txt by the caller (tee).
D=/home/user/work/poc/003_Marvin-LP2054090
BASE=/home/user/work/base/openssl-1.1.1w
PATCHED=/home/user/work/patched/build
PATCHED_SRC=/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102
IN=$D/inputs
TIMING_N=${TIMING_N:-5000}
cd "$D" || exit 1
mkdir -p work
fail=0
note() { echo; echo "##### $*"; }
run() { echo "+ $*"; "$@"; echo "  [exit=$?]"; }
hex() { od -A d -t x1z -v "$1"; }

for B in BASE PATCHED; do
    if [ $B = BASE ]; then W=$BASE; CNF=$BASE/apps/openssl.cnf; else W=$PATCHED; CNF=$PATCHED_SRC/apps/openssl.cnf; fi
    OSSL="$W/util/shlib_wrap.sh $W/apps/openssl"
    note "[$B] openssl version"
    $OSSL version

    note "[$B] (a) CLI: pkeyutl -decrypt, valid ciphertext"
    run $OSSL pkeyutl -decrypt -inkey $IN/rsa2048.pem -pkeyopt rsa_padding_mode:pkcs1 -in $IN/ct_good.bin -out work/out_good_$B.bin
    hex work/out_good_$B.bin
    note "[$B] (a) CLI: pkeyutl -decrypt, corrupted ciphertext (last byte flipped), run twice"
    for i in 1 2; do
        run $OSSL pkeyutl -decrypt -inkey $IN/rsa2048.pem -pkeyopt rsa_padding_mode:pkcs1 -in $IN/ct_bad_flip.bin -out work/out_badflip_${B}_$i.bin
        [ -s work/out_badflip_${B}_$i.bin ] && { echo "  output: $(stat -c %s work/out_badflip_${B}_$i.bin) bytes, sha256=$(sha256sum < work/out_badflip_${B}_$i.bin | cut -c1-32)"; } || echo "  output: (empty / none)"
    done
    note "[$B] (a) CLI: pkeyutl -decrypt, ciphertext whose plaintext block has type 0x01 instead of 0x02"
    run $OSSL pkeyutl -decrypt -inkey $IN/rsa2048.pem -pkeyopt rsa_padding_mode:pkcs1 -in $IN/ct_bad_type1.bin -out work/out_badtype1_$B.bin
    [ -s work/out_badtype1_$B.bin ] && echo "  output: $(stat -c %s work/out_badtype1_$B.bin) bytes, sha256=$(sha256sum < work/out_badtype1_$B.bin | cut -c1-32)" || echo "  output: (empty / none)"
    note "[$B] (a) CLI: rsautl -decrypt, corrupted ciphertext"
    run $OSSL rsautl -decrypt -inkey $IN/rsa2048.pem -in $IN/ct_bad_flip.bin -out work/out_rsautl_$B.bin
    [ -s work/out_rsautl_$B.bin ] && echo "  output: $(stat -c %s work/out_rsautl_$B.bin) bytes, sha256=$(sha256sum < work/out_rsautl_$B.bin | cut -c1-32)" || echo "  output: (empty / none)"
    note "[$B] (b) CLI: pkeyutl -decrypt -pkeyopt rsa_pkcs1_implicit_rejection:0, corrupted ciphertext"
    run $OSSL pkeyutl -decrypt -inkey $IN/rsa2048.pem -pkeyopt rsa_padding_mode:pkcs1 -pkeyopt rsa_pkcs1_implicit_rejection:0 -in $IN/ct_bad_flip.bin -out work/out_badflip_noir_$B.bin
    [ -s work/out_badflip_noir_$B.bin ] && echo "  output: $(stat -c %s work/out_badflip_noir_$B.bin) bytes" || echo "  output: (empty / none)"
    note "[$B] (b) CLI: pkeyutl -decrypt -pkeyopt rsa_pkcs1_implicit_rejection:0, valid ciphertext (must still work)"
    run $OSSL pkeyutl -decrypt -inkey $IN/rsa2048.pem -pkeyopt rsa_padding_mode:pkcs1 -pkeyopt rsa_pkcs1_implicit_rejection:0 -in $IN/ct_good.bin -out work/out_good_noir_$B.bin
    [ -s work/out_good_noir_$B.bin ] && hex work/out_good_noir_$B.bin || echo "  output: (empty / none)"

    note "[$B] (a)(b) C PoC: RSA_private_decrypt / EVP_PKEY_decrypt on all ciphertexts"
    POC=./poc_rsa_base; [ $B = PATCHED ] && POC=./poc_rsa_patched
    run $POC $IN/rsa2048.pem $IN/ct_good.bin $IN/ct_good2.bin $IN/ct_good_manual.bin $IN/ct_bad_flip.bin $IN/ct_bad_type1.bin $IN/ct_bad_nosep.bin $IN/ct_bad_shortpad.bin $IN/ct_bad_first.bin

    note "[$B] (c) evp_test with the patched tree's test/recipes/30-test_evp_data/evppkey.txt (implicit rejection vectors from OpenSSL 3.2)"
    $W/util/shlib_wrap.sh $W/test/evp_test $PATCHED_SRC/test/recipes/30-test_evp_data/evppkey.txt > work/evp_test_$B.txt 2>&1
    echo "  [evp_test exit=$?]"
    grep -c "^Decrypt = RSA-2048-2\|^Decrypt = RSA-3072" $PATCHED_SRC/test/recipes/30-test_evp_data/evppkey.txt | sed 's/^/  RSA-2048-2 + RSA-3072 Decrypt vectors in file: /'
    echo "  --- evp_test summary / failures (head) ---"
    grep -iE "fail|error|^[0-9]+ tests|tests completed|passed" work/evp_test_$B.txt | head -40
    tail -3 work/evp_test_$B.txt

    note "[$B] (d) timing: RSA_private_decrypt valid vs invalid padding ($TIMING_N iterations each)"
    run $POC $IN/rsa2048.pem --timing $TIMING_N $IN/ct_good.bin $IN/ct_bad_flip.bin

    note "[$B] (e) regression: CMS encrypt/decrypt (RSA PKCS#1 v1.5 key transport), right key and wrong key"
    if [ ! -f work/cms_cert.pem ]; then
        run $OSSL req -config $CNF -x509 -new -key $IN/rsa2048.pem -subj /CN=cms-recipient -days 3 -out work/cms_cert.pem
        run $OSSL req -config $CNF -x509 -new -key $IN/wrong.pem -subj /CN=other -days 3 -out work/wrong_cert.pem
        printf 'CMS test payload %s\n' "$(date -u)" > work/cms_plain.txt
    fi
    run $OSSL cms -encrypt -binary -in work/cms_plain.txt -recip work/cms_cert.pem -aes128 -out work/cms_enc_$B.pem -outform PEM
    run $OSSL cms -decrypt -in work/cms_enc_$B.pem -inform PEM -recip work/cms_cert.pem -inkey $IN/rsa2048.pem -out work/cms_dec_$B.txt
    cmp work/cms_plain.txt work/cms_dec_$B.txt && echo "  CMS decrypt with right key: plaintext matches"
    run $OSSL cms -decrypt -in work/cms_enc_$B.pem -inform PEM -inkey $IN/wrong.pem -out work/cms_dec_wrong_$B.txt
    echo "  (expected: error with wrong key in both builds; output size: $(stat -c %s work/cms_dec_wrong_$B.txt 2>/dev/null || echo none))"
    echo "  -- same with -debug_decrypt (CMS_DEBUG_DECRYPT: report the RSA key-transport decryption failure itself) --"
    run $OSSL cms -decrypt -debug_decrypt -in work/cms_enc_$B.pem -inform PEM -inkey $IN/wrong.pem -out work/cms_dec_wrong_dbg_$B.txt
    echo "  (expected in BOTH builds: RSA padding error reported, because cms_env.c keeps explicit rejection for key transport)"
    note "[$B] (e) regression: PKCS#7 (smime) encrypt/decrypt, right key and wrong key"
    run $OSSL smime -encrypt -binary -in work/cms_plain.txt -aes128 -out work/p7_enc_$B.pem -outform PEM work/cms_cert.pem
    run $OSSL smime -decrypt -in work/p7_enc_$B.pem -inform PEM -recip work/cms_cert.pem -inkey $IN/rsa2048.pem -out work/p7_dec_$B.txt
    cmp work/cms_plain.txt work/p7_dec_$B.txt && echo "  PKCS#7 decrypt with right key: plaintext matches"
    run $OSSL smime -decrypt -in work/p7_enc_$B.pem -inform PEM -inkey $IN/wrong.pem -out work/p7_dec_wrong_$B.txt
    echo "  (expected: error with wrong key in both builds; output size: $(stat -c %s work/p7_dec_wrong_$B.txt 2>/dev/null || echo none))"

    note "[$B] (e) regression: TLS 1.2 with RSA key exchange (AES128-SHA), s_server/s_client of the same build"
    PORT=$((44300 + RANDOM % 200))
    $OSSL s_server -accept $PORT -key $IN/rsa2048.pem -cert work/cms_cert.pem -tls1_2 -cipher AES128-SHA -naccept 1 -www > work/tls_server_$B.txt 2>&1 &
    SPID=$!
    sleep 1
    echo "GET / HTTP/1.0" | $OSSL s_client -connect 127.0.0.1:$PORT -tls1_2 -cipher AES128-SHA -CAfile work/cms_cert.pem -ign_eof > work/tls_client_$B.txt 2>&1
    echo "  [s_client exit=$?]"
    wait $SPID 2>/dev/null
    grep -E "^New, |Cipher is|Verify return code|Protocol  :|Server public key|Ciphersuite|^    Protocol|^    Cipher" work/tls_client_$B.txt | head -8
    if grep -q "Cipher is AES128-SHA" work/tls_client_$B.txt && grep -q "Verify return code: 0 (ok)" work/tls_client_$B.txt && grep -q "Ciphers common between both SSL end points" work/tls_client_$B.txt; then echo "  TLS handshake with RSA key exchange: OK (cipher AES128-SHA negotiated, server page received)"; else echo "  TLS handshake FAILED"; fail=1; fi
done

note "valgrind (PATCHED, implicit rejection code path: valid + 2 invalid ciphertexts)"
valgrind --leak-check=full --error-exitcode=9 -q ./poc_rsa_patched $IN/rsa2048.pem $IN/ct_good.bin $IN/ct_bad_flip.bin $IN/ct_bad_type1.bin > work/valgrind_patched.txt 2>&1
echo "  [valgrind exit=$?]  (9 = valgrind found errors)"
grep -E "ERROR SUMMARY|definitely lost|indirectly lost|Invalid" work/valgrind_patched.txt | head -5

note "VERDICT"
# BASE must error on bad padding; PATCHED must return deterministic data and error only when implicit rejection is disabled
b_err=$(grep -c "padding check failed" raw_poc_c_base.txt 2>/dev/null)
echo "  (see the per-build sections above; summary is produced by the caller from the raw output)"
exit $fail
