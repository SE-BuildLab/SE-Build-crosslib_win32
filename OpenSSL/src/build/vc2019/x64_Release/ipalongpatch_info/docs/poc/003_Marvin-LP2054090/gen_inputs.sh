#!/bin/bash
# Generates the RSA key and the test ciphertexts for item 003.
# The key / ciphertexts are build independent; the unpatched (BASE) build is
# used to create them (encryption is not affected by the patch).
set -e
D=/home/user/work/poc/003_Marvin-LP2054090
BASE=/home/user/work/base/openssl-1.1.1w
OSSL="$BASE/util/shlib_wrap.sh $BASE/apps/openssl"
cd "$D"
mkdir -p inputs
cd inputs
echo "+ generating RSA-2048 key (rsa2048.pem / rsa2048_pub.pem) and a second, unrelated key (wrong.pem)"
$OSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa2048.pem 2>/dev/null
$OSSL pkey -in rsa2048.pem -pubout -out rsa2048_pub.pem
$OSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out wrong.pem 2>/dev/null
printf 'Hello Marvin' > msg.txt
echo "+ ct_good.bin  : PKCS#1 v1.5 encryption of 'Hello Marvin' (random padding)"
$OSSL pkeyutl -encrypt -pubin -inkey rsa2048_pub.pem -pkeyopt rsa_padding_mode:pkcs1 -in msg.txt -out ct_good.bin
echo "+ ct_good2.bin : second PKCS#1 v1.5 encryption of the same message (different random padding)"
$OSSL pkeyutl -encrypt -pubin -inkey rsa2048_pub.pem -pkeyopt rsa_padding_mode:pkcs1 -in msg.txt -out ct_good2.bin
echo "+ crafting raw blocks with broken padding (python3 -I make_blocks.py)"
python3 -I "$D/make_blocks.py" . ct_good.bin
for b in blk_bad_type1 blk_bad_nosep blk_bad_shortpad blk_bad_first blk_good_manual; do
    # raw RSA (no padding) encryption of the crafted block -> ciphertext whose
    # decryption yields exactly that block
    $OSSL pkeyutl -encrypt -pubin -inkey rsa2048_pub.pem -pkeyopt rsa_padding_mode:none -in $b.bin -out ct_${b#blk_}.bin
    echo "+ ct_${b#blk_}.bin : raw-RSA encryption of $b.bin"
done
ls -la
sha256sum ct_*.bin
