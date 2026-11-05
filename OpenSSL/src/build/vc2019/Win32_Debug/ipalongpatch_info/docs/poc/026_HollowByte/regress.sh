#!/bin/bash
# Regression for item 026: (a) normal TLS1.2/TLS1.3 handshakes, (b) a certificate chain
# larger than one TLS record (Certificate message > 16384 bytes) received by the patched client.
set -u
PB=$1; BB=$2; PORT=$3
SRC=/home/user/work/src_1.1.1w/openssl-1.1.1w
CERT=$SRC/test/certs/servercert.pem; KEY=$SRC/test/certs/serverkey.pem
OUT=/home/user/work/poc/026_HollowByte/out
CHAIN=$OUT/bigchain.pem
# build a chain file from 24 test certificates (content irrelevant, size matters)
: > "$CHAIN"
for f in $(ls $SRC/test/certs/*-cert.pem | head -24); do cat "$f" >> "$CHAIN"; done
derbytes=0
for f in $(ls $SRC/test/certs/*-cert.pem | head -24); do
    n=$($PB/util/shlib_wrap.sh $PB/apps/openssl x509 -in "$f" -outform DER 2>/dev/null | wc -c); derbytes=$((derbytes + n)); done
echo "chain file: $(grep -c BEGIN "$CHAIN") certificates, $derbytes bytes of DER in total (> 16384 => Certificate message spans several records)"
pass=1
run_case() { # label server_build client_build proto extra_server_args
    local label=$1 sb=$2 cb=$3 proto=$4; shift 4
    $sb/util/shlib_wrap.sh $sb/apps/openssl s_server -accept $PORT -cert $CERT -key $KEY -www "$@" > $OUT/regress_server_$label.txt 2>&1 &
    local spid=$!; sleep 0.7
    echo -e "GET / HTTP/1.0\r\n\r\n" | $cb/util/shlib_wrap.sh $cb/apps/openssl s_client -connect 127.0.0.1:$PORT $proto -msg -ign_eof > $OUT/regress_client_$label.txt 2>&1
    kill $spid 2>/dev/null; wait $spid 2>/dev/null
    local http=$(grep -c "HTTP/1.0 200 ok" $OUT/regress_client_$label.txt)
    local ver=$(grep -oE "^(New|Reused), [A-Za-z0-9.]+, Cipher is [A-Z0-9_-]+" $OUT/regress_client_$label.txt | head -1)
    local certmsg=$(grep -E "<<< .*Handshake \[length [0-9a-f]+\], Certificate$" $OUT/regress_client_$label.txt | head -1)
    local hex=$(echo "$certmsg" | grep -oE "length [0-9a-f]+" | cut -d' ' -f2); local certlen=""
    [ -n "$hex" ] && certlen=$((16#$hex))
    echo "[$label] $ver; HTTP 200: $http; Certificate handshake message: ${certlen:-?} bytes"
    [ "$http" = 1 ] || pass=0
    echo "$certlen"
}
echo "(a) normal handshakes, patched server + patched client"
run_case tls12_small $PB $PB -tls1_2 | head -1
run_case tls13_small $PB $PB -tls1_3 | head -1
echo "(b) big chain: patched client receiving a Certificate message > 16 KiB (multi-record)"
l1=$(run_case tls12_bigchain_pp $PB $PB -tls1_2 -cert_chain $CHAIN | tee /dev/stderr | tail -1)
l2=$(run_case tls13_bigchain_pp $PB $PB -tls1_3 -cert_chain $CHAIN | tee /dev/stderr | tail -1)
l3=$(run_case tls12_bigchain_bp $BB $PB -tls1_2 -cert_chain $CHAIN | tee /dev/stderr | tail -1)
echo "(c) big chain: patched server, unpatched client (interoperability)"
l4=$(run_case tls13_bigchain_pb $PB $BB -tls1_3 -cert_chain $CHAIN | tee /dev/stderr | tail -1)
for l in "$l1" "$l2" "$l3" "$l4"; do if [ -z "$l" ] || [ "$l" -le 16384 ]; then pass=0; fi; done
echo "Certificate message sizes seen by the clients (TLS1.2 p/p, TLS1.3 p/p, TLS1.2 base-server/patched-client, TLS1.3 patched-server/base-client): $l1 $l2 $l3 $l4 bytes"
[ "$pass" = 1 ] && echo "REGRESSION: PASS" || echo "REGRESSION: FAIL"
