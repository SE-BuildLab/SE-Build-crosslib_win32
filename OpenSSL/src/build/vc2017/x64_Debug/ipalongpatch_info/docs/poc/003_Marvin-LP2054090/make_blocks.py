#!/usr/bin/env python3
# Creates raw 256-byte "plaintext blocks" with deliberately broken PKCS#1 v1.5
# type-2 padding (to be RSA-encrypted with rsa_padding_mode:none) and a
# 1-byte-corrupted copy of a valid ciphertext.
# usage: python3 -I make_blocks.py <outdir> <ct_good.bin>
import os
import sys

outdir = sys.argv[1]
ct_good = open(sys.argv[2], "rb").read()
k = len(ct_good)  # modulus size in bytes (256 for RSA-2048)
msg = b"Hello Marvin"

def write(name, data):
    with open(os.path.join(outdir, name), "wb") as f:
        f.write(data)
    print("wrote %-22s %d bytes  first bytes: %s" % (name, len(data), data[:12].hex()))

# 1. valid ciphertext with its last byte flipped: the RSA decryption result is
#    an essentially random block -> padding check fails
bad = bytearray(ct_good)
bad[-1] ^= 0x01
write("ct_bad_flip.bin", bytes(bad))

# 2. block type 1 (0x00 0x01) instead of type 2 (0x00 0x02)
padlen = k - 3 - len(msg)
write("blk_bad_type1.bin", b"\x00\x01" + b"\xff" * padlen + b"\x00" + msg)

# 3. type 2 but no 0x00 separator between padding and message at all
write("blk_bad_nosep.bin", b"\x00\x02" + b"\x55" * (k - 2))

# 4. type 2 but only 3 bytes of padding (minimum is 8)
write("blk_bad_shortpad.bin", b"\x00\x02" + b"\xaa" * 3 + b"\x00" + msg + b"\x00" * (k - 6 - len(msg)))

# 5. first byte not 0x00
write("blk_bad_first.bin", b"\x01\x02" + b"\xbb" * (k - 2 - len(msg) - 1) + b"\x00" + msg)

# 6. a correctly padded block (control: must decrypt to msg in every build)
pad = bytes([0x11 + (i % 200) for i in range(k - 3 - len(msg))])  # nonzero bytes
write("blk_good_manual.bin", b"\x00\x02" + pad + b"\x00" + msg)
