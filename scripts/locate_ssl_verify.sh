#!/usr/bin/env bash
# locate_ssl_verify.sh — helper that runs the string-anchor recon used to locate
# ssl_verify_peer_cert in a stripped libflutter.so. It does NOT auto-identify the
# function; it surfaces the anchors so you can finish the job in radare2 following
# docs/LOCATING.md.
#
# Requires: radare2 (rabin2/r2). Extract libflutter.so for your target ABI first:
#   unzip -j app.apk "lib/<abi>/libflutter.so" -d .
#
# Usage: ./locate_ssl_verify.sh path/to/libflutter.so
set -euo pipefail
LIB="${1:?usage: $0 path/to/libflutter.so}"

command -v rabin2 >/dev/null || { echo "[!] radare2 not found (rabin2)"; exit 1; }

echo "=== [1] engine / Dart version (dictates whether prebuilt tools will match) ==="
strings -n 6 "$LIB" | grep -iE 'Dart VM version' | head -1 || echo "  (not found)"

echo
echo "=== [2] .text section (offset == vaddr on typical builds) ==="
rabin2 -S "$LIB" 2>/dev/null | awk 'NR==1 || /\.text/'

echo
echo "=== [3] BoringSSL source anchor (ssl_verify_peer_cert lives in handshake.cc) ==="
rabin2 -z "$LIB" 2>/dev/null | grep -iE 'handshake\.cc' | head

echo
echo "=== [4] X509 verify error strings (nearby cert-chain code) ==="
rabin2 -z "$LIB" 2>/dev/null | grep -iE 'self signed certificate|unable to get local issuer|certificate verify' | head

echo
echo "Next: open in radare2 and xref the handshake.cc string to the functions that use it,"
echo "then match the control-flow signature in docs/LOCATING.md:"
echo "  r2 -A $LIB"
echo "  [0x..]> / handshake.cc          # find the string"
echo "  [0x..]> axt @ <string_addr>     # who references it"
echo "  [0x..]> pdf @ <candidate_fcn>   # disassemble & compare to the signature"
