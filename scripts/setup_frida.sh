#!/usr/bin/env bash
# setup_frida.sh — download the matching frida-server, push it to the device, and start it.
# For AUTHORIZED testing on a device/emulator you control (root required).
#
# Usage:
#   ./setup_frida.sh <frida-version>
#   FRIDA_VERSION=17.15.2 ./setup_frida.sh
#
# Pick a frida-server version that matches your host frida (`frida --version`).
set -euo pipefail

FRIDA_VERSION="${1:-${FRIDA_VERSION:-}}"
if [ -z "$FRIDA_VERSION" ]; then
  if command -v frida >/dev/null 2>&1; then
    FRIDA_VERSION="$(frida --version | tr -d '[:space:]')"
    echo "[*] no version given; matching host frida = $FRIDA_VERSION"
  else
    echo "[!] pass a frida-server version, e.g. ./setup_frida.sh 17.15.2"; exit 1
  fi
fi

# Map Android ABI -> frida-server arch label
ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '[:space:]')"
case "$ABI" in
  arm64-v8a) ARCH=arm64 ;;
  armeabi-v7a) ARCH=arm ;;
  x86_64) ARCH=x86_64 ;;
  x86) ARCH=x86 ;;
  *) echo "[!] unknown ABI: $ABI"; exit 1 ;;
esac

FNAME="frida-server-${FRIDA_VERSION}-android-${ARCH}"
URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FNAME}.xz"
TMP="$(mktemp -d)"

echo "[*] device ABI=$ABI -> arch=$ARCH"
echo "[*] downloading $URL"
curl -fsSL "$URL" -o "$TMP/fs.xz"
xz -d "$TMP/fs.xz"

echo "[*] pushing frida-server to /data/local/tmp/"
adb push "$TMP/fs" /data/local/tmp/frida-server >/dev/null
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"

# kill any old instance, then start detached
adb shell "su -c 'pkill -f frida-server || true'"
adb shell "su -c 'nohup /data/local/tmp/frida-server >/data/local/tmp/frida.log 2>&1 &'"
sleep 2

if adb shell "ps -A" | grep -q frida-server; then
  echo "[+] frida-server running on device."
  echo "    verify from host:  frida-ps -U | head"
else
  echo "[!] frida-server did not start; check /data/local/tmp/frida.log"; exit 1
fi
rm -rf "$TMP"
