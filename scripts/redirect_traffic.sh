#!/usr/bin/env bash
# redirect_traffic.sh — force a Flutter app's HTTPS through your intercepting proxy.
#
# Flutter ignores the Android system HTTP proxy, so even with TLS validation
# disabled the traffic never reaches your proxy. This installs a scoped iptables
# DNAT rule (device must be rooted) that redirects the app's outbound :443 to your
# proxy's INVISIBLE/transparent listener. Combine with flutter_unpin.py (TLS bypass).
#
# For AUTHORIZED testing on a device/emulator you control.
#
# Usage:
#   ./redirect_traffic.sh add <package> <proxy_host:port>     # e.g. 10.0.2.2:8083
#   ./redirect_traffic.sh del <package> <proxy_host:port>
#   ./redirect_traffic.sh status
#
# Notes:
#   * Your proxy listener must have "invisible/transparent proxying" enabled and
#     listen on all interfaces (Burp: Proxy > Options > Request handling).
#   * Emulator: proxy_host is 10.0.2.2 (AVD) or 10.0.3.2 (Genymotion). Physical
#     device: the LAN IP of your proxy machine (allow the port through its firewall).
set -euo pipefail

ACTION="${1:-}"; PKG="${2:-}"; PROXY="${3:-}"

uid_of() {
  adb shell dumpsys package "$1" 2>/dev/null | grep -m1 -oE 'userId=[0-9]+' | grep -oE '[0-9]+'
}

case "$ACTION" in
  add|del)
    [ -z "$PKG" ] || [ -z "$PROXY" ] && { echo "usage: $0 $ACTION <package> <host:port>"; exit 1; }
    PROXY_HOST="${PROXY%%:*}"
    UID_APP="$(uid_of "$PKG")"
    [ -z "$UID_APP" ] && { echo "[!] could not resolve UID for $PKG (installed?)"; exit 1; }
    OP=$([ "$ACTION" = add ] && echo -A || echo -D)
    RULE="OUTPUT -p tcp --dport 443 -m owner --uid-owner $UID_APP ! -d $PROXY_HOST -j DNAT --to-destination $PROXY"
    echo "[*] iptables -t nat $OP $RULE"
    adb shell "su -c 'iptables -t nat $OP $RULE'"
    echo "[+] done ($ACTION). App UID=$UID_APP -> $PROXY"
    ;;
  status)
    echo "[*] nat OUTPUT chain:"
    adb shell "su -c 'iptables -t nat -L OUTPUT -n -v'"
    ;;
  *)
    echo "usage:"
    echo "  $0 add <package> <host:port>"
    echo "  $0 del <package> <host:port>"
    echo "  $0 status"
    exit 1
    ;;
esac
