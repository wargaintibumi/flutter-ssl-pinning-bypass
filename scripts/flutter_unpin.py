#!/usr/bin/env python3
"""
flutter_unpin.py — disable Flutter (BoringSSL) TLS certificate validation
by neutralizing ssl_verify_peer_cert in libflutter.so.

Works when off-the-shelf pattern databases (reFlutter / NVISO) are too old for
the target's Flutter engine: you supply either the function OFFSET (found with
the radare2 recipe in docs/LOCATING.md) or a byte PATTERN, and this tool forces
ssl_verify_peer_cert to always return ssl_verify_ok (0).

For AUTHORIZED security testing only.

Examples
--------
  # Attach to a running app and hook by offset (arch-independent, reverts on exit)
  python flutter_unpin.py -p com.example.app --offset 0x844753 --mode attach

  # Spawn the app and locate the function by byte pattern
  python flutter_unpin.py -p com.example.app --pattern "55 41 57 41 56 ?? ..." --mode spawn

  # Persistent in-memory patch (survives Frida detaching) by offset
  python flutter_unpin.py -p com.example.app --offset 0x844753 --persist --mode attach

Requires: frida (host), frida-server running on the device (see setup_frida.sh).
"""
import argparse
import sys
import time

try:
    import frida
except ImportError:
    sys.exit("[!] frida not installed on host. `pip install frida-tools`")

JS_TEMPLATE = r"""
'use strict';
var LIB      = %LIB%;
var OFFSET   = %OFFSET%;    // Number or null
var PATTERN  = %PATTERN%;   // String or null
var PERSIST  = %PERSIST%;   // bool

// arch-aware "return 0" stub (used only for the persistent patch)
function retZeroStub() {
  switch (Process.arch) {
    case 'x64':
    case 'ia32': return [0x31, 0xC0, 0xC3];                          // xor eax,eax ; ret
    case 'arm64': return [0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6]; // mov w0,#0 ; ret
    default: return null; // arm(thumb) etc. -> use Interceptor.replace instead
  }
}

function scanModule(m, pattern) {
  var hit = null;
  var ranges = m.enumerateRanges('r-x'); // avoid unreadable ranges that break a whole-module scan
  for (var i = 0; i < ranges.length && hit === null; i++) {
    try {
      var res = Memory.scanSync(ranges[i].base, ranges[i].size, pattern);
      if (res.length > 0) hit = res[0].address;
    } catch (e) { /* skip unreadable range */ }
  }
  return hit;
}

function apply(addr) {
  if (PERSIST) {
    var stub = retZeroStub();
    if (stub === null) {
      console.log('[!] --persist unsupported on ' + Process.arch + '; using Interceptor.replace');
    } else {
      var before = addr.readByteArray(stub.length);
      Memory.patchCode(addr, stub.length, function (code) { code.writeByteArray(stub); });
      var after = addr.readByteArray(stub.length);
      var hex = function (b){return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(' ');};
      console.log('[+] persistent patch @ ' + addr + '  before=' + hex(before) + '  after=' + hex(after));
      return;
    }
  }
  // Default: Interceptor.replace -> NativeCallback returning ssl_verify_ok(0)
  Interceptor.replace(addr, new NativeCallback(function (hs) { return 0; }, 'int', ['pointer']));
  console.log('[+] ssl_verify_peer_cert replaced @ ' + addr + ' -> ssl_verify_ok(0)');
}

function main() {
  var m = Process.findModuleByName(LIB);
  if (m === null) { setTimeout(main, 300); return; }   // wait until the lib is loaded
  console.log('[*] ' + LIB + ' base=' + m.base + ' size=' + m.size + ' arch=' + Process.arch);

  var addr = null;
  if (PATTERN) {
    addr = scanModule(m, PATTERN);
    if (addr) console.log('[*] pattern matched @ ' + addr + ' (module+0x' + addr.sub(m.base).toString(16) + ')');
  }
  if (addr === null && OFFSET !== null) {
    addr = m.base.add(OFFSET);
    console.log('[*] using fixed offset -> ' + addr);
  }
  if (addr === null) { console.log('[!] target not found (no pattern match and no offset)'); return; }

  try { apply(addr); } catch (e) { console.log('[!] failed: ' + e); }
}
main();
"""


def js_literal(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return hex(v)
    return '"%s"' % v


def build_script(lib, offset, pattern, persist):
    return (JS_TEMPLATE
            .replace("%LIB%", js_literal(lib))
            .replace("%OFFSET%", js_literal(offset))
            .replace("%PATTERN%", js_literal(pattern))
            .replace("%PERSIST%", js_literal(persist)))


def main():
    ap = argparse.ArgumentParser(description="Disable Flutter TLS validation via ssl_verify_peer_cert.")
    ap.add_argument("-p", "--package", required=True, help="target app package name")
    ap.add_argument("--lib", default="libflutter.so", help="native lib name (default: libflutter.so)")
    ap.add_argument("--offset", type=lambda x: int(x, 0), default=None,
                    help="module-relative offset of ssl_verify_peer_cert (e.g. 0x844753)")
    ap.add_argument("--pattern", default=None, help='byte pattern to locate the function (e.g. "55 41 57 ?? ..")')
    ap.add_argument("--mode", choices=["spawn", "attach"], default="spawn",
                    help="spawn a fresh process (hooks before TLS) or attach to a running one")
    ap.add_argument("--persist", action="store_true",
                    help="patch memory in place (survives Frida detach) instead of Interceptor.replace")
    ap.add_argument("--keep", type=int, default=3600,
                    help="seconds to keep the Frida session alive (Interceptor.replace reverts on exit). Ignored with --persist.")
    ap.add_argument("-D", "--device", default=None, help="frida device id (default: first USB device)")
    args = ap.parse_args()

    if args.offset is None and args.pattern is None:
        ap.error("provide --offset or --pattern (see docs/LOCATING.md to find the offset)")

    dev = frida.get_device(args.device) if args.device else frida.get_usb_device(timeout=10)
    src = build_script(args.lib, args.offset, args.pattern, args.persist)

    if args.mode == "spawn":
        pid = dev.spawn([args.package])
        session = dev.attach(pid)
    else:
        session = dev.attach(args.package)
        pid = None

    script = session.create_script(src)
    script.on("message", lambda m, d: print("[msg]", m.get("payload") or m, flush=True))
    script.load()
    if pid is not None:
        dev.resume(pid)
        print("[*] resumed pid", pid, flush=True)

    if args.persist:
        time.sleep(2)  # give the retry loop time to find the lib, then detach; patch persists
        print("[*] detached; in-memory patch persists for the life of the process", flush=True)
        return

    print("[*] Interceptor.replace active. Keeping session for %ds (Ctrl+C to stop; hook reverts on exit)." % args.keep, flush=True)
    try:
        time.sleep(args.keep)
    except KeyboardInterrupt:
        print("\n[*] stopping.", flush=True)


if __name__ == "__main__":
    main()
