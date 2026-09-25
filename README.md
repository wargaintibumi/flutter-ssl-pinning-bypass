# Flutter SSL Pinning Bypass When reFlutter & NVISO Fail — Manually Locating `ssl_verify_peer_cert`

*Fixing `"[+] libFlutter was found, but ssl_verify_peer_cert could not be located"` on a Flutter engine too new for prebuilt pattern databases — via Frida + radare2, down to the byte offset.*

**Disable Flutter (BoringSSL) TLS certificate validation when off-the-shelf bypasses fail — by locating `ssl_verify_peer_cert` yourself in `libflutter.so`, then patching it to return `ssl_verify_ok`.**

<sub>Keywords: Flutter SSL pinning bypass · certificate pinning · `ssl_verify_peer_cert` · `libflutter.so` · BoringSSL · reFlutter not working · NVISO disable-flutter-tls-verification · Frida 17 · radare2 · Burp Suite · Android pentest · new Dart engine.</sub>

> ⚠️ **For authorized security testing only.** These tools are for apps you own or
> have written permission to assess, on devices/emulators you control. Everything
> here was developed during an authorized penetration test; all target identifiers
> are redacted. Don't point this at software you don't have permission to test.

---

## Why this exists

Flutter ships its own statically-linked, **stripped** copy of BoringSSL. All peer
certificate validation funnels through one function:

```c
enum ssl_verify_result_t ssl_verify_peer_cert(SSL_HANDSHAKE *hs);
```

Force it to always return `ssl_verify_ok (0)` and every certificate — including
your intercepting proxy's — is accepted.

Popular bypasses (reFlutter, the NVISO `disable-flutter-tls-verification` script)
find that function via **hardcoded byte patterns**. BoringSSL is recompiled for
every engine release, so when the target's engine is **newer than the tool's
pattern database**, the pattern misses and the bypass **fails silently**:

```
[+] libFlutter was found, but ssl_verify_peer_cert could not be located
```

The engine that prompted this repo was **Dart 3.13.4, built ten days before the
test** — no released pattern DB could match it. This repo's approach: locate the
function **manually** using its BoringSSL control-flow signature, then neutralize
it. No pattern DB to go stale.

> Installing your proxy CA into the Android trust store does **nothing** for
> Flutter — BoringSSL uses its own embedded trust store, not the OS one. Patching
> the code is the way in.

---

## Repo layout

| Path | What it does |
|------|--------------|
| `scripts/flutter_unpin.py` | Main tool. Hooks/patches `ssl_verify_peer_cert` by `--offset` or `--pattern` to always return `ssl_verify_ok(0)`. |
| `scripts/setup_frida.sh` | Download the matching `frida-server`, push to device, start it. |
| `scripts/locate_ssl_verify.sh` | Runs the string-anchor recon (rabin2) to help you find the function. |
| `scripts/redirect_traffic.sh` | iptables DNAT: force the app's `:443` to your proxy (Flutter ignores the system proxy). |
| `docs/LOCATING.md` | Full reverse-engineering walkthrough to locate the function on any build. |

---

## Requirements

- A **rooted** device or emulator you control.
- [`frida` / `frida-tools`](https://frida.re) on the host (`pip install frida-tools`).
- `adb` on `PATH`.
- For manual locating: [radare2](https://rada.re) (`rabin2`, `r2`).

---

## Quick start

```bash
# 1. Start frida-server matching your host frida version
./scripts/setup_frida.sh                 # auto-matches `frida --version`

# 2. Extract libflutter.so for your device's ABI and locate the function
unzip -j target.apk "lib/x86_64/libflutter.so" -d .
./scripts/locate_ssl_verify.sh libflutter.so
#   ...then follow docs/LOCATING.md in radare2 to confirm the offset

# 3. Disable TLS validation (persistent in-memory patch, survives Frida detach)
python scripts/flutter_unpin.py -p <package> --offset 0x844753 --persist --mode attach

# 4. Flutter ignores the system proxy — redirect its HTTPS to your proxy
#    (proxy must have invisible/transparent proxying enabled)
./scripts/redirect_traffic.sh add <package> 10.0.2.2:8083
```

Traffic now decrypts in your proxy. Remove the redirect when done:

```bash
./scripts/redirect_traffic.sh del <package> 10.0.2.2:8083
```

---

## `flutter_unpin.py` options

```
-p, --package   target package name (required)
--offset        module-relative offset of ssl_verify_peer_cert (e.g. 0x844753)
--pattern       byte pattern to locate it (e.g. "55 41 57 ?? ..")
--mode          spawn | attach   (spawn hooks before TLS; attach hits a running app)
--persist       overwrite the prologue in place (survives detach) instead of Interceptor.replace
--keep          seconds to hold the session for Interceptor.replace (default 3600)
--lib           native lib name (default: libflutter.so)
```

Provide **either** `--offset` **or** `--pattern`.

### Two ways to neutralize the function

- **`Interceptor.replace`** (default) — installs a `NativeCallback` returning `0`.
  Arch-independent and clean, but Frida **reverts it when the session detaches**,
  so the tool holds the session open (`--keep`).
- **`--persist`** — overwrites the first bytes of the function with an
  arch-appropriate `return 0` stub via `Memory.patchCode`. It's just modified
  process memory, so it **persists for the life of the process** — no session to
  babysit during interactive testing.

| Arch | Persistent stub | Meaning |
|------|-----------------|---------|
| x86-64 | `31 C0 C3` | `xor eax, eax ; ret` |
| arm64 | `00 00 80 52 C0 03 5F D6` | `mov w0, #0 ; ret` |

---

## Locating the function (summary)

Full walkthrough in [`docs/LOCATING.md`](docs/LOCATING.md). In short:

1. **Anchor** on the source string `.../boringssl/src/ssl/handshake.cc` and xref it
   in radare2 to reach the `handshake.cc` functions.
2. **Match the control-flow signature** of `ssl_verify_peer_cert`: single `hs`
   pointer arg → `ssl = hs->ssl` → reads `established_session` (`[…+0x1d0]`) →
   sets alert `0x2e` → checks `custom_verify_callback` (`[hs->config+0x30]`) →
   else calls `session_verify_cert_chain` via vtable → returns the enum in the
   return register.
3. **Record** the module-relative offset (and optionally a wildcarded prologue
   pattern) and feed it to `flutter_unpin.py`.

The offset is **build-specific**; the method transfers to any engine version.

---

## Frida 17 note

Frida 17 removed the built-in `Java`/`ObjC` bridge globals. Scripts that touch
`Java.*` throw `ReferenceError: 'Java' is not defined`. This tool uses only the
native `Process`/`Module`/`Interceptor` API and is unaffected. If you port an older
script that just reads `Java.available` as an "am I on Android?" flag, shim it:

```js
var Java = (typeof Java !== "undefined") ? Java : { available: true };
```

---

## License

MIT — see [LICENSE](LICENSE).
