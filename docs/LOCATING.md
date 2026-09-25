# Locating `ssl_verify_peer_cert` in a stripped `libflutter.so`

When prebuilt pattern databases (reFlutter, NVISO) don't match your Flutter
engine, find the function yourself. The library is stripped, but two things the
compiler can't fully hide remain: **string references** and **control-flow shape**.

## 0. Extract the right library

```bash
# pick the ABI your device actually runs (x86_64 on most emulators, arm64-v8a on phones)
unzip -j target.apk "lib/x86_64/libflutter.so" -d .
readelf -h libflutter.so | grep Machine     # confirm arch
```

> Modern APKs ship `extractNativeLibs=false`, so the lib is mmapped straight from
> the APK. In `/proc/<pid>/maps` it shows the `base.apk` path, but Frida still
> lists it by soname (`libflutter.so`) via `Process.enumerateModules()`.

## 1. Read the engine version

```bash
strings -n 6 libflutter.so | grep -i "Dart VM version"
# Dart VM version: 3.13.4 (stable) (Tue Sep 15 ...) on "android_x64"
```

If the build date is newer than your tool's pattern DB, that's exactly why the
prebuilt bypass fails. Proceed manually.

## 2. Anchor on the source-path string

`ssl_verify_peer_cert` is defined in `handshake.cc`. BoringSSL embeds that path in
assertion macros:

```bash
rabin2 -z libflutter.so | grep -i "handshake.cc"
# ../../flutter/third_party/boringssl/src/ssl/handshake.cc
```

In radare2, cross-reference the string to the functions that use it:

```
r2 -A libflutter.so
[0x..]> / handshake.cc         # locate the string, note its address
[0x..]> axt @ <string_addr>    # functions referencing it (the handshake.cc set)
```

Assertion line numbers passed near the call sites (immediates like `0x115`=277,
`0x140`=320, `0x14c`=332) fall inside the `ssl_verify_peer_cert` region.

## 3. Confirm by control-flow signature (x86-64)

Disassemble each candidate (`pdf @ fcn`) and match this shape. `ssl_verify_peer_cert`
is `enum ssl_verify_result_t ssl_verify_peer_cert(SSL_HANDSHAKE *hs)`:

- **single pointer arg** — `hs` in `rdi`.
- loads `ssl = hs->ssl` → `mov rbx, [rdi]`.
- reaches `ssl->s3->established_session` → `[rax+0x1d0]` (session-resumption
  cert-consistency check).
- fresh-verify path sets `alert = 0x2e` (`SSL_AD_CERTIFICATE_UNKNOWN`).
- checks `hs->config->custom_verify_callback` (`[hs->config + 0x30]`); if set,
  calls it and compares the result to `1` (`ssl_verify_invalid`).
- otherwise calls `x509_method->session_verify_cert_chain(...)` via a vtable slot
  (`ssl->ctx` at `[ssl+0x68]`, method table `+0x10`, slot `+0x48`), converting
  `bool → enum` with `xor al, 1`.
- returns the enum in `eax`; sends a fatal alert on the invalid path.

The neighbouring `handshake.cc` functions are the `x509_method` cert-chain
implementation and the custom-callback wrapper — ruled out by different argument
shape and call graph.

## 4. Record the offset and (optionally) a pattern

Note the **module-relative offset** (on typical builds `.text` file-offset == vaddr
== Frida `module.base`-relative offset — verify with `rabin2 -S`).

Grab the prologue as a reusable pattern (wildcard bytes that vary, e.g. jump
displacements). Example from one Dart 3.13.4 x86_64 build — **yours will differ**:

```
offset : libflutter.so + 0x844753
pattern: 55 41 57 41 56 41 55 41 54 53 50 49 89 FE 48 8B 1F 48 8B 43 30
         4C 8B B8 D0 01 00 00 4D 85 FF 74 ?? 4D 8B A6 00 08 00 00 45 8A AF B0 01 00 00
```

## 5. Neutralize it

Feed the offset or pattern to `flutter_unpin.py`:

```bash
python ../scripts/flutter_unpin.py -p <package> --offset 0x844753 --persist --mode attach
```

The tool forces the function to return `ssl_verify_ok (0)`. The persistent variant
overwrites the prologue with an arch-appropriate `return 0` stub
(x86-64: `31 C0 C3` = `xor eax,eax ; ret`; arm64: `mov w0,#0 ; ret`).

## Other architectures

The control-flow logic is identical on arm64; only registers and the vtable
offsets' encoding change. Locate via the same `handshake.cc` anchor, then match the
same load/compare/callback structure in AArch64. For patching, prefer
`Interceptor.replace` (arch-independent) unless you specifically need persistence.
