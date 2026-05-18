# Monocypher (vendored)

[Monocypher](https://monocypher.org/) v4.0.2 — a small, portable, easy-to-deploy
cryptographic library. Used here for Ed25519 signature verification of RVF
containers in `rvf_parser.c::rvf_verify_signature`.

## Why vendored

ESP-IDF v5.4's bundled mbedTLS does not expose Ed25519 at a stable C API
without enabling `CONFIG_MBEDTLS_EDDSA_C` and rebuilding. Vendoring a single
self-contained, public-domain implementation makes the firmware build
reproducible across ESP-IDF versions and removes the need for Kconfig
gymnastics during onboarding.

## Files

| File | Source | Notes |
|------|--------|-------|
| `monocypher.c` | [GitHub v4.0.2](https://github.com/LoupVaillant/Monocypher/blob/4.0.2/src/monocypher.c) | ~3,000 LoC, no allocations, no external deps |
| `monocypher.h` | [GitHub v4.0.2](https://github.com/LoupVaillant/Monocypher/blob/4.0.2/src/monocypher.h) | Public API |
| `LICENSE` | [GitHub v4.0.2](https://github.com/LoupVaillant/Monocypher/blob/4.0.2/LICENCE.md) | BSD-2-Clause OR CC-0 (dual-licensed) |

## Upgrading

```
cd firmware/esp32-csi-node/main/third_party/monocypher
curl -fsSL -o monocypher.c https://raw.githubusercontent.com/LoupVaillant/Monocypher/<VER>/src/monocypher.c
curl -fsSL -o monocypher.h https://raw.githubusercontent.com/LoupVaillant/Monocypher/<VER>/src/monocypher.h
curl -fsSL -o LICENSE      https://raw.githubusercontent.com/LoupVaillant/Monocypher/<VER>/LICENCE.md
```

Replace `<VER>` with the desired tag. Re-run the firmware host tests after upgrade:

```
cd firmware/esp32-csi-node/tests/host && make check
```

## What we use

Just `crypto_eddsa_check(sig, pubkey, msg, msg_len)` from the Ed25519 API.
None of the AEAD / Argon2 / X25519 / BLAKE2 surface is exercised by our
firmware, but they remain available for future use.

## Stack budget on ESP32-S3

`crypto_eddsa_check` is constant-time and allocation-free. Empirically uses
~1.5 KB of stack. The ESP-IDF default `httpd` task stack is 4 KB, which is
sufficient. If you see "Stack canary watchpoint triggered" near a `/wasm/upload`
call, raise `CONFIG_HTTPD_TASK_STACK_SIZE` in menuconfig.

License is reproduced verbatim in [LICENSE](./LICENSE).
