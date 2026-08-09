# Security audit — hardened fork of `ruvnet/RuView`

Fork: [`Bahuleyandr/RuView`](https://github.com/Bahuleyandr/RuView).
Rebased onto upstream `5780c239` (release `v2146`, 2026-08-02) on 2026-08-09.

The original review was performed against upstream `58cd860f` (2026-05-13).
Upstream advanced 730 commits between those two points and independently
fixed several of the findings — in some cases more thoroughly than this fork
did. This document records what was found, who fixed what, and what is still
carried here.

## Status against the original findings

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | RVF "signature" is `SHA-256(pubkey ‖ payload)` — anyone holding the *public* key can forge a valid signature for arbitrary WASM | **Critical** | **Fixed here only.** Upstream `v2146` still ships the forgeable scheme (it moved from mbedTLS to PSA Crypto but kept the construction). Verified on ESP32-S3 silicon — see below. |
| 2a | Sensing-server REST auth opt-in, no fail-closed bind | High | **Fixed here.** Upstream added OAuth (ADR-271) and fails closed on OAuth *misconfiguration*, but still only warns when binding a routable address with no auth at all. |
| 2b | OTA accepts unsigned firmware when no PSK is provisioned | High | **Fixed upstream.** `ota_check_auth` now rejects when no PSK is present. |
| 2c | `nvsim-server` had no auth and a wildcard CORS default | High | **Fixed here only.** Upstream still defaults `--allowed-origin=*` with no auth module. |
| 2d | `/ws/sensing` exempt from auth even with auth enabled | High | **Fixed upstream, better than here.** See "Superseded" below. |
| 2e | MAT API library exposes routers with no auth | High | **Fixed here only.** Upstream `api/` still has no auth module. |
| 3 | No TLS anywhere | High | **Out of scope** — terminate TLS at a reverse proxy. |
| 4 | Unsafe `exec()` in `mmwave_sensor.c` ([#414](https://github.com/ruvnet/RuView/issues/414)) | High | **Fixed upstream.** |
| 5 | UDP CSI ingest hardcoded to `0.0.0.0`, ignoring `--bind-addr` | Medium | **Fixed here.** Still hardcoded upstream. |
| 6 | `example.env` ships placeholder `SECRET_KEY`, `ENABLE_AUTHENTICATION=false`, wildcard CORS/hosts, `DEBUG=true` | Medium | **Fixed here only.** Upstream has not touched `example.env` since the fork point. |
| 7 | Dashboard transport could not send a bearer token | Medium | **Fixed here** for the nvsim dashboard (`dashboard/`). |
| 8 | Dependency vulnerabilities | Mixed | **Superseded** — re-audit against the current tree; the 2026-05 lockfile bumps were dropped in the rebase. |

## Finding 1 — the forgeable RVF signature (still open upstream)

`firmware/esp32-csi-node/main/rvf_parser.c::rvf_verify_signature` computed:

```c
expected = SHA-256(pubkey || header || manifest || wasm)
```

and compared the first 32 bytes of the 64-byte signature field against it.
The public key is public by definition, so any party holding it could
recompute the digest and mint a "valid signature" for arbitrary bytes. That
is tamper detection, not authentication — while the surrounding comment
claimed it stopped unauthorized publishers.

Upstream `v2146` still ships this. The only change since the fork point was
swapping mbedTLS hashing for PSA Crypto; the construction, and the comment
asserting it prevents forgery, are unchanged.

### What this fork does instead

* Vendors [Monocypher](https://monocypher.org/) 4.0.2 at
  `firmware/esp32-csi-node/main/third_party/monocypher/` (BSD-2-Clause OR
  CC-0). Chosen over Kconfig-gated mbedTLS EdDSA so the firmware build stays
  reproducible across ESP-IDF versions.
* `rvf_verify_signature` calls `crypto_ed25519_check` — real RFC 8032
  PureEd25519, constant-time, allocation-free.
* `scripts/sign-rvf.py` produces matching containers:
  `gen-keypair` / `sign` / `verify` / `inspect`.
* `provision.py --wasm-pubkey <hex>` writes the 32-byte public key into the
  `csi_cfg` NVS namespace, which the firmware already reads into
  `g_nvs_config.wasm_pubkey`.

### The SHA-512 vs BLAKE2b trap

Monocypher's default `crypto_eddsa_check` (in `monocypher.h`) is EdDSA with
curve25519 + **BLAKE2b** — a non-standard hash that does not interoperate
with RFC 8032. The first firmware build used it and rejected every valid
signature, because the Python signer uses SHA-512. The fix is the optional
`monocypher-ed25519.{c,h}` module (`crypto_ed25519_check`).

Host-side round-trip tests could not catch this: both sides of that test were
Python. Only running against silicon surfaced it. The trap is documented in
`main/third_party/monocypher/README.md`.

### Hardware verification — `MEASURED`

Run twice on ESP32-S3-DevKitC-1-N16R8 hardware: once before the rebase, and
again afterwards to confirm the same code still behaves identically now that
it sits on upstream's PSA-based `rvf_parser.c` and reorganised CMake. Both
runs flashed firmware built from this tree over USB and issued uploads
against `POST /wasm/upload` on port 8032; verdicts are quoted from the serial
log, not inferred from the HTTP status.

| Run | Board MAC | Firmware | ESP-IDF | Tree |
|-----|-----------|----------|---------|------|
| A | `44:1b:f6:ff:94:ac` | v0.6.4 | 5.4 | pre-rebase (fork of 58cd860f) |
| B | `44:1b:f6:fe:1e:0c` | v0.8.4 | 5.4 | post-rebase (this tree, on v2146) |

Both runs produced identical results:

| # | Input | Firmware log | HTTP |
|---|-------|--------------|------|
| 1 | Valid signed RVF | `Ed25519 signature verified` | 500 — WASM3 not compiled in, unrelated to the crypto gate |
| 2 | One byte flipped in the manifest | `Ed25519 signature verification failed` | 403 |
| 3 | One byte flipped in the WASM payload | `RVF parse failed: ESP_ERR_INVALID_CRC` | 400 — caught earlier by the build-hash check |
| 4 | Signed with a different Ed25519 key | `Ed25519 signature verification failed` | 403 |
| 5 | Raw `.wasm`, no RVF wrapper | `Raw WASM upload rejected (signature verification enabled)` | 403 |

Case 4 is the original attack: it is now rejected. Case 1's HTTP 500 comes
from `wasm_runtime_load` returning `ESP_ERR_NOT_SUPPORTED` because the WASM3
interpreter is behind a separate Kconfig (`W wasm_rt: WASM Tier 3 disabled`
at boot); the signature itself verified. Neither run produced a stack-canary
trip, a panic, or a boot loop.

Run B matters because a green `cargo check` cannot speak to firmware
behaviour, and the rebase moved this code onto a substantially different
base — upstream jumped the firmware from v0.4.3.1 to v0.8.4 across those 730
commits. It is also how the BLAKE2b/SHA-512 mismatch was originally caught:
host-side tests had Python on both ends and passed happily while the device
rejected every valid signature.

Raw serial logs for run B: `.local/phase-b/b1-rebased-boot.log` and
`.local/phase-b/b1-matrix.log` (untracked; `.local/` is gitignored).

## What this fork still carries

| Area | Change |
|---|---|
| `firmware/.../rvf_parser.c`, `main/CMakeLists.txt`, `third_party/monocypher/` | Real Ed25519 verification (above) |
| `firmware/.../provision.py` | `--wasm-pubkey <hex>`, wired into upstream's per-port merge state |
| `scripts/sign-rvf.py` | Ed25519 keypair + RVF signing/verification tool |
| `v2/crates/nvsim-server/src/auth.rs` (new) | Bearer auth over `/api/*` and `/ws/*`, gated by `NVSIM_API_TOKEN` |
| `v2/crates/nvsim-server/src/main.rs` | Refuses to start on non-loopback listen without a token, or on `--allowed-origin=*`, unless `NVSIM_ALLOW_OPEN=1`. Default origin is `http://localhost:5173` |
| `v2/crates/wifi-densepose-sensing-server/src/main.rs` | Refuses to start on a non-loopback bind with no auth configured unless `RUVIEW_ALLOW_OPEN=1`; gate runs before any socket is bound. UDP CSI receiver honours `--bind-addr` |
| `v2/crates/wifi-densepose-mat/src/api/auth.rs` (new) | `apply_bearer_auth` helper, `MAT_API_TOKEN`, plus a security note on `create_router` |
| `dashboard/` | nvsim dashboard sends `Authorization: Bearer` on REST and `bearer.<token>` as a WS subprotocol; token entry in settings |
| `example.env` | Secure defaults; dangerous toggles isolated in a marked section |
| `.gitignore` | `.local/`, `.tmp/` so signing keys and dev tokens cannot be committed |

## Superseded by upstream — dropped in the rebase

* **WebSocket auth gating.** Upstream's `bearer_auth.rs` (ADR-272) gates
  `/ws/*` *and* a `WS_PATHS_OUTSIDE_PREFIX` list covering upgrade endpoints
  that do not live under `/ws/` — notably `/api/v1/stream/pose`, which this
  fork's version missed. Browsers exchange their stored bearer at
  `POST /api/v1/ws-ticket` for a single-use, ~30-second ticket passed as
  `?ticket=`, so the long-lived token never enters a URL. This fork's
  `require_bearer_strict` + `Sec-WebSocket-Protocol: bearer.<token>` approach
  was removed in favour of it.
* **UI token handling.** Upstream ships a QuickSettings "API Access" panel
  that stores the token under `ruview-api-token` and applies it at module
  load. This fork's `#token=` URL-hash bootstrap in `ui/app.js` and the WS
  subprotocol changes in `ui/services/` were removed as redundant.
* **`sdkconfig.defaults` timer stack.** Upstream already carries
  `CONFIG_FREERTOS_TIMER_TASK_STACK_DEPTH=8192`. The local file had drifted
  from the template, which produced a boot loop
  (`***ERROR*** A stack overflow in task Tmr Svc`) during bring-up; the
  rebase resolves it by adopting upstream's file.
* **Dependency lockfile bumps** from the 2026-05 sweep — upstream's tree has
  moved; re-audit rather than replay them.

## Still open (not addressed in either tree)

1. **No TLS.** OTA, WASM upload, REST, and WebSocket are plain HTTP. The OTA
   PSK and bearer tokens travel in cleartext to anyone sniffing the WiFi —
   the same medium this product senses. Terminate TLS at a reverse proxy and
   keep the origin on loopback.
2. **Unauthenticated UDP CSI ingest** (port 5005). Anyone able to reach the
   bind address can inject frames and steer presence/vitals output. Fixing
   this properly needs a per-device HMAC provisioned alongside the WiFi
   credentials, or the QUIC transport stubbed in
   `wifi-densepose-hardware/src/esp32/quic_transport.rs` — both require
   matching firmware and server changes.
3. **Dependency posture** — re-run `cargo audit` and `npm audit` against the
   current tree.

## Reproducing

```bash
# Rust
cd v2 && cargo check -p nvsim-server -p wifi-densepose-mat -p wifi-densepose-sensing-server
cargo test -p nvsim-server auth
cargo test -p wifi-densepose-mat --lib api::auth

# Signing round-trip (no hardware needed)
python scripts/sign-rvf.py gen-keypair --out /tmp/keys.json
python scripts/sign-rvf.py sign --key /tmp/keys.json --wasm module.wasm \
    --module-name demo --out /tmp/demo.rvf
python scripts/sign-rvf.py verify --key /tmp/keys.json --rvf /tmp/demo.rvf

# Hardened server
export RUVIEW_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
cargo run -p wifi-densepose-sensing-server -- --bind-addr 0.0.0.0
# Without the token, the same command now exits 2 rather than serving openly.
```

## Upstreaming

Finding 1 is a live critical issue in upstream `v2146` with a working patch
and hardware evidence in this tree. It has not been reported upstream yet.
