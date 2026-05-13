# Security audit — `security/server-side-hardening` fork

This document records the security review performed on upstream
[`ruvnet/RuView`](https://github.com/ruvnet/RuView) at commit
`58cd860f` (the merge of PR #549, 2026-05-13), the server-side fixes
landed on this branch, and the firmware-side items deferred for a
follow-up pass that has hardware.

## Summary table

| # | Finding | Severity | Status on this branch |
|---|---------|----------|-----------------------|
| 1 | RVF "signature" is a keyed hash where the key is the public key (`rvf_verify_signature`) — anyone with the pubkey can forge a valid signature | **Critical** | **Deferred (firmware, needs ESP32-S3 to validate)** |
| 2a | REST API auth opt-in; default open (sensing-server) | High | Fixed: fail-closed bind check, strict middleware also gates `/ws/*` |
| 2b | OTA endpoint accepts unsigned firmware when no PSK is provisioned | High | Deferred (firmware) |
| 2c | `nvsim-server` had no auth at all + wildcard CORS default | High | Fixed: `NVSIM_API_TOKEN`, fail-closed non-loopback + fail-closed wildcard CORS |
| 2d | WebSocket `/ws/sensing` was explicitly exempt from auth even when API auth was on | High | Fixed: `require_bearer_strict` gates `/ws/*`; browser auth via `Sec-WebSocket-Protocol: bearer.<token>` |
| 2e | MAT API library exposes routers with no auth; library-only today but easy to misuse | High | Fixed: `apply_bearer_auth` helper + doc warning on `create_router` |
| 3  | No TLS anywhere | High | **Out of scope** — handled by reverse-proxy at deploy time |
| 4  | Unsafe `exec()` in `mmwave_sensor.c` (issue [#414](https://github.com/ruvnet/RuView/issues/414)) | High | Deferred (firmware) |
| 5  | UDP CSI ingest hardcoded to `0.0.0.0`, ignoring `--bind-addr`; anyone on LAN can spoof frames | Medium | Fixed: UDP receiver now honors `--bind-addr` |
| 6  | `example.env` shipped with `SECRET_KEY=your-secret-key-here-...`, `ENABLE_AUTHENTICATION=false`, wildcard CORS/hosts, `MOCK_HARDWARE=true`, `RELOAD=true`, etc. | Medium | Fixed: secure defaults, dangerous toggles isolated in a clearly-marked section |
| 7  | Dashboard transport had no way to send a bearer token | Medium | Fixed: `WsClient(baseUrl, { token })` sends `Authorization` + `Sec-WebSocket-Protocol: bearer.<token>` |
| 8  | Dependency vulnerabilities (`cargo audit` / `npm audit`) | Mixed | Mostly fixed (see "Dependency sweep" below); 7 residuals blocked behind transitive pins, off the hot path |

Out-of-scope (informational, no code change):
- Repo provenance: 53k stars on a 7-month-old project by an author with ~7.8k followers is wildly inconsistent with realistic organic growth. The codebase is heavily AI-scaffolded. Treat the star count as marketing, not a quality signal.

## Dependency sweep — 2026-05-14

Ran `cargo audit` (v0.22.1) on the workspace and `npm audit` on each
JS root.

### Rust — fixed

* `quinn-proto 0.11.13 → 0.11.14` — DoS in Quinn endpoints
  (`RUSTSEC-2026-0037`). Pulled in by `wifi-densepose-hardware`.
* `rustls-webpki 0.103.9 → 0.103.13` — 4 advisories
  (`RUSTSEC-2026-{0049,0098,0099,0104}`): CRL parsing panic, wildcard
  name-constraint bypass, URI name-constraint bypass, faulty CRL
  Distribution-Point matching.

Both bumps applied via `cargo update -p <crate>@<old>` (no `Cargo.toml`
edits required — the workspace's semver ranges already permitted the
patches).

### Rust — residual (7 advisories, blocked behind transitive pins)

* **`rustls-webpki 0.101.7`** — 4 advisories (same set as 0.103.x).
  Pulled in via `reqwest 0.11.27 → rustls 0.21 → rustls-webpki 0.101`.
  Bumping requires moving `reqwest` to 0.12 (workspace-wide change).
  **Hot-path risk**: the only crate calling `reqwest` is
  `wifi-densepose-desktop` (`commands/ota.rs`, `commands/wasm.rs`),
  which connects to ESP32 nodes over **plain HTTP on port 8032** —
  no TLS handshake happens, so the cert-validation bugs aren't
  reachable from RuView code. The advisory still counts because the
  crate is present, but exploitation would require the desktop crate
  to issue an HTTPS request, which it does not.
* **`rustls-webpki 0.102.8`** — 3 advisories. Pulled in via
  `midstreamer-quic 0.1.0 → rustls 0.22 → rustls-webpki 0.102`. Used
  only by `wifi-densepose-hardware`'s experimental QUIC aggregator
  path (`esp32/quic_transport.rs`). Bumping requires
  `midstreamer-quic` to update — that's a third-party crate from the
  `ruvnet` org. Until then, the residual risk is only relevant if
  the QUIC aggregator is enabled with TLS to peers outside the
  trusted LAN, which is not the default configuration.

`cargo audit` also flags 29 unmaintained/unsound advisories (`gtk-rs`
chain on the desktop crate, `bincode`, `paste`, `atomic-polyfill`,
`fxhash`, `rkyv 0.8`, etc.). None are exploitable on their own; they
are notices that the upstream maintainer has moved on. Not actioned
this pass — would require coordinated upstream bumps.

### npm — fixed

* `dashboard/`: `npm audit fix` cleared 5 of 10 vulns. Remaining 5 are
  dev-only in the `vitest → vite → esbuild` chain (`GHSA-67mh-4wv8-2f99`
  esbuild dev-server CORS). `npm audit --omit=dev` reports **0
  vulnerabilities** in the production bundle. The dev-only chain
  requires `npm audit fix --force` which bumps vitest 2→3 (breaking
  test harness changes) — left for a separate test-suite-migration PR.
* `v2/crates/wifi-densepose-desktop/ui/`: `npm audit fix` cleared all
  3 vulns (Vite dev-server path traversal + arbitrary file read).
  **0 vulnerabilities** remain.
* `ui/mobile/`: `npm audit fix` cleared 6 of 15 vulns. Remaining 9
  (5 low, 4 moderate) are in the `expo/cli → @expo/metro-config →
  postcss` build-tooling chain. Fixable only by `npm audit fix --force`,
  which advances `expo` past its current minor (55 → 56+) — a
  React Native major-version migration with non-trivial breakage.
  None are runtime vulnerabilities on the shipped app.

### How to re-run

```bash
# Rust
cd v2 && cargo audit

# JS
cd dashboard && npm audit
cd ui/mobile && npm audit
cd v2/crates/wifi-densepose-desktop/ui && npm audit
```

## What this branch changed

### `v2/crates/wifi-densepose-sensing-server/src/bearer_auth.rs`

- Added `require_bearer_strict` that gates **both** `/api/v1/*` and
  every `/ws/*` upgrade. Browser WebSockets supply the token via the
  `Sec-WebSocket-Protocol: bearer.<token>` subprotocol — the same
  pattern used by `kubectl exec`.
- Kept `require_bearer` for backward compatibility.
- Added unit tests for the strict path including the WS subprotocol
  flow and the no-op case.

### `v2/crates/wifi-densepose-sensing-server/src/main.rs`

- **Fail-closed bind check**: if `--bind-addr` is non-loopback and
  `RUVIEW_API_TOKEN` is unset, the process exits with code 2 before
  binding any sockets. Operators who insist on running open on a LAN
  must set `RUVIEW_ALLOW_OPEN=1` explicitly (so the choice leaves a
  trail in process env).
- Switched the HTTP and WebSocket routers to `require_bearer_strict`.
- Fixed `udp_receiver_task` to honour the `--bind-addr` flag — it was
  hardcoded to `0.0.0.0:{udp_port}` regardless of the user's choice.
- Boot banner now reflects the actual bind address.

### `v2/crates/nvsim-server/src/auth.rs` (new)

- Standalone bearer-auth middleware for nvsim-server, gating `/api/*`
  and `/ws/*`. Same constant-time compare + WS subprotocol fallback.
- Gated by `NVSIM_API_TOKEN`.

### `v2/crates/nvsim-server/src/main.rs`

- Default `--allowed-origin` changed from `*` (any) to
  `http://localhost:5173` (the local dashboard dev URL).
- Multiple origins are accepted as a comma-separated list.
- Passing `*` now requires `NVSIM_ALLOW_OPEN=1`; otherwise the server
  refuses to start.
- Non-loopback `--listen` without `NVSIM_API_TOKEN` also refuses to
  start (unless `NVSIM_ALLOW_OPEN=1`).
- Auth middleware applied to the router.

### `v2/crates/wifi-densepose-mat/src/api/auth.rs` (new)

- Same bearer-auth pattern as a library helper that consumers compose
  with `apply_bearer_auth(create_router(state), AuthState::from_env())`.
- Gated by `MAT_API_TOKEN`.

### `v2/crates/wifi-densepose-mat/src/api/mod.rs`

- Documented the lack of built-in auth on `create_router` and pointed
  callers at `apply_bearer_auth`.
- Re-exported `AuthState` + `apply_bearer_auth` from `crate::api`.

### `dashboard/src/transport/WsClient.ts`

- `WsClient` now takes an optional `{ token }` in its constructor,
  sends `Authorization: Bearer <token>` on REST calls, and passes
  `bearer.<token>` as a WebSocket subprotocol so the strict server
  middleware can authenticate browser connections.

### `example.env`

- Secure defaults: `HOST=127.0.0.1`, `DEBUG=false`, `RELOAD=false`,
  `ENABLE_AUTHENTICATION=true`, `ENABLE_RATE_LIMITING=true`,
  `MOCK_HARDWARE=false`, `ENABLE_TEST_ENDPOINTS=false`,
  docs URLs set to `null`.
- `SECRET_KEY` left blank with a `secrets.token_urlsafe(64)` recipe.
- New `RUVIEW_API_TOKEN` / `NVSIM_API_TOKEN` / `MAT_API_TOKEN` slots.
- Dangerous toggles (`RUVIEW_ALLOW_OPEN`, `NVSIM_ALLOW_OPEN`) and the
  full dev profile moved into a clearly-marked DANGER section at the
  bottom; not active by default.

## Items still TODO (need ESP32-S3 hardware)

### 1. Replace the RVF "signature" with real Ed25519 — CRITICAL

File: [`firmware/esp32-csi-node/main/rvf_parser.c`](../firmware/esp32-csi-node/main/rvf_parser.c), function `rvf_verify_signature`.

The current code computes:

```c
expected = SHA-256(pubkey || header || manifest || wasm)
```

and compares the first 32 bytes of the "signature" field. The pubkey
is, by definition, public — anyone who has it can recompute the hash
and produce a "valid signature" for arbitrary WASM. The inline comment
admits this is a SHA-256-HMAC integrity check but then claims it
prevents unauthorized publishers, which is materially false.

**Migration plan:**
1. Add a `tweetnacl` (or `monocypher`) dependency to the IDF component
   manifest — both implement Ed25519 in <2 KB of code without
   dynamic allocation and run fine on ESP32-S3.
2. Change the RVF format: the 64-byte `signature` field already
   matches Ed25519's signature length; no on-wire change needed.
   The pubkey provisioning path (`provision.py --wasm-pubkey`) stays.
3. In `rvf_verify_signature`, replace the SHA-256 step with
   `crypto_sign_verify_detached(sig, msg, msg_len, pubkey)`.
4. Re-issue any in-the-wild RVF modules with real Ed25519 signatures
   produced by the same key. The builder script in `scripts/` already
   has a placeholder for this.
5. Validate end-to-end on hardware: build firmware, flash, attempt to
   upload (a) a properly-signed RVF (must succeed), (b) a tampered
   RVF (must fail), (c) an RVF "signed" with the old SHA-256 scheme
   (must fail).

Until this lands, treat `POST /wasm/upload` on port 8032 as an
authenticated-only-by-OTA-PSK arbitrary-code-execution endpoint, and
keep the OTA PSK provisioned (see item 2).

### 2. Make OTA auth required by default — HIGH

File: [`firmware/esp32-csi-node/main/ota_update.c`](../firmware/esp32-csi-node/main/ota_update.c), function `ota_check_auth`.

`s_ota_psk[0] == '\0'` currently means "auth disabled, accept any
upload". Flip this: require a provisioned PSK, and fail closed if none
is set. The provision flow (`provision.py`) already accepts
`--ota-psk` — make it mandatory in the script.

### 3. Remove `system()`/`exec()` in `mmwave_sensor.c` — HIGH

Tracked upstream as issue
[#414](https://github.com/ruvnet/RuView/issues/414). Same class of bug
was fixed in `display_task.c` via [#310](https://github.com/ruvnet/RuView/pull/310);
follow the same recipe (replace shell-out with an ESP-IDF API call
or remove the path entirely).

### 4. Encrypt the CSI UDP ingest path — MEDIUM

Today, anyone on the LAN can spoof CSI frames to the sensing-server
UDP port (5005). The server-side bind is now restricted to
`--bind-addr`, but spoofing within that network is still possible.
Two ways to fix this, both requiring matching firmware changes:

- **Lower-effort**: HMAC-SHA256 over each frame using a per-device
  shared secret provisioned at the same time as the WiFi credentials.
  Server rejects frames whose HMAC doesn't verify.
- **Higher-effort**: switch the transport to QUIC (the codebase
  already has a `quic_transport.rs` stub in `wifi-densepose-hardware`).

## How to enable auth on this branch

Sensing-server:

```bash
export RUVIEW_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
# bind-addr can now be non-loopback safely:
cargo run -p wifi-densepose-sensing-server -- --bind-addr 0.0.0.0
```

nvsim-server:

```bash
export NVSIM_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
cargo run -p nvsim-server -- --listen 0.0.0.0:7878 \
                              --allowed-origin http://localhost:5173
```

Dashboard:

```ts
new WsClient('http://localhost:7878', { token: process.env.NVSIM_API_TOKEN })
```

## Verification

```bash
cd v2
cargo test -p wifi-densepose-sensing-server --lib bearer_auth
cargo test -p nvsim-server --lib auth
cargo test -p wifi-densepose-mat --lib api::auth
cargo check -p wifi-densepose-sensing-server -p nvsim-server -p wifi-densepose-mat
```

End-to-end verification (open WS without a token must 401):

```bash
RUVIEW_API_TOKEN=t1 cargo run -p wifi-densepose-sensing-server &
curl -i http://127.0.0.1:8080/api/v1/info                 # → 401
curl -i -H 'Authorization: Bearer t1' http://127.0.0.1:8080/api/v1/info  # → 200
# WebSocket without token:
websocat ws://127.0.0.1:8080/ws/sensing                   # → 401
# With token (subprotocol):
websocat -H 'Sec-WebSocket-Protocol: bearer.t1' ws://127.0.0.1:8080/ws/sensing  # → OK
```
