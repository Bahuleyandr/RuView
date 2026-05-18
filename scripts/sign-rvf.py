#!/usr/bin/env python3
"""
sign-rvf.py — Ed25519 keypair + RVF container tool.

Companion to firmware/esp32-csi-node/main/rvf_parser.c
(`rvf_verify_signature`). Produces RVF files whose 64-byte Ed25519
signature verifies against a public key provisioned to the device via
`provision.py --wasm-pubkey <hex>`.

Subcommands
-----------
* `gen-keypair --out keys.json`            — generate Ed25519 keypair, save JSON
* `sign --key keys.json --wasm <path> ...` — wrap a .wasm into a signed .rvf
* `verify --key keys.json --rvf <path>`    — round-trip verify (Python-side check)
* `inspect --rvf <path>`                   — dump header + manifest for debugging

The "verify" subcommand exists for end-to-end developer confidence: it
parses the RVF using the same byte layout the firmware uses, recomputes
the signed region, and runs ed25519 verification with the public key
half of the keypair. A failure here means the firmware will also reject.

Binary layout (must match `rvf_parser.h`):

    [Header: 32 bytes]
      magic u32 = 0x01465652  ("RVF\\x01" LE)
      format_version u16 = 1
      flags u16 = 1           (RVF_FLAG_HAS_SIGNATURE)
      manifest_len u32 = 96
      wasm_len u32
      signature_len u32 = 64
      test_vectors_len u32 = 0
      total_len u32
      reserved u32 = 0
    [Manifest: 96 bytes]
      module_name char[32] (null-padded)
      required_host_api u16 = 1
      capabilities u32
      max_frame_us u32
      max_events_per_sec u16
      memory_limit_kb u16
      event_schema_version u16
      build_hash u8[32]       (SHA-256 of WASM payload)
      min_subcarriers u16
      max_subcarriers u16
      author char[10] (null-padded)
      _reserved u8[2] = 0
    [WASM payload: wasm_len bytes]
    [Ed25519 signature: 64 bytes]   <- covers header || manifest || wasm

Requires: `pip install cryptography` (transitively installed by esptool).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        "error: missing dependency. Run:\n"
        "  python -m pip install cryptography\n"
        f"  (underlying: {exc})\n"
    )
    sys.exit(2)


# ── Constants matching rvf_parser.h ─────────────────────────────────────────
RVF_MAGIC           = 0x01465652
RVF_FORMAT_VERSION  = 1
RVF_HEADER_SIZE     = 32
RVF_MANIFEST_SIZE   = 96
RVF_HOST_API_V1     = 1
RVF_SIGNATURE_LEN   = 64
WASM_BINARY_MAGIC   = 0x6D736100  # "\0asm" LE

RVF_FLAG_HAS_SIGNATURE    = 1 << 0
RVF_FLAG_HAS_TEST_VECTORS = 1 << 1

RVF_CAP_READ_PHASE     = 1 << 0
RVF_CAP_READ_AMPLITUDE = 1 << 1
RVF_CAP_READ_VARIANCE  = 1 << 2
RVF_CAP_READ_VITALS    = 1 << 3
RVF_CAP_READ_HISTORY   = 1 << 4
RVF_CAP_EMIT_EVENTS    = 1 << 5
RVF_CAP_LOG            = 1 << 6
RVF_CAP_ALL            = 0x7F

HEADER_FMT = "<IHHIIIIII"      # 4+2+2+4+4+4+4+4+4 = 32
MANIFEST_FMT = "<32sHIIHHH32sHH10s2x"  # 32+2+4+4+2+2+2+32+2+2+10+2 = 96
assert struct.calcsize(HEADER_FMT) == RVF_HEADER_SIZE
assert struct.calcsize(MANIFEST_FMT) == RVF_MANIFEST_SIZE


# ── Keypair I/O ─────────────────────────────────────────────────────────────

def gen_keypair(out_path: Path) -> dict:
    """Generate a fresh Ed25519 keypair and write it to a JSON file.

    Format (intentionally simple — these are dev/build artifacts, not OS
    keys; treat the JSON file as a secret on disk):

        {
          "private_key_hex": "<64 hex chars>",
          "public_key_hex":  "<64 hex chars>",
          "scheme": "ed25519",
          "purpose": "rvf-wasm-signing"
        }
    """
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    data = {
        "scheme": "ed25519",
        "purpose": "rvf-wasm-signing",
        "private_key_hex": priv_bytes.hex(),
        "public_key_hex": pub_bytes.hex(),
    }
    out_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    # Tight perms when possible (POSIX-only effect; no-op on Windows).
    try:
        out_path.chmod(0o600)
    except OSError:
        pass
    return data


def load_keypair(key_path: Path) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, str]:
    """Load a keypair from the JSON produced by ``gen_keypair``."""
    data = json.loads(key_path.read_text(encoding="utf-8"))
    if data.get("scheme") != "ed25519":
        raise ValueError(f"{key_path}: not an ed25519 key file (scheme={data.get('scheme')!r})")
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["private_key_hex"]))
    pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(data["public_key_hex"]))
    return priv, pub, data["public_key_hex"]


# ── RVF build / parse ───────────────────────────────────────────────────────

def _pack_manifest(
    module_name: str,
    capabilities: int,
    max_frame_us: int,
    max_events_per_sec: int,
    memory_limit_kb: int,
    event_schema_version: int,
    build_hash: bytes,
    min_subcarriers: int,
    max_subcarriers: int,
    author: str,
) -> bytes:
    name_bytes = module_name.encode("ascii").ljust(32, b"\0")[:32]
    # Force null-termination even if name was exactly 32 bytes.
    if name_bytes[-1] != 0:
        name_bytes = name_bytes[:-1] + b"\0"
    author_bytes = author.encode("ascii").ljust(10, b"\0")[:10]
    return struct.pack(
        MANIFEST_FMT,
        name_bytes,
        RVF_HOST_API_V1,
        capabilities & 0xFFFFFFFF,
        max_frame_us & 0xFFFFFFFF,
        max_events_per_sec & 0xFFFF,
        memory_limit_kb & 0xFFFF,
        event_schema_version & 0xFFFF,
        build_hash,
        min_subcarriers & 0xFFFF,
        max_subcarriers & 0xFFFF,
        author_bytes,
    )


def _pack_header(wasm_len: int) -> bytes:
    total_len = RVF_HEADER_SIZE + RVF_MANIFEST_SIZE + wasm_len + RVF_SIGNATURE_LEN
    return struct.pack(
        HEADER_FMT,
        RVF_MAGIC,
        RVF_FORMAT_VERSION,
        RVF_FLAG_HAS_SIGNATURE,
        RVF_MANIFEST_SIZE,
        wasm_len,
        RVF_SIGNATURE_LEN,
        0,            # test_vectors_len
        total_len,
        0,            # reserved
    )


def build_signed_rvf(
    wasm_bytes: bytes,
    priv_key: ed25519.Ed25519PrivateKey,
    *,
    module_name: str,
    capabilities: int = RVF_CAP_ALL,
    max_frame_us: int = 0,
    max_events_per_sec: int = 0,
    memory_limit_kb: int = 0,
    event_schema_version: int = 1,
    min_subcarriers: int = 0,
    max_subcarriers: int = 0,
    author: str = "",
) -> bytes:
    """Build a signed RVF container."""
    if not (len(wasm_bytes) >= 8 and wasm_bytes[:4] == b"\x00asm"):
        raise ValueError("input does not look like a WASM module (bad magic)")
    if len(wasm_bytes) > 128 * 1024:
        raise ValueError(
            f"WASM payload too large for RVF parser ({len(wasm_bytes)} > 131072)"
        )
    build_hash = hashlib.sha256(wasm_bytes).digest()
    manifest = _pack_manifest(
        module_name=module_name,
        capabilities=capabilities,
        max_frame_us=max_frame_us,
        max_events_per_sec=max_events_per_sec,
        memory_limit_kb=memory_limit_kb,
        event_schema_version=event_schema_version,
        build_hash=build_hash,
        min_subcarriers=min_subcarriers,
        max_subcarriers=max_subcarriers,
        author=author,
    )
    header = _pack_header(len(wasm_bytes))
    signed_region = header + manifest + wasm_bytes
    signature = priv_key.sign(signed_region)
    assert len(signature) == RVF_SIGNATURE_LEN
    return signed_region + signature


# ── Parse (for verify + inspect) ────────────────────────────────────────────

def parse_rvf(blob: bytes) -> dict:
    """Parse an RVF and return its fields (no signature check)."""
    if len(blob) < RVF_HEADER_SIZE + RVF_MANIFEST_SIZE + 8:
        raise ValueError(f"RVF too short: {len(blob)} bytes")
    hdr_fields = struct.unpack(HEADER_FMT, blob[:RVF_HEADER_SIZE])
    (magic, fmt_ver, flags, manifest_len, wasm_len,
     sig_len, tvec_len, total_len, reserved) = hdr_fields
    if magic != RVF_MAGIC:
        raise ValueError(f"bad RVF magic: 0x{magic:08x}")
    if fmt_ver != RVF_FORMAT_VERSION:
        raise ValueError(f"unsupported RVF version: {fmt_ver}")
    if manifest_len != RVF_MANIFEST_SIZE:
        raise ValueError(f"bad manifest_len: {manifest_len}")
    if sig_len not in (0, RVF_SIGNATURE_LEN):
        raise ValueError(f"bad signature_len: {sig_len}")
    expected_total = RVF_HEADER_SIZE + RVF_MANIFEST_SIZE + wasm_len + sig_len + tvec_len
    if total_len != expected_total:
        raise ValueError(f"total_len mismatch: header={total_len}, computed={expected_total}")
    if len(blob) < expected_total:
        raise ValueError(f"RVF truncated: have {len(blob)}, need {expected_total}")

    offset = RVF_HEADER_SIZE
    manifest_bytes = blob[offset:offset + RVF_MANIFEST_SIZE]
    offset += RVF_MANIFEST_SIZE
    wasm_bytes = blob[offset:offset + wasm_len]
    offset += wasm_len
    signature = blob[offset:offset + sig_len] if sig_len else None
    offset += sig_len
    test_vectors = blob[offset:offset + tvec_len] if tvec_len else None

    (name_b, host_api, capabilities, max_frame_us,
     max_events_per_sec, memory_limit_kb, event_schema_version,
     build_hash, min_sub, max_sub, author_b) = struct.unpack(MANIFEST_FMT, manifest_bytes)

    name = name_b.split(b"\0", 1)[0].decode("ascii", errors="replace")
    author = author_b.split(b"\0", 1)[0].decode("ascii", errors="replace")

    return {
        "header": {
            "magic": f"0x{magic:08x}",
            "format_version": fmt_ver,
            "flags": flags,
            "wasm_len": wasm_len,
            "signature_len": sig_len,
            "test_vectors_len": tvec_len,
            "total_len": total_len,
        },
        "manifest": {
            "module_name": name,
            "required_host_api": host_api,
            "capabilities_hex": f"0x{capabilities:04x}",
            "max_frame_us": max_frame_us,
            "max_events_per_sec": max_events_per_sec,
            "memory_limit_kb": memory_limit_kb,
            "event_schema_version": event_schema_version,
            "build_hash_hex": build_hash.hex(),
            "min_subcarriers": min_sub,
            "max_subcarriers": max_sub,
            "author": author,
        },
        "wasm_bytes": wasm_bytes,
        "signature": signature,
        "test_vectors": test_vectors,
        "signed_region": blob[:RVF_HEADER_SIZE + RVF_MANIFEST_SIZE + wasm_len],
    }


# ── CLI subcommands ─────────────────────────────────────────────────────────

def _parse_int(s: str) -> int:
    """Accept decimal or 0x-prefixed hex from the CLI."""
    return int(s, 0)


def cmd_gen(args) -> int:
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"refusing to overwrite existing keypair: {out}", file=sys.stderr)
        print("pass --force to replace.", file=sys.stderr)
        return 2
    data = gen_keypair(out)
    print(f"Ed25519 keypair written to {out}")
    print()
    print(f"  public_key_hex:  {data['public_key_hex']}")
    print()
    print("Provision this key onto a board with:")
    print(
        f"  python firmware/esp32-csi-node/provision.py --port COMx "
        f"--ssid <S> --password <P> --target-ip <IP> "
        f"--wasm-pubkey {data['public_key_hex']}"
    )
    return 0


def cmd_sign(args) -> int:
    priv, _pub, _pub_hex = load_keypair(Path(args.key))
    wasm = Path(args.wasm).read_bytes()
    rvf = build_signed_rvf(
        wasm, priv,
        module_name=args.module_name,
        capabilities=args.capabilities,
        max_frame_us=args.max_frame_us,
        max_events_per_sec=args.max_events_per_sec,
        memory_limit_kb=args.memory_limit_kb,
        event_schema_version=args.event_schema_version,
        min_subcarriers=args.min_subcarriers,
        max_subcarriers=args.max_subcarriers,
        author=args.author,
    )
    Path(args.out).write_bytes(rvf)
    print(f"Wrote {args.out} ({len(rvf)} bytes)")
    print(
        f"  module={args.module_name!r} wasm={len(wasm)}B "
        f"caps=0x{args.capabilities:04x} signed=ed25519"
    )
    return 0


def cmd_verify(args) -> int:
    _priv, pub, pub_hex = load_keypair(Path(args.key))
    blob = Path(args.rvf).read_bytes()
    parsed = parse_rvf(blob)
    if parsed["signature"] is None:
        print(f"{args.rvf}: NO signature in RVF", file=sys.stderr)
        return 1
    try:
        pub.verify(parsed["signature"], parsed["signed_region"])
    except InvalidSignature:
        print(f"{args.rvf}: signature INVALID against pubkey {pub_hex}", file=sys.stderr)
        return 1
    # Also re-check the SHA-256 build hash, mirroring rvf_parse() in C.
    recomputed = hashlib.sha256(parsed["wasm_bytes"]).digest()
    if recomputed.hex() != parsed["manifest"]["build_hash_hex"]:
        print(
            f"{args.rvf}: signature OK but build_hash mismatch — manifest is "
            f"stale or corrupt",
            file=sys.stderr,
        )
        return 1
    print(f"{args.rvf}: signature OK (ed25519, {len(parsed['wasm_bytes'])}B WASM)")
    return 0


def cmd_inspect(args) -> int:
    blob = Path(args.rvf).read_bytes()
    parsed = parse_rvf(blob)
    summary = {
        "file_size": len(blob),
        "header": parsed["header"],
        "manifest": parsed["manifest"],
        "signature_hex_prefix": (
            parsed["signature"][:16].hex() + "..." if parsed["signature"] else None
        ),
        "test_vectors_len": len(parsed["test_vectors"]) if parsed["test_vectors"] else 0,
    }
    print(json.dumps(summary, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sign-rvf.py", description=__doc__.splitlines()[1])
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-keypair", help="Generate Ed25519 keypair")
    g.add_argument("--out", required=True, help="Output JSON path (chmod 600)")
    g.add_argument("--force", action="store_true", help="Overwrite if exists")
    g.set_defaults(func=cmd_gen)

    s = sub.add_parser("sign", help="Wrap a WASM module into a signed RVF")
    s.add_argument("--key", required=True, help="Keypair JSON from gen-keypair")
    s.add_argument("--wasm", required=True, help="Path to .wasm input")
    s.add_argument("--out", required=True, help="Output .rvf path")
    s.add_argument("--module-name", required=True, help="<=31 ASCII chars")
    s.add_argument("--capabilities", type=_parse_int, default=RVF_CAP_ALL,
                   help="Capability bitmask (decimal or 0x-hex). Default 0x7F (all).")
    s.add_argument("--max-frame-us", type=int, default=0)
    s.add_argument("--max-events-per-sec", type=int, default=0)
    s.add_argument("--memory-limit-kb", type=int, default=0)
    s.add_argument("--event-schema-version", type=int, default=1)
    s.add_argument("--min-subcarriers", type=int, default=0)
    s.add_argument("--max-subcarriers", type=int, default=0)
    s.add_argument("--author", default="")
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="Verify a signed RVF (host-side check)")
    v.add_argument("--key", required=True, help="Keypair JSON (uses public half)")
    v.add_argument("--rvf", required=True, help="Path to .rvf to verify")
    v.set_defaults(func=cmd_verify)

    i = sub.add_parser("inspect", help="Pretty-print RVF header + manifest")
    i.add_argument("--rvf", required=True)
    i.set_defaults(func=cmd_inspect)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
