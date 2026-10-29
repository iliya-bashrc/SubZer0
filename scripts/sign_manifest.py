#!/usr/bin/env python3
"""Sign the published snapshot manifest with Ed25519 (RFC 8032, pure stdlib).

The browser verifies snapshot/manifest.sig against the public key embedded in
site/app.js, so a mirror can copy the site but cannot publish *signed* data.

  python3 scripts/sign_manifest.py --site _site     # uses $SUBZER0_SIGNING_KEY (hex seed)
  python3 scripts/sign_manifest.py --genkey         # prints a new seed + public key

If SUBZER0_SIGNING_KEY is not set the step is skipped (exit 0): the site still
works, it just shows no "signed" badge.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import secrets
import sys
from pathlib import Path

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = (x * I) % P
    if x % 2:
        x = P - x
    return x


_BY = 4 * pow(5, P - 2, P) % P
B = (_xrecover(_BY), _BY, 1, (_xrecover(_BY) * _BY) % P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s: int, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _encode(p) -> bytes:
    x, y, z, _ = p
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _h(m: bytes) -> int:
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _expand(seed: bytes):
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _encode(_mul(a, B))


def sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(seed)
    pk = _encode(_mul(a, B))
    r = _h(prefix + msg) % L
    rb = _encode(_mul(r, B))
    s = (r + _h(rb + pk + msg) * a) % L
    return rb + int.to_bytes(s, 32, "little")


def parse_seed(raw: str) -> bytes | None:
    """Accept the bare 64-hex seed, or a pasted note that contains exactly one."""
    raw = raw.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        return bytes.fromhex(raw)
    found = set(re.findall(r"(?<![0-9A-Za-z+/])[0-9a-fA-F]{64}(?![0-9A-Za-z+/=])", raw))
    return bytes.fromhex(found.pop()) if len(found) == 1 else None


def embedded_public_key(site: Path) -> str | None:
    """SIGN_PK from the shipped app.js, so a wrong key can never publish bad signatures."""
    for path in (site / "app.js",):
        if path.is_file():
            m = re.search(r"SIGN_PK='([A-Za-z0-9+/=]{44})'", path.read_text(encoding="utf-8", errors="replace"))
            if m:
                return m.group(1)
    return None



def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--site", type=Path, help="built site root containing snapshot/manifest.json")
    ap.add_argument("--genkey", action="store_true", help="print a fresh signing seed and its public key")
    args = ap.parse_args(argv)

    if args.genkey:
        seed = secrets.token_bytes(32)
        print("SUBZER0_SIGNING_KEY (secret, hex):", seed.hex())
        print("public key (base64, goes in site/app.js):", base64.b64encode(public_key(seed)).decode())
        return 0
    if not args.site:
        ap.error("--site is required")

    raw = os.environ.get("SUBZER0_SIGNING_KEY", "")
    if not raw.strip():
        print("sign_manifest: SUBZER0_SIGNING_KEY not set; skipping signature", file=sys.stderr)
        return 0
    seed = parse_seed(raw)
    if seed is None:
        # Never block a deploy over the optional signature: warn and ship unsigned.
        print("::warning::sign_manifest: SUBZER0_SIGNING_KEY has no single 64-hex key; shipping unsigned", file=sys.stderr)
        return 0
    expected = embedded_public_key(args.site)
    if expected and base64.b64encode(public_key(seed)).decode() != expected:
        print("::warning::sign_manifest: key does not match SIGN_PK in app.js; shipping unsigned", file=sys.stderr)
        return 0

    manifest = args.site / "snapshot" / "manifest.json"
    if not manifest.is_file():
        print(f"sign_manifest: {manifest} not found", file=sys.stderr)
        return 1
    pk = base64.b64encode(public_key(seed)).decode()
    # the snapshot manifest, plus the live early-warning layer and the first-paint briefing when present
    for path in (manifest, args.site / "live" / "early.json", args.site / "brief" / "briefing.json"):
        if path.is_file():
            sig = sign(seed, path.read_bytes())
            path.with_suffix(".sig").write_text(base64.b64encode(sig).decode() + "\n", encoding="ascii")
            print(f"sign_manifest: signed {path} with key {pk}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
