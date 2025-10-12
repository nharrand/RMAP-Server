#!/usr/bin/env python3
# rmap_client.py
"""
Forgiving RMAP client.

It:
  1) Loads the client's PRIVATE key (ASCII-armored .asc) and the server's PUBLIC key (.asc)
  2) Performs the RMAP handshake against an API:
       POST /api/rmap-initiate
       POST /api/rmap-get-link
       POST /api/rmap-get-link/<hex>
     trying up to three on-the-wire encodings for each message:
       (1) PGParmored_no_header_no_signing(msg)                 [armor body, no base64]
       (2) base64(PGParmored(msg))                              [full armor, base64]
       (3) base64(PGParmored_no_header_no_signing(msg))         [armor body, base64]
  3) Decrypts all server responses with a forgiving decoder
  4) Downloads the resulting PDF and saves it to an output directory

Usage:
  python rmap_client.py \
    --client-priv ./testassets/clients/Jean_private.asc \
    --identity "Jean" \
    --server-pub ./testassets/server_pub.asc \
    --server 127.0.0.1 \
    --outdir ./downloads
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
import secrets
import warnings
try:
    from cryptography.utils import CryptographyDeprecationWarning
except Exception:  # fallback, just in case
    CryptographyDeprecationWarning = DeprecationWarning

# Hide all cryptography deprecation warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
import requests
from pgpy import PGPKey

# Import the v2 compatibility helpers from your installed library
from rmap.compat_helpers import (
    _pgp_encrypt_armored_body,               # (1) armor body (no headers), NO base64
    _pgp_encrypt_armored_and_base64,         # (2) full armor, base64
    _pgp_encrypt_armored_body_and_base64,    # (3) armor body, base64
    decrypt_forgiving_json,                  # forgiving decrypt+JSON parse
)
from rmap.identity_manager import DecryptionError, EncryptionError  # for clear errors


# ------------------------- Pretty printing / colors ------------------------- #
class C:
    R = "\033[31m"   # red
    G = "\033[32m"   # green
    Y = "\033[33m"   # yellow
    B = "\033[34m"   # blue
    C = "\033[36m"   # cyan
    M = "\033[35m"   # magenta
    DIM = "\033[2m"
    RST = "\033[0m"


def info(msg: str): print(f"{C.C}• {msg}{C.RST}")
def step(msg: str): print(f"{C.B}⇒ {msg}{C.RST}")
def ok(msg: str):   print(f"{C.G}✓ {msg}{C.RST}")
def warn(msg: str): print(f"{C.Y}! {msg}{C.RST}")
def err(msg: str):  print(f"{C.R}✗ {msg}{C.RST}")


# ------------------------- Helpers ------------------------- #
def load_private_key(path: Path) -> PGPKey:
    try:
        key, _ = PGPKey.from_file(str(path))
    except Exception as e:
        raise RuntimeError(f"Failed to load client private key: {e}") from e
    if key.is_public:
        raise RuntimeError("Provided client key is a PUBLIC key; need a PRIVATE key")
    if key.is_protected:
        raise RuntimeError("Client private key is passphrase-protected; "
                           "provide an unprotected key for this client script.")
    return key


def load_public_key(path: Path) -> PGPKey:
    try:
        key, _ = PGPKey.from_file(str(path))
    except Exception as e:
        raise RuntimeError(f"Failed to load server public key: {e}") from e
    if not key.is_public:
        key = key.pubkey
    return key


def post_json(url: str, data: dict, timeout: float = 10.0) -> tuple[int, dict | None, str | None]:
    """Return (status_code, json_or_none, err_text_or_none)."""
    try:
        r = requests.post(url, json=data, timeout=timeout)
    except requests.RequestException as e:
        return (0, None, f"network error: {e}")
    try:
        return (r.status_code, r.json(), None)
    except Exception:
        return (r.status_code, None, r.text)


def try_send_payload(
    base_url: str,
    endpoint: str,
    plaintext_obj: dict,
    server_pub: PGPKey,
    try_order: list[str],
    who: str,
) -> tuple[str, dict, str]:
    """
    Attempt sending 'plaintext_obj' encrypted using each format in 'try_order'
    until the server responds with HTTP 200 and a JSON containing 'payload'.
    Returns (format_used, response_json, payload_str).
    """
    # map names -> encryptor
    encoders = {
        "armor_body": _pgp_encrypt_armored_body,
        "armored_b64": _pgp_encrypt_armored_and_base64,
        "armor_body_b64": _pgp_encrypt_armored_body_and_base64,
    }

    payload_json = json.dumps(plaintext_obj, separators=(",", ":"), sort_keys=True)

    for fmt in try_order:
        enc = encoders[fmt]
        step(f"{who}: trying format '{fmt}'")
        try:
            payload = enc(server_pub, payload_json)
        except Exception as e:
            warn(f"encryption failed for {fmt}: {e}")
            continue

        status, resp, raw = post_json(f"{base_url}{endpoint}", {"payload": payload})
        if status == 0:
            # unreachable – per spec, stop here (do not try other formats)
            raise RuntimeError(f"Server unreachable while calling {endpoint}: {raw}")
        if status >= 400 or not isinstance(resp, dict) or "error" in (resp or {}):
            warn(f"server error on {endpoint} with '{fmt}': "
                 f"{resp.get('error') if isinstance(resp, dict) else raw}")
            continue

        if "payload" not in resp:
            # Some servers may skip encryption and return plaintext fields; still accept for robustness
            return (fmt, resp, None)  # payload missing

        ok(f"{who}: server accepted format '{fmt}'")
        return (fmt, resp, resp["payload"])

    raise RuntimeError(f"All formats failed for {endpoint} (server reachable but returned errors).")


def main():
    ap = argparse.ArgumentParser(description="Forgiving RMAP client")
    ap.add_argument("--client-priv", required=True, type=Path, help="Path to client's PRIVATE key (.asc)")
    ap.add_argument("--identity", required=True, type=str, help='Client identity (e.g., "Jean" or "Group 7")')
    ap.add_argument("--server-pub", required=True, type=Path, help="Path to server PUBLIC key (.asc)")
    ap.add_argument("--server", required=True, type=str, help="Server IP or hostname (port is 5000)")
    ap.add_argument("--outdir", type=Path, default=Path("./downloads"), help="Directory to save the PDF")
    args = ap.parse_args()

    # Load keys
    step("Loading keys")
    client_priv = load_private_key(args.client_priv)
    server_pub = load_public_key(args.server_pub)
    ok("Keys loaded")
    
    rmap_client_run(client_priv, server_pub, args.server, args.identity, args.outdir)

def rmap_client_run(client_priv: PGPKey, server_pub: PGPKey, server_addr: str, identity: str, outdir: str):
    base_url = f"http://{server_addr}:5000"
    initiate_ep = "/api/rmap-initiate"
    getlink_ep = "/api/rmap-get-link"

    # Generate client nonce (u64)
    nonce_client = secrets.randbits(64)
    info(f"nonceClient = {nonce_client}")

    # 1) MESSAGE 1: initiate
    step("Sending Message 1 (/api/rmap-initiate)")

    # Try formats in this order
    order_m1 = ["armor_body", "armored_b64", "armor_body_b64"]
    fmt_used_m1, resp1, payload1 = try_send_payload(
        base_url,
        initiate_ep,
        {"identity": identity, "nonceClient": nonce_client},
        server_pub,
        order_m1,
        who="Message 1",
    )

    # Decrypt Response 1 (if encrypted)
    if payload1 is not None:
        try:
            plain1 = decrypt_forgiving_json(client_priv, payload1)
        except DecryptionError as e:
            raise RuntimeError(f"Failed to decrypt Response 1 payload: {e}") from e
    else:
        # Already plaintext JSON from server
        plain1 = resp1

    info("Response 1 (decrypted or plaintext):")
    print(json.dumps(plain1, indent=2, sort_keys=True))

    # Validate structure
    try:
        nc = int(plain1["nonceClient"])
        ns = int(plain1["nonceServer"])
    except Exception:
        raise RuntimeError("Response 1 missing 'nonceClient' or 'nonceServer'")

    if nc != nonce_client:
        warn(f"nonceClient mismatch (echoed={nc}, expected={nonce_client})")

    # 2) MESSAGE 2: confirm
    step("Sending Message 2 (/api/rmap-get-link)")

    # For Message 2, start with the format that worked for Message 1, then try the others
    order_m2 = [fmt_used_m1] + [x for x in ["armor_body", "armored_b64", "armor_body_b64"] if x != fmt_used_m1]

    fmt_used_m2, resp2, payload2 = try_send_payload(
        base_url,
        getlink_ep,
        {"nonceServer": ns},
        server_pub,
        order_m2,
        who="Message 2",
    )

    # Decrypt Response 2 (if encrypted)
    if payload2 is not None:
        try:
            plain2 = decrypt_forgiving_json(client_priv, payload2)
        except DecryptionError as e:
            raise RuntimeError(f"Failed to decrypt Response 2 payload: {e}") from e
    else:
        plain2 = resp2

    info("Response 2 (decrypted or plaintext):")
    print(json.dumps(plain2, indent=2, sort_keys=True))

    # Expect: {"result": "<32-hex NonceClient||NonceServer>"}
    if "result" not in plain2 or not isinstance(plain2["result"], str):
        raise RuntimeError("Response 2 does not contain a 'result' string")
    link_hex = plain2["result"]
    ok(f"Received secret link token: {link_hex}")

    # 3) DOWNLOAD the PDF
    step(f"Downloading PDF via /api/get-version/{link_hex}")
    status, _, raw = post_json(f"{base_url}/api/get-version/{link_hex}", {})
    if status == 0:
        raise RuntimeError(f"Server unreachable during PDF download: {raw}")

    # When endpoint returns a binary PDF with POST, many servers still return JSON unless configured.
    # If we got JSON or text, try a second attempt using requests directly to fetch content.
    resp = requests.get(f"{base_url}/api/get-version/{link_hex}", json={}, timeout=15)
    if resp.status_code >= 400:
        raise RuntimeError(f"Download failed: HTTP {resp.status_code}: {resp.text}")

    pdf_bytes = resp.content
    # Rudimentary content-type check
    ctype = resp.headers.get("Content-Type", "")
    if "pdf" not in ctype.lower():
        warn(f"Content-Type is '{ctype}' (expected PDF). Proceeding to save anyway.")

    outdir.mkdir(parents=True, exist_ok=True)
    # Filename: <identity>_<first8 of token>.pdf
    fname = f"{identity.replace(' ', '_')}_{link_hex[:8]}.pdf"
    outpath = outdir / fname
    outpath.write_bytes(pdf_bytes)
    ok(f"Saved file: {outpath.resolve()}")

    print()
    ok("RMAP client run finished successfully.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        err("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        err(str(e))
        sys.exit(1)

