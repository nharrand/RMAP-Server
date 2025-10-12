# src/rmap/compat_helpers.py
"""
Compatibility helpers for RMAP v2.
This module provides three encrypt/decrypt helpers (one per format) and a
'decrypt_forgiving_json' that tries all formats until it can parse a JSON object.

Message formats handled
-----------------------
1) base64(PGParmored(msg))
   -> encrypt: _pgp_encrypt_armored_and_base64
   -> decrypt: _pgp_decrypt_armored_b64

2) base64(PGParmored_no_header_no_signing(msg))
   -> encrypt: _pgp_encrypt_armored_body_and_base64
   -> decrypt: _pgp_decrypt_armored_body_b64

3) PGParmored_no_header_no_signing(msg)      # i.e., the ASCII-armor BODY ONLY
   -> encrypt: _pgp_encrypt_armored_body
   -> decrypt: _pgp_decrypt_armored_body

Notes
-----
- "no signing" simply means we perform encryption-only (the default with PGPy).
- "armor body" means the lines between the blank line after the BEGIN header
  and the END footer; this includes the CRC line that starts with '=', if present.
- These helpers are intentionally low-level; your higher-level code can select
  a preferred format or call `decrypt_forgiving_json` for backward compatibility.
"""

from __future__ import annotations

import base64
import json
from typing import Optional, Tuple

from pgpy import PGPKey, PGPMessage

# Reuse your project's exceptions if available; fall back to plain Exceptions.
try:
    from .identity_manager import DecryptionError, EncryptionError  # type: ignore
except Exception:  # pragma: no cover
    class DecryptionError(Exception): ...
    class EncryptionError(Exception): ...


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _armor_body_from_armored(armored_text: str) -> str:
    """
    Extract the ASCII-armor BODY ONLY (including the CRC line if present),
    i.e., the lines between the first blank line after BEGIN and the END line.
    Preserves internal newlines.
    """
    lines = armored_text.splitlines()
    if not lines:
        raise DecryptionError("Empty armored text")

    # Find "-----BEGIN" line
    try:
        begin_idx = next(i for i, ln in enumerate(lines) if ln.startswith("-----BEGIN "))
    except StopIteration:
        raise DecryptionError("BEGIN armor header not found")

    # Find the blank line that separates headers from body (may be immediately after BEGIN)
    i = begin_idx + 1
    while i < len(lines) and lines[i].strip() != "":
        # skip header fields like 'Version:' or 'Comment:'
        i += 1
    if i >= len(lines):
        raise DecryptionError("Armor body separator not found")

    body_start = i + 1  # first line after the blank line
    # Find END
    try:
        end_idx = next(i for i, ln in enumerate(lines) if ln.startswith("-----END "))
    except StopIteration:
        raise DecryptionError("END armor footer not found")

    # Body is between body_start (inclusive) and end_idx (exclusive)
    body_lines = lines[body_start:end_idx]
    if not body_lines:
        raise DecryptionError("Empty armor body")

    # Keep original newlines (important for CRC line that starts with '=')
    return "\n".join(body_lines).rstrip()  # strip trailing whitespace/newlines


def _armored_from_armor_body(armor_body: str) -> str:
    """
    Construct a full ASCII-armored PGP message from a BODY ONLY string.
    We do not add Version/Comment headers; we keep the body as-is.
    """
    return "-----BEGIN PGP MESSAGE-----\n\n" + armor_body.strip() + "\n-----END PGP MESSAGE-----\n"


def _encrypt_to_armored(pubkey: PGPKey, plaintext: str) -> str:
    """
    Encrypt 'plaintext' to 'pubkey' and return full ASCII-armored ciphertext.
    (Encryption only; no signing)
    """
    try:
        msg = PGPMessage.new(plaintext)
        enc = pubkey.encrypt(msg)
        return str(enc)  # ASCII-armored text with headers/footers
    except Exception as exc:  # pragma: no cover
        raise EncryptionError(f"PGP encryption failed: {exc}") from exc


def _decrypt_armored_with_key(privkey: PGPKey, armored_text: str, passphrase: Optional[str]) -> str:
    """
    Decrypt ASCII-armored ciphertext with the provided private key.
    Returns the plaintext string.
    """
    try:
        pgp_msg = PGPMessage.from_blob(armored_text)
    except Exception as exc:
        raise DecryptionError(f"Invalid armored message: {exc}") from exc

    try:
        if privkey.is_protected and passphrase is None:
            raise DecryptionError("Private key requires a passphrase")

        if privkey.is_protected:
            with privkey.unlock(passphrase):
                dec = privkey.decrypt(pgp_msg)
        else:
            dec = privkey.decrypt(pgp_msg)

        return dec.message
    except DecryptionError:
        raise
    except Exception as exc:
        raise DecryptionError(f"PGP decryption failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Encrypt helpers (3 formats)
# ---------------------------------------------------------------------------

def _pgp_encrypt_armored_and_base64(pubkey: PGPKey, text: str) -> str:
    """
    Format #1: base64(PGParmored(msg))

    Returns: ASCII string (base64)
    """
    armored = _encrypt_to_armored(pubkey, text)
    return base64.b64encode(armored.encode("utf-8")).decode("ascii")


def _pgp_encrypt_armored_body_and_base64(pubkey: PGPKey, text: str) -> str:
    """
    Format #2: base64(PGParmored_no_header_no_signing(msg))

    Steps: encrypt -> ASCII-armor -> extract BODY ONLY -> base64-encode that body (including CRC line)
    Returns: ASCII string (base64)
    """
    armored = _encrypt_to_armored(pubkey, text)
    body = _armor_body_from_armored(armored)  # keep internal newlines/CRC
    return base64.b64encode(body.encode("ascii")).decode("ascii")


def _pgp_encrypt_armored_body(pubkey: PGPKey, text: str) -> str:
    """
    Format #3: PGParmored_no_header_no_signing(msg)

    Steps: encrypt -> ASCII-armor -> return BODY ONLY (including CRC line), as a multi-line string.
    Returns: ASCII string (may include newlines)
    """
    armored = _encrypt_to_armored(pubkey, text)
    return _armor_body_from_armored(armored)


# ---------------------------------------------------------------------------
# Decrypt helpers (3 formats)
# ---------------------------------------------------------------------------

def _pgp_decrypt_armored_b64(privkey: PGPKey, payload_b64: str, passphrase: Optional[str] = None) -> str:
    """
    Format #1: base64(PGParmored(msg)) -> plaintext
    """
    try:
        armored = base64.b64decode("".join(payload_b64.split()), validate=False)
    except Exception as exc:
        raise DecryptionError(f"Invalid base64 for armored message: {exc}") from exc
    return _decrypt_armored_with_key(privkey, armored, passphrase)


def _pgp_decrypt_armored_body_b64(privkey: PGPKey, payload_b64: str, passphrase: Optional[str] = None) -> str:
    """
    Format #2: base64(PGParmored_no_header_no_signing(msg)) -> plaintext

    Steps: base64-decode -> reconstruct full ASCII-armored message -> decrypt
    """
    try:
        body = base64.b64decode("".join(payload_b64.split()), validate=False)
    except Exception as exc:
        raise DecryptionError(f"Invalid base64 for armor body: {exc}") from exc

    armored = _armored_from_armor_body(body)
    return _decrypt_armored_with_key(privkey, armored, passphrase)


def _pgp_decrypt_armored_body(privkey: PGPKey, payload_body: str, passphrase: Optional[str] = None) -> str:
    """
    Format #3: PGParmored_no_header_no_signing(msg) -> plaintext

    Steps: build full ASCII-armored message around the provided BODY ONLY -> decrypt
    """
    if not isinstance(payload_body, str) or not payload_body.strip():
        raise DecryptionError("Armor body payload must be a non-empty ASCII string")
    armored = _armored_from_armor_body(payload_body)
    return _decrypt_armored_with_key(privkey, armored, passphrase)



# ---------------------------------------------------------------------------
# Forgiving decoder (tries all formats until it can parse JSON)
# ---------------------------------------------------------------------------

def decrypt_forgiving_json(
    privkey: PGPKey,
    payload: str,
    passphrase: Optional[str] = None,
) -> dict:
    """
    Try to decrypt 'payload' assuming each known on-the-wire format, in order:

        1) base64(PGParmored(msg))
        2) base64(PGParmored_no_header_no_signing(msg))
        3) PGParmored_no_header_no_signing(msg)

    For each attempt, also parse the resulting plaintext as JSON.
    Returns the parsed JSON object on the first success.

    Raises DecryptionError with a summary of all failures otherwise.
    """
    errors: list[Tuple[str, str]] = []

    # Attempt 1
    try:
        plain1 = _pgp_decrypt_armored_b64(privkey, payload, passphrase)
        return json.loads(plain1)
    except Exception as exc1:
        errors.append(("base64(PGParmored)", str(exc1)))

    # Attempt 2
    try:
        plain2 = _pgp_decrypt_armored_body_b64(privkey, payload, passphrase)
        return json.loads(plain2)
    except Exception as exc2:
        errors.append(("base64(armor_body)", str(exc2)))

    # Attempt 3
    try:
        plain3 = _pgp_decrypt_armored_body(privkey, payload, passphrase)
        return json.loads(plain3)
    except Exception as exc3:
        errors.append(("armor_body", str(exc3)))

    # If we reach here, all attempts failed
    details = "; ".join([f"{fmt}: {err}" for fmt, err in errors])
    raise DecryptionError(f"decrypt_forgiving_json failed for all formats ({details})")

