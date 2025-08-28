# src/rmap/rmap.py

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from .identity_manager import (
    IdentityManager,
    IdentityManagerError,
    DecryptionError,
    EncryptionError,
    UnknownIdentityError,
)


class RMAPError(Exception):
    """Base error for RMAP."""


class ValidationError(RMAPError):
    """Raised when an incoming message is malformed."""


def _is_u64(n: int) -> bool:
    return isinstance(n, int) and 0 <= n <= (2**64 - 1)


@dataclass
class RMAP:
    """
    RMAP server-side protocol logic.

    Responsibilities
    ---------------
    - Uses IdentityManager for all OpenPGP crypto.
    - Tracks per-identity (nonceClient, nonceServer) pairs after Message 1.
    - Produces JSON responses only (no networking, no side effects).

    Persistent State
    ----------------
    nonces: Dict[identity, (nonceClient, nonceServer)]
    identity_public_keys: Dict[identity, PGPKey] (view from IdentityManager)
    server_public_key / server_private_key: (views from IdentityManager)

    Usage
    -----
    >>> im = IdentityManager("./clients", "./server_pub.asc", "./server_priv.asc", None)
    >>> rmap = RMAP(im)
    >>> # Message 1 (encrypted to server's pubkey):
    >>> resp1 = rmap.handle_message1({"payload": "<base64-asc-pgp>"})
    >>> # Message 2 (encrypted to server's pubkey):
    >>> resp2 = rmap.handle_message2({"payload": "<base64-asc-pgp>"})
    """

    identity_manager: IdentityManager
    nonces: Dict[str, Tuple[int, int]] = field(default_factory=dict)

    # ---- Convenience views over IdentityManager (kept in sync on access) ----
    @property
    def identity_public_keys(self):
        return self.identity_manager.identity_public_keys

    @property
    def server_public_key(self):
        return self.identity_manager.server_public_key

    @property
    def server_private_key(self):
        return self.identity_manager.server_private_key

    # ---------------------------------------------------------------------- #
    # Message 1: Client -> Server
    # Incoming: {"payload": "<b64(ASCII-armored-PGP)>"}
    #   Decrypts to JSON: {"nonceClient": <u64>, "identity": "<str>"}
    # Response: {"payload": "<b64(ASCII-armored-PGP)>"} where decrypted JSON is:
    #   {"nonceClient": <u64>, "nonceServer": <u64>}
    # ---------------------------------------------------------------------- #
    def handle_message1(self, incoming: dict) -> dict:
        """
        Process Message 1 and return Response 1.

        Returns a dict either of shape:
          {"payload": "<base64-asc-pgp>"}  on success
        or {"error": "<reason>"}          on failure
        """
        try:
            payload_b64 = self._extract_payload(incoming)
            obj = self.identity_manager.decrypt_for_server(payload_b64)
            identity, nonce_client = self._parse_msg1(obj)
            if identity not in self.identity_public_keys:
                raise UnknownIdentityError(f"Unknown identity: {identity}")

            # Generate server nonce (u64)
            nonce_server = secrets.randbits(64)

            # Save/overwrite state for this identity
            self.nonces[identity] = (nonce_client, nonce_server)

            # Prepare response object and encrypt to the client's public key
            resp_obj = {"nonceClient": nonce_client, "nonceServer": nonce_server}
            payload_out = self.identity_manager.encrypt_for_identity(identity, resp_obj)
            return {"payload": payload_out}

        except (ValidationError, DecryptionError, EncryptionError, IdentityManagerError) as exc:
            return {"error": str(exc)}
        except Exception as exc:  # safety net
            return {"error": f"Unhandled error in handle_message1: {exc}"}

    # ---------------------------------------------------------------------- #
    # Message 2: Client -> Server
    # Incoming: {"payload": "<b64(ASCII-armored-PGP)>"}
    #   Decrypts to JSON: {"nonceServer": <u64>}
    # Response: {"result": "<hex-concat-NonceClient||NonceServer>"} (lowercase, no '0x')
    # The server looks up the identity via the nonceServer stored after Message 1.
    # ---------------------------------------------------------------------- #
    def handle_message2(self, incoming: dict) -> dict:
        """
        Process Message 2 and return the final result.

        Returns a dict either of shape:
          {"result": "<hex>"}             on success
        or {"error": "<reason>"}          on failure
        """
        try:
            payload_b64 = self._extract_payload(incoming)
            obj = self.identity_manager.decrypt_for_server(payload_b64)
            nonce_server = self._parse_msg2(obj)

            # Find which identity stored this nonceServer
            identity = self._find_identity_by_nonce_server(nonce_server)
            if identity is None:
                raise ValidationError("nonceServer does not match any pending session")

            nonce_client, stored_nonce_server = self.nonces[identity]
            if stored_nonce_server != nonce_server:
                # Extremely defensive check (shouldn't happen if lookup succeeded)
                raise ValidationError("nonceServer mismatch for resolved identity")

            # Concatenate as 128-bit value: NonceClient || NonceServer (big-endian)
            combined = (int(nonce_client) << 64) | int(nonce_server)
            # Produce zero-padded 32-hex-digit string (128 bits)
            hex_str = f"{combined:032x}"

            # Optionally clear state for one-time use
            # del self.nonces[identity]

            return {"result": hex_str}

        except (ValidationError, DecryptionError) as exc:
            return {"error": str(exc)}
        except Exception as exc:  # safety net
            return {"error": f"Unhandled error in handle_message2: {exc}"}

    # ----------------------------- Internals ------------------------------ #

    @staticmethod
    def _extract_payload(incoming: dict) -> str:
        if not isinstance(incoming, dict):
            raise ValidationError("Incoming message must be a JSON object")
        if "payload" not in incoming:
            raise ValidationError("Missing 'payload' field")
        payload = incoming["payload"]
        if not isinstance(payload, str) or not payload:
            raise ValidationError("'payload' must be a non-empty base64 string")
        return payload

    @staticmethod
    def _parse_msg1(obj: dict) -> Tuple[str, int]:
        if not isinstance(obj, dict):
            raise ValidationError("Decrypted payload must be a JSON object")
        if "identity" not in obj or "nonceClient" not in obj:
            raise ValidationError("Message 1 must contain 'identity' and 'nonceClient'")
        identity = obj["identity"]
        nonce_client = obj["nonceClient"]
        if not isinstance(identity, str) or not identity:
            raise ValidationError("'identity' must be a non-empty string")
        if not _is_u64(nonce_client):
            raise ValidationError("'nonceClient' must be a 64-bit unsigned integer")
        return identity, int(nonce_client)

    @staticmethod
    def _parse_msg2(obj: dict) -> int:
        if not isinstance(obj, dict):
            raise ValidationError("Decrypted payload must be a JSON object")
        if "nonceServer" not in obj:
            raise ValidationError("Message 2 must contain 'nonceServer'")
        nonce_server = obj["nonceServer"]
        if not _is_u64(nonce_server):
            raise ValidationError("'nonceServer' must be a 64-bit unsigned integer")
        return int(nonce_server)

    def _find_identity_by_nonce_server(self, nonce_server: int) -> Optional[str]:
        for ident, (_nc, ns) in self.nonces.items():
            if ns == nonce_server:
                return ident
        return None

    # ------------------------- Optional Helpers --------------------------- #

    def export_state(self) -> str:
        """
        Debug/diagnostic helper: returns a JSON string of current nonce state.
        Values are integers; keys are identities.
        """
        snapshot = {ident: {"nonceClient": nc, "nonceServer": ns} for ident, (nc, ns) in self.nonces.items()}
        return json.dumps(snapshot, sort_keys=True, indent=2)

