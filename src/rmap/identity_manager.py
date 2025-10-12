# src/rmap/identity_manager.py

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Dict, Optional, Union
from rmap.compat_helpers import decrypt_forgiving_json, _armor_body_from_armored

try:
    # Pure-Python OpenPGP implementation (no gpg binary required)
    from pgpy import PGPKey, PGPMessage
    from pgpy.constants import PubKeyAlgorithm  # noqa: F401  (kept for future extensions)
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "The 'pgpy' package is required for IdentityManager. "
        "Install with: pip install pgpy"
    ) from exc


class IdentityManagerError(Exception):
    """Base class for IdentityManager exceptions."""


class UnknownIdentityError(IdentityManagerError):
    """Raised when an operation references an unknown identity."""


class DecryptionError(IdentityManagerError):
    """Raised when a payload cannot be decrypted."""


class EncryptionError(IdentityManagerError):
    """Raised when a payload cannot be encrypted."""


class IdentityManager:
    """
    Handles all cryptographic operations for RMAP using OpenPGP keys.

    Conventions
    ----------
    - Incoming and outgoing "payload" fields are Base64 strings of the *ASCII-armored*
      OpenPGP message. This keeps JSON clean and portable.
    - Decryption uses the server's private key.
    - Encryption targets a specific client's public key, chosen by identity.

    Parameters
    ----------
    client_keys_dir : Union[str, Path]
        Directory containing client **public** keys (*.asc), named by identity
        (e.g., "Jean.asc" => identity "Jean").
    server_public_key_path : Union[str, Path]
        Path to the server **public** key (.asc).
    server_private_key_path : Union[str, Path]
        Path to the server **private** key (.asc).
    server_private_key_passphrase : Optional[str]
        Passphrase used to unlock the server private key, if it is protected.

    Attributes
    ----------
    identity_public_keys : Dict[str, PGPKey]
        Mapping of identity -> PGP public key object.
    server_public_key : PGPKey
    server_private_key : PGPKey
    """

    def __init__(
        self,
        client_keys_dir: Union[str, Path],
        server_public_key_path: Union[str, Path],
        server_private_key_path: Union[str, Path],
        server_private_key_passphrase: Optional[str] = None,
    ) -> None:
        self._client_dir = Path(client_keys_dir)
        self._server_pub_path = Path(server_public_key_path)
        self._server_priv_path = Path(server_private_key_path)
        self._server_passphrase = server_private_key_passphrase

        if not self._client_dir.is_dir():
            raise FileNotFoundError(f"Client keys directory not found: {self._client_dir}")
        if not self._server_pub_path.is_file():
            raise FileNotFoundError(f"Server public key not found: {self._server_pub_path}")
        if not self._server_priv_path.is_file():
            raise FileNotFoundError(f"Server private key not found: {self._server_priv_path}")

        # Load server keys
        self.server_public_key, _ = PGPKey.from_file(str(self._server_pub_path))
        self.server_private_key, _ = PGPKey.from_file(str(self._server_priv_path))

        # Load client public keys by identity (file stem)
        self.identity_public_keys: Dict[str, PGPKey] = {}
        for asc_path in sorted(self._client_dir.glob("*.asc")):
            identity = asc_path.stem
            try:
                key, _ = PGPKey.from_file(str(asc_path))
            except Exception as exc:
                raise IdentityManagerError(
                    f"Failed to load client public key '{asc_path}': {exc}"
                ) from exc

            if not key.is_public:
                # If a private key was accidentally provided, take its public part
                key = key.pubkey
            self.identity_public_keys[identity] = key

        if not self.identity_public_keys:
            raise IdentityManagerError(
                f"No client public keys (*.asc) found in directory: {self._client_dir}"
            )

    # -------------------------
    # Public API
    # -------------------------

    def list_identities(self) -> Dict[str, str]:
        """
        Returns a mapping of identity -> key fingerprint (string).
        Useful for diagnostics and tests.
        """
        return {ident: str(key.fingerprint) for ident, key in self.identity_public_keys.items()}

    def has_identity(self, identity: str) -> bool:
        """Check whether a public key for the given identity is loaded."""
        return identity in self.identity_public_keys

    def encrypt_for_identity(self, identity: str, payload_obj: dict) -> str:
        """
        Encrypt a JSON-serializable object for the given identity's public key.

        Returns
        -------
        str
            Base64 string of the ASCII-armored OpenPGP ciphertext.
            Example output shape for JSON message:
            {"payload": "<base64-of-ascii-armored-pgp-message>"}
        """
        if identity not in self.identity_public_keys:
            raise UnknownIdentityError(f"Unknown identity: {identity}")

        try:
            plaintext = _json_compact_dumps(payload_obj)
            message = PGPMessage.new(plaintext)
            encrypted = self.identity_public_keys[identity].encrypt(message)
            armored = str(encrypted)  # ASCII-armored PGP message (-----BEGIN PGP MESSAGE----- ...)
            #return base64.b64encode(armored.encode("utf-8")).decode("ascii")
            return _armor_body_from_armored(armored)
        except Exception as exc:
            raise EncryptionError(f"Failed to encrypt for identity '{identity}': {exc}") from exc

    def decrypt_for_server(self, payload_b64: str) -> dict:
        """
        Decrypt a Base64-encoded, ASCII-armored OpenPGP message using the server's private key.

        Parameters
        ----------
        payload_b64 : str
            Base64 string of ASCII-armored PGP ciphertext.

        Returns
        -------
        dict
            The parsed JSON object carried in the decrypted message.

        Raises
        ------
        DecryptionError
            If the payload cannot be base64-decoded, decrypted, or parsed as JSON.
        """
        # Decode Base64 to get the ASCII-armored PGP text

        try:
            return decrypt_forgiving_json(self.server_private_key, payload_b64, self._server_passphrase)
        except Exception as exc:
            raise DecryptionError(f"Decrypted payload is not valid JSON: {exc}") from exc

    def export_server_public_key_asc(self) -> str:
        """Return the server's public key in ASCII-armored form."""
        return str(self.server_public_key)

    # -------------------------
    # Helper for tests / utilities
    # -------------------------
        
    def encrypt_for_server(self, payload_obj: dict) -> str:
        """
        Utility: encrypt a JSON object **to the server's public key**.
        This mirrors what a client would do and is useful for unit tests.

        Returns
        -------
        str
            Base64 string of the ASCII-armored OpenPGP ciphertext.
        """
        try:
            plaintext = _json_compact_dumps(payload_obj)
            message = PGPMessage.new(plaintext)
            encrypted = self.server_public_key.encrypt(message)
            armored = str(encrypted)
            return base64.b64encode(armored.encode("utf-8")).decode("ascii")
            #return cleanup(armored)
        except Exception as exc:
            raise EncryptionError(f"Failed to encrypt for server: {exc}") from exc


# -------------------------
# Internal utilities
# -------------------------


def _json_compact_dumps(obj: dict) -> str:
    """
    Deterministically encode JSON without spaces/newlines, to get stable ciphertexts in tests.
    """
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, sort_keys=True)

