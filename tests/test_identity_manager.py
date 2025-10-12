# tests/test_identity_manager.py
#
# These tests use pre-generated keys from testassets/ (no key generation here).
# Assumed layout:
# testassets/
#   clients/
#     Jean.asc             # Jean's PUBLIC key
#     Jean_private.asc     # Jean's PRIVATE key (tests only)
#     Alice.asc            # Alice's PUBLIC key
#     Alice_private.asc    # Alice's PRIVATE key (tests only)
#   server_pub.asc         # Server PUBLIC key
#   server_priv.asc        # Server PRIVATE key (unprotected for tests)
#
# Note: IdentityManager loads every *.asc in clients/. If private keys are present
# in that folder, it will read them and use their .pubkey automatically, which is fine.
# For decrypting test outputs, we explicitly load the private keys ourselves.

import base64
import json
from pathlib import Path

import pytest
from pgpy import PGPKey, PGPMessage
from rmap.compat_helpers import _armored_from_armor_body

from rmap.identity_manager import (
    IdentityManager,
    UnknownIdentityError,
    DecryptionError,
)


@pytest.fixture(scope="module")
def testassets_dir() -> Path:
    # repo_root/tests/test_identity_manager.py -> repo_root
    return Path(__file__).resolve().parents[1] / "testassets"


@pytest.fixture()
def identity_manager_env(testassets_dir: Path):
    clients_dir = testassets_dir / "clients"
    server_pub_path = testassets_dir / "server_pub.asc"
    server_priv_path = testassets_dir / "server_priv.asc"

    # Sanity checks so failures are informative
    assert clients_dir.is_dir(), f"Missing clients dir: {clients_dir}"
    assert (clients_dir / "Jean.asc").is_file(), "Expected Jean.asc (public key)"
    assert (clients_dir / "Alice.asc").is_file(), "Expected Alice.asc (public key)"
    assert (clients_dir / "Jean_private.asc").is_file(), "Expected Jean_private.asc (private key for tests)"
    assert (clients_dir / "Alice_private.asc").is_file(), "Expected Alice_private.asc (private key for tests)"
    assert server_pub_path.is_file(), f"Missing server public key: {server_pub_path}"
    assert server_priv_path.is_file(), f"Missing server private key: {server_priv_path}"

    # Build IdentityManager from static assets
    im = IdentityManager(
        client_keys_dir=clients_dir,
        server_public_key_path=server_pub_path,
        server_private_key_path=server_priv_path,
    )

    # Load client private keys (ONLY for decrypting test outputs)
    jean_priv, _ = PGPKey.from_file(str(clients_dir / "Jean_private.asc"))
    alice_priv, _ = PGPKey.from_file(str(clients_dir / "Alice_private.asc"))

    return {
        "im": im,
        "jean_priv": jean_priv,
        "alice_priv": alice_priv,
        "clients_dir": clients_dir,
        "server_pub_path": server_pub_path,
        "server_priv_path": server_priv_path,
    }


def test_loads_identities_and_server_keys(identity_manager_env):
    im: IdentityManager = identity_manager_env["im"]

    # At minimum, "Jean" and "Alice" identities must be present
    idents = set(im.list_identities().keys())
    assert "Jean" in idents
    assert "Alice" in idents
    assert im.has_identity("Jean") is True
    assert im.has_identity("Alice") is True
    assert im.has_identity("Bob") is False

    # Export server pubkey (armored)
    asc = im.export_server_public_key_asc()
    assert "BEGIN PGP PUBLIC KEY BLOCK" in asc


def test_encrypt_for_server_and_decrypt_roundtrip(identity_manager_env):
    im: IdentityManager = identity_manager_env["im"]

    obj = {"nonceClient": 54891657, "identity": "Jean"}
    payload_b64 = im.encrypt_for_server(obj)

    out = im.decrypt_for_server(payload_b64)
    assert out == obj


def test_encrypt_for_identity_and_decrypt_with_client_priv(identity_manager_env):
    im: IdentityManager = identity_manager_env["im"]
    jean_priv: PGPKey = identity_manager_env["jean_priv"]

    resp_obj = {"nonceClient": 54891657, "nonceServer": 987612354}

    # Encrypt to Jean's public key (held by IdentityManager)
    payload_b64 = im.encrypt_for_identity("Jean", resp_obj)

    # Decrypt using Jean's private key to verify contents
    #armored = base64.b64decode(payload_b64).decode("utf-8")
    #pgp_msg = PGPMessage.from_blob(armored)
    pgp_msg = PGPMessage.from_blob(_armored_from_armor_body(payload_b64))
    decrypted = jean_priv.decrypt(pgp_msg).message
    out = json.loads(decrypted)

    assert out == resp_obj


def test_encrypt_for_unknown_identity_raises(identity_manager_env):
    im: IdentityManager = identity_manager_env["im"]
    with pytest.raises(UnknownIdentityError):
        im.encrypt_for_identity("Bob", {"foo": "bar"})


def test_decrypt_for_server_bad_base64_raises(identity_manager_env):
    im: IdentityManager = identity_manager_env["im"]
    with pytest.raises(DecryptionError):
        im.decrypt_for_server("not-a-base64-string!!")


def test_decrypt_for_server_non_json_raises(identity_manager_env):
    im: IdentityManager = identity_manager_env["im"]

    # Craft a valid PGP message to the server containing a NON-JSON plaintext
    msg = PGPMessage.new("this is not json")
    enc = im.server_public_key.encrypt(msg)
    payload_b64 = base64.b64encode(str(enc).encode("utf-8")).decode("ascii")

    with pytest.raises(DecryptionError):
        im.decrypt_for_server(payload_b64)

