# tests/test_rmap.py

import base64
import json
from pathlib import Path

import pytest
from pgpy import PGPKey, PGPMessage

from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP


@pytest.fixture(scope="module")
def testassets_dir() -> Path:
    # repo_root/tests/test_rmap.py -> repo_root
    return Path(__file__).resolve().parents[1] / "testassets"


@pytest.fixture()
def rmap_env(testassets_dir: Path):
    """
    Build an RMAP environment from static keys in testassets/.
    """
    clients_dir = testassets_dir / "clients"
    server_pub = testassets_dir / "server_pub.asc"
    server_priv = testassets_dir / "server_priv.asc"

    assert clients_dir.is_dir(), f"Missing clients dir: {clients_dir}"
    assert server_pub.is_file(), f"Missing server public key: {server_pub}"
    assert server_priv.is_file(), f"Missing server private key: {server_priv}"

    im = IdentityManager(
        client_keys_dir=clients_dir,
        server_public_key_path=server_pub,
        server_private_key_path=server_priv,
    )
    rmap = RMAP(im)

    # Load Jean's private key (tests only; not used by the library)
    jean_priv_path = clients_dir / "Jean_private.asc"
    assert jean_priv_path.is_file(), f"Missing client private key: {jean_priv_path}"
    jean_priv, _ = PGPKey.from_file(str(jean_priv_path))

    return {"im": im, "rmap": rmap, "jean_priv": jean_priv}


def test_message1_success_flow(rmap_env):
    im: IdentityManager = rmap_env["im"]
    rmap: RMAP = rmap_env["rmap"]
    jean_priv: PGPKey = rmap_env["jean_priv"]

    nonce_client = 54891657
    msg1_plain = {"nonceClient": nonce_client, "identity": "Jean"}
    msg1 = {"payload": im.encrypt_for_server(msg1_plain)}

    resp1 = rmap.handle_message1(msg1)
    assert "payload" in resp1 and "error" not in resp1

    # Client (Jean) decrypts response to verify it's encrypted to her key
    armored = base64.b64decode(resp1["payload"]).decode("utf-8")
    pgp = PGPMessage.from_blob(armored)
    plaintext = jean_priv.decrypt(pgp).message
    out = json.loads(plaintext)

    assert out["nonceClient"] == nonce_client
    assert isinstance(out["nonceServer"], int)
    assert 0 <= out["nonceServer"] <= 2**64 - 1

    # Server stored nonces
    assert "Jean" in rmap.nonces
    nc, ns = rmap.nonces["Jean"]
    assert nc == nonce_client
    assert ns == out["nonceServer"]


def test_message1_unknown_identity(rmap_env):
    im: IdentityManager = rmap_env["im"]
    rmap: RMAP = rmap_env["rmap"]

    msg1_plain = {"nonceClient": 1, "identity": "Bob"}  # not in clients/
    msg1 = {"payload": im.encrypt_for_server(msg1_plain)}

    resp1 = rmap.handle_message1(msg1)
    assert "error" in resp1
    assert "Unknown identity" in resp1["error"]


def test_message1_bad_payload(rmap_env):
    rmap: RMAP = rmap_env["rmap"]

    # Not base64
    resp1 = rmap.handle_message1({"payload": "!!!not_base64!!!"})
    assert "error" in resp1


def test_message2_success_flow(rmap_env):
    im: IdentityManager = rmap_env["im"]
    rmap: RMAP = rmap_env["rmap"]

    # First, complete message 1 to establish nonces
    nonce_client = 123456789
    msg1_plain = {"nonceClient": nonce_client, "identity": "Jean"}
    msg1 = {"payload": im.encrypt_for_server(msg1_plain)}
    resp1 = rmap.handle_message1(msg1)
    assert "payload" in resp1

    # Extract nonceServer from stored state
    nc, ns = rmap.nonces["Jean"]
    assert nc == nonce_client

    # Message 2: send back nonceServer (encrypted to server)
    msg2_plain = {"nonceServer": ns}
    msg2 = {"payload": im.encrypt_for_server(msg2_plain)}

    resp2 = rmap.handle_message2(msg2)
    assert "result" in resp2 and "error" not in resp2

    # Check hex concatenation: NonceClient || NonceServer (big-endian)
    combined = (nonce_client << 64) | ns
    expected_hex = f"{combined:032x}"
    assert resp2["result"] == expected_hex
    assert len(resp2["result"]) == 32
    int(resp2["result"], 16)  # parses as hex


def test_message2_nonce_not_found(rmap_env):
    im: IdentityManager = rmap_env["im"]
    rmap: RMAP = rmap_env["rmap"]

    # Send a nonceServer that doesn't exist
    msg2_plain = {"nonceServer": 2**63}  # arbitrary, no session
    msg2 = {"payload": im.encrypt_for_server(msg2_plain)}

    resp2 = rmap.handle_message2(msg2)
    assert "error" in resp2
    assert "does not match any pending session" in resp2["error"]


def test_message2_bad_payload(rmap_env):
    rmap: RMAP = rmap_env["rmap"]
    resp2 = rmap.handle_message2({"payload": "not_base64"})
    assert "error" in resp2

