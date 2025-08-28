# usage_example.py
"""
End-to-end example of the RMAP flow using the package.

It:
  1) Loads pre-made keys from ./testassets
  2) Builds IdentityManager and RMAP
  3) Simulates the full two-message handshake for identity "Jean"
  4) Pretty-prints every message both ENCRYPTED (JSON with base64 payload)
     and DECRYPTED (plaintext JSON)

Assumed layout (created by the keygen script you ran earlier):

testassets/
  clients/
    Jean.asc
    Jean_private.asc
  server_pub.asc
  server_priv.asc
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from pgpy import PGPKey, PGPMessage

# --- Allow running without installing the package (`pip install -e .`)  ----
# If 'rmap' can't be imported, fall back to adding ./src to sys.path.
try:
    from rmap.identity_manager import IdentityManager
    from rmap.rmap import RMAP
except ModuleNotFoundError:
    repo_root = Path(__file__).resolve().parent
    src_dir = repo_root / "src"
    sys.path.insert(0, str(src_dir))
    from rmap.identity_manager import IdentityManager  # type: ignore
    from rmap.rmap import RMAP  # type: ignore


def pp(title: str, obj) -> None:
    print(f"\n=== {title} ===")
    if isinstance(obj, (dict, list)):
        print(json.dumps(obj, indent=2, sort_keys=True))
    else:
        print(obj)


def main() -> None:
    repo_root = Path(__file__).resolve().parent
    assets = repo_root / "testassets"
    clients_dir = assets / "clients"
    server_pub = assets / "server_pub.asc"
    server_priv = assets / "server_priv.asc"
    jean_priv_path = clients_dir / "Jean_private.asc"

    # Sanity checks
    for p in [clients_dir, server_pub, server_priv, jean_priv_path]:
        if not p.exists():
            raise FileNotFoundError(f"Missing required asset: {p}")

    # Build crypto manager + RMAP
    im = IdentityManager(
        client_keys_dir=clients_dir,
        server_public_key_path=server_pub,
        server_private_key_path=server_priv,
    )
    rmap = RMAP(im)

    # Load Jean's private key so the "client" can decrypt server responses (demo only)
    jean_priv, _ = PGPKey.from_file(str(jean_priv_path))

    # ---------------------------
    # Client -> Server : Message 1
    # ---------------------------
    nonce_client = 54891657
    msg1_plain = {"nonceClient": nonce_client, "identity": "Jean"}
    msg1 = {"payload": im.encrypt_for_server(msg1_plain)}

    pp("Client→Server | Message 1 (decrypted)", msg1_plain)
    pp("Client→Server | Message 1 (encrypted JSON)", msg1)

    # Server decrypts to show what's inside (for demo)
    srv_seen_msg1 = im.decrypt_for_server(msg1["payload"])
    pp("Server view after decrypting Message 1", srv_seen_msg1)

    # Server handles Message 1 and sends Response 1 (encrypted to Jean's public key)
    resp1 = rmap.handle_message1(msg1)
    if "error" in resp1:
        pp("Server→Client | Response 1 (ERROR)", resp1)
        return
    pp("Server→Client | Response 1 (encrypted JSON)", resp1)

    # Client decrypts Response 1 with Jean's private key to inspect it
    armored = base64.b64decode(resp1["payload"]).decode("utf-8")
    pgp_msg = PGPMessage.from_blob(armored)
    resp1_plain = json.loads(jean_priv.decrypt(pgp_msg).message)
    pp("Server→Client | Response 1 (decrypted)", resp1_plain)

    # ---------------------------
    # Client -> Server : Message 2
    # ---------------------------
    # Use the nonceServer provided by the server in Response 1
    nonce_server = int(resp1_plain["nonceServer"])
    msg2_plain = {"nonceServer": nonce_server}
    msg2 = {"payload": im.encrypt_for_server(msg2_plain)}

    pp("Client→Server | Message 2 (decrypted)", msg2_plain)
    pp("Client→Server | Message 2 (encrypted JSON)", msg2)

    # Server decrypts Message 2 (for demo)
    srv_seen_msg2 = im.decrypt_for_server(msg2["payload"])
    pp("Server view after decrypting Message 2", srv_seen_msg2)

    # Server handles Message 2 and returns the final result (hex string)
    resp2 = rmap.handle_message2(msg2)
    if "error" in resp2:
        pp("Server→Client | Response 2 (ERROR)", resp2)
        return
    pp("Server→Client | Response 2 (hex result)", resp2)

    # Validate the hex concatenation locally for demonstration
    combined = (int(nonce_client) << 64) | int(nonce_server)
    expected_hex = f"{combined:032x}"
    print("\nVerification:", "OK ✅" if resp2["result"] == expected_hex else "MISMATCH ❌")


if __name__ == "__main__":
    main()

