# RMAP-Server

Python implementation of the Roger Michael Authentication Protocol

Disclaimer: This library is intended to be use solely in the context of a software security course for pedagogical purposes.


## Usage

```python
#Creating an IdentityManager
IdentityManager(client_keys_dir, server_public_key_path, server_private_key_path, server_private_key_passphrase=None)
```
Arguments:

 - `client_keys_dir`: directory with client public keys named `<identity>.asc`.
If a private key is present by mistake, its public part is used.

 - `server_public_key_path` / `server_private_key_path`: server keypair (ASCII-armored).

 - Optional `server_private_key_passphrase` if the private key is protected.

```python
RMAP(identity_manager: IdentityManager)
```

## Handlers

 * `handle_message1(incoming: dict) -> dict`

    - Incoming JSON: `{"payload": "<base64(ASCII-armored PGP)>"}`

    - Decrypts to: `{"nonceClient": <u64>, "identity": "<str>"}` (encrypted to server)

    - On success: returns `{"payload": "<base64(...)>"}` where decrypted content is `{"nonceClient": <u64>, "nonceServer": <u64>}` (encrypted to the identity’s public key).

    - On error: `{"error": "<reason>"}`

 * `handle_message2(incoming: dict) -> dict`

    - Incoming JSON: `{"payload": "<base64(...)>"}`

    - Decrypts to: `{"nonceServer": <u64>}` (encrypted to server)

    - On success: `{"result": "<32-hex NonceClient||NonceServer>"}`

    - On error: `{"error": "<reason>"}`

### Notes

All integers are unsigned 64-bit (0 .. 2^64-1).

Payload strings are base64 of the ASCII-armored PGP message to keep JSON clean.

See `usage_example.py` for a complete, pretty-printed walkthrough.


### Message formats (decrypted):

```
    Message 1 (client → server)
    {"nonceClient": 54891657, "identity": "Jean"}

    Response 1 (server → client)
    {"nonceClient": 54891657, "nonceServer": 987612354}

    Message 2 (client → server)
    {"nonceServer": 987612354}

    Response 2 (server → client)
    {"result": "00000000348a2f...<total 32 hex chars>"}
```

### "Encrypted message format:

```json
    {"payload": "rhpnOFBUOE...=="}
```
Payload being a base64 payload encrypted with GPG.
