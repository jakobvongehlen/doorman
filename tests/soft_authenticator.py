"""A minimal software passkey (P-256, attestation 'none') for testing WebAuthn flows."""

import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self, rp_id: str, origin: str):
        self.rp_id = rp_id
        self.origin = origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.sign_count = 0

    def _cose_key(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})

    def _auth_data(self, attested: bool) -> bytes:
        self.sign_count += 1
        flags = 0x01 | 0x04 | (0x40 if attested else 0)
        data = hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.sign_count)
        if attested:
            data += bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id + self._cose_key()
        return data

    def _client_data(self, kind: str, challenge: str) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": self.origin,
                           "crossOrigin": False}).encode()

    def create(self, options: dict) -> dict:
        client_data = self._client_data("webauthn.create", options["challenge"])
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": self._auth_data(True)})
        return {"id": b64url(self.credential_id), "rawId": b64url(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64url(client_data), "attestationObject": b64url(attestation)},
                "clientExtensionResults": {}}

    def get(self, options: dict) -> dict:
        client_data = self._client_data("webauthn.get", options["challenge"])
        auth_data = self._auth_data(False)
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64url(self.credential_id), "rawId": b64url(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64url(client_data), "authenticatorData": b64url(auth_data),
                             "signature": b64url(signature), "userHandle": b64url(b"doorman-owner")},
                "clientExtensionResults": {}}
