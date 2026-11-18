"""Web Push to the owner app: VAPID (RFC 8292) and aes128gcm payload encryption (RFC 8291).

Doorman signs every push with its own VAPID key and encrypts the payload to the subscribing
browser, so the push service (Google, Apple, Mozilla) sees only that a message went to an endpoint.
"""

import base64
import json
import os
import struct
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RECORD_SIZE = 4096
JWT_LIFETIME = 12 * 3600  # push services refuse VAPID tokens that live longer than 24 hours


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def raw_public(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """The 65-byte uncompressed P-256 point that browsers and push services exchange."""
    return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def _hmac(key: bytes, data: bytes) -> bytes:
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def load_subscriber_key(p256dh: str) -> bytes:
    """Checks a subscription's p256dh key and returns its raw bytes; raises ValueError if it isn't a P-256 point."""
    raw = b64url_decode(p256dh)
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    return raw


def encrypt(payload: bytes, p256dh: str, auth: str, *, salt: bytes | None = None,
            sender_key: ec.EllipticCurvePrivateKey | None = None) -> bytes:
    """Encrypts one payload for one subscription as a single aes128gcm record (RFC 8291, section 3.4)."""
    ua_public = load_subscriber_key(p256dh)
    auth_secret = b64url_decode(auth)
    sender_key = sender_key or ec.generate_private_key(ec.SECP256R1())
    as_public = raw_public(sender_key.public_key())
    salt = salt or os.urandom(16)
    header = salt + struct.pack("!IB", RECORD_SIZE, len(as_public)) + as_public
    if len(header) + len(payload) + 1 + 16 > RECORD_SIZE:  # delimiter and GCM tag; 3993 bytes at most
        raise ValueError("payload too large for one record")
    shared = sender_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public))
    ikm = _hmac(_hmac(auth_secret, shared), b"WebPush: info\x00" + ua_public + as_public + b"\x01")
    prk = _hmac(salt, ikm)
    cek = _hmac(prk, b"Content-Encoding: aes128gcm\x00\x01")[:16]
    nonce = _hmac(prk, b"Content-Encoding: nonce\x00\x01")[:12]
    ciphertext = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)  # 0x02 marks the last record
    return header + ciphertext


class Vapid:
    """Doorman's application server key: browsers subscribe with it, push services check it."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self.key = private_key

    @classmethod
    def generate(cls) -> "Vapid":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: str) -> "Vapid":
        key = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise ValueError("the VAPID key must be a P-256 private key")
        return cls(key)

    def to_pem(self) -> str:
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()).decode()

    @property
    def public_key(self) -> str:
        """The applicationServerKey the owner app passes to pushManager.subscribe()."""
        return b64url(raw_public(self.key.public_key()))

    def authorization(self, endpoint: str, subject: str, now: int) -> str:
        parts = urlsplit(endpoint)
        claims = {"aud": f"{parts.scheme}://{parts.netloc}", "exp": now + JWT_LIFETIME, "sub": subject}
        segments = [b64url(json.dumps(part, separators=(",", ":")).encode())
                    for part in ({"typ": "JWT", "alg": "ES256"}, claims)]
        signing_input = ".".join(segments).encode()
        r, s = decode_dss_signature(self.key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        signature = b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        return f"vapid t={'.'.join(segments)}.{signature}, k={self.public_key}"
