"""Passkeys (WebAuthn) for owner login and for signing approvals."""

import json
import secrets
from datetime import timedelta
from urllib.parse import urlparse

from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from . import clock
from .auth import Auth
from .plugin_api import Denied

CHALLENGE_MINUTES = 5


class Passkeys:
    def __init__(self, db, public_url: str):
        self.db = db
        parsed = urlparse(public_url)
        self.rp_id = parsed.hostname
        self.origin = f"{parsed.scheme}://{parsed.netloc}"

    # challenge bookkeeping

    def _store_challenge(self, purpose: str, challenge: bytes, ref: str | None = None) -> str:
        challenge_id = secrets.token_hex(8)
        self.db.exec("INSERT INTO challenges(id, purpose, challenge, created, ref) VALUES(?,?,?,?,?)",
                     (challenge_id, purpose, challenge, clock.iso(), ref))
        return challenge_id

    def _take_challenge(self, challenge_id: str, purpose: str) -> tuple[bytes, str | None]:
        row = self.db.one("SELECT * FROM challenges WHERE id=? AND purpose=?", (challenge_id or "", purpose))
        self.db.exec("DELETE FROM challenges WHERE id=?", (challenge_id or "",))
        oldest = clock.iso(clock.now() - timedelta(minutes=CHALLENGE_MINUTES))
        self.db.exec("DELETE FROM challenges WHERE created<?", (oldest,))
        if row is None or row["created"] < oldest:
            raise Denied("the passkey prompt expired; try again", "challenge")
        return row["challenge"], row["ref"]

    def credentials(self) -> list[dict]:
        rows = self.db.all("SELECT id, label, created, sign_count, rp_id FROM webauthn_credentials ORDER BY created")
        for row in rows:  # a passkey works only on the domain it was made on; unknown for ones from before
            row["here"] = row["rp_id"] in (None, self.rp_id)
        return rows

    def remove(self, credential_id: str) -> dict:
        """Never the last one: without a passkey nobody can log in until a setup code from the host. The
        device it was on is logged out and gets no more pushes (Auth.end_passkey_sessions)."""
        with self.db.tx() as conn:
            count = conn.execute("SELECT COUNT(*) FROM webauthn_credentials").fetchone()[0]
            if not conn.execute("SELECT 1 FROM webauthn_credentials WHERE id=?", (credential_id,)).fetchone():
                raise Denied("no such passkey", "not_found")
            if count <= 1:
                raise Denied("that's your only passkey; add another one first", "last_passkey")
            conn.execute("DELETE FROM webauthn_credentials WHERE id=?", (credential_id,))
            return Auth(self.db).end_passkey_sessions(credential_id, conn)

    def has_credentials(self) -> bool:
        return bool(self.db.one("SELECT 1 AS x FROM webauthn_credentials LIMIT 1"))

    # registration

    def registration_options(self) -> dict:
        # Only passkeys made on this domain: a password manager refuses a new one when it holds any listed id,
        # even one made for an old address it would never offer here (Bitwarden, Vaultwarden).
        existing = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"])) for c in self.credentials()
                    if c["rp_id"] == self.rp_id]
        options = generate_registration_options(
            rp_id=self.rp_id, rp_name="Doorman", user_name="owner", user_id=b"broker-owner",  # from before the rename; registered passkeys carry this handle
            user_display_name="Owner",
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED),
            exclude_credentials=existing,
        )
        challenge_id = self._store_challenge("register", options.challenge)
        return {"challenge_id": challenge_id, "options": json.loads(options_to_json(options))}

    def register(self, challenge_id: str, credential: dict, label: str) -> str:
        challenge, _ = self._take_challenge(challenge_id, "register")
        try:
            verified = verify_registration_response(
                credential=credential, expected_challenge=challenge, expected_rp_id=self.rp_id,
                expected_origin=self.origin, require_user_verification=True)
        except InvalidRegistrationResponse as exc:
            raise Denied(f"passkey registration failed: {exc}", "passkey") from None
        credential_id = bytes_to_base64url(verified.credential_id)
        self.db.exec("INSERT INTO webauthn_credentials(id, public_key, sign_count, label, created, rp_id) "
                     "VALUES(?,?,?,?,?,?)", (credential_id, verified.credential_public_key, verified.sign_count,
                                             label[:100], clock.iso(), self.rp_id))
        return credential_id

    # authentication: login, or signing a specific challenge (approvals)

    def authentication_options(self, purpose: str, challenge: bytes | None = None, ref: str | None = None) -> dict:
        allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"])) for c in self.credentials() if c["here"]]
        if not allow:
            raise Denied("no passkey for this address yet; add one with a setup code", "passkey")
        options = generate_authentication_options(
            rp_id=self.rp_id, challenge=challenge, allow_credentials=allow,
            user_verification=UserVerificationRequirement.REQUIRED)
        challenge_id = self._store_challenge(purpose, options.challenge, ref)
        return {"challenge_id": challenge_id, "options": json.loads(options_to_json(options))}

    def verify(self, challenge_id: str, purpose: str, credential: dict,
               expected_challenge: bytes | None = None, ref: str | None = None) -> str:
        challenge, stored_ref = self._take_challenge(challenge_id, purpose)
        if expected_challenge is not None and challenge != expected_challenge:
            raise Denied("this signature is for a different payload", "passkey")
        if ref is not None and stored_ref != ref:
            raise Denied("this signature is for a different request", "passkey")
        row = self.db.one("SELECT * FROM webauthn_credentials WHERE id=?", (credential.get("id", ""),))
        if row is None:
            raise Denied("unknown passkey", "passkey")
        try:
            verified = verify_authentication_response(
                credential=credential, expected_challenge=challenge, expected_rp_id=self.rp_id,
                expected_origin=self.origin, credential_public_key=row["public_key"],
                credential_current_sign_count=row["sign_count"], require_user_verification=True)
        except InvalidAuthenticationResponse as exc:
            raise Denied(f"passkey check failed: {exc}", "passkey") from None
        self.db.exec("UPDATE webauthn_credentials SET sign_count=? WHERE id=?", (verified.new_sign_count, row["id"]))
        return row["id"]
