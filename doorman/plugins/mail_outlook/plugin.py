"""Microsoft 365 / Outlook.com mail over IMAP and SMTP with XOAUTH2. Everything but the login is
mail_imap's.

Many university tenants don't let students consent to apps of their own (AADSTS65002, or "needs
admin approval"), but have Thunderbird allowed. So by default this signs in with Thunderbird's public
client id (no secret, redirect https://localhost), the way mutt_oauth2.py and email-oauth2-proxy do.
Set `client_id` (and `redirect_uri`) to use your own app registration instead.

Doorman does what email-oauth2-proxy would do: it keeps the refresh token in the vault, gets an
access token when it needs one, and logs in to outlook.office365.com and smtp.office365.com with
XOAUTH2. The agent never sees a token; it gets the same mail tools as with any IMAP account.

Exchange Online files mail sent through SMTP in Sent Items itself, so Doorman doesn't add a copy.
Two tenant settings can still stop this: IMAP switched off for the mailbox, and SMTP AUTH switched off
for the tenant (error 5.7.139). check() reports the first; a send reports the second as not sent.
Not tested against Microsoft; tests use a fake login and Dovecot/aiosmtpd with XOAUTH2.
"""

import smtplib

from imapclient import IMAPClient

from doorman.ms_login import THUNDERBIRD, MicrosoftLogin
from doorman.plugin_api import PluginError, before_sending
from doorman.plugins.mail_imap.plugin import Plugin as ImapPlugin

SCOPES = "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access"
DEFAULTS = {"imap_host": "outlook.office365.com", "imap_port": 993, "imap_security": "ssl",
            "smtp_host": "smtp.office365.com", "smtp_port": 587, "smtp_security": "starttls",
            "server_files_sent": True}


def xoauth2(user: str, token: str) -> str:
    return f"user={user}\x01auth=Bearer {token}\x01\x01"


class Plugin(MicrosoftLogin, ImapPlugin):
    DEFAULT_CLIENT_ID = THUNDERBIRD
    DEFAULT_TENANT = "common"
    DEFAULT_SCOPES = SCOPES
    DEFAULT_REDIRECT = "https://localhost"
    LOGIN_LABEL = "Outlook mail"

    def __init__(self, ctx, manifest):
        super().__init__(ctx, manifest)
        self.config = {**DEFAULTS, **{k: v for k, v in self.config.items() if v not in (None, "")}}

    def user(self) -> str:
        user = self.config.get("address") or self.credentials.get("account")
        if not user:
            raise PluginError(f"{self.ctx.instance}: set config.address (your mail address)")
        return user

    def login_hint(self):
        return self.config.get("address")

    def mailbox(self) -> str | None:
        try:
            user = self.user()
        except PluginError:
            return None
        return f"{user} on {self.config.get('imap_host')}".strip().lower()

    def sender(self):
        return self.config.get("from_address") or self.user()

    def imap_login(self, client: IMAPClient) -> None:
        user = self.user()
        try:
            client.oauth2_login(user, self.access_token())
        except IMAPClient.Error as exc:
            raise PluginError(f"Outlook refused the IMAP login for {user}: {exc}. If the Microsoft login "
                              "works, IMAP may be switched off for this mailbox.") from exc

    def smtp_send(self, message, recipients):
        before_sending(self.access_token)  # before connecting: an expired login means nothing went out
        super().smtp_send(message, recipients)

    def smtp_login(self, smtp: smtplib.SMTP, security: str) -> None:
        user, token = self.user(), self.access_token()
        smtp.ehlo_or_helo_if_needed()
        try:
            # the second call answers the server's error challenge with an empty line, as RFC 7628 asks
            smtp.auth("XOAUTH2", lambda challenge=None: xoauth2(user, token) if challenge is None else "")
        except smtplib.SMTPAuthenticationError as exc:
            if b"5.7.139" not in (exc.smtp_error or b""):
                raise
            hint = b" (SMTP AUTH is switched off for this tenant, so mail can't be sent this way)"
            raise smtplib.SMTPAuthenticationError(exc.smtp_code, exc.smtp_error + hint) from exc

    def check(self):
        problem = self.check_login()
        return problem or super().check()
