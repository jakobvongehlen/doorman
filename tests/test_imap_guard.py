"""SafeIMAPClient against a stand-in IMAP server, so it runs without Dovecot (test_mail_imap needs one)."""
import base64
import socketserver
import threading

import pytest

from doorman.plugin_api import Denied
from doorman.plugins.mail_imap.plugin import SafeIMAPClient


class XOAuthIMAP(socketserver.StreamRequestHandler):
    """Just enough IMAP for a sign-in with AUTHENTICATE XOAUTH2, the way Microsoft 365 takes it."""

    def handle(self):
        self.wfile.write(b"* OK ready\r\n")
        while line := self.rfile.readline():
            tag, command = (line.decode().split() + ["", ""])[:2]
            command = command.upper()
            if command == "CAPABILITY":
                self.wfile.write(f"* CAPABILITY IMAP4rev1 AUTH=XOAUTH2\r\n{tag} OK done\r\n".encode())
            elif command == "AUTHENTICATE":
                self.wfile.write(b"+ \r\n")
                self.server.signed_in.append(base64.b64decode(self.rfile.readline().strip()))
                self.wfile.write(f"{tag} OK signed in\r\n".encode())
            elif command == "LOGOUT":
                self.wfile.write(f"* BYE\r\n{tag} OK bye\r\n".encode())
                return
            else:
                self.wfile.write(f"{tag} BAD not here\r\n".encode())


@pytest.fixture
def server():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), XOAuthIMAP)
    srv.daemon_threads = True  # a client that failed mid-command leaves its connection open: don't wait for it
    srv.block_on_close = False
    srv.signed_in = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_xoauth2_sign_in_passes_the_line_break_guard(server):
    """imaplib tells AUTHENTICATE's answer (a method it calls for each challenge) from a literal by comparing
    its type with type(self._command). The guard that keeps line breaks out of commands wraps _command; as a
    plain function it made every XOAUTH2 sign-in (mail_outlook) fail with "object of type 'method' has no
    len()", while password logins went on working."""
    client = SafeIMAPClient("127.0.0.1", port=server.server_address[1], ssl=False, timeout=5)
    client.oauth2_login("anna@uni.example", "token-1")
    assert server.signed_in == [b"user=anna@uni.example\x01auth=Bearer token-1\x01\x01"]
    with pytest.raises(Denied, match="line break"):  # the guard is still on imaplib's door
        client._imap._command("SELECT", b"INBOX\r\nA2 DELETE INBOX")
    client.logout()
