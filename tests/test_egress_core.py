"""Network watch, the shared core (doorman/egress/): fingerprints of what the agent read, the decoding that
finds them again inside an outgoing request, the owner's rules, and the GeoIP table. These modules run in
the proxy's image too, without Doorman's dependencies, so they may import only the standard library."""

import base64
import gzip
import hashlib
import json
import os
import subprocess
import sys
import time
import zlib
from pathlib import Path
from urllib.parse import quote, urlencode

import pytest

from doorman.egress import decode, fingerprint, geoip, rules
from doorman.egress.fingerprint import K, W, normalize, prints, prints_of_data, strings_of
from doorman.egress.rules import Conn, decide, parse_target, matches

ROOT = Path(__file__).resolve().parent.parent

MAIL = ("Hi Robin, thanks for sending the draft of the funding application so quickly. I went through the "
        "budget section with Marieke this morning and we both think the travel costs for the Lisbon workshop "
        "are too low; the hotel alone will be around 140 euros a night in September. Could you also add the "
        "two student assistants for the second year? The deadline at the faculty office is Friday at noon, "
        "so I would like to send it to Prof. Müller by Thursday evening. Café on Monday? Best, Annelies")
SECRET = MAIL[60:360]  # the 300-character excerpt an agent might paste somewhere

RECIPE = ("Preheat the oven to 180 degrees. Whisk the eggs with the sugar until pale and fluffy, then fold in "
          "the flour, a pinch of salt and the melted butter. Pour the batter into a greased tin and bake for "
          "about thirty five minutes, until a skewer comes out clean. Let it cool before slicing.")


def leaked(texts: list[str], secret: str = SECRET) -> bool:
    want = prints(secret)
    return any(prints(t) & want for t in texts)


# ---------------------------------------------------------------------- fingerprints

def test_normalize_drops_datamark_and_punctuation():
    assert normalize("Helloˆworld, 42!") == "helloworld42"
    assert normalize("ＦＵＬＬ width ﬁ Straße") == "fullwidthfistrasse"  # NFKC, then casefold
    assert normalize("") == ""


def test_short_text_has_no_prints():
    assert prints("") == set()
    assert prints("Re: Lisbon workshop") == set()
    assert prints("Annelies de Vries <annelies@uni.example>") != set()  # 31 normalized characters
    exact = "abcdefghijklmnopqrstuvwx"
    assert len(normalize(exact)) == K and len(prints(exact)) == 1
    assert prints(exact[:-1]) == set()
    # subjects and names alone never produce prints, so they can't match anything
    assert prints_of_data([{"subject": "Lunch?", "from": "Anna"}, {"subject": "Re: budget"}]) == set()


def test_same_text_same_prints_across_spacing():
    plain = prints(MAIL)
    assert plain
    assert prints(MAIL.replace(" ", "ˆ")) == plain  # how the agent saw it: datamarked
    assert prints(MAIL.replace(" ", "\n")) == plain
    assert prints(MAIL.upper()) == plain
    assert prints("  ".join(MAIL.split())) == plain


def test_substring_of_35_chars_shares_a_print():
    assert W + K - 1 == 35
    norm = normalize(MAIL)
    full = prints(MAIL)
    for i in range(len(norm) - 35 + 1):
        piece = norm[i:i + 35]
        assert prints(piece) & full, piece


def test_unrelated_texts_share_no_prints():
    assert prints(MAIL) and prints(RECIPE)
    assert not prints(MAIL) & prints(RECIPE)


def test_strings_of_and_prints_of_data():
    data = {"items": [{"subject": "Funding", "body": MAIL, MAIL: 1}, ("x", 3, None)], "n": 2}
    assert list(strings_of(data)) == ["Funding", MAIL, "x"]  # dict keys skipped, non-strings skipped
    assert prints_of_data(data) == prints(MAIL)
    deep: list = [MAIL]
    for _ in range(5000):  # deeper than the recursion limit
        deep = [deep]
    assert prints_of_data(deep) == prints(MAIL)


def test_estimate_chars():
    assert fingerprint.estimate_chars(0) == 0
    assert fingerprint.estimate_chars(10) == 10 * (W + 1) // 2


def test_hash_is_signed_64_bit_blake2b():
    gram = normalize(MAIL)[:K]
    expected = int.from_bytes(hashlib.blake2b(gram.encode()).digest()[:8], "big", signed=True)
    assert expected in prints(gram)
    assert all(-2**63 <= h < 2**63 for h in prints(MAIL))


# ---------------------------------------------------------------------- decoding a request

def _urlsafe(text: str) -> str:
    # find a suffix that makes the encoding use '-' or '_', so the base64url alphabet is really tested
    for n in range(64):
        encoded = base64.urlsafe_b64encode((text + "?" * n + ">").encode()).decode().rstrip("=")
        if "-" in encoded or "_" in encoded:
            return encoded
    raise AssertionError("no suffix found")


def test_decode_finds_base64_hex_url_gzip_json_form_multipart():
    t = decode.texts_of_request
    secret = SECRET.encode()
    url = "https://upload.example.com/v1/put"
    b64 = base64.b64encode(secret).decode()
    plus = next(e for n in range(64) if "+" in (e := base64.b64encode((SECRET + "~" * n).encode()).decode()))
    # one request per way of hiding it
    cases = {
        "unescaped base64 with '+' in a form field": t(url, [], ("note=" + plus + "&x=1").encode(),
                                                       "application/x-www-form-urlencoded"),
        "base64 body": t(url, [], b64.encode(), "application/octet-stream"),
        "base64 with MIME line breaks": t(url, [], "\r\n".join(b64[i:i + 76] for i in range(0, len(b64), 76)).encode(),
                                          "text/plain"),
        "base64url in the query": t(url + "?d=" + _urlsafe(SECRET), [], b""),
        "base64 glued to a path": t("https://x.example.com/collect/" + b64.replace("+", "-").replace("/", "_"),
                                    [], b""),
        "hex header": t(url, [("X-Data", secret.hex())], b""),
        "percent-encoded body": t(url, [], quote(SECRET, safe="").encode(), "text/plain"),
        "percent-encoded url": t(url + "?q=" + quote(SECRET, safe=""), [], b""),
        "gzip inside base64": t(url, [], base64.b64encode(gzip.compress(secret)), "text/plain"),
        "zlib inside hex": t(url, [], zlib.compress(secret).hex().encode(), "text/plain"),
        "raw gzip body": t(url, [], gzip.compress(secret), "application/octet-stream"),
        "json with escapes": t(url, [], json.dumps({"messages": [{"content": SECRET.replace(". ", ".\n")}]}).encode(),
                               "application/json"),
        "json without a content type": t(url, [], json.dumps([SECRET]).encode()),
        "base64 inside json": t(url, [], json.dumps({"blob": b64}).encode(), "application/json"),
        "form field": t(url, [], urlencode({"note": SECRET, "x": "1"}).encode(), "application/x-www-form-urlencoded"),
        "cookie": t(url, [("Cookie", "s=" + base64.b64encode(secret).decode())], b""),
        "base64 of base64 (depth 2)": t(url, [], base64.b64encode(b64.encode()), "text/plain"),
    }
    boundary = "----doormanboundary7MA4YWxkTrZu0gW"
    multipart = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nNotes\r\n"
                 f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"n.txt\"\r\n"
                 f"Content-Type: text/plain; charset=utf-8\r\n\r\n{SECRET}\r\n"
                 f"--{boundary}\r\nContent-Disposition: form-data; name=\"gz\"; filename=\"n.gz\"\r\n"
                 f"Content-Type: application/gzip\r\n\r\n").encode() + gzip.compress(RECIPE.encode()) + \
        f"\r\n--{boundary}--\r\n".encode()
    multi = t(url, [], multipart, f"multipart/form-data; boundary={boundary}")
    cases["multipart"] = multi
    for name, texts in cases.items():
        assert leaked(texts), name
    assert leaked(multi, RECIPE)  # the gzip file part, inflated


def test_decode_scans_every_header_but_fixed_vocabularies():
    # the agent writes every header (Host, User-Agent, cookies, Sec-*): all of them can carry data
    for name in ("Host", "User-Agent", "Accept-Language", "If-None-Match", "Cache-Control", "Content-Type",
                 "Sec-Fetch-Mode", "Cookie", "X-Note", "Accept-Encoding", "Connection"):
        texts = decode.texts_of_request("https://example.com/", [(name, MAIL)], b"")
        assert leaked(texts, MAIL), name
    assert decode.SKIP_HEADERS == {"content-length"}  # digits, checked by mitmproxy
    # what real clients send gives no prints at all: too short, so nothing to ask Doorman about
    real = [("Host", "api.github.com"), ("User-Agent", "curl/8.5.0"), ("Accept", "*/*"),
            ("Accept-Encoding", "gzip, deflate, br, zstd"), ("Connection", "keep-alive"),
            ("Accept-Language", "de-DE,de;q=0.9,en;q=0.8")]
    assert not any(prints(t) for t in decode.texts_of_request("https://api.github.com/", real, b""))


def test_random_base64_is_not_text():
    url = "https://api.example.com/v1/items"
    for _ in range(50):
        blob = base64.b64encode(os.urandom(32)).decode()
        assert decode.texts_of_request(url, [], json.dumps({"token": blob}).encode(), "application/json") \
            == ["/v1/items", blob]
        urlsafe = base64.urlsafe_b64encode(os.urandom(48)).decode()
        assert decode.texts_of_request(url + "?sig=" + urlsafe, [("Authorization", "Bearer " + blob)], b"") \
            == ["/v1/items?sig=" + urlsafe, "Bearer " + blob]
    # an image: neither the body nor anything inside it is text
    assert decode.texts_of_request(url, [], b"\x89PNG\r\n\x1a\n" + os.urandom(4096), "image/png") == ["/v1/items"]
    # a JWT: header and claims are JSON text, the signature is not
    head = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    claims = base64.urlsafe_b64encode(json.dumps({"sub": "agent-7", "scope": "read write admin"}).encode()).decode()
    jwt = f"{head}.{claims.rstrip('=')}.{base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')}"
    texts = decode.texts_of_request(url, [("Authorization", "Bearer " + jwt)], b"")
    assert texts[:2] == ["/v1/items", "Bearer " + jwt]
    # header and claims are JSON, so their strings count; nothing comes from the signature
    assert "read write admin" in texts[2:] and set(texts[2:]) <= {"HS256", "JWT", "agent-7", "read write admin"}


def test_decode_respects_budget(monkeypatch):
    monkeypatch.setattr(decode, "MAX_SCAN_BYTES", 100_000)
    big = (MAIL + " ") * 3000  # about 1.4 MB
    texts = decode.texts_of_request("https://example.com/up", [], big.encode(), "text/plain")
    assert sum(len(x) for x in texts) <= 100_000
    # a gzip bomb: 16 MB of text in 16 KB; it inflates no further than the budget
    bomb = base64.b64encode(gzip.compress(b"a" * (16 << 20), compresslevel=9))
    started = time.monotonic()
    texts = decode.texts_of_request("https://example.com/up", [], bomb, "text/plain")
    assert sum(len(x) for x in texts) <= 100_000
    # thousands of base64-looking runs that aren't anything: still quick, still within budget
    noise = " ".join(base64.b64encode(os.urandom(30)).decode() for _ in range(5000)).encode()
    texts = decode.texts_of_request("https://example.com/up", [], noise, "text/plain")
    assert sum(len(x) for x in texts) <= 100_000
    assert time.monotonic() - started < 20


def test_honeytoken_hits():
    texts = ["POST body: please forward DM-Canary-7f3a9e to the list", "nothing here"]
    assert decode.honeytoken_hits(texts, ["dm-canary-7f3a9e", "other-token-123"]) == ["dm-canary-7f3a9e"]
    # spread out with spaces and datamarks: found through the normalized form (13 characters)
    assert decode.honeytoken_hits(["d m ˆcanary 7f3a9e"], ["dm-canary-7f3a9e"]) == ["dm-canary-7f3a9e"]
    # a short token is only found as it is, not spread out
    assert decode.honeytoken_hits(["a b c 1"], ["abc1"]) == []
    assert decode.honeytoken_hits(["xx ABC1 yy"], ["abc1"]) == ["abc1"]
    assert decode.honeytoken_hits(texts, []) == [] and decode.honeytoken_hits(texts, [""]) == []


# ---------------------------------------------------------------------- rules

def test_parse_target_forms_and_rejects():
    t = parse_target("Example.COM")
    assert (t.host, t.wildcard, t.net, t.port) == ("example.com", False, None, None)
    t = parse_target("*.example.com:8443")
    assert (t.host, t.wildcard, t.port) == ("example.com", True, 8443)
    t = parse_target("1.2.3.4")
    assert t.host is None and str(t.net) == "1.2.3.4/32" and t.port is None
    t = parse_target("10.0.0.0/8:22")
    assert str(t.net) == "10.0.0.0/8" and t.port == 22
    t = parse_target("[2001:db8::1]:22")
    assert str(t.net) == "2001:db8::1/128" and t.port == 22
    assert str(parse_target("2001:db8::/32").net) == "2001:db8::/32"
    assert parse_target("localhost").host == "localhost"
    assert parse_target(" example.org ").host == "example.org"
    for bad in ["", "  ", "exa mple.com", "https://example.com", "example.com/path", "example.com:0",
                "example.com:70000", "example.com:http", "*", "*.", "-bad-.com", "a..b", "[2001:db8::1",
                "ex$ample.com", "10.0.0.0/33", "example.com:22:33"]:
        assert parse_target(bad) is None, bad


def test_matches_suffix_wildcard_cidr_port():
    t = parse_target
    assert matches(t("example.com"), "example.com", None, 443)
    assert matches(t("example.com"), "api.Example.com.", None, 443)
    assert not matches(t("example.com"), "badexample.com", None, 443)
    assert not matches(t("*.example.com"), "example.com", None, 443)
    assert matches(t("*.example.com"), "a.b.example.com", None, 443)
    assert matches(t("10.0.0.0/8"), None, "10.1.2.3", 22)
    assert not matches(t("10.0.0.0/8"), None, "11.1.2.3", 22)
    assert matches(t("10.0.0.0/8"), "10.9.9.9", None, 22)  # an IP literal as the host
    assert matches(t("1.2.3.4"), None, "::ffff:1.2.3.4", 80)  # IPv4-mapped IPv6
    assert not matches(t("1.2.3.4"), None, "2001:db8::1", 80)
    assert matches(t("[2001:db8::1]:22"), None, "2001:db8::1", 22)
    assert matches(t("example.com:22"), "git.example.com", None, 22)
    assert not matches(t("example.com:22"), "git.example.com", None, 443)
    assert not matches(t("example.com"), None, "1.2.3.4", 443)
    assert not matches(t("1.2.3.4"), "example.com", None, 443)
    assert not matches(t("1.2.3.4"), None, "not an ip", 443)


def _policy(**changes) -> dict:
    policy = rules.policy_example()
    policy.update(changes)
    return policy


def test_decide_order_and_copy():
    now = time.time()

    def d(conn: Conn, **changes):
        decision = decide(_policy(**changes), conn)
        return decision.action, decision.rule, decision.detail

    post = Conn("http", "webhook.site", "46.4.105.116", 443, method="POST", now=now)
    assert d(post) == ("deny", "exfil_upload",
                       "webhook.site is a paste, webhook or tunnel service; uploads to it are blocked")
    assert d(Conn("http", "abc.ngrok-free.app", None, 443, method="PUT", now=now))[1] == "exfil_upload"
    assert d(Conn("http", "webhook.site", None, 443, method="GET", now=now))[:2] == ("allow", "default")
    assert d(post, exemptions=[{"target": "webhook.site", "expires": now + 60}])[:2] == ("allow", "exemption")
    assert d(post, allow=["webhook.site"])[:2] == ("allow", "allow_list")
    # the allow list beats the deny list, an exemption beats both
    assert d(post, allow=["webhook.site"], deny=["webhook.site"])[:2] == ("allow", "allow_list")
    assert d(post, deny=["other.example", "webhook.site"]) == \
        ("deny", "deny_list", "webhook.site is on the owner's deny list")
    assert d(post, deny=["webhook.site"], exemptions=[{"target": "webhook.site:443", "expires": now + 60}])[:2] == \
        ("allow", "exemption")

    tunnel = Conn("dns", "nbswy3dpeb3w64tmmqqgc3tegbxxe3dfmuyde.attacker.example", None, 53, now=now)
    assert d(tunnel) == ("deny", "dns_tunnel", "the name looks like data hidden in DNS")
    assert d(Conn("dns", "mail.google.com", None, 53, now=now))[:2] == ("allow", "default")

    ru = Conn("http", "news.example", "5.6.7.8", 443, country="RU", now=now)
    assert d(ru) == ("deny", "countries", "5.6.7.8 is in RU, a country on the owner's block list")
    assert d(Conn("http", "news.example", "5.6.7.8", 443, country="NL", now=now))[:2] == ("allow", "default")

    assert d(Conn("http", "invoice.ZIP", None, 443, now=now)) == \
        ("deny", "risky_tlds", ".zip is on the list of domains often used for abuse")

    bare = Conn("tcp", None, "203.0.113.5", 22, now=now)
    assert d(bare) == ("deny", "bare_ip_nonweb", "a port 22 connection to a bare IP address that no name lookup led to")
    assert d(Conn("tcp", "203.0.113.5", "203.0.113.5", 22, now=now))[1] == "bare_ip_nonweb"
    named = Conn("tcp", "git.example.com", "203.0.113.5", 22, resolved=True, now=now)
    assert d(named)[:2] == ("allow", "default")
    assert d(Conn("tcp", None, "203.0.113.5", 22, resolved=True, now=now))[:2] == ("allow", "default")
    assert d(named, nonweb="block") == ("deny", "nonweb_block", "only web traffic is allowed here (port 22)")

    # a category switched off doesn't block
    off = {**rules.policy_example()["categories"], "exfil_upload": False, "bare_ip_nonweb": False}
    assert d(post, categories=off)[:2] == ("allow", "default")
    assert d(bare, categories=off)[:2] == ("allow", "default")
    assert d(Conn("http", "example.com", "93.184.215.14", 443, method="GET", now=now)) == ("allow", "default", "")


def test_exemption_expiry():
    now = time.time()
    post = Conn("http", "paste.ee", None, 443, method="POST", now=now)
    assert decide(_policy(exemptions=[{"target": "paste.ee", "expires": now - 1}]), post).rule == "exfil_upload"
    assert decide(_policy(exemptions=[{"target": "paste.ee", "expires": now + 1}]), post).rule == "exemption"
    # a broken entry is ignored rather than breaking the decision
    assert decide(_policy(exemptions=[{"target": "not a target", "expires": now + 9}]), post).rule == "exfil_upload"


def test_dns_suspicious():
    assert rules.dns_suspicious("a" * 51 + ".x.com")
    assert not rules.dns_suspicious("mail.google.com")
    assert not rules.dns_suspicious("mail.google.com.")
    label = base64.b32encode(hashlib.sha256(b"doorman").digest()[:20]).decode().lower()
    assert len(label) == 32 and rules.dns_suspicious(label + ".evil.example")
    assert rules.dns_suspicious(".".join(["abcdefghij"] * 12) + ".com")  # longer than 120
    # long but plain words are a normal name
    assert not rules.dns_suspicious("storage-account-backups-westeurope.blob.example.net")
    assert not rules.dns_suspicious("")
    assert not rules.dns_suspicious("production-database-replica-eu-west.example.com")
    assert rules.dns_suspicious("446561722042616b6f622c20796f7572206772.evil.example")  # hex of a mail
    assert rules.dns_suspicious("3a9f0c2be4d17785a1c09e6b2f4d8e10.evil.example")  # hex of random bytes


def test_default_lists():
    exfil = rules.default_list("exfil_hosts")
    for host in ["pastebin.com", "webhook.site", "ngrok-free.app", "trycloudflare.com", "oast.fun", "paste.rs"]:
        assert host in exfil
    assert all(parse_target(h) for h in exfil)
    risky = rules.default_list("risky_tlds")
    assert {"zip", "mov", "tk", "top", "su"} <= set(risky)
    assert not any(x.startswith("#") or not x for x in exfil + risky)
    with pytest.raises(ValueError):
        rules.default_list("../secrets")


def test_policy_example_decides():
    policy = rules.policy_example()
    assert set(policy) == {"version", "nonweb", "web_ports", "categories", "countries", "risky_tlds", "exfil_hosts",
                           "deny", "allow", "passthrough", "no_scan", "exemptions", "honeytokens", "decoys",
                           "when_doorman_down", "unscanned", "match"}
    assert len(policy["version"]) == 64 and policy["version"] == rules.policy_version(policy)
    assert policy["match"] == {"k": K, "w": W, "note_chars": 40}
    assert policy["web_ports"] == [80, 443, 8080, 8443] and policy["when_doorman_down"] == "allow"
    assert "api.anthropic.com" in policy["no_scan"] and policy["countries"] == ["RU", "BY", "KP", "IR"]
    json.dumps(policy)
    assert decide(policy, Conn("http", "example.com", None, 443, method="GET", now=time.time())).action == "allow"
    assert decide(policy, Conn("http", "pastebin.com", None, 443, method="POST", now=time.time())).action == "deny"
    changed = {**policy, "allow": ["example.org"]}
    assert rules.policy_version(changed) != policy["version"]


# ---------------------------------------------------------------------- GeoIP

GEO_CSV = "1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.3.255,CN\n5.6.0.0,5.6.255.255,RU\n2001:db8::,2001:db8::ffff,NL\n"


@pytest.mark.parametrize("packed", [False, True])
def test_geoip_lookup(tmp_path, packed):
    if packed:
        path = tmp_path / "dbip-country-lite-2026-11.csv.gz"
        path.write_bytes(gzip.compress(GEO_CSV.encode()))
    else:
        path = tmp_path / "countries.csv"
        path.write_text(GEO_CSV)
    db = geoip.GeoIP.load(str(path))
    assert db.rows == 3  # the IPv6 row is left out
    assert db.date == ("2026-11" if packed else None)
    assert db.country("1.0.0.0") == "AU" and db.country("1.0.0.255") == "AU"
    assert db.country("1.0.1.0") == "CN" and db.country("1.0.2.7") == "CN" and db.country("1.0.3.255") == "CN"
    assert db.country("5.6.7.8") == "RU" and db.country("::ffff:5.6.7.8") == "RU"
    assert db.country("0.255.255.255") is None and db.country("1.0.4.0") is None
    assert db.country("255.255.255.255") is None and db.country("2001:db8::1") is None
    assert db.country("nonsense") is None


# ---------------------------------------------------------------------- the proxy image has no dependencies

def test_core_imports_only_the_standard_library():
    # -I -S: no site-packages at all, so a third-party import would fail; and nothing outside the
    # standard library may show up in sys.modules
    code = ("import sys; sys.path.insert(0, sys.argv[1]);"
            "import doorman.egress.fingerprint, doorman.egress.decode, doorman.egress.rules,"
            " doorman.egress.geoip, doorman.egress.observer;"
            "print(sorted({m.split('.')[0] for m in sys.modules} - set(sys.stdlib_module_names)"
            " - {'doorman', '__main__'}))")
    out = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(ROOT)],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"


# ---------------------------------------------------------------------- review fixes: decoding

def _shared(texts, secret=SECRET):
    want = prints(secret)
    got = set()
    for t in texts:
        got |= prints(t)
    return len(got & want) / len(want)


def test_decode_survives_charsets_bom_and_stray_bytes():
    t = decode.texts_of_request
    url = "https://x.example.com/up"
    cases = {
        "trailing 0xff": t(url, [], SECRET.encode() + b"\xff", "text/plain"),
        "a stray byte in the middle": t(url, [], SECRET[:150].encode() + b"\xfe" + SECRET[150:].encode(),
                                         "text/plain"),
        "latin-1 form": t(url, [], ("note=Grüße " + SECRET).encode("latin-1"),
                          "application/x-www-form-urlencoded"),
        "a form field without '='": t(url, [], ("Grüße " + SECRET).encode("latin-1"),
                                      "application/x-www-form-urlencoded"),
        "a form field's name": t(url, [], (SECRET.replace(" ", "+") + "=1").encode(),
                                 "application/x-www-form-urlencoded"),
        "utf-16 with charset": t(url, [], SECRET.encode("utf-16"), "text/plain; charset=utf-16"),
        "utf-16 BOM, no charset": t(url, [], SECRET.encode("utf-16"), "application/octet-stream"),
        "utf-16-le without BOM": t(url, [], SECRET.encode("utf-16-le"), ""),
        "utf-32 BOM": t(url, [], SECRET.encode("utf-32"), ""),
        "declared cp1252": t(url, [], ("Grüße " + SECRET).encode("cp1252"), "text/plain; charset=windows-1252"),
        "\\x01 between characters": t(url, [], "\x01".join(SECRET).encode(), "text/plain"),
        "NULs between characters": t(url, [], "\x00".join(SECRET).encode(), "text/plain"),
        "secret in random binary": t(url, [], os.urandom(4000) + SECRET.encode() + os.urandom(4000),
                                     "application/octet-stream"),
        "secret behind a binary header in base64": t(url, [], base64.b64encode(os.urandom(3000) + SECRET.encode()),
                                                     "text/plain"),
    }
    for name, texts in cases.items():
        assert _shared(texts) > 0.8, name


def test_decode_unwraps_deeper_than_two():
    t = decode.texts_of_request
    url = "https://x.example.com/up"
    b3 = base64.b64encode(base64.b64encode(base64.b64encode(SECRET.encode())))
    gg = gzip.compress(gzip.compress(SECRET.encode()))
    mixed = base64.b64encode(zlib.compress(base64.b64encode(gzip.compress(SECRET.encode())))).hex().encode()
    assert decode.MAX_DEPTH >= 6
    assert leaked(t(url, [], b3, "text/plain")), "triple base64"
    assert leaked(t(url, [], gg, "application/octet-stream")), "double gzip"
    assert leaked(t(url, [], base64.b64encode(gg), "text/plain")), "double gzip in base64"
    assert leaked(t(url, [], mixed, "text/plain")), "hex of base64 of zlib of base64 of gzip"


def test_decode_deep_json_does_not_raise():
    body = ("[" * 100_000 + "]" * 100_000).encode()
    decode.texts_of_request("/", [], body, "application/json")  # no RecursionError
    nested = ("[" * 100_000 + json.dumps(SECRET) + "]" * 100_000).encode()
    assert leaked(decode.texts_of_request("/", [], nested, "application/json"))


def test_random_binary_still_gives_no_text():
    url = "https://api.example.com/v1/items"
    for _ in range(20):
        assert decode.texts_of_request(url, [], os.urandom(8192), "application/octet-stream") == ["/v1/items"]
        assert decode.texts_of_request(url, [], os.urandom(8192), "text/plain; charset=latin-1") == ["/v1/items"]


# ---------------------------------------------------------------------- review fixes: fingerprints, rules

def test_winnow_is_in_text_order_and_matches_prints():
    norm = normalize(MAIL)
    ordered = fingerprint.winnow(norm)
    assert set(ordered) == prints(MAIL) and len(ordered) == len(set(ordered))
    first = fingerprint.winnow(normalize(MAIL[:200]))
    assert ordered[:len(first) - 1] == first[:-1]  # a prefix of the text: a prefix of the prints
    assert fingerprint.winnow("short") == []


def test_exemption_for_some_clients_only():
    now = time.time()
    post = Conn("http", "paste.ee", None, 443, method="POST", now=now, client="172.29.0.5")
    ex = {"target": "paste.ee", "expires": now + 60}
    assert decide(_policy(exemptions=[{**ex, "clients": ["172.29.0.5"]}]), post).rule == "exemption"
    assert decide(_policy(exemptions=[{**ex, "clients": ["172.29.0.6"]}]), post).rule == "exfil_upload"
    assert decide(_policy(exemptions=[{**ex, "clients": []}]), post).rule == "exfil_upload"  # nobody
    assert decide(_policy(exemptions=[ex]), post).rule == "exemption"  # no field: everyone
    anon = Conn("http", "paste.ee", None, 443, method="POST", now=now)
    assert decide(_policy(exemptions=[{**ex, "clients": ["172.29.0.5"]}]), anon).rule == "exfil_upload"
    assert rules.exemption_applies({**ex, "clients": ["1.2.3.4"]}, "1.2.3.4", now)
    assert not rules.exemption_applies({**ex, "clients": ["1.2.3.4"]}, "1.2.3.5", now)
    assert not rules.exemption_applies({**ex, "expires": now - 1}, None, now)


def test_deny_by_name_only_looks_at_the_name():
    p = _policy(deny=["evil.example", "45.33.32.0/24"])
    assert rules.deny_by_name(p, "api.evil.example", 443, "GET").rule == "deny_list"
    assert rules.deny_by_name(p, "x.trycloudflare.com", 443, "POST").rule == "exfil_upload"
    assert rules.deny_by_name(p, "x.trycloudflare.com", 443, "GET") is None
    assert rules.deny_by_name(p, "invoice.zip", 443, "GET").rule == "risky_tlds"
    tunnel = "a" * 51 + ".example.com"
    assert rules.deny_by_name(p, tunnel, 443, "GET").rule == "dns_tunnel"
    assert rules.deny_by_name(p, "example.com", 443, "POST") is None
    assert rules.deny_by_name(p, None, 443, "POST") is None
    # countries and address entries are not about the name
    assert rules.deny_by_name(_policy(countries=["US"]), "example.com", 443, "GET") is None
    off = {**rules.policy_example()["categories"], "risky_tlds": False}
    assert rules.deny_by_name(_policy(categories=off), "invoice.zip", 443, "GET") is None


def test_registrable_domain():
    r = rules.registrable_domain
    assert r("a.b.example.com") == "example.com"
    assert r("x.y.bbc.co.uk") == "bbc.co.uk"
    assert r("q1.data.example.com.au") == "example.com.au"
    assert r("www.uni.ac.jp") == "uni.ac.jp"
    assert r("example.com") == "example.com" and r("com") == "com"
    assert r("a.b.Example.COM.") == "example.com"


def test_name_rate_blocks_many_new_names_under_one_domain():
    rate = rules.NameRate(limit=30, window=300, block=600)
    now = 1000.0
    for i in range(30):
        assert rate.check("10.0.0.5", f"c{i}.exfil.example", now + i) is None
    assert rate.check("10.0.0.5", "c30.exfil.example", now + 31) == "exfil.example"
    assert rate.check("10.0.0.5", "c99.exfil.example", now + 500) == "exfil.example"   # 10 minutes
    assert rate.check("10.0.0.5", "c3.exfil.example", now + 40) is None                 # seen before
    assert rate.check("10.0.0.6", "c99.exfil.example", now + 40) is None                # another client
    assert rate.check("10.0.0.5", "www.other.example", now + 40) is None                # another domain
    assert rate.check("10.0.0.5", "c100.exfil.example", now + 31 + 601) is None         # block over
    # a CDN-heavy page: many names once each, then the same names again: only new names count
    cdn = rules.NameRate(limit=30, window=300, block=600)
    names = [f"img{i}.cdn.example" for i in range(25)]
    for t in range(10):
        for name in names:
            assert cdn.check("c", name, now + t) is None
    # slowly over a long time is fine
    slow = rules.NameRate(limit=30, window=300, block=600)
    for i in range(100):
        assert slow.check("c", f"n{i}.slow.example", now + i * 20) is None


def test_name_rate_is_bounded():
    rate = rules.NameRate(limit=30, window=300, block=600, max_names=1000)
    for i in range(5000):
        rate.check("c", f"n{i}.d{i % 400}.example", 1000.0 + i * 0.001)
    assert len(rate.seen) <= 1000 and len(rate.recent) <= 1000


# ---------------------------------------------------------------------- the deployment (deploy/, egress/)

def _merge(base, over):
    """Compose's merge of -f files, as far as these files need it: mappings merge, lists add up."""
    if isinstance(base, dict) and isinstance(over, dict):
        return {**base, **{k: _merge(base[k], v) if k in base else v for k, v in over.items()}}
    if isinstance(base, list) and isinstance(over, list):
        return base + [x for x in over if x not in base]
    return over


def _compose_file(name: str) -> dict:
    import yaml
    return yaml.safe_load((ROOT / "deploy" / name).read_text())


def _compose(*names: str) -> dict:
    """The stack as COMPOSE_FILE builds it; by default the full one, network watch with Hermes."""
    merged: dict = {}
    for name in names or ("compose.yaml", "compose.egress.yaml", "compose.hermes.yaml"):
        merged = _merge(merged, _compose_file(name))
    return merged


def test_compose_setups_each_stand_on_their_own():
    """Every network and volume a service uses is declared in its setup; the base alone knows nothing of the
    proxy, and every agent service gets an image only from the agent's own file."""
    setups = [("compose.yaml",), ("compose.yaml", "compose.egress.yaml", "compose.hermes.yaml")]
    for setup in setups:
        compose = _compose(*setup)
        declared_nets, declared_vols = set(compose["networks"]) | {"default"}, set(compose.get("volumes", {}))
        for name, svc in compose["services"].items():
            assert "image" in svc or "build" in svc, (setup, name)
            assert set(svc.get("networks", ["default"])) <= declared_nets, (setup, name)
            for vol in svc.get("volumes", []):
                source = vol.split(":")[0]
                assert source.startswith((".", "/")) or source in declared_vols, (setup, name, vol)
    base = _compose("compose.yaml")
    assert not any(net.startswith("egress") for svc in base["services"].values() for net in svc.get("networks", []))
    assert "image" not in _compose_file("compose.egress.yaml")["services"]["agent"]
    # .env.example names only files that exist (or the copy it tells you to make)
    example = (ROOT / "deploy" / ".env.example").read_text()
    for line in example.splitlines():
        if "COMPOSE_FILE=" in line:
            for name in line.split("=", 1)[1].split(":"):
                assert name == "compose.myagent.yaml" or (ROOT / "deploy" / name).exists(), name


def test_compose_agent_file_cannot_loosen_the_wrapper():
    """compose.hermes.yaml (and so every copy of it) names the image and how it runs, nothing that keeps it in."""
    hermes = _compose_file("compose.hermes.yaml")["services"]
    agent = hermes["agent"]
    assert set(agent) <= {"image", "build", "command", "environment", "volumes", "shm_size", "mem_limit"}
    assert set(agent["environment"]) <= {"AGENT_USER", "AGENT_BOOTSTRAP", "AGENT_WORKDIR", "HERMES_ALLOW_ROOT_GATEWAY",
                                         "HERMES_DOCKER_EXEC_AS_ROOT", "HERMES_DASHBOARD_BASIC_AUTH_USERNAME",
                                         "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"}
    assert all(not v.startswith(("/var/run/docker.sock", "egress")) for v in agent["volumes"])
    # the Webapp's forwarder: its port and the web apps' 3000-3009, no rights, never a router between the agent's
    # network and its own
    webapp = hermes["agent-webapp"]
    assert webapp["cap_drop"] == ["ALL"] and "cap_add" not in webapp and not webapp.get("privileged")
    assert webapp["sysctls"]["net.ipv4.ip_forward"] == 0
    assert webapp["ports"] == ["127.0.0.1:${HERMES_WEBAPP_PORT:-9120}:9120", "127.0.0.1:3000-3009:3000-3009"]


def test_compose_keeps_the_proxys_control_traffic_off_the_agents_network():
    import ipaddress
    compose = _compose()
    services, networks = compose["services"], compose["networks"]
    url = services["egress"]["environment"]["DOORMAN_URL"]
    doorman_ip = services["doorman"]["networks"]["egress-control-doorman"]["ipv4_address"]
    assert url == f"http://{doorman_ip}:8710"
    assert networks["egress-control-doorman"]["internal"] is True
    members = sorted(name for name, svc in services.items()
                     if isinstance(svc.get("networks"), dict) and "egress-control-doorman" in svc["networks"])
    assert members == ["doorman", "egress"]
    # fixed addresses lie outside the range Docker hands out
    for name in ("egress", "egress-control", "egress-control-doorman"):
        config = networks[name]["ipam"]["config"][0]
        subnet, dynamic = ipaddress.ip_network(config["subnet"]), ipaddress.ip_network(config["ip_range"])
        assert dynamic.subnet_of(subnet)
        for svc in services.values():
            nets = svc.get("networks")
            fixed = nets.get(name) if isinstance(nets, dict) else None
            if isinstance(fixed, dict) and fixed.get("ipv4_address"):
                addr = ipaddress.ip_address(fixed["ipv4_address"])
                assert addr in subnet and addr not in dynamic, (name, addr)
    assert networks["egress"]["driver_opts"]["com.docker.network.bridge.name"] == "br-doorman-egr"


def test_compose_agent_and_observer_capabilities():
    services = _compose()["services"]
    agent, observer = services["agent"], services["egress-observer"]
    assert agent["cap_drop"] == ["ALL"] and not {"KILL", "NET_RAW", "SYS_PTRACE"} & set(agent["cap_add"])
    assert observer["cap_drop"] == ["ALL"]
    assert set(observer["cap_add"]) == {"SYS_PTRACE", "DAC_READ_SEARCH", "SETUID", "SETGID"}
    for name in ("egress", "agent"):
        assert services[name]["sysctls"]["net.ipv6.conf.all.disable_ipv6"] == 1
    assert agent["environment"]["AGENT_USER"] == "${AGENT_USER-hermes}"
    dockerfile = (ROOT / "deploy" / "egress" / "observer.Dockerfile").read_text()
    assert '"--reuid", "10004"' in dockerfile and "--ambient-caps=+sys_ptrace,+dac_read_search" in dockerfile


def test_compose_gives_the_agent_a_fixed_address():
    """A quarantine is kept by address: a re-created agent container must come back at the same one."""
    services = _compose()["services"]
    address = services["agent"]["networks"]["egress"]["ipv4_address"]
    assert address == "172.29.0.3" and list(services["agent"]["networks"]) == ["egress"]
    assert services["egress-observer"]["environment"]["AGENT_IP"] == address
    for doc in ("deploy/egress/README.md", "docs/network-watch.md"):
        assert address in (ROOT / doc).read_text(), doc


def test_compose_names_nothing_the_agent_can_see_after_the_decoys():
    """The agent reads its mounts' volume names in /proc/self/mountinfo: the decoy keys' volume has a plain one."""
    agent = _compose()["services"]["agent"]
    secrets = [v for v in agent["volumes"] if ".config/secrets" in v]
    assert secrets == ["agent-config:${AGENT_HOME:-/opt/data}/.config/secrets:ro"]
    for volume in agent["volumes"]:
        assert not any(word in volume.split(":")[0].lower() for word in ("decoy", "honey", "trap", "canary"))


def test_agent_entrypoint_drops_net_raw_and_the_selftest_checks_it():
    entry = (ROOT / "deploy" / "egress" / "agent-entrypoint.sh").read_text()
    assert 'drop="-net_admin,-net_raw,-setpcap,-setuid,-setgid"' in entry
    assert 'caps="--bounding-set=$drop --inh-caps=$drop --ambient-caps=$drop"' in entry
    selftest = (ROOT / "deploy" / "egress" / "selftest.sh").read_text()
    for check in ('"NET_ADMIN 0x1000"', '"NET_RAW 0x2000"', "telnet://$HOST_GW:22", "http://$HOST_GW:8711/"):
        assert check in selftest
    entrypoint = (ROOT / "deploy" / "egress" / "entrypoint.sh").read_text()
    assert "--set connection_strategy=lazy --set rawtcp=false" in entrypoint
    for script in ("agent-entrypoint.sh", "selftest.sh", "entrypoint.sh"):
        out = subprocess.run(["sh", "-n", str(ROOT / "deploy" / "egress" / script)], capture_output=True, text=True)
        assert out.returncode == 0, (script, out.stderr)


def test_agent_entrypoint_refuses_an_unset_agent_user_and_allows_root_only_on_purpose():
    """An agent file that forgets AGENT_USER is refused: root has to be chosen with AGENT_USER="" (Hermes with
    apt, on a Docker of its own), since a root agent could change the image's programs, which the wrapper
    runs as root with NET_ADMIN on the next start. The self-test says so instead of failing."""
    script = str(ROOT / "deploy" / "egress" / "agent-entrypoint.sh")
    # no PATH: the script stops at "needs iproute2" at the latest, never touches this machine's route. `id`
    # says the script runs as root, and that any named user is uid 10000 (root: 0)
    fake_id = 'id() { case "$*" in -u) echo 0 ;; *root) echo 0 ;; *) echo 10000 ;; esac; }; . "$0"'
    run = lambda env: subprocess.run(["/bin/sh", "-c", fake_id, script, "true"],
                                     capture_output=True, text=True, env={"PATH": "/nonexistent", **env})
    out = run({})
    assert out.returncode == 1 and "AGENT_USER isn't set" in out.stderr
    for user in ("", "hermes", "10000:10000", "1000"):  # on to the next check: the user is fine
        out = run({"AGENT_USER": user})
        assert out.returncode == 1 and "iproute2" in out.stderr and "AGENT_USER" not in out.stderr, user
    entry = (ROOT / "deploy" / "egress" / "agent-entrypoint.sh").read_text()
    assert "take the route back then" in entry
    selftest = (ROOT / "deploy" / "egress" / "selftest.sh").read_text()
    assert "awk '/^Uid/" in selftest and 'as AGENT_USER=\\"\\" chooses' in selftest
