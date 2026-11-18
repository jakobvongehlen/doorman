"""The owner's rules for the agent's connections: allowed, or blocked and why.

Doorman keeps the rules and sends them to the proxy as one policy dict (policy_example() has the shape);
the proxy calls decide() for every DNS question, every non-web connection and every HTTP request, so a
decision never waits for Doorman. The order:

1. an exception the owner granted that hasn't run out ("Allow once", "For this task"), for the clients it
   names (Doorman lists the addresses of the agent that asked; no list: everyone);
2. the owner's allow list, then the deny list (an allow beats a deny, so a narrow allow can open a hole
   in a broad deny);
3. the categories blocked by default, each with its own switch: names that look like data hidden in DNS,
   countries on the owner's block list, top-level domains often used for abuse, uploads to paste,
   webhook and tunnel services, and non-web connections to bare IP addresses no name lookup led to (how
   a reverse shell or a hard-coded drop server looks);
4. non-web connections when the owner allows only web traffic;
5. everything else is allowed (and logged by the proxy).

A target names what a rule is about: "example.com" (that host and its subdomains), "*.example.com"
(subdomains only), "1.2.3.4", "10.0.0.0/8" or "[2001:db8::1]", each with an optional ":port".

The detail strings are shown to the agent in the proxy's 403 and to the owner in the log, so they are
written for people.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .fingerprint import K, W

CATEGORIES = ("exfil_upload", "risky_tlds", "countries", "bare_ip_nonweb", "dns_tunnel")
UPLOAD_METHODS = frozenset({"POST", "PUT", "PATCH"})
DATA = Path(__file__).resolve().parent / "data"

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")


@dataclass
class Conn:
    kind: str                     # "http" | "tcp" | "dns"
    host: str | None
    ip: str | None
    port: int
    method: str | None = None
    resolved: bool = False        # a DNS answer through the proxy led to this IP
    country: str | None = None
    now: float = 0.0              # epoch seconds; 0 means the current time
    client: str | None = None     # the agent container's address (an exemption may name the clients it is for)


@dataclass
class Decision:
    action: str                   # "allow" | "deny"
    rule: str
    detail: str


@dataclass(frozen=True)
class Target:
    host: str | None              # lower-case, without "*." and trailing dot
    wildcard: bool                # "*.example.com": subdomains only
    net: IPNetwork | None
    port: int | None


def _port(text: str) -> int | None:
    if not (text.isascii() and text.isdigit() and len(text) <= 5):
        return None
    port = int(text)
    return port if 1 <= port <= 65535 else None


def _net(text: str) -> IPNetwork | None:
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _addr(text: str | None) -> IPAddress | None:
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def _host(text: str | None) -> str | None:
    return text.strip().lower().rstrip(".") or None if text else None


@lru_cache(maxsize=4096)
def parse_target(text: str) -> Target | None:
    if not isinstance(text, str):
        return None
    text = text.strip()
    if not text or len(text) > 300 or any(c.isspace() for c in text) or "://" in text:
        return None
    if text.startswith("["):  # [2001:db8::1] or [2001:db8::1]:22
        inner, sep, rest = text[1:].partition("]")
        port = _port(rest[1:]) if rest.startswith(":") else None
        net = _net(inner)
        if not sep or net is None or (rest and port is None):
            return None
        return Target(None, False, net, port)
    if text.count(":") > 1:  # a bare IPv6 address or network: no port
        net = _net(text)
        return Target(None, False, net, None) if net else None
    host, sep, port_text = text.partition(":")
    port = _port(port_text) if sep else None
    if sep and port is None:
        return None
    net = _net(host)
    if net is not None:
        return Target(None, False, net, port)
    if "/" in host:
        return None  # a path, or a network that doesn't parse
    host = host.lower().rstrip(".")
    wildcard = host.startswith("*.")
    if wildcard:
        host = host[2:]
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if not host or len(host) > 253 or not all(_LABEL.fullmatch(label) for label in host.split(".")):
        return None
    return Target(host, wildcard, None, port)


def matches(target: Target, host: str | None, ip: str | None, port: int) -> bool:
    if target.port is not None and target.port != port:
        return False
    if target.net is not None:
        addr = _addr(ip) or _addr(host)
        return addr is not None and addr.version == target.net.version and addr in target.net
    host = _host(host)
    if not host:
        return False
    if target.wildcard:
        return host.endswith("." + target.host)
    return host == target.host or host.endswith("." + target.host)


def _first_match(entries: list | None, host: str | None, ip: str | None, port: int) -> str | None:
    for entry in entries or []:
        target = parse_target(entry) if isinstance(entry, str) else None
        if target and matches(target, host, ip, port):
            return entry.strip()
    return None


def _entropy(text: str) -> float:
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values()) if n else 0.0


def _encoded(label: str) -> bool:
    """Base32 or hex rather than words: very random (≥ 4.1 bits per character), or no hyphen and at least 15%
    digits with some randomness. Hex has an entropy of only ~3.6, below many descriptive names
    ("production-database-replica-eu-west": 3.85), so entropy alone can't tell them apart; digits can."""
    digits = sum(c.isdigit() for c in label) / len(label)
    entropy = _entropy(label)
    return entropy >= 4.1 or ("-" not in label and digits >= 0.15 and entropy >= 3.0)


def dns_suspicious(name: str) -> bool:
    """A name that looks like data hidden in DNS: very long, a very long label, or a long label as random
    as encoded data (base32 or hex of something, rather than words)."""
    name = (name or "").lower().rstrip(".")
    if len(name) > 120:
        return True
    for label in name.split("."):
        if len(label) > 50 or (len(label) >= 30 and _encoded(label)):
            return True
    return False


def exemption_applies(exemption, client: str | None, now: float) -> bool:
    """Whether an exemption entry is in force for this client: not run out, and either for everyone (no
    "clients") or for a list of client addresses that holds this one (an empty list: for nobody)."""
    if not isinstance(exemption, dict):
        return False
    expires = exemption.get("expires")
    if isinstance(expires, (int, float)) and expires <= now:
        return False
    if "clients" in exemption:
        clients = exemption.get("clients")
        return isinstance(clients, list) and client is not None and client in clients
    return True


def deny_by_name(policy: dict, host: str | None, port: int, method: str | None = None) -> Decision | None:
    """The deny rules that are about a name alone: the deny list, names that look like data hidden in DNS,
    abuse-heavy top-level domains, uploads to paste, webhook and tunnel services. The proxy applies them to
    every name a connection claims, also when an allow or exception by address lets the connection through:
    an address entry is about the address, never a reason to send data to a denied name."""
    host = _host(host)
    if not host:
        return None
    if entry := _first_match(policy.get("deny"), host, None, port):
        return Decision("deny", "deny_list", f"{entry} is on the owner's deny list")
    if _addr(host) is not None:
        return None
    on = policy.get("categories") or {}
    if on.get("dns_tunnel", True) and dns_suspicious(host):
        return Decision("deny", "dns_tunnel", "the name looks like data hidden in DNS")
    if on.get("risky_tlds", True) and "." in host:
        tld = host.rsplit(".", 1)[1]
        if tld in {str(t).lower().lstrip(".") for t in policy.get("risky_tlds") or []}:
            return Decision("deny", "risky_tlds", f".{tld} is on the list of domains often used for abuse")
    if (on.get("exfil_upload", True) and (method or "").upper() in UPLOAD_METHODS
            and _first_match(policy.get("exfil_hosts"), host, None, port)):
        return Decision("deny", "exfil_upload",
                        f"{host} is a paste, webhook or tunnel service; uploads to it are blocked")
    return None


def decide(policy: dict, conn: Conn) -> Decision:
    now = conn.now or time.time()
    host = _host(conn.host)
    for exemption in policy.get("exemptions") or []:
        if not exemption_applies(exemption, conn.client, now):
            continue
        if entry := _first_match([exemption.get("target")], host, conn.ip, conn.port):
            return Decision("allow", "exemption", f"the owner made an exception for {entry}")
    if entry := _first_match(policy.get("allow"), host, conn.ip, conn.port):
        return Decision("allow", "allow_list", f"{entry} is on the owner's allow list")
    if entry := _first_match(policy.get("deny"), host, conn.ip, conn.port):
        return Decision("deny", "deny_list", f"{entry} is on the owner's deny list")

    on = policy.get("categories") or {}
    if on.get("dns_tunnel", True) and conn.kind == "dns" and host and dns_suspicious(host):
        return Decision("deny", "dns_tunnel", "the name looks like data hidden in DNS")
    country = (conn.country or "").upper()
    if on.get("countries", True) and country and country in {str(c).upper() for c in policy.get("countries") or []}:
        return Decision("deny", "countries",
                        f"{conn.ip or host} is in {country}, a country on the owner's block list")
    if on.get("risky_tlds", True) and host and "." in host and _addr(host) is None:
        tld = host.rsplit(".", 1)[1]
        if tld in {str(t).lower().lstrip(".") for t in policy.get("risky_tlds") or []}:
            return Decision("deny", "risky_tlds", f".{tld} is on the list of domains often used for abuse")
    if (on.get("exfil_upload", True) and (conn.method or "").upper() in UPLOAD_METHODS and host
            and _first_match(policy.get("exfil_hosts"), host, None, conn.port)):
        return Decision("deny", "exfil_upload",
                        f"{host} is a paste, webhook or tunnel service; uploads to it are blocked")
    if (on.get("bare_ip_nonweb", True) and conn.kind == "tcp" and not conn.resolved
            and (host is None or _addr(host) is not None)):
        return Decision("deny", "bare_ip_nonweb",
                        f"a port {conn.port} connection to a bare IP address that no name lookup led to")
    if policy.get("nonweb") == "block" and conn.kind == "tcp":
        return Decision("deny", "nonweb_block", f"only web traffic is allowed here (port {conn.port})")
    return Decision("allow", "default", "")


# second-level labels under a two-letter country code that are a public suffix themselves (co.uk, com.au)
_SHORT_SUFFIXES = frozenset({"co", "com", "ac", "gov", "org", "net", "edu"})


def registrable_domain(name: str) -> str:
    """The domain someone registered, approximately: the last two labels, three under a country code with
    a short public-suffix-like second level (bbc.co.uk, example.com.au)."""
    labels = (name or "").lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SHORT_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


DNS_RATE_DETAIL = "many different names under {domain}: looks like data hidden in DNS"


class NameRate:
    """Data hidden in DNS a few characters per name gets past dns_suspicious(): short, plain-looking labels,
    but many different ones under one domain. This counts, per client and registrable domain, the names it
    hasn't seen that client ask for before; `limit` new names within `window` seconds and further new names
    under that domain are refused for `block` seconds. Names seen before keep working, so a page that pulls
    from forty CDN hosts again and again isn't hit. Bounded: at most `max_names` remembered names and
    domains each (the oldest go first)."""

    def __init__(self, limit: int = 30, window: float = 300.0, block: float = 600.0, max_names: int = 100_000):
        self.limit, self.window, self.block, self.max_names = limit, window, block, max_names
        self.seen: OrderedDict[tuple, None] = OrderedDict()           # (client, name)
        self.recent: OrderedDict[tuple, deque] = OrderedDict()        # (client, domain) -> times of new names
        self.blocked: dict[tuple, float] = {}                         # (client, domain) -> until

    def check(self, client: str | None, name: str, now: float) -> str | None:
        """None when the name may be asked for (and remembers it), else the domain it is refused under."""
        name = (name or "").lower().rstrip(".")
        key = (client, name)
        if key in self.seen:
            self.seen.move_to_end(key)
            return None
        domain = registrable_domain(name)
        dkey = (client, domain)
        until = self.blocked.get(dkey)
        if until is not None:
            if until > now:
                return domain
            del self.blocked[dkey]
        times = self.recent.get(dkey)
        if times is None:
            times = self.recent[dkey] = deque()
        self.recent.move_to_end(dkey)
        while times and times[0] <= now - self.window:
            times.popleft()
        if len(times) >= self.limit:
            self.blocked[dkey] = now + self.block
            times.clear()
            if len(self.blocked) > self.max_names:
                self.blocked = {k: t for k, t in self.blocked.items() if t > now}
            return domain
        times.append(now)
        self.seen[key] = None
        while len(self.seen) > self.max_names:
            self.seen.popitem(last=False)
        while len(self.recent) > self.max_names:
            self.recent.popitem(last=False)
        return None


@lru_cache(maxsize=None)
def _read_list(name: str) -> tuple[str, ...]:
    lines = (DATA / f"{name}.txt").read_text(encoding="utf-8").splitlines()
    return tuple(entry for line in lines if (entry := line.split("#", 1)[0].strip().lower()))


def default_list(name: str) -> list[str]:
    """A built-in list from data/{name}.txt: one entry per line, "#" starts a comment."""
    if not re.fullmatch(r"[a-z_]+", name or ""):
        raise ValueError(f"not a list name: {name!r}")
    return list(_read_list(name))


def policy_version(policy: dict) -> str:
    """sha256 of the policy without its version: the proxy sees at a glance whether anything changed."""
    rest = {k: v for k, v in policy.items() if k != "version"}
    return hashlib.sha256(json.dumps(rest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def policy_example() -> dict:
    """A complete policy with the defaults, as Doorman sends it to the proxy (for tests)."""
    policy = {
        "nonweb": "log",
        "web_ports": [80, 443, 8080, 8443],
        "categories": {name: True for name in CATEGORIES},
        "countries": ["RU", "BY", "KP", "IR"],
        "risky_tlds": default_list("risky_tlds"),
        "exfil_hosts": default_list("exfil_hosts"),
        "deny": [], "allow": [], "passthrough": [],
        "no_scan": ["api.anthropic.com", "api.openai.com", "openrouter.ai", "inference-api.nousresearch.com",
                    "generativelanguage.googleapis.com", "api.deepseek.com"],
        "exemptions": [],
        "honeytokens": [],
        "decoys": [],      # the decoy keys among the honeytokens: looked for in what goes to no_scan hosts
        "when_doorman_down": "allow", "unscanned": "allow",
        "match": {"k": K, "w": W, "note_chars": 40},
    }
    return {"version": policy_version(policy), **policy}
