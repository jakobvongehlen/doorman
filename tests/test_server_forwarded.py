"""Whose X-Forwarded-For the agent API believes (server.forwarded_from), and that uvicorn then gives the
agent's own address to Doorman, as network watch needs it to tie an address to a key."""

import asyncio

from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from doorman.server import forwarded_from


def test_only_loopback_by_default():
    assert forwarded_from({}) == "127.0.0.1"
    assert forwarded_from({"agent_forwarded_from": None}) == "127.0.0.1"


def test_the_relay_is_added_and_what_isnt_an_address_is_left_out():
    config = {"agent_forwarded_from": ["172.31.0.250", " 172.31.0.250", "172.31.0.0/24", "relay", 7]}
    assert forwarded_from(config) == "127.0.0.1,172.31.0.250"


def _client_seen(peer: str, forwarded: str, trusted: str) -> str:
    seen = {}

    async def app(scope, receive, send):
        seen["client"] = scope["client"][0]

    scope = {"type": "http", "client": (peer, 40000), "scheme": "http",
             "headers": [(b"x-forwarded-for", forwarded.encode())]}
    asyncio.run(ProxyHeadersMiddleware(app, trusted_hosts=trusted)(scope, None, None))
    return seen["client"]


def test_the_agents_address_through_the_relay_and_never_from_anyone_else():
    trusted = forwarded_from({"agent_forwarded_from": ["172.31.0.250"]})
    assert _client_seen("172.31.0.250", "172.29.0.130", trusted) == "172.29.0.130"
    # anyone else on Doorman's networks can't claim an address
    assert _client_seen("172.31.0.7", "172.29.0.130", trusted) == "172.31.0.7"
