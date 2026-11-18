"""Doorman's proxy API, as the egress proxy calls it.

Six calls, each authenticated with the proxy token (DOORMAN_EGRESS_TOKEN, made under More > Network in the
owner app), none of them carrying content: the policy (the owner's rules, polled), a check (fingerprints of
what a request carries, never the request itself), the connection log, a status beat, the decoy keys file
the proxy puts in the agent's container, and the tripwire (the observer saw that file touched).

Standard library only, blocking: the addon runs these through asyncio.to_thread. Every call gives up after
`timeout` seconds and answers None or False instead of raising, so Doorman being down is an ordinary answer
the addon acts on (when_doorman_down). Proxy variables in the environment are ignored: these calls go
straight to Doorman, never through a proxy (least of all this one).
"""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request

MAX_ANSWER = 8 * 1024 * 1024  # a policy with long lists is a few hundred KB
CHECK_TIMEOUT = 6.0           # Doorman answers a check within 4 s, "unknown" if its fingerprints lag behind


class DoormanClient:
    def __init__(self, base_url: str, token: str, timeout: float = 2.0, check_timeout: float = CHECK_TIMEOUT):
        self.base_url = (base_url or "").rstrip("/")
        self.token = token or ""
        self.timeout = timeout
        self.check_timeout = check_timeout
        self.last_error: str | None = None
        self.last_status: int | None = None   # the HTTP status of the last call that got one
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _call(self, method: str, path: str, body: dict | None = None, timeout: float | None = None) -> dict | None:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(self.base_url + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if data is not None else {}),
        })
        try:
            with self._opener.open(request, timeout=timeout or self.timeout) as response:
                answer = json.loads(response.read(MAX_ANSWER + 1)[:MAX_ANSWER] or b"{}")
        except urllib.error.HTTPError as e:
            self.last_error, self.last_status = f"{method} {path}: HTTP {e.code}", e.code
            return None
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
            self.last_error, self.last_status = f"{method} {path}: {e}", None
            return None
        self.last_error, self.last_status = None, response.status
        return answer if isinstance(answer, dict) else None

    def policy(self) -> dict | None:
        """The owner's rules (rules.policy_example() has the shape), or None when Doorman can't be asked."""
        answer = self._call("GET", "/v1/egress/proxy/policy")
        if answer is not None and "version" not in answer and isinstance(answer.get("policy"), dict):
            answer = answer["policy"]  # tolerate {"policy": {...}}
        return answer if answer and isinstance(answer.get("version"), str) else None

    def check(self, body: dict) -> dict | None:
        """{client_ip, host, url, method, prints, honeytokens[, kind]} -> {action, chars, sources, reason}, or
        None: also when Doorman answers "unknown" (it couldn't finish the check in time), which the proxy
        treats like Doorman being unreachable."""
        answer = self._call("POST", "/v1/egress/proxy/check", body, timeout=self.check_timeout)
        if answer and answer.get("action") == "unknown":
            self.last_error = f"Doorman couldn't finish the check in time: {answer.get('reason') or 'no reason given'}"
            return None
        return answer if answer and answer.get("action") in ("allow", "deny") else None

    def send_log(self, records: list[dict]) -> bool:
        return self._call("POST", "/v1/egress/proxy/log", {"records": records}) is not None

    def status(self, body: dict) -> bool:
        return self._call("POST", "/v1/egress/proxy/status", body) is not None

    def decoys(self) -> dict | None:
        """{"version": str, "filename": "api-keys.env", "content": str | None} (content None: decoys are off,
        the file goes), or None when Doorman can't be asked or answers something else."""
        answer = self._call("GET", "/v1/egress/proxy/decoys")
        if not answer or not isinstance(answer.get("version"), str):
            return None
        content = answer.get("content")
        return answer if content is None or isinstance(content, str) else None

    def tripwire(self, body: dict) -> dict | None:
        """{client_ip, event: "open" | "access" | "dir_open", path, ts} -> {"ok": true, "action": ...}, or None."""
        answer = self._call("POST", "/v1/egress/proxy/tripwire", body)
        return answer if answer and answer.get("ok") else None
