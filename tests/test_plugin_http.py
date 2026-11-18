"""plugin_api.http_json: whether a failed request could have done anything (NotSent or not)."""

import httpx
import pytest

from doorman.plugin_api import NotSent, PluginError, before_sending, http_json

URL = "https://api.example/v1/things?x=1"


def answer(status, body=None):
    return httpx.MockTransport(lambda request: httpx.Response(status, json=body) if body is not None
                               else httpx.Response(status))


def raises(error):
    def handler(request):
        raise error("boom", request=request)
    return httpx.MockTransport(handler)


def expired():
    raise PluginError("Example login failed: invalid_grant (connect again)")


def test_json_back_empty_body_and_allowed_statuses():
    assert http_json("Example", "GET", URL, transport=answer(200, {"a": 1})) == {"a": 1}
    assert http_json("Example", "DELETE", URL, transport=answer(204)) == {}
    assert http_json("Example", "GET", URL, transport=answer(404, {}), allow=(404, 410)) is None


@pytest.mark.parametrize("method, transport, token, expected, words", [
    # nothing left the box: certainly not sent
    ("POST", answer(200, {}), expired, NotSent, "connect again"),
    ("POST", raises(httpx.ConnectError), None, NotSent, "Example unreachable"),
    ("POST", raises(httpx.ConnectTimeout), None, NotSent, "Example unreachable"),
    # the request may have been carried out
    ("POST", raises(httpx.ReadTimeout), None, PluginError, "ReadTimeout"),
    ("POST", raises(httpx.RemoteProtocolError), None, PluginError, "RemoteProtocolError"),
    ("POST", answer(502, {"error": {"message": "Bad gateway"}}), None, PluginError, "failed with 502: Bad gateway"),
    # a GET changes nothing, however it fails
    ("GET", raises(httpx.ReadTimeout), None, NotSent, "ReadTimeout"),
    ("GET", answer(503, {}), None, NotSent, "failed with 503"),
    # 4xx: the service refused, so nothing happened; 401 says to connect again
    ("POST", answer(403, {"error": {"code": "Forbidden"}}), None, NotSent, "failed with 403: Forbidden"),
    ("POST", answer(401, {"error": "unauthorized"}), None, NotSent, "connect it again"),
])
def test_what_a_failure_means(method, transport, token, expected, words):
    with pytest.raises(PluginError) as err:
        http_json("Example", method, URL, token=token, transport=transport)
    assert type(err.value) is expected and words in str(err.value)
    assert "?x=1" not in str(err.value)  # the query (ids, filters) stays out of the message


def test_a_4xx_counts_as_refused_only_when_the_service_says_so():
    with pytest.raises(PluginError) as err:
        http_json("Example", "POST", URL, transport=answer(409, {"message": "conflict"}), refused_4xx=False)
    assert type(err.value) is PluginError and "conflict" in str(err.value)
    with pytest.raises(NotSent, match="ask your admin"):
        http_json("Example", "POST", URL, transport=answer(403, {}), hints={403: "ask your admin"})


def test_before_sending_turns_a_failed_step_into_not_sent():
    assert before_sending(lambda: "token") == "token"
    with pytest.raises(NotSent, match="connect again"):
        before_sending(expired)
    with pytest.raises(NotSent):
        before_sending(lambda: (_ for _ in ()).throw(httpx.ConnectError("no route")))
    with pytest.raises(KeyError):  # a bug isn't a known outcome
        before_sending(lambda: {}["x"])
