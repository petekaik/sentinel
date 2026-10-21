"""The model client: one request, a key in one header and nowhere else."""

import http.server
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import llm_advisor                                # noqa: E402


class _Handler(http.server.BaseHTTPRequestHandler):
    requests = []
    reply = {"choices": [{"message": {"content": "{\"insights\": [], "
                                                 "\"proposals\": []}"}}],
             "usage": {"prompt_tokens": 11, "completion_tokens": 7}}
    status = 200
    delay = 0.0
    location = ""
    truncate = False

    def do_POST(self):
        import time
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        _Handler.requests.append({
            "path": self.path,
            "port": self.server.server_address[1],
            "headers": dict(self.headers),
            "body": json.loads(body.decode() or "{}"),
        })
        if _Handler.delay:
            time.sleep(_Handler.delay)
        payload = json.dumps(_Handler.reply).encode()
        self.send_response(_Handler.status)
        if _Handler.location:
            self.send_header("Location", _Handler.location)
        self.send_header("Content-Type", "application/json")
        if _Handler.truncate:
            # Promise 100 bytes and send 6: the client must call this a
            # malformed response instead of letting IncompleteRead escape.
            self.send_header("Content-Length", "100")
        self.end_headers()
        self.wfile.write(payload[:6] if _Handler.truncate else payload)

    def do_GET(self):
        # urllib follows a 302 by re-issuing the request as a GET, headers
        # included, so a redirect target that only counted POSTs would look
        # clean while the key was already there.
        self.do_POST()

    def log_message(self, *a):
        pass


def _serve():
    _Handler.requests = []
    _Handler.status, _Handler.delay, _Handler.location = 200, 0.0, ""
    _Handler.truncate = False
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, "http://127.0.0.1:%d" % httpd.server_address[1]


def test_one_request_with_the_key_only_in_the_header(results):
    httpd, base = _serve()
    try:
        client = llm_advisor.OpenAIClient(base, "canary-key-123", "probe")
        content, tin, tout = client.complete("sys", "user")
        results.check(
            "the call makes exactly one request, never a retry",
            len(_Handler.requests) == 1,
            "%d requests arrived: %r"
            % (len(_Handler.requests), _Handler.requests))
        req = _Handler.requests[0]
        results.check(
            "the client posts to /v1/chat/completions",
            req["path"] == "/v1/chat/completions", "path=%r" % req["path"])
        results.check(
            "the key is in the Authorization header and no other request field",
            req["headers"].get("Authorization") == "Bearer canary-key-123"
            and "canary-key-123" not in json.dumps(req["body"]),
            "headers=%r body=%r" % (req["headers"], req["body"]))
        results.check("the response content is returned",
                      "insights" in content and tin == 11 and tout == 7,
                      "content=%r usage=%r/%r" % (content, tin, tout))
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_failing_request_never_names_the_key(results):
    httpd, base = _serve()
    try:
        _Handler.status = 500
        _Handler.reply = {"error": "boom"}
        client = llm_advisor.OpenAIClient(base, "canary-key-123", "probe")
        try:
            client.complete("sys", "user")
        except llm_advisor.ModelError as exc:
            results.check(
                "a 500 is a ModelError without the key",
                "canary-key-123" not in str(exc), "error=%r" % (exc,))
        else:
            results.check("a 500 is a ModelError", False, "no exception")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_slow_endpoint_times_out_and_says_so(results):
    httpd, base = _serve()
    try:
        _Handler.delay = 0.5
        client = llm_advisor.OpenAIClient(base, "", "probe", timeout_s=0.1)
        try:
            client.complete("sys", "user")
        except llm_advisor.ModelError as exc:
            results.check("a timeout is a visible ModelError",
                          "timed out" in str(exc).lower(), "error=%r" % (exc,))
        else:
            results.check("a timeout is a ModelError", False, "no exception")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_malformed_json_is_a_model_error_not_an_empty_success(results):
    httpd, base = _serve()
    try:
        _Handler.reply = {"choices": "not a list"}
        client = llm_advisor.OpenAIClient(base, "", "probe")
        try:
            client.complete("sys", "user")
        except llm_advisor.ModelError as exc:
            results.check("a malformed body is a ModelError",
                          "malformed" in str(exc).lower(), "error=%r" % (exc,))
        else:
            results.check("a malformed body is a ModelError", False,
                          "the client returned a green empty answer")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_redirect_is_refused_and_never_reaches_its_target(results):
    target, target_base = _serve()
    target_port = target.server_address[1]
    httpd, base = _serve()
    try:
        _Handler.status = 302
        _Handler.reply = {}
        _Handler.location = target_base + "/v1/chat/completions"
        client = llm_advisor.OpenAIClient(base, "canary-key-123", "probe")
        try:
            client.complete("sys", "user")
        except llm_advisor.ModelError as exc:
            results.check(
                "a redirect is a ModelError, not a followed request",
                "302" in str(exc) and "canary-key-123" not in str(exc),
                "error=%r" % (exc,))
        else:
            results.check("a redirect is a ModelError", False, "no exception")
        followed = [r for r in _Handler.requests if r["port"] == target_port]
        results.check(
            "the key never follows a redirect to another host",
            not followed, "the Location host received %r" % (followed,))
    finally:
        httpd.shutdown()
        httpd.server_close()
        target.shutdown()
        target.server_close()


def test_a_non_dict_usage_is_ignored_rather_than_crashing(results):
    httpd, base = _serve()
    try:
        _Handler.reply = {"choices": [{"message": {"content": "{}"}}],
                          "usage": ["not", "a", "dict"]}
        client = llm_advisor.OpenAIClient(base, "", "probe")
        try:
            content, tin, tout = client.complete("sys", "user")
        except llm_advisor.ModelError as exc:
            results.check("a non-dict usage does not break the call", False,
                          "error=%r" % (exc,))
        else:
            results.check("a non-dict usage does not break the call",
                          content == "{}" and tin is None and tout is None,
                          "content=%r usage=%r/%r" % (content, tin, tout))
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_truncated_body_is_a_model_error_not_a_traceback(results):
    httpd, base = _serve()
    try:
        _Handler.truncate = True
        client = llm_advisor.OpenAIClient(base, "", "probe")
        try:
            client.complete("sys", "user")
        except llm_advisor.ModelError as exc:
            results.check("a truncated body is a ModelError",
                          "malformed" in str(exc).lower(), "error=%r" % (exc,))
        except Exception as exc:                     # noqa: BLE001
            results.check("a truncated body is a ModelError", False,
                          "%s escaped: %r" % (type(exc).__name__, exc))
        else:
            results.check("a truncated body is a ModelError", False,
                          "no exception")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_reasoning_model_with_no_content_names_the_cause(results):
    httpd, base = _serve()
    try:
        _Handler.reply = {
            "choices": [{"message": {"content": None},
                         "finish_reason": "length"}],
            "usage": {},
        }
        client = llm_advisor.OpenAIClient(base, "", "probe")
        try:
            client.complete("sys", "user")
        except llm_advisor.ModelError as exc:
            results.check(
                "a content-less reasoning response names the cause",
                "finish_reason=length" in str(exc)
                and "reasoning" in str(exc),
                "error=%r" % (exc,))
        else:
            results.check("a content-less reasoning response names the cause",
                          False, "no exception")
    finally:
        httpd.shutdown()
        httpd.server_close()


TESTS = (
    test_one_request_with_the_key_only_in_the_header,
    test_a_reasoning_model_with_no_content_names_the_cause,
    test_a_failing_request_never_names_the_key,
    test_a_slow_endpoint_times_out_and_says_so,
    test_malformed_json_is_a_model_error_not_an_empty_success,
    test_a_redirect_is_refused_and_never_reaches_its_target,
    test_a_non_dict_usage_is_ignored_rather_than_crashing,
    test_a_truncated_body_is_a_model_error_not_a_traceback,
)
