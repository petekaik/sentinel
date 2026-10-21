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

    def do_POST(self):
        import time
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        _Handler.requests.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": json.loads(body.decode() or "{}"),
        })
        if _Handler.delay:
            time.sleep(_Handler.delay)
        self.send_response(_Handler.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(_Handler.reply).encode())

    def log_message(self, *a):
        pass


def _serve():
    _Handler.requests = []
    _Handler.status, _Handler.delay = 200, 0.0
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, "http://127.0.0.1:%d" % httpd.server_address[1]


def test_one_request_with_the_key_only_in_the_header(results):
    httpd, base = _serve()
    try:
        client = llm_advisor.OpenAIClient(base, "canary-key-123", "probe")
        content, tin, tout = client.complete("sys", "user")
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


TESTS = (
    test_one_request_with_the_key_only_in_the_header,
    test_a_failing_request_never_names_the_key,
    test_a_slow_endpoint_times_out_and_says_so,
    test_malformed_json_is_a_model_error_not_an_empty_success,
)
