"""LLM advisor: the same contract as every advisor, egress opt-in.

Without BOTH a provider and an endpoint this class does nothing and says so.
It never constructs a prompt from the store directly; it consumes an
`advisors.Snapshot`, which is the platform's scoped, bounded read API -- so the
window honesty and the caps apply to an LLM exactly as they do to the reference
advisor.

THE API KEY IS A CREDENTIAL. It is held for the provider client below and is
never written to an insight, an advisor run's detail, a log line or the config
summary. A traceback from this module must not carry it either, which is why the
error below names the missing transport and nothing else in the configuration.

TRANSPORT IS NOT WIRED INTO THE ADVISOR IN THIS DELIVERY. `OpenAIClient` makes
one OpenAI-compatible chat-completions request and is the cycle's transport;
`LlmAdvisor` does not call it yet. A configured advisor RAISES rather than
returning an empty list: the runner records the error row, so an operator who
selects it sees "not implemented" instead of a silent green epoch that looks
like a clean diagnosis of nothing.
"""

import json
import urllib.error
import urllib.request

import advisors


class ModelError(RuntimeError):
    """A model call failed. The message never contains the key."""


class OpenAIClient:
    """One OpenAI-compatible chat-completions request. No retry: the next
    intelligence cycle is the retry."""

    def __init__(self, endpoint, key="", model="", timeout_s=30):
        self.endpoint = str(endpoint or "").rstrip("/")
        self.key = key or ""
        self.model = model or ""
        self.timeout_s = timeout_s

    def complete(self, system, user):
        if not self.endpoint or not self.model:
            raise ModelError("the model backend needs an endpoint and a model")
        url = self.endpoint + "/v1/chat/completions"
        body = json.dumps({
            "model": self.model,
            "temperature": 0,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }).encode()
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = "Bearer %s" % self.key
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise ModelError("the model endpoint answered HTTP %s" % exc.code)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # `exc` from urllib can name the URL; the key is only in a header,
            # but build a fresh message anyway so no client stack leaks.
            raise ModelError("the model endpoint timed out or was unreachable")
        try:
            payload = json.loads(raw.decode())
            content = payload["choices"][0]["message"]["content"]
            usage = payload.get("usage") or {}
        except (ValueError, KeyError, IndexError, TypeError):
            raise ModelError("the model endpoint returned a malformed body")
        if not isinstance(content, str):
            raise ModelError("the model endpoint returned no message content")
        return (content, usage.get("prompt_tokens"),
                usage.get("completion_tokens"))


class LlmAdvisor(advisors.Advisor):
    id = "llm"
    title = "LLM diagnosis and summaries"
    # Platform-owned: the advice spans every module.
    module = "platform"
    history_days = 7

    def __init__(self, provider="", endpoint="", api_key="", model=""):
        self.provider = provider
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model

    @property
    def configured(self):
        # Both are required: a provider with no endpoint cannot be called, and
        # an endpoint with no provider names no protocol.
        return bool(self.provider and self.endpoint)

    def advise(self, ctx, snapshot):
        if not self.configured:
            return []                    # unconfigured is not an insight
        raise RuntimeError(
            "the LLM transport via OpenAIClient is not implemented in this "
            "delivery; the advisor's advise_views entry point is not wired up")
