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

TRANSPORT: `advise_views` IS THE ONE ENTRY POINT. The intelligence cycle packs
every granted module's view into ONE request and calls `advise_views` once;
`OpenAIClient` is that request and there is no retry -- the next cycle is the
retry. `advise()` is not the path: the per-epoch advisor runner hands an advisor
a single snapshot, and a model that saw one module at a time would be N calls
and N leaks instead of one bounded pack.
"""

import http.client
import json
import urllib.error
import urllib.request

import advisors


class ModelError(RuntimeError):
    """A model call failed. The message never contains the key."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is a second request to a host nobody configured, and urllib
    replays the request headers there -- `Authorization` included. Refuse."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused",
                                     headers, fp)


# The opener is stateless and holds the single policy a client may have.
_OPENER = urllib.request.build_opener(_NoRedirect)


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
            raise ModelError(
                "the model backend needs an endpoint and a model") from None
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
            with _OPENER.open(req, timeout=self.timeout_s) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise ModelError("the model endpoint answered HTTP %s"
                             % exc.code) from None
        except http.client.HTTPException:
            # Includes IncompleteRead and BadStatusLine: the peer controlled
            # the bytes, so its text must not reach a traceback.
            raise ModelError(
                "the model endpoint returned a malformed response") from None
        except OSError:
            # URLError and TimeoutError are OSErrors. urllib's text can name
            # the URL, so build a fresh message anyway: the key lives only in
            # a header, and no client stack should leak.
            raise ModelError(
                "the model endpoint timed out or was unreachable") from None
        try:
            payload = json.loads(raw.decode())
            content = payload["choices"][0]["message"]["content"]
            usage = payload.get("usage")
            if not isinstance(usage, dict):
                usage = {}
        except (ValueError, KeyError, IndexError, TypeError):
            raise ModelError(
                "the model endpoint returned a malformed body") from None
        if not isinstance(content, str):
            raise ModelError(
                "the model endpoint returned no message content") from None
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
            "the LLM advisor runs through the intelligence cycle's single "
            "advise_views call, which packs every granted module into one "
            "request; this per-snapshot entry point has no fleet-wide pack to "
            "send")

    def advise_views(self, ctx, views, cfg):
        """The cycle's ONE model call. Returns validated insights and proposals.

        A failure RAISES `ModelError` (or lets a `ModelError` through) so the
        cycle can record an error row; an empty result here always means the
        model answered, never that it could not be asked.
        """
        if not self.configured:
            return {"insights": [], "proposals": [], "tokens_in": None,
                    "tokens_out": None, "dropped": {}, "usage": {}}
        if self.provider != "openai":
            raise ModelError(
                "provider %r is not supported; this delivery speaks the "
                "OpenAI-compatible wire format" % (self.provider,))
        import intelligence_layer
        grants = {}
        for mid, view in views.items():
            mod = getattr(view, "mod", None)
            if mod is None:
                mod = next((m for m in getattr(ctx, "modules", ())
                            if m.id == mid), None)
            supported = (tuple(mod.intelligence) if mod is not None
                         else ("observe",))
            grants[mid] = cfg.intelligence_grant(mid, supported)[0]
        system, user, usage = intelligence_layer.pack_views(
            views, grants, cfg.intelligence_model_max_tokens)  # secretscan:ignore -- identifier
        # The pack redacts where it is built; this is the second pass, on the
        # exact text that leaves the box, because that is where the promise is.
        user = intelligence_layer.redact(
            user, intelligence_layer._secret_values(cfg))
        client = OpenAIClient(
            self.endpoint, self.api_key, self.model,
            timeout_s=max(1, cfg.intelligence_budget_ms // 1000))
        content, tin, tout = client.complete(system, user)
        try:
            payload = json.loads(content)
        except ValueError:
            raise ModelError(
                "the model returned content that is not JSON") from None
        kept, proposals, dropped = intelligence_layer.validate_model_output(
            payload, views, grants,
            conn=intelligence_layer._conn_from_views(views))
        return {"insights": kept, "proposals": proposals,
                "tokens_in": tin, "tokens_out": tout,
                "dropped": dropped, "usage": usage}
