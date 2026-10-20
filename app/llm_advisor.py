"""LLM advisor: the same contract as every advisor, egress opt-in.

Without BOTH a provider and an endpoint this class does nothing and says so.
It never constructs a prompt from the store directly; it consumes an
`advisors.Snapshot`, which is the platform's scoped, bounded read API -- so the
window honesty and the caps apply to an LLM exactly as they do to the reference
advisor.

THE API KEY IS A CREDENTIAL. It is held for the future provider client and is
never written to an insight, an advisor run's detail, a log line or the config
summary. A traceback from this module must not carry it either, which is why the
error below names the missing transport and nothing else in the configuration.

TRANSPORT IS NOT IMPLEMENTED IN THIS DELIVERY. A configured advisor RAISES
rather than returning an empty list: the runner records the error row, so an
operator who selects it sees "not implemented" instead of a silent green epoch
that looks like a clean diagnosis of nothing.
"""

import advisors


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
            "LLM transport is not implemented in this delivery; configure it in "
            "the follow-up that adds the provider client")
