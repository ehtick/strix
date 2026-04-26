"""Shared model-retry policy used across every Strix LLM call."""

from __future__ import annotations

from agents.retry import (
    ModelRetryBackoffSettings,
    ModelRetrySettings,
    retry_policies,
)


# Retry: 5 attempts with ``min(90, 2*2^n)`` backoff. 4xx auth/validation
# errors are excluded from the retryable status list — they can't be
# fixed by retrying and should fail fast. Used by every ``RunConfig``
# Strix builds, plus the dedupe path's one-shot LLM call outside
# ``Runner.run``.
DEFAULT_RETRY = ModelRetrySettings(
    max_retries=5,
    backoff=ModelRetryBackoffSettings(
        initial_delay=2.0,
        max_delay=90.0,
        multiplier=2.0,
        jitter=False,
    ),
    policy=retry_policies.any(
        retry_policies.provider_suggested(),
        retry_policies.network_error(),
        retry_policies.http_status((429, 500, 502, 503, 504)),
    ),
)
