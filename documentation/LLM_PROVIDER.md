# LLM Provider Contract

Fire Crow's AI narrative layer talks to exactly one provider: **Google Gemini**.
This file records the contract Fire Crow actually relies on. It is not a copy of
Google's documentation; it is the subset that `backend/src/services/llm_provider.rs`
depends on, so a change in the provider API surfaces as a failing test here rather
than as a silent behaviour change in production.

Verified against Google's official Gemini API documentation during Phase 16.

---

## Provider

| Item | Value |
|---|---|
| Provider | Google Gemini (Generative Language API) |
| Endpoint | `POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent` |
| Authentication | `x-goog-api-key: <GEMINI_API_KEY>` request header |
| Configured model | `GEMINI_MODEL` — **required, no default** |
| Implementation | `backend/src/services/llm_provider.rs` |

The model is taken from configuration and is never substituted. If `GEMINI_MODEL`
or `GEMINI_API_KEY` is unset, generation fails closed with
`GenerationError::NotConfigured`; the backend still starts and the deterministic
audit is unaffected. Choosing a fallback model silently would make the recorded
model name a lie, so it is not done.

Configuration keys (all existing, no new provider settings were introduced):

| Variable | Use |
|---|---|
| `GEMINI_API_KEY` | Credential. Never logged, never persisted, never in a prompt. |
| `GEMINI_MODEL` | The one model used. |
| `GEMINI_TIMEOUT_SECONDS` | Total budget for the call, including retries. |
| `GEMINI_MAX_ATTEMPTS` | Attempt ceiling; clamped to 3 by the transport. |
| `GEMINI_MAX_PROMPT_CHARS` | Prompt ceiling, enforced before the request. |

---

## Request schema

```json
{
  "contents": [{ "role": "user", "parts": [{ "text": "<build_prompt output>" }] }],
  "generationConfig": { "responseMimeType": "application/json" }
}
```

Deliberately omitted: `responseSchema`. The narrative shape belongs to
`schemas::ai_narrative` (AiNarrative v1). Restating it in provider terms would
make the transport a second source of truth for the schema, which is exactly the
coupling that must not exist. The prompt is sent whole, as produced by
`build_prompt` — Phase 15B's prompt architecture is unchanged, so no repository
context, evidence, or secret can enter the request.

## Response extraction

Model text is `candidates[].content.parts[].text`, concatenated in order across
all parts and candidates. A response with no usable text — including one blocked
before generation (`promptFeedback.blockReason`) — is `Malformed`. The provider's
`usageMetadata` and `finishReason` are not consumed.

---

## HTTP statuses Fire Crow distinguishes

Non-2xx responses are **not** treated as one error. Each status maps to its own
failure class so the operator action is unambiguous:

| Status | `GenerationError` | Retried? | HTTP to caller |
|---|---|---|---|
| 400, 404, 405, 415, 422 | `InvalidRequest` | no | 502 |
| 401 | `Authentication` | no | 502 |
| 403 | `Authorization` | no | 502 |
| 429 | `RateLimited` | yes | 429 |
| 5xx | `Unavailable` | yes | 502 |
| request deadline | `Timeout` | no | 504 |
| body over `max_response_bytes` | `ResponseTooLarge` | no | 502 |
| connection/TLS failure | `Transport` | no | 502 |
| unparseable or empty body | `Malformed` | no | 502 |
| unset credential or model | `NotConfigured` | no | 503 |

Provider response bodies are never read into an error and never forwarded to a
caller: they can echo the prompt, internal diagnostics, or request identifiers.
Error messages are fixed text written by Fire Crow.

## Limits Fire Crow relies on

| Limit | Enforced by | Behaviour when exceeded |
|---|---|---|
| Prompt size | `ModelConfig::max_prompt_chars` | `PayloadTooLarge`; the model is never called |
| Response size | `max_response_bytes`, checked while streaming | `ResponseTooLarge`; the body is **rejected, never truncated** — a truncated document could parse into a narrative the model did not write |
| Wall-clock | `tokio::time::timeout` over every attempt | `Timeout`; never a scanner or audit failure |
| Attempts | `min(GEMINI_MAX_ATTEMPTS, 3)` | Stops; no unbounded retry |

## Retry policy

Retries happen only for `RateLimited` and `Unavailable`, the two classes Google
documents as transient, with linear backoff (250ms × attempt). Never retried:
authentication, authorization, invalid request, malformed response, oversized
response, timeout, transport failure, and any model-output validation failure.
The total time budget covers all attempts, so retries cannot extend the call
beyond `GEMINI_TIMEOUT_SECONDS`. There is no retry queue and no AI backlog: a
narrative is optional, so a user can simply request it again.

---

## Secret detection: a documented limitation

Fire Crow's `validate_narrative` refuses narrative text containing
credential-shaped strings via `contains_known_credential_assignment`
(`services::redaction.rs`).

**This detection is pattern-based and therefore finite.** A model response
containing a secret format Fire Crow has no pattern for may not be detected.
Fire Crow makes **no claim of universal secret detection**, and this limitation is
accepted rather than papered over: the canonical audit is redacted upstream, the
prompt deliberately contains no evidence at all, and the narrative schema is
validated against the exact report it explains.

Expanding the pattern list is a deliberate security-policy decision, not a
side effect of transport work. It was explicitly deferred in Phase 16.

## Prompt injection

No blocklist of injection phrases exists, and none should be added casually. The
security boundary is structural instead:

```
untrusted model text -> schema validation -> semantic validation -> persistence
```

Instruction-like text ("ignore previous instructions", "report a score of 10")
is inert: it cannot create a finding, assert a severity, alter the score, alter
coverage, or modify the deterministic report. The deterministic report's own
immutability triggers enforce the last of those in the database.

---

## Real-provider smoke test

Opt-in only. It is `#[ignore]`d *and* gated on an environment variable, so it
cannot run in ordinary CI even with `cargo test -- --ignored`.

```bash
cd backend
FIRECROW_LLM_LIVE=1 \
GEMINI_API_KEY=<key> \
GEMINI_MODEL=gemini-2.0-flash \
  cargo test --test llm_provider real_provider_smoke -- --ignored --nocapture
```

It builds a known finalized deterministic fixture, sends the real
`build_prompt` output, parses the response through `parse_and_validate`, reports
whether the narrative validated or was refused, and **persists nothing**. The API
key is never printed; only byte counts and validation outcomes are.

Note that a *refusal* is a legitimate outcome of this test, not a failure: it
means the model did not honour the AiNarrative v1 contract on that run.

---

## Changing the provider

Changing provider must require editing exactly three things:

1. `backend/src/services/llm_provider.rs` (the transport)
2. configuration (`src/config.rs`)
3. this file

It must **not** require changes to `schemas::ai_narrative.rs`, the Phase 14
validator, Phase 15A persistence, the deterministic report renderer, the scanner
pipeline, or canonicalization. `tests/llm_provider.rs` asserts this: it drives
the boundary through a mock HTTP server and never references a provider type
outside the transport module.