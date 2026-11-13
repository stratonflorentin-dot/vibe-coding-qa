# Vibe Intelligence (Core v1)

An internal, modular intelligence service inside Vibe Coding QA. It **orchestrates**
the existing AI capability — it does not replace it, and it never applies code or
deploys (that stays in the controlled remediation + release-gate workflows). The
backend starts and runs fine **without any AI provider configured**.

## Pieces

| Module | Role |
|---|---|
| `contracts.py` | Typed Pydantic request + one result envelope (status, confidence, validated evidence refs, limitations) for the 8 operations. |
| `exceptions.py` | Structured, client-safe errors with stable `code` + HTTP status. |
| `model_registry.py` | Provider/model + capability view from the existing `AIConfig`. Adapter kinds: `openai_compatible` / `ollama` / `vllm` over one OpenAI-shaped client. **Never returns the API key.** |
| `router.py` | Deterministic routing. AI ops degrade to deterministic evidence (or `unavailable`) when no capable provider exists; capability mismatches are flagged, never a silent downgrade. |
| `context_engine.py` | Minimum **redacted** context from the store (metadata, scan, findings, optional architecture/dependencies), budgeted, with real evidence refs. Source contents off by default. |
| `gateway.py` | validate → resolve/authorise project → prepare context → route → execute → persist task + model execution → structured result. |
| `handlers.py` | Deterministic handlers + AI handlers that reuse the tested AI service for finding-grounded ops. A standing system guard treats project content as untrusted **data** (prompt-injection defence). Verification never fabricates passing tests. |
| `evaluations.py` | Evidence-reference validation, result scoring, and a synthetic benchmark description. Confidence is kept separate from measured accuracy. |

## Operations

`analyze_project`, `discover_features`, `map_architecture`, `generate_test_plan`,
`diagnose_failure`, `propose_repair`, `analyze_regression`, `summarize_verification`.

Deterministic (no AI needed): `map_architecture`, `analyze_regression`,
`summarize_verification`. The rest prefer an AI model and degrade gracefully.

## API (internal — not exposed publicly by default)

Behind the existing session gate + RBAC. Reads need any authenticated user;
running a task needs **security analyst or above**.

```
GET  /api/intelligence/health          # configured?, provider/model counts, operations (no secrets)
GET  /api/intelligence/providers
GET  /api/intelligence/models
POST /api/intelligence/tasks           # body: IntelligenceRequest (operation + ids + context options)
GET  /api/intelligence/tasks/{id}      # task + its model executions
```

## Configuration

Uses the **existing** AI settings — no new secrets. Set the provider via the
dashboard Settings page or the environment:

```
VCQA_AI_PROVIDER=openrouter
VCQA_AI_API_KEY=<server-side only; never sent to the frontend>
VCQA_AI_BASE_URL=https://openrouter.ai/api/v1   # or an Ollama/vLLM OpenAI-compatible URL
VCQA_AI_MODEL=openai/gpt-4o-mini
```

The key lives server-side only (env or in-memory from the settings form); it is
never persisted to SQLite, never returned by any endpoint, and redacted from
every message sent to a provider.

## Persistence

Migration **v5**: `intelligence_tasks` (one row per task) and `model_executions`
(provider/model/latency/fallback). No secrets, prompts, or source are stored.
