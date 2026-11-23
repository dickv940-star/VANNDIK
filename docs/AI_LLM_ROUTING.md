# VANNDIK Smart LLM Router

## What it does

The Agent Room classifies each incoming message into one of two execution tiers:

- `chat`: greetings, casual conversation, and short/simple questions. The router prioritizes the fast/light provider order.
- `work`: implementation, coding, research, SEO, writing, analytics, planning, integrations, debugging, and multi-step tasks. The router prioritizes the configured work models and uses the free-only fallback chain.

The classifier is deterministic and rule-based. It does not spend an extra model call to classify the message. A future classifier may be introduced only if its additional inference cost is justified and it remains behind the free-only policy.

## Provider order

| Tier | Priority |
|---|---|
| Chat | Cloudflare Workers AI → Gemini → Groq → hosted Gemma → OpenRouter Free |
| Work | Gemini → hosted Gemma → Groq → OpenRouter Free → Cloudflare Workers AI |

A provider is skipped unless its existing free-only configuration gate is satisfied. OpenRouter must use a model ID ending in `:free`. If no configured free provider succeeds, the request is stored in the D1 queue and retried by the existing scheduler. There is no paid fallback.

## Model override naming

The router supports model selection by provider, agent, and tier. Use Cloudflare Pages **Variables and Secrets** (Production) to configure plain-text model IDs; never put API keys in these variables.

Pattern:

```text
<PROVIDER>_<AGENT_ID>_<CHAT|WORK>_MODEL
<PROVIDER>_<CHAT|WORK>_MODEL
<PROVIDER>_MODEL
```

Provider prefixes:

- `GEMINI`
- `CF_AI`
- `GEMMA`
- `GROQ`
- `OPENROUTER`

Stable agent IDs:

- `TEAM`
- `SYSADMIN`
- `RESEARCHER`
- `WRITER`
- `SEO`
- `ANALYST`
- `EDITOR`
- `MEDIA`
- `CATALOG`
- `WEB`

Examples:

```text
GEMINI_WORK_MODEL=your-verified-free-work-model
GEMINI_RESEARCHER_WORK_MODEL=your-verified-free-research-model
GEMINI_WRITER_WORK_MODEL=your-verified-free-writing-model
CF_AI_CHAT_MODEL=@cf/google/gemma-4-26b-a4b-it
CF_AI_SYSADMIN_WORK_MODEL=your-verified-cloudflare-coding-model
GROQ_ANALYST_WORK_MODEL=your-verified-free-analysis-model
OPENROUTER_FREE_ONLY=true
OPENROUTER_WORK_MODEL=provider/model:free
```

These are examples of variable names and formats, not a recommendation that any particular external model is currently free or available. Verify each model ID and its provider's free quota before configuring it. Do not add a billing method or select a paid-only model.

Agent-specific override wins over tier-wide override, which wins over the provider-wide model, which wins over the built-in safe default. When an agent-specific model is not configured, that agent inherits the tier model.

## Dashboard visibility

The authenticated `GET /api/cms/ai-room/messages` response includes:

- `routing.strategy`
- `routing.chat_priority` and `routing.work_priority`
- `routing.models` for provider-level chat/work model choices
- `routing.agent_models` for the per-agent preferred chat/work model choices

The Agent Room displays the model preference for each agent. This is a configured preference, not proof that the model answered a particular message. Actual replies include the provider and model selected for that request; provider failures and queued work remain visible.

## Important limitations

- The task classifier is heuristic, so ambiguous messages may be classified incorrectly.
- Model selection does not grant tools or permissions. Agent capabilities still depend on implemented, authorized tools.
- Model IDs, provider availability, free quotas, and terms can change. A model being listed here does not mean it is active or free.
- A free provider can reject requests after its quota is exhausted. VANNDIK must queue work instead of silently switching to a paid service.
- Do not claim an agent has executed a task until a real tool result or verifiable artifact exists.
