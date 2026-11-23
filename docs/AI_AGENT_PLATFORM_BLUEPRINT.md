# VANNDIK AI Agent Platform — Zero-Cost Implementation Blueprint

Status: implementation specification; this document does not claim that integrations are connected or production-ready.

## Non-negotiable operating constraints

- Target operating cost: Rp0. Never add a paid API, paid hosting plan, billing method, credit purchase, or paid fallback.
- Use free/open-source software and official platform APIs only. A free software license does not make compute, storage, or third-party API quotas unlimited.
- When a provider quota or free allocation is exhausted, persist work in D1, pause/retry with bounded backoff, and report the exact blocker. Never silently switch to paid service.
- The user's laptop is not a production server. The platform must operate from Cloudflare-hosted components when free quotas permit.
- Human approval is mandatory before publishing, deleting permanently, changing security, migrating data, or taking other consequential actions.

## Agent roster

Keep the existing stable IDs and names in `functions/api/cms/[[path]].js`:

| ID | Agent | Responsibility |
|---|---|---|
| team | Tim VANNDIK | Master Director / Chief of Staff; always accepts Director instructions, plans and delegates |
| sysadmin | Arka | Cloudflare, application reliability, security, recovery |
| researcher | Ethan | Research, source verification, affiliate link validation |
| writer | Sophia | Articles, news, product copy, scripts |
| seo | Daniel | Technical SEO, metadata, indexing, growth |
| analyst | Isabella | Traffic, content performance, clicks, conversions, commissions |
| editor | Lucas | Fact checking, quality assurance, approval preparation |
| media | Maya | Media library, images, Google Drive, media hygiene |
| catalog | Rafi | Affiliate product, game, app/tool catalog |
| web | Nadia | Website UX, theme, navigation, language |

Do not create duplicate agents or replace these identities without Director approval.

## Group conversation behavior

- One shared WhatsApp-style group room. All agents can read the shared conversation and approved shared memory.
- Master Director is the default always-on coordinator. A directly addressed specialist can respond outside its scheduled work window.
- In group mode, the Conversation Orchestrator selects only relevant specialists. Specialists may respond to one another, ask clarifying questions, challenge unsupported claims, and hand off work.
- Use bounded discussion rounds, a maximum number of speakers per turn, duplicate-response detection, relevance checks, and a stop condition. Never create an endless agent loop or make every agent reply to every message.
- Distinguish actual tool execution from model-generated suggestions. Agents must never claim a search, upload, publication, OAuth connection, or database change succeeded unless a tool confirmed it.
- Persist each message, speaker ID, provider/model, task correlation ID, and outcome in D1.
- Keep a single model provider invocation where a simple answer is enough; use additional specialist inference only when it materially improves the result and free quota is available.

## Daily goals, schedule, and work queue

- Master Director proposes daily goals using business priorities, content calendar, due dates, backlog, performance evidence, and available free compute.
- Director can add, edit, reprioritize, pause, or cancel goals at any time.
- Every task must have an owner agent, expected output, priority, due time in Asia/Jakarta, status, dependencies, and approval requirement.
- Show today's goals, weekly calendar, assigned agent, progress, pending approvals, blockers, failed/paused work, and end-of-day report in the CMS dashboard.
- Scheduler executes only due tasks. It may wake on a Cloudflare Cron trigger, but should not call an LLM when no work is due.
- Daily cycle: plan → execute → quality review → Director approval → publish/execute → analytics → end-of-day report.
- A task is not complete until a verifiable artifact or tool result is stored. Unfinished work is rescheduled with an explicit reason.
- Respect publication deadlines; content must be researched, written, fact-checked, SEO-reviewed, and approved before its scheduled publish time.

## Open-source components to evaluate and reuse

### Automation and MCP

- [Activepieces](https://github.com/activepieces/activepieces) — MIT Community Edition; its pieces can be exposed as MCP tools. Useful as a reference for integration adapters and workflow concepts. Self-hosting still needs compute and supporting services; do not assume it can be deployed directly to Cloudflare Pages/Workers.
- [MCP specification and reference servers](https://github.com/modelcontextprotocol/modelcontextprotocol) and [reference servers](https://github.com/modelcontextprotocol/servers) — use the protocol to standardize tool discovery and invocation. The VANNDIK UI must show tool calls and require human approval for consequential actions.
- [Postiz](https://github.com/gitroomhq/postiz-app) — AGPL-3.0 self-hosted social publishing/scheduling reference. Hosted Postiz is paid; self-hosting requires a server and its own platform OAuth apps. Reuse/adapt only after license and deployment review; do not add its paid hosted service.
- Do not introduce a second always-running automation platform if its hosting, database, queue, or media requirements break the Rp0 Cloudflare-first constraint.

### Platform connectors

Use official APIs and OAuth, not browser scraping, password sharing, unofficial private endpoints, or anti-bot workarounds.

- Instagram: official Instagram API with Instagram Login; requires an eligible Professional account and the relevant permissions such as `instagram_business_basic` and `instagram_business_content_publishing`. Confirm current Meta app configuration, permissions, and review requirements before enabling publishing.
- Facebook Pages: official Graph API Page publishing; requires a Page access token and permissions such as `pages_manage_posts`, `pages_read_engagement`, and `pages_show_list`.
- YouTube Shorts: use the official YouTube Data API `videos.insert` upload path and OAuth. Shorts are uploaded videos, not a separate API. Respect the project's upload and other quota buckets; do not assume unlimited uploads.
- Shopee Affiliate: use the Indonesian official Affiliate Open API Explorer/schema and the user's approved Shopee Affiliate App ID/Secret. Supported surfaces include product/offer queries, short-link generation, and conversion/validated reports. A GitHub SDK/sample is reference code only; adapt it to the current Indonesia endpoint and schema, and do not scrape or fabricate API credentials.
- Build each connector as a small provider adapter with explicit scopes, encrypted token storage, token refresh, status/health check, quota/error reporting, and a disconnect/revoke path.
- Publishing actions must enter the Director approval queue. A successful OAuth connection does not mean that publishing has been approved or tested.

## Cloudflare-first target architecture

- Pages Functions: authenticated CMS APIs, orchestration, connector callbacks, approval and publishing endpoints.
- D1: agent memory, messages, daily goals, tasks, schedule, approvals, integration metadata, audit log, and retry queue.
- Cloudflare Cron Worker: wakes on a schedule and processes only due tasks; do not run inference when the queue is empty.
- Existing Workers AI binding: primary inference provider while its free allocation is available. Keep the existing explicit free-only provider gates; do not configure a provider unless its current free terms and quota are verified.
- Existing Google Drive media connection may remain the media store where the account's free storage and API quotas allow. Do not assume unlimited storage or use it for public sensitive files.
- Secrets and OAuth tokens stay in Cloudflare secrets or encrypted D1 storage, never in Git or browser code.

## Required dashboard areas

1. AI Agent Room — shared group chat, roster, speaker identity, tool activity, provider status.
2. Daily Goals — proposed/approved goals, progress, add-goal command, and end-of-day outcome.
3. Calendar & Schedule — day/week views, drag/reorder only after validation, due times in WIB, owner and dependencies.
4. Task Board — queued, running, awaiting approval, completed, paused, failed, and retry history.
5. Integrations — Instagram, Facebook Pages, YouTube, Shopee Affiliate, MCP tools; show connected/scopes/health/quota, never expose secrets.
6. Approval Center — preview exact content/action, destination account, scheduled time, approve/reject/edit.
7. Analytics — actual data with source and last-updated timestamp; label estimates separately.

## Delivery phases

1. Stabilize the current AI room and provider response parsing; preserve the merged unlimited-local-message change and bounded retry policy.
2. Implement a bounded multi-agent Conversation Orchestrator and shared memory behavior.
3. Add D1-backed daily goals, task ownership, dependencies, schedules, and dashboard views.
4. Add a generic MCP/tool registry with allowlists, audit logs, approval gates, and per-tool permissions.
5. Add official platform connectors one by one: YouTube, Meta/Instagram/Facebook, then Shopee Affiliate after credentials and access are available.
6. Add publishing approval workflow and analytics feedback loop.
7. Test end-to-end using free quotas only; do not claim an integration is active until OAuth, a read operation, and (after approval) a test publication succeed.

## Acceptance criteria

- No paid API, paid provider fallback, paid hosting dependency, or billing method is introduced.
- Master Director can accept a message at any time while specialists follow schedules unless explicitly summoned.
- Group discussion has bounded rounds and does not spam.
- Each daily goal and task appears in the dashboard and has an auditable owner/status/result.
- A task survives scheduler restarts and is safely retried without duplicate publication.
- Each connector reports its real authorization and quota status; missing credentials are shown as “not connected,” not “working.”
- No public content is published without Director approval.
- If all free AI capacity is unavailable, messages/tasks are persisted and clearly marked queued/paused.

## Important references

- [Activepieces source and license](https://github.com/activepieces/activepieces)
- [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol)
- [Postiz source](https://github.com/gitroomhq/postiz-app)
- [Meta Instagram API changelog](https://developers.facebook.com/docs/instagram/platform/instagram-api/changelog/)
- [Facebook Page feed publishing requirements](https://developers.facebook.com/docs/graph-api/reference/page/feed/)
- [YouTube videos.insert](https://developers.google.com/youtube/data/v3/docs/videos/insert)
- [YouTube API quota documentation](https://developers.google.com/youtube/data/determine_quota_cost)
- [Shopee Indonesia Affiliate Open API Explorer](https://open-api.affiliate.shopee.co.id/explorer/v2)
- [Shopee Affiliate API access overview](https://help.shopee.sg/portal/10/article/191702-API-Access)
