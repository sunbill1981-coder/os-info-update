---
name: windows-os-intelligence
description: "Collect, discover, correlate, and assess Windows release, update, vulnerability, behavior-change, compatibility, and cloud-desktop risk intelligence for a historical or rolling time range. Use for Windows 10/11 and Windows Server 2019/2022/2025 monitoring; not for non-Windows OS research."
---

# Windows OS Intelligence

Collect useful Windows intelligence as normalized events, not as a list of search results. The goal is to determine whether a change affects a defined Windows product and a cloud-desktop role (guest, host, broker, or supporting service), retain evidence, and make an actionable recommendation.

## Choose the collection window

Resolve the requested interval before collecting. Treat dates as inclusive and state the time zone used.

- **Backfill:** use explicit `start` and `end` dates. For intervals over 31 days, process calendar-month chunks and merge before reporting. Do not send one notification per historical item; produce a reviewable summary and write deduplicated history.
- **Rolling:** use an explicit duration such as `last 7 days` or `last 90 days`.
- **Incremental:** use the latest successful checkpoint and a configurable overlap window (default: 72 hours) so late edits and revised advisories are detected. If no checkpoint exists, ask for a window or use the caller's stated default.

For long backfills, report progress by chunk and keep a source-level checkpoint. Never silently substitute a short rolling window for an explicitly requested historical range.

## Scope the Windows products precisely

Record the most specific product identity supported by evidence:

`product family → release/version → edition → installation option → architecture → build range → servicing channel → cloud-desktop role`

Do not infer an Edition from a generic Windows announcement. When a source does not distinguish editions, mark applicability as `not specified` rather than claiming Pro, Enterprise, Education, LTSC, Multi-session, Server Core, or Desktop Experience coverage.

Map each event to one or more affected product profiles. Keep Windows client and server separate, and preserve roles such as guest, Hyper-V host, RDS host, broker, directory service, or file/profile service.

## Collect in source order

Use [source priority and collection guidance](references/source-priority.md). Prefer official APIs, feeds, and stable release-health pages. Use browser automation only for content that cannot be retrieved reliably through those paths or that requires an authorized interactive session.

For every candidate, retain the canonical source URL, publisher, published and updated times, a short evidence excerpt, and source identifiers such as CVE, KB, Windows known-issue, build, safeguard hold, or advisory ID. Respect source terms, robots controls, rate limits, and authentication boundaries.

Do not limit discovery to known bugs and CVEs. Look for security enforcement, default changes, new prerequisites, deprecations, unsupported configurations becoming blocked, host/guest version constraints, regressions, and changes that expose latent deployment risk. Read [risk discovery and early-warning guidance](references/risk-discovery.md) when performing a discovery or enrichment pass.

For CVE events, enrich from CISA KEV and FIRST EPSS when configured. Keep threat urgency separate from technical risk and confidence. Preserve three field states: `已发布`, `明确无记录`, and `获取失败`; never convert an unavailable feed into a negative finding. On a transient outage, report a run-level coverage gap and retain the last successful enrichment for existing events; use `获取失败` when no prior successful value exists. A changing EPSS probability may refresh the record but must not alter the source-fact fingerprint or independently resend an alert. A new KEV listing or authoritative exploitation-status change may escalate an alert.

## Run the deterministic collector

Run the bundled Python 3.9+ collector from the repository root. It uses only the Python standard library and therefore works on macOS and Windows without installing packages.

```bash
# Explicit historical range
python3 skills/windows-os-intelligence/scripts/collect.py \
  --mode backfill --start 2026-01-01 --end 2026-08-31

# Last 14 days
python3 skills/windows-os-intelligence/scripts/collect.py \
  --mode rolling --days 14

# Continue from source checkpoints with a 72-hour overlap
python3 skills/windows-os-intelligence/scripts/collect.py --mode incremental
```

Use `py` or `python` instead of `python3` on Windows if that is the configured launcher. Use `--sources msrc,release-health,lifecycle,windows-insider` to select sources. The collector writes raw snapshots under `data/raw`, the current normalized corpus to `data/normalized/events.ndjson`, checkpoints and change history to `data/state/os-intel.sqlite3`, and per-run Markdown, JSON, and self-contained HTML reports under `reports`. `reports/latest.html` is a portable copy of the newest interactive report. Keep every displayed conclusion and recommendation linked directly to its supporting public source; retain all official page references when one issue spans product or status pages.

For signals discovered through web research or a source not handled by the deterministic collectors, write one evidence record per source to `data/inbox/signals.ndjson`, following [the event model](references/event-model.md), then run:

```bash
python3 skills/windows-os-intelligence/scripts/collect.py \
  --mode rolling --days 30 --sources signals
```

Never encode an observed incident, KB number, error code, or product-specific workaround as a privileged production rule. Examples belong in tests. Production classification must use configurable change, precondition, workflow, symptom, environment, and evidence dimensions.

Treat exit code `0` as full source success and exit code `2` as a partial run with at least one failed source. Partial output remains usable, but the report's coverage-gap section must be reviewed.

## Normalize, correlate, and assess

Read [the event model](references/event-model.md) before creating or changing a data store schema.

1. Create or update an event using stable source identifiers first. A KB may link to multiple CVEs and known issues; do not collapse them into an unrelated single record.
2. Preserve a change timeline when an authoritative source changes status, scope, workaround, resolution, or affected build. Never overwrite the history.
3. Assign separate **risk** and **confidence** values. A community-only signal can be urgent to investigate but must not be presented as a confirmed Microsoft issue.
4. Assess cloud-desktop relevance against the affected component, deployment role, workflow, precondition, and the configured environment profile. Explain why an event is relevant or why it is out of scope.
5. Keep **technical risk**, **environment relevance**, **confidence**, and **action priority** separate. Low confidence changes the alert state from confirmed to investigative; it must not automatically hide a potentially severe, highly relevant signal.
6. Correlate sources only when they describe the same coherent risk. A shared KB alone is insufficient because one update can contain many unrelated changes.
7. Preserve patch relationships from official remediation data: resolving KB, fixed build, supersedence, and restart requirement. Do not infer a supersedence edge from publication order alone.
8. Translate every retained event into a decision-ready cloud-desktop analysis card. Follow [the cloud-desktop guidance](references/cloud-desktop-guidance.md): summarize the concrete problem, infer the potential Guest/Host and delivery-chain impact, propose executable tests and rollout gates, and list targeted questions still needing validation. Clearly separate public facts from engineering inference.

If no local environment profile exists, use the conservative unconfigured profile and do not claim that a public Windows issue applies internally. Direct first-time users to `scripts/setup_environment.py`; keep `config/environment.local.json` local and untracked. For multiple baselines, read [the environment profile guide](references/environment-profile.md) and define separate asset groups. Treat the matched asset count as a candidate scope, never as confirmed impact.

When the environment is identified as Ruijie Cloud Desktop, read [the Ruijie public capability profile](references/ruijie-cloud-desktop-profile.md). Use it to expand risk routes, test ideas, and clarification questions across VDI, IDV, TCI/VOI, and VAPP. Public vendor capabilities are not evidence that a deployment enabled them: only confirmed local architectures and components may raise environment relevance. In particular, do not equate all Ruijie remote sessions with RDP because public materials also describe EST/HEST protocols.

For an original-equipment-manufacturer or product-team scope, set `scope_type` to `product_portfolio`. Treat every declared delivery architecture as a validation surface, order recommendations by `architecture_priorities`, and use the wording "product validation scope" rather than implying that every customer deployment is affected. A high VDI priority means VDI is tested first, not that IDV, TCI/VOI, or VAPP can be omitted.

Use structured extraction for factual fields and retain source wording for evidence. Do not fabricate affected builds, mitigations, CVE exploitability, or compatibility conclusions. Label uncertainty and list the missing evidence.

## Deliverable, storage, and Feishu publication

All human-facing output must be in Simplified Chinese, including report headings, synthesized titles, summaries, status labels, risk explanations, recommendations, command-line progress, and coverage warnings. Keep official product names, CVE/KB/build identifiers, protocol abbreviations, canonical URLs, and original evidence unchanged where translation would damage auditability. Store original source text in the structured record for traceability, but do not use it as the visible report narrative.

Return a compact report grouped into:

- newly discovered or materially updated events;
- high-priority cloud-desktop risks and recommended action;
- compatibility and lifecycle items;
- early signals awaiting confirmation; and
- coverage gaps or failed sources.

Within each event, show the public fact summary first, then the potential cloud-desktop impact, recommended tests, prevention/rollout gates, targeted exploration questions, and environment applicability. Generic advice such as "perform regression testing" is insufficient; name the workflow and scenario to exercise.

Local files and SQLite remain the auditable source of truth. When Feishu publication is requested, read [the Feishu integration guide](references/feishu-integration.md). Keep collection and publication as separate commands. Run the publisher in dry-run mode first, validate the target table schema, and never place a real Feishu credential, Base/table/chat/user identifier, webhook, or internal record in the repository.

For an existing state database, run `scripts/migrate.py --dry-run` before `--apply`. The migration creates a consistent backup and establishes the v4 fact/v2 assessment fingerprint baseline. Release Health observations that share Microsoft's stable issue identifier must become one logical event while retaining every official page reference. Do not enable group alerts until a no-alert Feishu synchronization has refreshed the baseline.

For a first-time Feishu connection, prefer the bundled `scripts/setup_feishu.py` interactive wizard. It previews data before connecting, stores credentials only in ignored local files, validates authentication and schema, and requires a separate explicit confirmation before creating fields, writing a sample, importing a baseline, or sending a test message. Use `--preview` and `--check` for read-only operation.

The Feishu publisher consumes `events.ndjson`, upserts the event table by stable event ID and content fingerprint, and optionally synchronizes evidence, environment-profile, change-history, and run-history tables from SQLite. It may seed a new applicability review and a new remediation record, but those tables are human-owned: once a primary key exists, the publisher must never update or delete that record. Alert cards may link to the official source and the corresponding Base record, and are sent only for configured alert levels whose alert fingerprint has not been recorded. Historical backfills should normally publish records without sending one message per event. Do not claim a Feishu publication succeeded unless the publisher completed successfully.

Only send immediate alerts for authoritative, high-risk changes or when the caller explicitly asks. Historical backfills normally finish with one digest. In incremental mode, remain quiet when there is no material change.
