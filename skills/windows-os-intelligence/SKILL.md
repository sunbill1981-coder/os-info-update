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

Use `py` or `python` instead of `python3` on Windows if that is the configured launcher. Use `--sources msrc,release-health,lifecycle,windows-insider` to select sources. The collector writes raw snapshots under `data/raw`, the current normalized corpus to `data/normalized/events.ndjson`, checkpoints and change history to `data/state/os-intel.sqlite3`, and a per-run Markdown/JSON report under `reports`.

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

Use structured extraction for factual fields and retain source wording for evidence. Do not fabricate affected builds, mitigations, CVE exploitability, or compatibility conclusions. Label uncertainty and list the missing evidence.

## Deliverable, storage, and Feishu publication

All human-facing output must be in Simplified Chinese, including report headings, synthesized titles, summaries, status labels, risk explanations, recommendations, command-line progress, and coverage warnings. Keep official product names, CVE/KB/build identifiers, protocol abbreviations, canonical URLs, and original evidence unchanged where translation would damage auditability. Store original source text in the structured record for traceability, but do not use it as the visible report narrative.

Return a compact report grouped into:

- newly discovered or materially updated events;
- high-priority cloud-desktop risks and recommended action;
- compatibility and lifecycle items;
- early signals awaiting confirmation; and
- coverage gaps or failed sources.

Local files and SQLite remain the auditable source of truth. When Feishu publication is requested, read [the Feishu integration guide](references/feishu-integration.md). Keep collection and publication as separate commands. Run the publisher in dry-run mode first, validate the target table schema, and never place a real Feishu credential, Base/table/chat/user identifier, webhook, or internal record in the repository.

The Feishu publisher consumes `events.ndjson`, upserts the event table by stable event ID and content fingerprint, and can send alerts only for configured alert levels whose alert fingerprint has not been recorded. Historical backfills should normally publish records without sending one message per event. Do not claim a Feishu publication succeeded unless the publisher completed successfully.

Only send immediate alerts for authoritative, high-risk changes or when the caller explicitly asks. Historical backfills normally finish with one digest. In incremental mode, remain quiet when there is no material change.
