---
name: windows-os-intelligence
description: "Collect, normalize, and assess Windows release, update, vulnerability, compatibility, and cloud-desktop intelligence for a specified historical or rolling time range. Use for Windows 10/11 and Windows Server 2019/2022/2025 monitoring; not for non-Windows OS research."
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

## Normalize, correlate, and assess

Read [the event model](references/event-model.md) before creating or changing a data store schema.

1. Create or update an event using stable source identifiers first. A KB may link to multiple CVEs and known issues; do not collapse them into an unrelated single record.
2. Preserve a change timeline when an authoritative source changes status, scope, workaround, resolution, or affected build. Never overwrite the history.
3. Assign separate **risk** and **confidence** values. A community-only signal can be urgent to investigate but must not be presented as a confirmed Microsoft issue.
4. Assess cloud-desktop relevance against the affected component, deployment role, and any supplied internal product matrix. Explain why an event is relevant or why it is out of scope.

Use structured extraction for factual fields and retain source wording for evidence. Do not fabricate affected builds, mitigations, CVE exploitability, or compatibility conclusions. Label uncertainty and list the missing evidence.

## Deliverable and storage

Return a compact report grouped into:

- newly discovered or materially updated events;
- high-priority cloud-desktop risks and recommended action;
- compatibility and lifecycle items;
- early signals awaiting confirmation; and
- coverage gaps or failed sources.

When a Feishu Base destination is supplied, use linked tables for Events, Event Changes, Windows Product Profiles, Sources, Assessments, and Collection Runs. Upsert events idempotently, batch writes where supported, and keep raw snapshots/checkpoints outside the Base. If no destination is supplied, return a structured event list suitable for review; do not create or message external systems without authorization.

Only send immediate alerts for authoritative, high-risk changes or when the caller explicitly asks. Historical backfills normally finish with one digest. In incremental mode, remain quiet when there is no material change.
