# Windows Event Model

## Event identity

An Event represents one coherent change or issue. Use one or more stable identifiers where present:

- `CVE-YYYY-NNNN`
- `KBxxxxxxx`
- Microsoft known-issue ID
- safeguard hold ID
- vendor advisory ID
- canonical publisher URL

Use relationships instead of flattening: one KB can resolve several events, an event can affect several product profiles, and an event can have multiple source updates.

## Event information and storage locations

This table describes the information to retain, not a JSON object whose every row is mandatory. Event fields use the names/defaults in scripts/osintel/model.py; source acquisition and first-seen metadata also live in Store tables. Use the separate review contracts below for constraints, risks and feedback. Reviewed reading themes use the separate [theme contract](engineer-report.md); they are derived interpretations, not event source facts or cross-period causality proofs.

| Field | Meaning |
|---|---|
| Event ID | Internal immutable ID |
| Title | Neutral factual title |
| Type | release, feature, update, regression, known issue, vulnerability, compatibility, limitation, deprecation, lifecycle |
| Status | discovered, reported, investigating, confirmed, mitigated, resolved, verified, closed |
| Source tier | P0–P3 provenance class assigned by a trusted collector, not by inbox self-report |
| Confidence | 0–100, based on authority, evidence quality and independent corroboration |
| Risk score | 0–100, based on technical and operational impact; internal relevance remains separate |
| Product profiles | Linked affected Windows profiles |
| Role | guest, host, broker, directory, profile/file service, or unknown |
| Components | Normalized component tags |
| Change kinds | Security enforcement, default change, deprecation, regression, prerequisite change, or version-combination constraint |
| Preconditions | Configuration, deployment pattern, version state, driver, hardware, or environment required to trigger the risk |
| Affected workflows | User or platform workflows that can fail, such as provisioning, sign-in, session connection, update, boot, or profile access |
| Symptoms | Observable failures, error classes, event IDs, and other diagnostic signatures |
| IDs | CVE, KB, build, known-issue, advisory and safeguard IDs |
| Times | Event published_at/updated_at; source raw-document fetched_at and Store first_seen/last_seen/collected_at; resolution times only where explicitly supplied by the source, not a required standalone Event field |
| Evidence | canonical URL and brief supporting excerpt |
| Assessment | technical risk, environment relevance, action priority, workaround, recommended action, and uncertainty |
| Threat enrichment | exploitation status, CISA KEV, FIRST EPSS, threat urgency, and per-field acquisition state |
| Update details | Product-specific introducing KB/Build, fixing KB/Build, mitigation KB, fix scope (complete/partial/unconfirmed), trigger clues, direct source URL; MSRC resolving KB, supersedence and restart requirement |
| Asset match | matched local asset-group names and candidate affected count |
| Affected scope | versioned CPU architectures, per-product CPU scope, named affected applications, condition clues, explicit/hedged exclusions, recognized symptoms and directly cited source excerpts |
| Applicability review | matching/nonmatching/unknown checks against declared baselines; independent of risk scores and coarse asset candidates, not proof of actual impact |
| Evidence review | `evidence-review-v1`: source kind, proof state, snapshot hash, review time/note, original origin, author/independence basis, reproduction note and missing evidence; metadata alone is not semantic proof |
| Correlation | Explicit semantic risk keys and number of independent supporting sources |
| Source activity | Current CVRF document update time and original revision dates/descriptions; traces monthly activity, not a historical as-of snapshot |
| Fact hash aliases | Local compatibility keys for unchanged canonical facts; excluded from all fingerprints and cleared on a real fact change |
| Alert level | confirmed alert, investigation alert, priority watch, watch, or archive |

## Windows product profile fields

Use a separate profile for each internally relevant combination:

- product family: `client` or `server`
- product: Windows 10, Windows 11, Windows Server 2019/2022/2025
- release/version and build range
- edition: Home, Pro, Pro for Workstations, Enterprise, Education, Enterprise multi-session, LTSC, IoT, Standard, Datacenter, Azure Edition, or `not specified`
- installation option: Desktop Experience, Server Core, or `not specified`
- architecture and servicing channel
- deployment role and internal usage/criticality

## Cloud-desktop component tags

Use only evidence-supported tags. Typical tags include `RDP`, `RDS`, `RemoteApp`, `RD Gateway`, `NLA`, `CredSSP`, `Hyper-V`, `VBS`, `HVCI`, `Credential Guard`, `GPU-P`, `vGPU`, `WDDM`, `DWM`, `FSLogix`, `profile container`, `Winlogon`, `LSASS`, `Kerberos`, `Entra ID`, `GPO`, `SMB`, `printing`, `USB redirection`, `audio/video redirection`, `display`, `networking`, `Windows Update`, `image management`, and `recovery`.

## Scoring

Keep the scores separate.

**Technical risk (0–100):** security or stability impact, affected workflows, trigger conditions, urgency, scope, and recovery difficulty. Do not use publisher authority here.

Collectors may provide a source-derived technical score, for example from CVSS or an official severity. The deterministic assessment also calculates an inferred operational-impact score from normalized change, precondition, workflow, and symptom dimensions. The final technical risk is `max(source-derived risk, inferred risk)`: inference may raise an understated source score but must not lower an explicit authoritative severity. Environment relevance remains separate and must never be folded into technical risk.

**Environment relevance (0–100):** match against internal products, roles, components, critical workflows, and known deployment patterns. Unknown environment values must not be treated as a match.

**Confidence (0–100):** publisher authority, identifier quality, evidence completeness, and independent corroboration. Community-only reports should normally remain below the confirmed-alert threshold until corroborated.

**Action priority (0–100):** a weighted operational ordering derived from technical risk, environment relevance, and confidence. Preserve the component scores so users can understand why an item ranked highly.

**Threat urgency (0–100):** current exploitation pressure derived from authoritative exploitation status, CISA KEV, and FIRST EPSS. It may raise action priority but must not be described as technical severity or source confidence. Store feed results with `已发布`, `明确无记录`, `获取失败`, or `不适用` so an unavailable source is not misread as a negative finding.

An authoritative OOB update, active exploitation statement, data loss, bulk sign-in failure, boot failure, blue/black screen, or widespread session outage merits immediate review even when the exact internal edition has not yet been confirmed.

## External investigation digest

Short data/reports paths in this reference are relative to runtime/<purpose>/, default trial; package files use caller-selected explicit paths.

`reports/run-NNNNNN.triage.json` is a derived report (`external-triage-v1`), not an Event schema migration or a new alert policy. It does not change facts, scores or notification fingerprints. Its scope follows the report: window events for historical/rolling runs, new or materially changed events for incremental runs.

- `items` retains every input event's investigation assessment; `queue` contains only the bounded digest. No events are merged by category or KB.
- `external_relevance` records direct/shared workflow candidates and the structured dimensions supporting them. It does not read environment relevance or claim that the product uses those paths. Internal applicability is copied separately and may remain unknown.
- `priority` is a qualitative investigation label. Concrete changes to requirements can warrant examination before any reported failure. A single community failure may warrant examination while remaining an unconfirmed user report.
- `summary` distinguishes all retained items, eligible candidates, shown candidates, low-signal retained items and high-attention overflow. `not_shown` includes all undisplayed items; `eligible_not_shown` counts only eligible ones. Budget limits never certify omitted items as safe.
- `review` contains a suggested time and triggers, with `scheduled: false`. The date is based on the actual generation time, not a historical report month's end; no reminder, follow-up execution or product test has been scheduled.

`config/triage.json` controls generic workflow relations, notable change categories, severe symptom classes, reading budget and review intervals. Do not introduce incident-specific IDs, failure signatures or product workarounds. Full facts and original scope remain in the event archive; external source prose must be reviewed or classified through the existing evidence pipeline before being used as structured dimensions.

## Timeline and deduplication

Store every material source update as a linked Event Change containing prior and new status or scope, changed fields, time, source URL, and evidence hash. Upsert only when the identity matches; otherwise create a candidate relation for review. Do not merge events merely because they mention the same Windows version or KB.

When several sources support one risk, give every source its own evidence record. Use a shared semantic correlation key only when the change, trigger/precondition, affected workflow, and symptom are coherent. Two independent lower-tier sources can raise an investigation alert; only authoritative evidence can make an official confirmation claim.

## Fingerprints and alert lifecycle

Set-valued identifiers, patch rows and their product/KB memberships are sorted and deduplicated before hashing; ordered revision timelines are preserved. The CVRF document container ID is provenance and does not independently change the CVE fact hash. Both stored and incoming payloads are compared under the same canonical rules, so legacy order differences do not add change history. Only unchanged canonical facts retain old hash aliases for alert compatibility; real fact changes clear those aliases.

Use separate versioned fingerprints. `fact_hash_v4` covers source facts, evidence, exploitation status, official update relationships, and stable identifiers and anchored URLs for all official page references. Whole-page raw hashes remain available for audit but are excluded because unrelated page edits must not change an event fingerprint. `assessment_hash_v2` covers derived classification, scoring, threat enrichment, field state, and asset matching; `record_hash_v1` decides whether the stored or Base record needs refreshing. Alert idempotency uses the fact fingerprint, alert threshold, stable KEV membership, and exploitation status. Wording, ordinary score tuning, or an EPSS probability refresh cannot resend an old alert.

Formal alerts require authoritative P0/P1 evidence. Inbox records cannot self-assign authoritative status, P0/P1, or review metadata. The optional `discovery` collector assigns publisher/path provenance only after validating a cached snapshot and quotation, with reviewer-supplied semantic interpretation. Reviewed community sources remain P3/reported and cannot claim internal reproduction or official confirmation. Corroboration for reviewed discovery uses independent observers/origins: repeated authors on one platform, reposts and multiple pages by one publisher do not add independent confirmations; unverified reports from one community host count at most once. Legacy records without review metadata retain the publisher/source identity fallback. Counts are recomputed over related current/historical evidence rather than trusting an inherited count. This corroboration lookup keeps the existing 30-day last_seen window; it is separate from the unbounded-age active/unknown constraint lookup in continuity. Same-author cross-platform and same-organization independence still require reviewer judgment.

`evidence_review` is an assessment field, not part of the existing fact fingerprint; adding review metadata does not change old fact identities or introduce UUIDs. Empty new metadata is omitted from assessment/record fingerprints to avoid global churn for legacy events. Source factual title/summary/quotation changes still change the source-fact fingerprint normally. For reviewed extraction, supplied dimensions are authoritative to the assessment pipeline (not an assertion of official truth); missing dimensions remain unknown rather than reclassifying incidental/negated words in the reviewed summary.

`affected_scope` (`scope-v1`) and `applicability_review` (`applicability-v1`) are included in the assessment fingerprint, not the existing fact/alert fingerprint. Scope backfills cannot independently resend historical alerts. This iteration does not replace IDs or introduce permanent UUIDs. For interpretation and current limitations, read [scope interpretation](scope-interpretation.md).

Alert delivery states are `发送中`, `已发送`, and `已抑制`. Persist `发送中` before calling the messaging API and reuse the same idempotency key after an interrupted delivery.

## 独立派生对象与运行空间（0.4.0-rc.1）

Event 的身份与事实/评估指纹保持不变。Store 增量增加 derived_records、derived_changes 和 metadata：约束、组合风险、私有反馈各自使用稳定标识与修订历史，不挤入原始事件事实。源事实或依赖约束变化时运行视图增加 needs_review，不悄悄覆盖已核验结论。

run_purpose 隔离数据库、检查点及报告；candidate/approved 是包验收状态；publish target 是另一选择。旧数据保持未分类，不自动晋升。公共 dataset-v1 包使用白名单、版本和校验清单，私有反馈独立，不作为公共事实。具体字段、引文核验和导入/重评/回退协议见 [预发布操作指南](pre-release-operations.md)。

报告视图的 dataset_status=candidate 表示本轮输出尚待审阅，不会改变已验收包本身的状态。活动基线另用 active_dataset 与 active_dataset_status=approved 标识；报告可以同时引用已验收基线和保留的现场观察。不能仅凭 production 目录认定所有新采集数据已经验收。
