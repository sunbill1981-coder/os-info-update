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

## Required event fields

| Field | Meaning |
|---|---|
| Event ID | Internal immutable ID |
| Title | Neutral factual title |
| Type | release, feature, update, regression, known issue, vulnerability, compatibility, limitation, deprecation, lifecycle |
| Status | discovered, reported, investigating, confirmed, mitigated, resolved, verified, closed |
| Source confidence | 0–100, based on evidence tier and corroboration |
| Risk score | 0–100, based on impact and internal relevance |
| Product profiles | Linked affected Windows profiles |
| Role | guest, host, broker, directory, profile/file service, or unknown |
| Components | Normalized component tags |
| Change kinds | Security enforcement, default change, deprecation, regression, prerequisite change, or version-combination constraint |
| Preconditions | Configuration, deployment pattern, version state, driver, hardware, or environment required to trigger the risk |
| Affected workflows | User or platform workflows that can fail, such as provisioning, sign-in, session connection, update, boot, or profile access |
| Symptoms | Observable failures, error classes, event IDs, and other diagnostic signatures |
| IDs | CVE, KB, build, known-issue, advisory and safeguard IDs |
| Times | published, updated, first seen, resolved, and collected times |
| Evidence | canonical URL and brief supporting excerpt |
| Assessment | technical risk, environment relevance, action priority, workaround, recommended action, and uncertainty |
| Correlation | Explicit semantic risk keys and number of independent supporting sources |
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

**Environment relevance (0–100):** match against internal products, roles, components, critical workflows, and known deployment patterns. Unknown environment values must not be treated as a match.

**Confidence (0–100):** publisher authority, identifier quality, evidence completeness, and independent corroboration. Community-only reports should normally remain below the confirmed-alert threshold until corroborated.

**Action priority (0–100):** a weighted operational ordering derived from technical risk, environment relevance, and confidence. Preserve the component scores so users can understand why an item ranked highly.

An authoritative OOB update, active exploitation statement, data loss, bulk sign-in failure, boot failure, blue/black screen, or widespread session outage merits immediate review even when the exact internal edition has not yet been confirmed.

## Timeline and deduplication

Store every material source update as a linked Event Change containing prior and new status or scope, changed fields, time, source URL, and evidence hash. Upsert only when the identity matches; otherwise create a candidate relation for review. Do not merge events merely because they mention the same Windows version or KB.

When several sources support one risk, give every source its own evidence record. Use a shared semantic correlation key only when the change, trigger/precondition, affected workflow, and symptom are coherent. Two independent lower-tier sources can raise an investigation alert; only authoritative evidence can make an official confirmation claim.
