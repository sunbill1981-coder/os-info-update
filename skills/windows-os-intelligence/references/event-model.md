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
| IDs | CVE, KB, build, known-issue, advisory and safeguard IDs |
| Times | published, updated, first seen, resolved, and collected times |
| Evidence | canonical URL and brief supporting excerpt |
| Assessment | impact, workaround, recommended action, uncertainty |

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

**Risk (0–100):** internal product/profile match (0–25), cloud-desktop component relevance (0–25), security or stability impact (0–20), urgency/exploitability/OOB/rollback difficulty (0–20), and affected scope (0–10).

**Confidence (0–100):** publisher authority, identifier quality, evidence completeness, and independent corroboration. Community-only reports should normally remain below the confirmed-alert threshold until corroborated.

An authoritative OOB update, active exploitation statement, data loss, bulk sign-in failure, boot failure, blue/black screen, or widespread session outage merits immediate review even when the exact internal edition has not yet been confirmed.

## Timeline and deduplication

Store every material source update as a linked Event Change containing prior and new status or scope, changed fields, time, source URL, and evidence hash. Upsert only when the identity matches; otherwise create a candidate relation for review. Do not merge events merely because they mention the same Windows version or KB.
