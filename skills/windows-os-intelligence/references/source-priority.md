# Source Priority and Collection Guidance

## Source tiers

Use the highest available tier for factual claims. Record the source tier on each event.

| Tier | Primary sources | Use |
|---|---|---|
| P0 | Microsoft Windows Release Health; Microsoft Graph Windows Updates; MSRC Security Update Guide/CVRF; Windows Update history and KB articles; Microsoft Lifecycle | Known and resolved issues, patches, CVEs, safeguards, builds, lifecycle |
| P1 | Windows Insider Blog and Flight Hub; Windows IT Pro/TechCommunity; Microsoft Learn release and feature pages; Azure Virtual Desktop, RDS, Hyper-V, Remote Desktop, and FSLogix release notes | Early feature signals, deployment changes, cloud-desktop components |
| P2 | Citrix, Omnissa, NVIDIA vGPU, Intel, AMD, OEM, EDR, VPN, peripheral, and application-vendor advisories | Compatibility and ecosystem impact |
| P3 | Microsoft Q&A, vendor forums, GitHub issues, technical communities, reputable specialist press | Unconfirmed early signals only |

## Preferred retrieval methods

1. Documented API or downloadable structured feed.
2. RSS/Atom or stable JSON endpoint.
3. Static public release page with conditional requests (`ETag` / `Last-Modified`) when available.
4. Browser automation for dynamic or authenticated pages after a stable non-browser path is unavailable.

Browser automation is a fallback, not the source of truth. Do not rely on a user browser session for unattended production collection unless the user has explicitly authorized that design and a session-expiry recovery path exists.

## Source-specific notes

- **Release Health:** capture issue status, history, affected platforms, originating/resolving KBs, safeguard holds, and update timestamps. The Microsoft Graph surface is beta; preserve a public-page fallback and test schema changes before relying on it.
- **MSRC:** use CVRF data to link CVE, affected product, severity, exploitability, and security update. A monthly security release can contain many separate event relationships.
- **Update history / KB:** extract build, quality changes, known issues, prerequisites, rollback, OOB and KIR information. KB content may be revised after publication; retain revisions.
- **Insider:** tag every event as `preview`; features may be staged, changed, or never reach general availability.
- **Vendor sources:** capture exact product and driver versions. A generic GPU issue is not automatically a VDI issue without a match to the relevant driver, vGPU, GPU-P, or client stack.

## Change detection and source health

Store a content hash plus retrieval metadata for every raw document. A material change includes a new or removed affected platform, status transition, new workaround, new resolving KB/OOB update, revised CVE severity/exploitability, lifecycle date change, or substantive compatibility statement.

Log source failures independently from “no changes.” A failed source must never advance its checkpoint. Report persistent source failures as coverage gaps.

## Collection cadence

- Backfill: chunk by calendar month; use a shorter chunk only when a source has pagination or rate limits.
- Normal: check official status and vulnerability sources at least daily; check sources around Patch Tuesday more frequently if the user requests it.
- Incremental: retain a 72-hour overlap by default and deduplicate against stable identifiers and source-content hashes.

These are defaults, not a substitute for a user's explicit schedule or source restrictions.
