# Detection Insight Lite

A public-safe, local-first detection validator for security teams protecting
SaaS, cloud, identity, regulated, and high-security environments.

## Why Lite

- No API keys or backend
- No telemetry, cookies, or external calls
- No internal rule pack or proprietary infrastructure assumptions
- All analysis stays in the browser
- Deployable as a static GitHub Pages site

The production page includes a restrictive Content Security Policy with
`connect-src 'none'`. This instructs compatible browsers to block fetch, XHR,
WebSocket, EventSource, and beacon connections—even if future client-side code
attempts to transmit a rule. There are no third-party scripts, analytics, forms,
cookies, accounts, or server-side application components.

## Supported rule types

- Splunk SPL
- Microsoft Sentinel KQL
- Sigma YAML
- Chronicle YARA-L

The deterministic validator checks security coverage, performance, metadata,
privacy, portability, and test readiness. Results are guidance—not a substitute
for compiling a rule in the target platform and testing it against representative
authorized telemetry.

## Run locally

Serve the repository with any static web server, for example:

```bash
python3 -m http.server 8080
```

Then open `http://localhost:8080`.

## Test

```bash
npm test
npm run check
```

No package installation is required; tests use Node's built-in test runner.

## GitHub Pages

In repository settings, choose Pages **Deploy from a branch**, **main**,
and **/(root)**. Upload the contents of the release ZIP to the repository root,
preserving the `src/`, `tests/`, and `scripts/` folders.

## Scope

Detection Insight Lite does not execute searches, validate schema against a
live tenant, or prove that a detection identifies malicious behavior. Use the
generated test plan to validate every rule in an authorized test environment.

## Response playbooks and ATT&CK catalog (v0.3.0)

Choose **EDR response**, load the sample, or paste sanitized normalized JSON.
Search the bundled ATT&CK catalog by technique ID, name, tactic, or platform,
and use **Add technique to alert**. Selecting an ID is an analyst assertion.
Native vendor exports need normalization; this app does not infer behavior from
free text, contact a tenant, or execute containment.

```json
{
  "technique_ids": ["T1486"],
  "severity": "high",
  "prevention_status": "not_blocked",
  "asset": { "criticality": "standard" },
  "evidence": { "confirmed_malicious": true }
}
```

An optional `category` can explicitly select one of 15 authored response families:
`ransomware`, `credential_theft`, `malware`, `suspicious_script`,
`lateral_movement`, `persistence`, `privilege_escalation`,
`command_and_control`, `exfiltration`, `defense_evasion`, `oauth_abuse`,
`account_takeover`, `inbox_rules`, `remote_access_abuse`, `data_destruction`.

Mapped catalog IDs select families; mapped parent techniques also apply to active
sub-techniques unless an explicit sub-technique mapping overrides them. Multiple
families are combined for analyst review. Unmapped techniques get generic
investigation and a coverage-gap notice. The 697 active Enterprise techniques and
sub-techniques in this bundle do **not** imply 697 tailored response playbooks.

Reported prevention (`blocked`), unconfirmed activity, and unknown or
`critical`/`production`/`safety` asset criticality defer disruptive recommendations.
Only an explicit `confirmed_malicious: true` is treated as analyst confirmation;
severity and technique selection do not establish compromise. All containment
and recovery steps require approval. Each action includes rationale,
prerequisites, impact, verification, and public reference links. Templates are
original guidance, without MITRE or vendor endorsement, and need operational
review before use.

JSON exports exclude original alert content and host identifiers. They contain
selected taxonomy IDs, context flags, recommendations, and uncertainty notes.
All steps have `executed: false`. Inputs remain in browser memory; the app has
no storage or data-upload endpoint.

## Taxonomy provenance and refresh

The offline catalog was generated from MITRE's official Enterprise ATT&CK STIX
bundle, version **19.2**, with 697 active techniques and sub-techniques. Source
and SHA-256 are recorded in `src/attack-catalog.js`; the upstream license is
preserved in `THIRD_PARTY_NOTICES.md`. Names, IDs, tactics, platforms, and
reference URLs are included; revoked/deprecated entries are excluded.

To refresh, download an official versioned bundle from
https://github.com/mitre-attack/attack-stix-data and run:

```bash
python3 scripts/import-attack.py enterprise-attack.json
npm run check
```

Review changes in IDs, platforms, family mappings, and tests before release.
The import is a maintainer task; user alerts never leave the browser.

Response-process reference: [CISA Incident and Vulnerability Response Playbooks](https://www.cisa.gov/sites/default/files/publications/Cybersecurity_Incident_Vulnerability_Response_Playbooks_508C.pdf).
Technique references link to the respective official MITRE ATT&CK pages.
