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

The included workflow publishes the static repository whenever `main` is
updated. In repository settings, set Pages source to **GitHub Actions**.

## Scope

Detection Insight Lite does not execute searches, validate schema against a
live tenant, or prove that a detection identifies malicious behavior. Use the
generated test plan to validate every rule in an authorized test environment.

## EDR response playbooks (v0.2.0)

Choose **EDR response**, load the sample, and paste sanitized JSON using the
normalized schema shown below. This mode generates local, deterministic response
recommendations, not executable vendor rules or automated containment. Native
Defender, CrowdStrike, or SentinelOne exports are not automatically parsed.

```json
{
  "category": "ransomware",
  "severity": "high",
  "asset": { "criticality": "standard" },
  "evidence": { "encryption_observed": true }
}
```

Supported categories: `ransomware`, `credential_theft`, `malware`,
`suspicious_script`, `lateral_movement`. Other categories get generic triage.
The category selects the template; evidence does not independently prove
compromise. Criticality values `critical`, `production`, and `safety` trigger
coordinated containment guidance. Missing context is explicitly reported.

The JSON export contains recommendations and uncertainty notes, not the original
alert or host identifiers. All steps have `executed: false`. Disruptive actions
require analyst approval and local operational review.

Response references:
- Joint CISA/FBI/NSA/MS-ISAC StopRansomware Guide: https://www.ic3.gov/CSA/2023/231019.pdf
- Microsoft incident response approach: https://learn.microsoft.com/en-us/security/ransomware/incident-response-playbook-dart-ransomware-approach

The app uses original templates informed by these references; it does not claim
vendor endorsement or compliance certification.
