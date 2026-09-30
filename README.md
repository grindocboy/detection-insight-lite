# Detection Insight Lite

A public-safe, local-first detection validator for security teams protecting
SaaS, cloud, identity, regulated, and high-security environments.

## Why Lite

- No API keys or backend
- No telemetry, cookies, or external calls
- No internal rule pack or proprietary infrastructure assumptions
- All analysis stays in the browser
- Deployable as a static GitHub Pages site

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
