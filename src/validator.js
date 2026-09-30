const severityPenalty = { high: 18, medium: 9, low: 3 };

export const RULE_TYPES = Object.freeze({
  spl: "Splunk SPL",
  kql: "Microsoft Sentinel KQL",
  sigma: "Sigma YAML",
  yaral: "Chronicle YARA-L"
});

export const samples = Object.freeze({
  spl: `index=cloud sourcetype=aws:cloudtrail earliest=-15m
eventName IN ("CreateAccessKey", "UpdateAssumeRolePolicy", "PutUserPolicy")
| stats count values(eventName) as actions values(sourceIPAddress) as src by userIdentity.arn
| where count >= 2
| rename userIdentity.arn as principal`,
  kql: `AuditLogs
| where TimeGenerated > ago(15m)
| where OperationName in ("Add member to role", "Update application")
| summarize Actions=make_set(OperationName), Count=count() by InitiatedBy, bin(TimeGenerated, 5m)
| where Count >= 2`,
  sigma: `title: Suspicious SaaS Administrative Changes
id: 4c034e9e-e1c0-4f79-99a9-dfb37a197b6d
status: experimental
description: Detects a cluster of high-impact administrative changes.
author: Detection Insight Lite
date: 2026-09-30
logsource:
  category: application
  product: saas
detection:
  selection:
    event.action:
      - role.add_member
      - application.update
  condition: selection
falsepositives:
  - Approved administrative change
level: high
tags:
  - attack.t1098`,
  yaral: `rule suspicious_saas_admin_changes {
  meta:
    author = "Detection Insight Lite"
    description = "Detects clustered high-impact SaaS administrative changes"
    severity = "HIGH"
    mitre_attack_tactic = "TA0003"
  events:
    $e.metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT"
    $e.security_result.action = "ALLOW"
  match:
    $e.principal.user.userid over 15m
  condition:
    #e >= 2
}`
});

function finding(id, severity, category, title, detail, remediation) {
  return { id, severity, category, title, detail, remediation };
}

function has(text, expression) {
  return expression.test(text);
}

function countMatches(text, expression) {
  return (text.match(expression) || []).length;
}

function commonChecks(text) {
  const findings = [];
  const secretPatterns = [
    [/AKIA[0-9A-Z]{16}/, "AWS access key"],
    [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, "private key"],
    [/(?:api[_-]?key|client[_-]?secret|password)\s*[:=]\s*["'][^"']{8,}["']/i, "embedded credential"],
    [/gh[pousr]_[A-Za-z0-9_]{20,}/, "GitHub token"],
    [/xox[baprs]-[A-Za-z0-9-]{10,}/, "Slack token"]
  ];

  for (const [pattern, label] of secretPatterns) {
    if (pattern.test(text)) {
      findings.push(finding(`secret-${label}`, "high", "privacy", `Possible ${label} detected`, "The rule resembles a credential-bearing string and may be unsafe to publish.", "Replace the value with a neutral placeholder and rotate any live credential before publishing."));
    }
  }

  if (has(text, /\b(?:prod|production)[-_]?(?:account|tenant|cluster|index|vpc)\b/i)) {
    findings.push(finding("internal-label", "medium", "privacy", "Environment-specific label", "The rule may expose an internal production naming convention.", "Use documented macros, lookup aliases, or generic placeholders in the public version."));
  }
  if (has(text, /\b(?:\d{1,3}\.){3}\d{1,3}\b/)) {
    findings.push(finding("ip-address", "medium", "privacy", "Literal IP address", "A literal IP can expose infrastructure details and reduces portability.", "Move approved values into a lookup/watchlist and use documentation-safe example ranges for public rules."));
  }
  if (has(text, /\b\d{12}\b/)) {
    findings.push(finding("account-id", "medium", "privacy", "Possible cloud account identifier", "A 12-digit value may be an AWS account ID or tenant-specific identifier.", "Replace it with an alias, parameter, or sanitized example value."));
  }
  return findings;
}

function splChecks(text) {
  const f = [];
  if (!/\b(index|tstats|mstats|inputlookup)\s*[=]/i.test(text)) f.push(finding("spl-scope", "high", "coverage", "No searchable data scope", "The search does not identify an index, accelerated data model, metric store, or lookup.", "Declare the expected data source and document the required sourcetype or data model."));
  if (/\bindex\s*=\s*\*/i.test(text)) f.push(finding("spl-index-all", "high", "performance", "Unbounded index wildcard", "index=* can scan unrelated data, increase latency, and make behavior environment-dependent.", "Name the required indexes directly or use a governed macro."));
  if (!/\b(?:earliest|latest)\s*=/i.test(text) && !/\b_?time\s*[><=]/i.test(text)) f.push(finding("spl-time", "medium", "performance", "No explicit time bound", "The rule relies on the scheduler or user interface for its search window.", "Define the intended detection window in the saved search and document it beside the rule."));
  if (/\|\s*transaction\b/i.test(text)) f.push(finding("spl-transaction", "medium", "performance", "Expensive transaction command", "transaction can retain large event sets in memory.", "Prefer stats, streamstats, or eventstats with explicit grouping and time constraints."));
  if (/\|\s*join\b/i.test(text)) f.push(finding("spl-join", "medium", "performance", "Join may truncate or centralize work", "join has result limits and often moves computation to the search head.", "Prefer stats-based correlation, lookups, or append with an aggregation strategy."));
  if (/\[\s*search\b/i.test(text)) f.push(finding("spl-subsearch", "low", "performance", "Subsearch requires limit review", "Subsearches have execution and result limits that can silently change coverage.", "Confirm subsearch limits or replace it with a lookup or stats-based correlation."));
  if (/\b(?:search|where)\b[^\n]*\*[^=\s]*\*/i.test(text)) f.push(finding("spl-leading-wildcard", "medium", "performance", "Broad wildcard comparison", "Leading or contains wildcards can prevent efficient filtering.", "Use exact matches, prefixes, indexed fields, or a normalized field where possible."));
  if (!/\|\s*(?:stats|tstats|mstats|timechart|chart|rare|top)\b/i.test(text)) f.push(finding("spl-aggregation", "low", "quality", "No aggregation or threshold", "The search may emit raw events without a behavioral threshold.", "Confirm whether the alert is intended to be atomic; otherwise aggregate by entity and add a justified threshold."));
  if (!/\b(?:user|user_id|src|sourceIPAddress|principal|identity|actor|account)\b/i.test(text)) f.push(finding("spl-entity", "medium", "coverage", "No identity or source entity", "The output may be difficult to investigate or risk-score.", "Return at least one normalized user, principal, source, application, or account field."));
  return f;
}

function kqlChecks(text) {
  const f = [];
  const firstMeaningful = text.split("\n").map(x => x.trim()).find(x => x && !x.startsWith("//")) || "";
  if (!/^(?:let\b|union\b|[A-Za-z][A-Za-z0-9_]*)/.test(firstMeaningful)) f.push(finding("kql-source", "high", "coverage", "Missing source table", "A Sentinel analytics rule should begin from a table, union, or named expression.", "Specify the required table and document connectors and schemas."));
  if (!/\bTimeGenerated\b[^\n]*(?:ago\(|between|>|>=)/i.test(text)) f.push(finding("kql-time", "medium", "performance", "No TimeGenerated filter", "The query does not show an explicit time predicate.", "Filter TimeGenerated early and align the window with the analytics rule schedule."));
  if (/\bsearch\s+\*/i.test(text) || /^\s*search\b/im.test(text)) f.push(finding("kql-search", "high", "performance", "Workspace-wide search", "The search operator can scan every table and column.", "Select the required tables and fields explicitly."));
  if (/\bcontains\b/i.test(text)) f.push(finding("kql-contains", "low", "performance", "Contains operator requires review", "contains is slower and broader than token- or prefix-based alternatives.", "Use has, has_any, startswith, or an exact comparison when semantics permit."));
  if (/\bjoin\s+kind\s*=\s*(?:inner|fullouter|leftouter|rightouter)\b/i.test(text) && !/hint\.(?:strategy|shufflekey)/i.test(text)) f.push(finding("kql-join", "low", "performance", "Join strategy is implicit", "Large cross-table joins may consume substantial resources.", "Reduce both sides before joining and test whether broadcast or shuffle hints are appropriate."));
  if (!/\b(?:Account|User|UserId|Identity|InitiatedBy|IPAddress|Caller|Principal)\w*\b/i.test(text)) f.push(finding("kql-entity", "medium", "coverage", "No investigation entity", "The result does not clearly expose an identity or source entity.", "Project normalized account, host, IP, application, or cloud-resource entities."));
  if (!/\b(?:summarize|distinct|top|make_set|count)\b/i.test(text)) f.push(finding("kql-threshold", "low", "quality", "No aggregation or threshold", "The query appears to emit atomic events.", "Document why a single event is high signal or add entity-based aggregation and a tested threshold."));
  return f;
}

function sigmaChecks(text) {
  const f = [];
  const required = ["title", "logsource", "detection", "condition", "level"];
  for (const key of required) {
    const pattern = new RegExp(`^\\s*${key}:`, "mi");
    if (!pattern.test(text)) f.push(finding(`sigma-${key}`, key === "detection" || key === "condition" ? "high" : "medium", "structure", `Missing ${key} field`, `The Sigma document does not include the ${key} metadata or logic field.`, `Add a valid ${key} value and verify the rule with a Sigma-compatible validator.`));
  }
  if (!/^\s*(?:product|category|service):/mi.test(text)) f.push(finding("sigma-logsource-detail", "medium", "coverage", "Log source is underspecified", "The rule does not declare a product, category, or service beneath logsource.", "Identify the source family and document the expected vendor field mapping."));
  if (!/^\s*falsepositives:/mi.test(text)) f.push(finding("sigma-fp", "low", "quality", "False positives are undocumented", "Analysts lack tuning guidance for expected administrative or automation activity.", "Add realistic false-positive cases and the fields needed to distinguish them."));
  if (!/^\s*tags:/mi.test(text) || !/attack\.[a-z0-9]+/i.test(text)) f.push(finding("sigma-attack", "low", "coverage", "No ATT&CK tag", "The rule is not mapped to an ATT&CK technique or tactic.", "Add supported attack.* tags after validating that the behavior—not merely the tool—matches the technique."));
  if (/condition:\s*(?:selection|filter)?\s*$/mi && countMatches(text, /^\s{2,}[A-Za-z0-9_-]+:/gm) < 2) f.push(finding("sigma-narrow", "low", "quality", "Minimal detection logic", "The rule has little observable selection context.", "Add discriminating fields or document why the event is independently high signal."));
  return f;
}

function yaralChecks(text) {
  const f = [];
  if (!/^\s*rule\s+[A-Za-z][A-Za-z0-9_]*\s*\{/m.test(text)) f.push(finding("yaral-rule", "high", "structure", "Invalid or missing rule declaration", "The content does not begin with a recognizable YARA-L rule block.", "Add a valid rule name and enclosing braces, then compile in the target Chronicle environment."));
  for (const section of ["meta", "events", "condition"]) {
    if (!new RegExp(`^\\s*${section}:`, "mi").test(text)) f.push(finding(`yaral-${section}`, section === "events" || section === "condition" ? "high" : "medium", "structure", `Missing ${section} section`, `The YARA-L rule has no ${section} section.`, `Add ${section} content and validate it against the current target rule engine.`));
  }
  if (!/metadata\.event_type\s*=/.test(text)) f.push(finding("yaral-event-type", "medium", "coverage", "No UDM event type", "The event selection does not constrain metadata.event_type.", "Select the relevant UDM event type to reduce noise and make telemetry assumptions explicit."));
  if (!/^\s*match:/mi.test(text)) f.push(finding("yaral-match", "low", "quality", "No match window", "The rule does not correlate events by an entity over time.", "If this is behavioral detection, add a match entity and justified time window; atomic rules may omit it."));
  if (!/description\s*=/.test(text)) f.push(finding("yaral-description", "low", "metadata", "Missing description", "The rule does not explain its security intent.", "Add a concise behavior-focused description and required telemetry notes."));
  if (!/(?:mitre_attack|attack|tactic|technique)\w*\s*=/i.test(text)) f.push(finding("yaral-attack", "low", "coverage", "No ATT&CK metadata", "The rule is not mapped to a defensive behavior framework.", "Add a validated tactic or technique mapping where applicable."));
  return f;
}

function positiveFindings(text, type, findings) {
  const passes = [];
  if (!findings.some(x => x.category === "privacy")) passes.push(finding("pass-privacy", "pass", "privacy", "No common secret pattern found", "The local scan did not identify common credentials, literal IPs, or cloud account IDs.", "Perform a human review before publishing; pattern matching cannot prove content is sanitized."));
  const hasAttack = /attack\.[a-z0-9]+|TA\d{4}|T\d{4}/i.test(text);
  if (hasAttack) passes.push(finding("pass-attack", "pass", "coverage", "ATT&CK context present", "The rule contains a tactic or technique reference.", "Confirm the mapping describes the observed behavior."));
  if ((type === "spl" && /\b(?:earliest|latest)\s*=/.test(text)) || (type === "kql" && /TimeGenerated/.test(text)) || (type === "yaral" && /^\s*match:/mi.test(text)) || type === "sigma") passes.push(finding("pass-window", "pass", "quality", "Detection window can be reviewed", "The rule contains a time, correlation, or portable rule context.", "Validate cadence, ingestion delay, and lookback in the target platform."));
  return passes;
}

function makeTestPlan(type, text) {
  const entity = /(?:user|principal|identity|account|actor)/i.test(text) ? "identity" : "primary entity";
  return [
    `Positive: replay a sanitized event sequence that should satisfy the ${RULE_TYPES[type]} logic.`,
    `Negative: replay normal administrative activity by an approved ${entity} and confirm it does not alert.`,
    "Boundary: test immediately below, at, and above every count or time threshold.",
    "Freshness: measure ingestion delay and ensure the scheduler lookback prevents gaps and duplicate alerts.",
    "Schema drift: remove or rename a required field and verify monitoring detects the resulting loss of coverage."
  ];
}

export function validateDetection(type, input) {
  const text = String(input || "").trim();
  if (!RULE_TYPES[type]) throw new Error("Unsupported rule type");
  if (!text) return { type, score: 0, grade: "Not assessed", findings: [finding("empty", "high", "structure", "Rule is empty", "There is no detection content to analyze.", "Paste a rule or load a sample.")], passes: [], testPlan: [], stats: { high: 1, medium: 0, low: 0 } };
  if (text.length > 100000) throw new Error("Rule exceeds the 100,000 character local analysis limit");

  const typeChecks = { spl: splChecks, kql: kqlChecks, sigma: sigmaChecks, yaral: yaralChecks };
  const findings = [...commonChecks(text), ...typeChecks[type](text)];
  const stats = { high: 0, medium: 0, low: 0 };
  for (const item of findings) if (item.severity in stats) stats[item.severity] += 1;
  const penalty = findings.reduce((sum, item) => sum + (severityPenalty[item.severity] || 0), 0);
  const score = Math.max(0, Math.min(100, 100 - penalty));
  const grade = score >= 90 ? "Strong" : score >= 75 ? "Review" : score >= 55 ? "Needs work" : "High risk";
  return { type, score, grade, findings, passes: positiveFindings(text, type, findings), testPlan: makeTestPlan(type, text), stats };
}

export function sanitizeForExport(input) {
  return String(input || "")
    .replace(/AKIA[0-9A-Z]{16}/g, "<AWS_ACCESS_KEY_REDACTED>")
    .replace(/gh[pousr]_[A-Za-z0-9_]{20,}/g, "<GITHUB_TOKEN_REDACTED>")
    .replace(/xox[baprs]-[A-Za-z0-9-]{10,}/g, "<SLACK_TOKEN_REDACTED>")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "<IP_ADDRESS_REDACTED>")
    .replace(/\b\d{12}\b/g, "<CLOUD_ACCOUNT_ID_REDACTED>");
}
