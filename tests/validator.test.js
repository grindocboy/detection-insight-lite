import test from "node:test";
import assert from "node:assert/strict";
import { samples, sanitizeForExport, validateDetection } from "../src/validator.js";

test("all bundled samples return an assessment", () => {
  for (const [type, rule] of Object.entries(samples)) {
    const result = validateDetection(type, rule);
    assert.equal(result.type, type);
    assert.ok(result.score >= 0 && result.score <= 100);
    assert.equal(result.testPlan.length, 5);
  }
});

test("SPL flags index wildcard and missing time bound", () => {
  const result = validateDetection("spl", "index=* | search action=login | table user");
  assert.ok(result.findings.some(item => item.id === "spl-index-all"));
  assert.ok(result.findings.some(item => item.id === "spl-time"));
});

test("KQL flags workspace-wide search", () => {
  const result = validateDetection("kql", "search *\n| where OperationName contains 'role'");
  assert.ok(result.findings.some(item => item.id === "kql-search"));
  assert.ok(result.findings.some(item => item.id === "kql-time"));
});

test("Sigma identifies missing required structure", () => {
  const result = validateDetection("sigma", "title: Incomplete rule\nlogsource:\n  product: saas");
  assert.ok(result.findings.some(item => item.id === "sigma-detection"));
  assert.ok(result.findings.some(item => item.id === "sigma-condition"));
});

test("YARA-L identifies missing required sections", () => {
  const result = validateDetection("yaral", "rule incomplete {\n meta:\n  author = \"test\"\n}");
  assert.ok(result.findings.some(item => item.id === "yaral-events"));
  assert.ok(result.findings.some(item => item.id === "yaral-condition"));
});

test("common checks detect and sanitize sensitive values", () => {
  const value = "account=123456789012 src=10.20.30.40 key=AKIAABCDEFGHIJKLMNOP";
  const result = validateDetection("spl", `index=cloud earliest=-15m ${value}`);
  assert.ok(result.findings.some(item => item.id === "account-id"));
  assert.ok(result.findings.some(item => item.id === "ip-address"));
  assert.ok(result.findings.some(item => item.id.startsWith("secret-")));
  const sanitized = sanitizeForExport(value);
  assert.ok(!sanitized.includes("123456789012"));
  assert.ok(!sanitized.includes("10.20.30.40"));
  assert.ok(!sanitized.includes("AKIAABCDEFGHIJKLMNOP"));
});

test("empty and unsupported rules fail safely", () => {
  assert.equal(validateDetection("spl", "").score, 0);
  assert.throws(() => validateDetection("unknown", "anything"), /Unsupported/);
});
