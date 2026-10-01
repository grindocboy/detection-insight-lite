import test from 'node:test';
import assert from 'node:assert/strict';
import { generatePlaybook, edrSample } from '../src/edr.js';
test('ransomware sample yields a recommendation-only playbook', () => {
  const result = generatePlaybook(edrSample);
  assert.equal(result.category, 'ransomware');
  assert.ok(result.steps.every(s => s.executed === false));
  assert.ok(result.steps.find(s => s.phase === 'Contain').approvalRequired);
});
test('critical asset requires coordinated containment', () => {
  const result = generatePlaybook(JSON.stringify({category:'malware', asset:{criticality:'production'}}));
  assert.match(result.steps.find(s => s.phase === 'Contain').action, /service owner/);
});
test('unknown and inherited category names cannot select a template', () => {
  for (const category of ['unknown','constructor','__proto__']) {
    const result = generatePlaybook(JSON.stringify({category}));
    assert.equal(result.category,'unknown');
    assert.ok(result.unknowns.length);
  }
});
test('reject malformed, vendor-native and oversized input', () => {
  for (const input of ['{','[]','null','{}', 'x'.repeat(100001)]) assert.throws(() => generatePlaybook(input));
});
test('all categories provide investigation and recovery steps', () => {
  for (const category of ['credential_theft','malware','suspicious_script','lateral_movement']) {
    const result = generatePlaybook(JSON.stringify({category}));
    assert.equal(result.category,category);
    assert.equal(result.steps.length,7);
  }
});
