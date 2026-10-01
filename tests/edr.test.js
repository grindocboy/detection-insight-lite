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

import { techniques, catalogMeta } from '../src/attack-catalog.js';
import { familyForTechnique, responseFamilies } from '../src/edr.js';
const play = (extra = {}) => generatePlaybook(JSON.stringify({technique_ids:['T1486'], asset:{criticality:'standard'}, evidence:{confirmed_malicious:true}, ...extra}));
test('catalog has unique active technique IDs and pinned provenance', () => {
  assert.equal(techniques.length, catalogMeta.count);
  assert.equal(new Set(techniques.map(t => t.id)).size, techniques.length);
  assert.match(catalogMeta.bundleSha256, /^[a-f0-9]{64}$/);
  assert.ok(techniques.every(t => /^T\d{4}(\.\d{3})?$/.test(t.id) && t.url.startsWith('https://attack.mitre.org/')));
});
test('explicit mappings and parent mappings select useful families', () => {
  assert.equal(familyForTechnique('T1059.001'), 'suspicious_script');
  assert.equal(familyForTechnique('T1114.003'), 'inbox_rules');
  assert.equal(familyForTechnique('T1550.001'), 'oauth_abuse');
  assert.equal(familyForTechnique('T9999'), null);
  assert.equal(responseFamilies.length,15);
  for (const category of responseFamilies) assert.equal(play({category,technique_ids:[]}).category,category);
});
test('prevention and evidence change containment recommendations', () => {
  assert.match(play().steps.find(s => s.phase === 'Contain').action,/network isolation/);
  assert.match(play({prevention_status:'blocked'}).steps.find(s => s.phase === 'Contain').action,/Verify prevention/);
  for (const confirmed_malicious of [false, 'true', undefined]) {
    const result = play({evidence:{confirmed_malicious}});
    assert.match(result.steps.find(s => s.phase === 'Contain').action,/corroborating evidence/);
    assert.match(result.steps.find(s => s.phase === 'Recover').action,/Defer changes/);
  }
});
test('critical and unknown assets defer disruptive changes', () => {
  for (const criticality of ['critical','production','safety','unknown']) {
    assert.match(play({asset:{criticality}}).steps.find(s => s.phase === 'Contain').action,/coordinated containment plan/);
  }
});
test('mixed mapped and unmapped techniques retain coverage gaps', () => {
  const result = play({technique_ids:['T1486','T1003.001','T1595']});
  assert.deepEqual(result.families,['ransomware','credential_theft']);
  assert.ok(result.steps.some(s => s.family === 'unknown' && s.action.includes('T1595')));
  assert.ok(result.unknowns.some(s => s.includes('no authored response mapping')));
  assert.equal(play({technique_ids:['T1595']}).category,'unknown');
});
test('invalid ID lists fail and unknown IDs are transparent', () => {
  for (const technique_ids of ['T1486',[1],['SECRET-USER-CONTENT'],Array(21).fill('T1486')]) assert.throws(() => play({technique_ids}));
  assert.ok(play({technique_ids:['T9999']}).unknowns.some(s => s.includes('absent')));
});
test('every action carries context and exports exclude original entities', () => {
  const result = play({alert_id:'PRIVATE-123',asset:{criticality:'standard',hostname:'PRIVATE-HOST'}});
  for (const step of result.steps) {
    for (const key of ['rationale','prerequisites','impact','verification']) assert.ok(step[key].length);
    assert.ok(step.sources.length);
    assert.equal(step.executed,false);
    if (['Contain','Recover'].includes(step.phase)) assert.equal(step.approvalRequired,true);
  }
  assert.ok(!JSON.stringify(result).includes('PRIVATE-'));
});

test('unrecognized criticality is normalized and never copied into exports', () => {
 const result = play({asset:{criticality:'PRIVATE-ASSET'}});
 assert.equal(result.context.assetCriticality,'unknown');
 assert.ok(!JSON.stringify(result).includes('PRIVATE-ASSET'));
});
