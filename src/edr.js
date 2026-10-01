import { techniques, catalogMeta } from "./attack-catalog.js";
export const edrSample = JSON.stringify({
  vendor: "Generic EDR", alert_id: "DEMO-001", title: "Possible ransomware activity",
  category: "ransomware", technique_ids: ["T1486"], severity: "high", prevention_status: "not_blocked",
  asset: { criticality: "standard", os: "Windows" },
  evidence: { confirmed_malicious: true, encryption_observed: true, process_tree_available: true }
}, null, 2);

const categories = {
  ransomware: ["Ransomware", "Assess encryption activity and backup impact; coordinate containment across affected assets.", "Use approved EDR network isolation for confirmed affected endpoints. Keep forensic access available; avoid powering off solely for containment when isolation is available.", "After scoping and evidence preservation, rebuild confirmed compromised assets from trusted images and restore validated backups."],
  credential_theft: ["Credential theft", "Review logon history, privileged sessions, credential access evidence, and related SaaS audit logs.", "For confirmed affected identities, revoke sessions and rotate exposed credentials from a trusted device; coordinate service-account changes with owners.", "Remove confirmed persistence and review MFA, OAuth grants, and privileged access before restoring identity access."],
  malware: ["Malware", "Validate the process tree, file origin, signature, hash reputation, and execution evidence.", "For confirmed malicious activity, isolate the endpoint and quarantine validated artifacts through approved EDR controls after preserving evidence.", "Remove confirmed persistence or rebuild if host integrity cannot be established; remediate the initial entry point."],
  suspicious_script: ["Suspicious script", "Review script content, parent process, signer, user intent, and approved automation baselines.", "If execution is confirmed malicious, isolate the endpoint and stop the validated malicious process through approved controls; do not block a scripting interpreter globally based on one alert.", "Remove confirmed persistence and remediate the delivery mechanism; tune approved automation separately."],
  lateral_movement: ["Lateral movement", "Correlate source and destination logons, remote services, administrative shares, and identity privileges.", "Coordinate isolation of confirmed affected assets and revoke compromised sessions while preserving incident-response access.", "Remove confirmed persistence, rotate exposed credentials, and correct the access path that enabled movement."],
  persistence: ["Persistence", "Inspect autoruns, scheduled tasks, services, startup items, and identity changes; separate authorized administration from malicious persistence.", "Disable only validated malicious persistence after capturing configuration and evidence; coordinate affected service dependencies.", "Restore approved configurations and verify persistence does not return after reboot or sign-in."],
  privilege_escalation: ["Privilege escalation", "Review privilege changes, exploit evidence, local administrators, and privileged sessions.", "Revoke unauthorized grants and compromised sessions after verifying owner and emergency-access requirements.", "Correct the enabling vulnerability or access policy and validate least-privilege access."],
  command_and_control: ["Command and control", "Correlate process lineage, DNS, proxy, and connection telemetry; verify destination attribution and legitimate service use.", "Isolate confirmed compromised endpoints and block validated malicious destinations with scoped controls; review shared-service impact.", "Remove confirmed implants and persistence and confirm beaconing has stopped across related assets."],
  exfiltration: ["Data exfiltration", "Scope data access, outbound transfers, SaaS downloads, and affected data owners; preserve access and egress logs.", "Restrict confirmed malicious transfers and revoke compromised sessions in coordination with data owners and incident leadership.", "Close the access or egress path, assess exposure through the approved incident process, and validate authorized data flows."],
  defense_evasion: ["Defense evasion and sensor tampering", "Review security-policy changes, sensor health, disabled logging, exclusions, and actor privileges.", "Isolate confirmed compromised assets where feasible; restore protection using trusted management and validate exclusion changes.", "Restore approved security policies, remove unauthorized exclusions, and verify telemetry continuity."],
  oauth_abuse: ["OAuth and token abuse", "Review consent grants, application publishers, requested scopes, service principals, and token-use audit evidence.", "Revoke confirmed malicious grants and sessions; disable implicated applications only after checking business dependencies.", "Restore approved consent controls, rotate exposed application credentials, and verify remaining grants."],
  account_takeover: ["Cloud or SaaS account takeover", "Review sign-ins, MFA changes, device registrations, role changes, and application activity across affected identities.", "Revoke compromised sessions and unauthorized authentication methods; reset exposed credentials from a trusted device with owner coordination.", "Restore trusted authentication methods, review delegated access, and validate conditional-access enforcement."],
  inbox_rules: ["Malicious inbox rules", "Review mailbox audit logs, forwarding settings, rule creation, delegates, and approved workflow exceptions.", "Remove confirmed malicious rules or forwarding after preserving evidence, and revoke compromised mailbox sessions.", "Restore approved mailbox permissions and verify forwarding and rule activity do not recur."],
  remote_access_abuse: ["Remote-access tool abuse", "Review remote-tool installation, session evidence, operator identity, and approved support baselines.", "Terminate confirmed unauthorized remote sessions and isolate impacted hosts; avoid disabling authorized support globally.", "Remove unauthorized remote tools and persistence and verify remote-access policy enforcement."],
  data_destruction: ["Data destruction", "Scope destructive operations, backup access, affected assets, and ongoing impact; preserve forensic evidence where feasible.", "Coordinate rapid isolation of confirmed affected systems and protection of backups; evaluate availability and recovery dependencies.", "Rebuild trusted systems, restore validated backups, and verify data integrity and the initial entry point."]
};

export const responseFamilies = Object.freeze(Object.keys(categories));
const mappings = {
  T1486: "ransomware", T1003: "credential_theft", T1555: "credential_theft",
  T1059: "suspicious_script", T1021: "lateral_movement",
  T1547: "persistence", T1053: "persistence", T1543: "persistence",
  T1068: "privilege_escalation", T1548: "privilege_escalation",
  T1071: "command_and_control", T1095: "command_and_control",
  T1041: "exfiltration", T1048: "exfiltration", T1567: "exfiltration",
  T1562: "defense_evasion", T1070: "defense_evasion",
  "T1528": "oauth_abuse", "T1550.001": "oauth_abuse",
  T1078: "account_takeover", T1098: "account_takeover",
  "T1114.003": "inbox_rules", T1219: "remote_access_abuse",
  T1485: "data_destruction", T1490: "data_destruction"
};
const responseSource = "https://www.cisa.gov/sites/default/files/publications/Cybersecurity_Incident_Vulnerability_Response_Playbooks_508C.pdf";
export function familyForTechnique(id) {
  if (!techniques.some(t => t.id === id)) return null;
  return mappings[id] || mappings[id.split(".")[0]] || null;
}

export function generatePlaybook(input) {
  if (typeof input !== "string" || input.length > 100000) throw new Error("Use JSON under 100,000 characters.");
  let alert;
  try { alert = JSON.parse(input); } catch { throw new Error("Invalid JSON. Load the sample to see the supported alert schema."); }
  if (!alert || typeof alert !== "object" || Array.isArray(alert)) throw new Error("Provide one JSON alert object.");
  if (alert.technique_ids !== undefined && (!Array.isArray(alert.technique_ids) || alert.technique_ids.length > 20 || alert.technique_ids.some(id => typeof id !== "string" || !/^T\d{4}(\.\d{3})?$/.test(id)))) throw new Error("technique_ids must be an array of up to 20 ATT&CK IDs such as T1486 or T1059.001.");
  if (typeof alert.category !== "string" && !alert.technique_ids?.length) throw new Error("Provide a category or technique_ids array. Use the catalog to select a technique.");
  const unknowns = [];
  const matchedTechniques = [];
  const families = new Set();
  if (typeof alert.category === "string" && Object.hasOwn(categories, alert.category)) families.add(alert.category);
  for (const id of new Set(alert.technique_ids || [])) {
    const technique = techniques.find(t => t.id === id);
    if (!technique) { unknowns.push(`Technique ${id} is absent from the active bundled catalog; verify the ID or taxonomy version.`); continue; }
    matchedTechniques.push(technique);
    const family = familyForTechnique(id);
    if (family) families.add(family);
    else unknowns.push(`${id} has no authored response mapping. Use generic investigation for that technique.`);
  }
  if (families.size > 1) unknowns.push("Multiple response families apply; reconcile recommendations before operational use.");
  if (!families.size) unknowns.push("No authored response family matched; generic triage only.");
  if (!alert.severity) unknowns.push("Severity is missing; urgency is not inferred.");
  const suppliedCriticality = String(alert.asset?.criticality || "unknown").toLowerCase();
  const criticality = ["standard", "critical", "production", "safety"].includes(suppliedCriticality) ? suppliedCriticality : "unknown";
  const critical = ["critical", "production", "safety"].includes(criticality);
  const assetKnown = critical || criticality === "standard";
  if (!assetKnown) unknowns.push("Asset criticality is unknown; service-owner review is required before disruptive changes.");
  const confirmed = alert.evidence?.confirmed_malicious === true;
  const blocked = alert.prevention_status === "blocked";
  if (!confirmed) unknowns.push("Malicious activity is unconfirmed. Technique IDs and alert severity are not proof of compromise.");
  if (blocked) unknowns.push("Prevention is reported as blocked; verify that execution and downstream impact were prevented before closing.");
  const allowDisruptive = confirmed && !blocked && assetKnown && !critical;
  const steps = [];
  const step = (phase, action, approvalRequired = false, extra = {}) => ({phase, action, approvalRequired, executed: false,
    rationale: "Reduce uncertainty and guide a coordinated response.", prerequisites: "Authorized analyst, validated alert, and approved incident procedures.",
    impact: approvalRequired ? "May affect identity access, workloads, or availability." : "Investigation may consume resources; follow evidence-handling procedures.",
    verification: "Record findings and confirm the intended outcome using independent telemetry.", sources: [responseSource], ...extra});
  steps.push(step("Triage", "Validate alert origin, event freshness, sensor health, affected entities, and incident ownership. Confirm the selected ATT&CK IDs describe observed behavior."));
  steps.push(step("Preserve evidence", "Capture relevant process, identity, network, application, and volatile evidence using approved procedures. Record timestamps and custody; balance collection with stopping ongoing damage."));
  const unmapped = matchedTechniques.filter(t => !familyForTechnique(t.id));
  if (families.size && unmapped.length) steps.push(step("Investigate", `Review observed behavior for unmapped techniques ${unmapped.map(t => t.id).join(", ")}; no tailored containment or recovery is available for them.`, false, {family:"unknown", sources:[responseSource,...unmapped.map(t => t.url)]}));
  const planned = families.size ? [...families] : ["unknown"];
  for (const family of planned) {
    const selected = categories[family];
    const label = selected?.[0] || "Generic triage";
    steps.push(step("Investigate", selected?.[1] || "Review process, identity, network, and file evidence; classify behavior before selecting remediation.", false, {family, rationale: `Validate evidence for ${label}.`, sources:[responseSource,...matchedTechniques.filter(t => familyForTechnique(t.id) === family).map(t => t.url)]}));
    const gate = blocked ? "Verify prevention and hunt for earlier or related activity. Defer disruptive containment unless investigation establishes continuing compromise."
      : !confirmed ? "Collect corroborating evidence and have the incident lead and service owner assess containment. Do not perform template-driven isolation or credential changes solely from this alert."
      : critical || !assetKnown ? "Have the incident lead and service owner choose a coordinated containment plan before disruptive changes; assess availability, safety, and response-access dependencies."
      : selected?.[2] || "Choose containment after validating behavior and business impact.";
    steps.push(step("Contain", gate, true, {family, rationale:"Limit confirmed compromise while accounting for business impact.", prerequisites:"Incident-lead approval, validated scope, evidence capture where feasible, and an agreed rollback or restoration plan.", verification:"Confirm the containment control took effect and related malicious activity ceased."}));
    steps.push(step("Recover", allowDisruptive ? selected?.[3] || "Select recovery based on confirmed root cause and scope." : "Defer changes until investigation, scope, and service-owner approval establish a recovery need. Retain evidence and review the relevant recovery template with the incident lead.", true, {family, rationale:"Restore trusted operation without destroying needed evidence.", prerequisites:"Validated root cause, agreed recovery scope, evidence retained, and service-owner approval.", verification:"Verify trusted configuration, sensor health, data integrity, and absence of recurring behavior."}));
  }
  steps.push(step("Verify", "Confirm scope across related assets and identities, sensor health, and absence of continuing behavior over an incident-specific monitoring period before lifting containment.", true));
  steps.push(step("Close", "Document evidence, decisions, approvals, recovery results, and detection improvements in the approved incident system."));
  return {mode:"edr", category: planned[0], families:[...families], template: families.size ? [...families].map(f => categories[f][0]).join(" + ") : "Generic triage",
    execution:"Recommendations only; no actions executed", basis:"Explicit category and verified catalog IDs select authored templates. Input evidence flags are analyst assertions, not independently validated facts. Native vendor alerts require normalization.",
    taxonomy:catalogMeta, techniques:matchedTechniques, context:{confirmedMalicious:confirmed,preventionBlocked:blocked,assetCriticality:criticality}, unknowns,steps,
    sources:[responseSource,...matchedTechniques.map(t=>t.url)]};
}
