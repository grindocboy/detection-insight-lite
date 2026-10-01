export const edrSample = JSON.stringify({
  vendor: "Generic EDR", alert_id: "DEMO-001", title: "Possible ransomware activity",
  category: "ransomware", severity: "high", status: "active",
  asset: { criticality: "standard", os: "Windows" },
  evidence: { encryption_observed: true, process_tree_available: true }
}, null, 2);

const categories = {
  ransomware: ["Ransomware", "Assess encryption activity and backup impact; coordinate containment across affected assets.", "Use approved EDR network isolation for confirmed affected endpoints. Keep forensic access available; avoid powering off solely for containment when isolation is available.", "After scoping and evidence preservation, rebuild confirmed compromised assets from trusted images and restore validated backups."],
  credential_theft: ["Credential theft", "Review logon history, privileged sessions, credential access evidence, and related SaaS audit logs.", "For confirmed affected identities, revoke sessions and rotate exposed credentials from a trusted device; coordinate service-account changes with owners.", "Remove confirmed persistence and review MFA, OAuth grants, and privileged access before restoring identity access."],
  malware: ["Malware", "Validate the process tree, file origin, signature, hash reputation, and execution evidence.", "For confirmed malicious activity, isolate the endpoint and quarantine validated artifacts through approved EDR controls after preserving evidence.", "Remove confirmed persistence or rebuild if host integrity cannot be established; remediate the initial entry point."],
  suspicious_script: ["Suspicious script", "Review script content, parent process, signer, user intent, and approved automation baselines.", "If execution is confirmed malicious, isolate the endpoint and stop the validated malicious process through approved controls; do not block a scripting interpreter globally based on one alert.", "Remove confirmed persistence and remediate the delivery mechanism; tune approved automation separately."],
  lateral_movement: ["Lateral movement", "Correlate source and destination logons, remote services, administrative shares, and identity privileges.", "Coordinate isolation of confirmed affected assets and revoke compromised sessions while preserving incident-response access.", "Remove confirmed persistence, rotate exposed credentials, and correct the access path that enabled movement."]
};

export function generatePlaybook(input) {
  if (typeof input !== "string" || input.length > 100000) throw new Error("Use JSON under 100,000 characters.");
  let alert;
  try { alert = JSON.parse(input); } catch { throw new Error("Invalid JSON. Load the sample to see the supported alert schema."); }
  if (!alert || typeof alert !== "object" || Array.isArray(alert)) throw new Error("Provide one JSON alert object.");
  if (typeof alert.category !== "string") throw new Error("Add category: ransomware, credential_theft, malware, suspicious_script, lateral_movement, or unknown.");
  const selected = Object.hasOwn(categories, alert.category) ? categories[alert.category] : null;
  const critical = ["critical", "production", "safety"].includes(String(alert.asset?.criticality || "").toLowerCase());
  const unknowns = [];
  if (!selected) unknowns.push("Category is unrecognized; only a generic triage plan is available.");
  if (!alert.severity) unknowns.push("Alert severity is missing; urgency has not been inferred.");
  if (!alert.asset?.criticality) unknowns.push("Asset criticality is missing; assess business impact before containment.");
  if (!alert.evidence || typeof alert.evidence !== "object" || Array.isArray(alert.evidence)) unknowns.push("Supporting evidence is missing; the alert alone does not confirm compromise.");
  const step = (phase, action, approvalRequired = false) => ({ phase, action, approvalRequired, executed: false });
  return {
    mode: "edr", category: selected ? alert.category : "unknown",
    template: selected?.[0] || "Generic triage", execution: "Recommendations only; no actions executed",
    basis: "Explicit alert category selects a local template. Severity is reported, not independently verified. Vendor-native formats must be normalized first.",
    unknowns,
    steps: [
      step("Triage", "Validate the alert in the originating EDR, confirm asset identity, evidence freshness, sensor health, and analyst ownership."),
      step("Investigate", selected?.[1] || "Review process, identity, network, and file evidence; classify the behavior before choosing category-specific remediation."),
      step("Preserve evidence", "Preserve the alert, process tree, relevant logs, and volatile evidence using approved procedures. Record timestamps and chain of custody; balance evidence collection against ongoing damage."),
      step("Contain", critical ? "This is a critical, production, or safety-sensitive asset. Have the incident lead and service owner choose a coordinated containment plan before isolation or disruptive changes." : selected?.[2] || "Have the incident lead select containment based on confirmed evidence and business impact; do not isolate solely on an unclassified alert.", true),
      step("Recover", selected?.[3] || "Select recovery actions after scoping and confirming root cause; do not delete artifacts or rebuild based on an unclassified alert.", true),
      step("Verify", "Confirm no continuing malicious activity, review related assets and identities, verify EDR sensor health, and use an agreed monitoring period before lifting containment.", true),
      step("Close", "Document evidence, decisions, approvals, recovery results, and detection improvements in the approved incident system.")
    ],
    sources: ["https://www.ic3.gov/CSA/2023/231019.pdf", "https://learn.microsoft.com/en-us/security/ransomware/incident-response-playbook-dart-ransomware-approach"]
  };
}
