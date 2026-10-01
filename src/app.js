import { techniques, catalogMeta } from "./attack-catalog.js";
import { edrSample, generatePlaybook, familyForTechnique, responseFamilies } from "./edr.js";
import { RULE_TYPES, samples, sanitizeForExport, validateDetection } from "./validator.js";

const input = document.querySelector("#ruleInput");
const results = document.querySelector("#resultsPanel");
const charCount = document.querySelector("#charCount");
const tabs = [...document.querySelectorAll("[data-type]")];
let currentType = "spl";
let lastAssessment = null;

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
}

function updateCount() {
  charCount.textContent = `${input.value.length.toLocaleString()} characters`;
}

function loadSample() {
  input.value = currentType === "edr" ? edrSample : samples[currentType];
  lastAssessment = null;
  updateCount();
  input.focus();
}

function findingHtml(item) {
  return `<article class="finding ${item.severity}">
    <div class="finding-head"><h4>${escapeHtml(item.title)}</h4><span class="tag">${escapeHtml(item.severity)} · ${escapeHtml(item.category)}</span></div>
    <p>${escapeHtml(item.detail)} <strong>Next:</strong> ${escapeHtml(item.remediation)}</p>
  </article>`;
}

function renderPlaybook(assessment) {
  results.innerHTML = `<p class="label">EDR response playbook</p><h2>${escapeHtml(assessment.template)}</h2><p>${escapeHtml(assessment.execution)}</p><p>${escapeHtml(assessment.basis)}</p><p>ATT&amp;CK ${escapeHtml(assessment.taxonomy.version)} · ${assessment.taxonomy.count} active techniques · ${responseFamilies.length} authored response families</p>
    ${assessment.techniques.map(t => `<article class="finding pass"><h4>${escapeHtml(t.id)} · ${escapeHtml(t.name)}</h4><p>${escapeHtml(t.tactics.join(", "))} · ${escapeHtml(t.platforms.join(", "))}</p><a href="${escapeHtml(t.url)}" target="_blank" rel="noopener noreferrer">Technique reference</a></article>`).join("")}
    ${assessment.unknowns.map(note => `<article class="finding medium"><p>${escapeHtml(note)}</p></article>`).join("")}
    ${assessment.steps.map(step => `<article class="finding ${step.approvalRequired ? "medium" : "pass"}"><h4>${escapeHtml(step.phase)}${step.approvalRequired ? " · Approval required" : ""}</h4><p>${escapeHtml(step.action)}</p><p><strong>Why:</strong> ${escapeHtml(step.rationale)}</p><p><strong>Prerequisites:</strong> ${escapeHtml(step.prerequisites)}</p><p><strong>Impact:</strong> ${escapeHtml(step.impact)}</p><p><strong>Verify:</strong> ${escapeHtml(step.verification)}</p><p>Reference: <a href="${escapeHtml(step.sources[0])}" target="_blank" rel="noopener noreferrer">CISA response guidance</a></p></article>`).join("")}
    <div class="actions"><button class="secondary-button" id="downloadReport">Download playbook JSON</button></div>`;
  document.querySelector("#downloadReport").addEventListener("click", downloadReport);
}

function render(assessment) {
  const { score, grade, findings, passes, stats, testPlan } = assessment;
  const summary = findings.length ? `${findings.length} item${findings.length === 1 ? "" : "s"} need review before platform testing.` : "No deterministic issue was found. Live compilation and telemetry testing are still required.";
  results.innerHTML = `
    <div class="score-row">
      <div class="score">${score}<small>/ 100</small></div>
      <div class="score-copy"><p class="label">${escapeHtml(RULE_TYPES[currentType] || "EDR alert JSON")}</p><h2>${escapeHtml(grade)}</h2><p>${escapeHtml(summary)}</p></div>
    </div>
    <div class="summary-grid">
      <div><strong>${stats.high}</strong><span>High</span></div>
      <div><strong>${stats.medium}</strong><span>Medium</span></div>
      <div><strong>${stats.low}</strong><span>Low</span></div>
    </div>
    ${findings.length ? `<section class="result-section"><h3>Prioritized findings</h3>${findings.map(findingHtml).join("")}</section>` : ""}
    <section class="result-section"><h3>Positive indicators</h3>${passes.map(findingHtml).join("") || `<article class="finding low"><h4>No positive indicator scored</h4><p>Add metadata, explicit scope, and testable context.</p></article>`}</section>
    <section class="result-section"><h3>Minimum test plan</h3>${testPlan.map((step, index) => `<article class="finding pass"><div class="finding-head"><h4>Test ${index + 1}</h4></div><p>${escapeHtml(step)}</p></article>`).join("")}</section>
    <div class="actions"><button class="secondary-button" id="downloadReport">Download report</button><button class="secondary-button" id="copySanitized">Copy sanitized rule</button></div>`;

  document.querySelector("#downloadReport").addEventListener("click", downloadReport);
  document.querySelector("#copySanitized").addEventListener("click", copySanitized);
}

function analyze() {
  try {
    lastAssessment = currentType === "edr" ? generatePlaybook(input.value) : validateDetection(currentType, input.value);
    if (currentType === "edr") renderPlaybook(lastAssessment); else render(lastAssessment);
  } catch (error) {
    lastAssessment = null;
    results.innerHTML = `<div class="empty-state"><h2>Analysis stopped</h2><p>${escapeHtml(error.message)}</p></div>`;
  }
}

function downloadReport() {
  if (!lastAssessment) return;
  const report = { generatedAt: new Date().toISOString(), disclaimer: "Local deterministic guidance; compile and test in the authorized target platform.", ...lastAssessment };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const anchor = document.createElement("a");
  anchor.href = URL.createObjectURL(blob);
  anchor.download = `detection-insight-${currentType}-report.json`;
  anchor.click();
  URL.revokeObjectURL(anchor.href);
}

async function copySanitized() {
  const button = document.querySelector("#copySanitized");
  try {
    await navigator.clipboard.writeText(sanitizeForExport(input.value));
    button.textContent = "Copied";
  } catch {
    button.textContent = "Clipboard unavailable";
  }
  setTimeout(() => { button.textContent = "Copy sanitized rule"; }, 1800);
}

for (const tab of tabs) {
  tab.addEventListener("click", () => {
    currentType = tab.dataset.type;
    tabs.forEach(item => item.classList.toggle("active", item === tab));
    tabs.forEach(item => item.setAttribute("aria-selected", String(item === tab)));
    document.querySelector("#attackCatalog").hidden = currentType !== "edr";
    document.querySelector("#analyzeButton").firstChild.textContent = currentType === "edr" ? "Generate response playbook " : "Analyze detection ";
    loadSample();
    results.innerHTML = `<div class="empty-state"><div class="radar-icon">⌁</div><h2>${escapeHtml(RULE_TYPES[currentType] || "EDR alert JSON")}</h2><p>Sample loaded. Analyze it or replace it with your own public-safe rule.</p></div>`;
  });
}

document.querySelector("#sampleButton").addEventListener("click", loadSample);
document.querySelector("#analyzeButton").addEventListener("click", analyze);
input.addEventListener("input", updateCount);

loadSample();

const search = document.querySelector("#techniqueSearch");
const select = document.querySelector("#techniqueSelect");
function renderCatalog() {
  const term = search.value.trim().toLowerCase();
  const matches = techniques.filter(t => [t.id,t.name,...t.tactics,...t.platforms].join(" ").toLowerCase().includes(term));
  select.replaceChildren(...matches.slice(0,80).map(t => {
    const option = document.createElement("option"); option.value=t.id;
    option.textContent=`${t.id} — ${t.name} (${familyForTechnique(t.id) || "generic investigation"})`; return option;
  }));
  document.querySelector("#catalogStatus").textContent=`ATT&CK ${catalogMeta.version} · ${matches.length} matches; showing up to 80. Selecting a technique is an analyst assertion, not confirmation of malicious activity.`;
}
search.addEventListener("input",renderCatalog);
document.querySelector("#addTechnique").addEventListener("click",() => {
  try {
    const alert=JSON.parse(input.value);
    if (!alert || typeof alert !== "object" || Array.isArray(alert)) throw new Error("Expected one alert object.");
    if (!select.value) throw new Error("Select a technique first.");
    if (alert.technique_ids !== undefined && !Array.isArray(alert.technique_ids)) throw new Error("technique_ids must be an array.");
    alert.technique_ids=[...new Set([...(alert.technique_ids || []),select.value])];
    input.value=JSON.stringify(alert,null,2); updateCount(); lastAssessment=null;
    document.querySelector("#catalogStatus").textContent="Technique added. Review the alert category and evidence before generating a playbook.";
  } catch (error) { document.querySelector("#catalogStatus").textContent=error.message; }
});
renderCatalog();
