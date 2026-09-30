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
  input.value = samples[currentType];
  updateCount();
  input.focus();
}

function findingHtml(item) {
  return `<article class="finding ${item.severity}">
    <div class="finding-head"><h4>${escapeHtml(item.title)}</h4><span class="tag">${escapeHtml(item.severity)} · ${escapeHtml(item.category)}</span></div>
    <p>${escapeHtml(item.detail)} <strong>Next:</strong> ${escapeHtml(item.remediation)}</p>
  </article>`;
}

function render(assessment) {
  const { score, grade, findings, passes, stats, testPlan } = assessment;
  const summary = findings.length ? `${findings.length} item${findings.length === 1 ? "" : "s"} need review before platform testing.` : "No deterministic issue was found. Live compilation and telemetry testing are still required.";
  results.innerHTML = `
    <div class="score-row">
      <div class="score">${score}<small>/ 100</small></div>
      <div class="score-copy"><p class="label">${escapeHtml(RULE_TYPES[currentType])}</p><h2>${escapeHtml(grade)}</h2><p>${escapeHtml(summary)}</p></div>
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
    lastAssessment = validateDetection(currentType, input.value);
    render(lastAssessment);
  } catch (error) {
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
    loadSample();
    results.innerHTML = `<div class="empty-state"><div class="radar-icon">⌁</div><h2>${escapeHtml(RULE_TYPES[currentType])}</h2><p>Sample loaded. Analyze it or replace it with your own public-safe rule.</p></div>`;
  });
}

document.querySelector("#sampleButton").addEventListener("click", loadSample);
document.querySelector("#analyzeButton").addEventListener("click", analyze);
input.addEventListener("input", updateCount);

loadSample();
