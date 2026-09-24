// Same-origin: the backend serves this file directly (see main.py's
// StaticFiles mount), so this works unedited on localhost and on Render.
const API_BASE = "";

// ---------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------
let allLogs = [];              // every flow we know about, most-recent-first
let totalFlowsEver = 0;        // cumulative counter, survives log ring-buffer trimming
let modelPerf = null;          // cached /model/performance response
let modelInfo = null;          // cached /model/info response
let featureImportance = null;  // cached /model/feature-importance response

const trafficSeries = { labels: [], total: [], attacks: [] };
const MAX_SERIES_POINTS = 20;

const BUCKET_COLORS = {
  DoS: "#ef4444", DDoS: "#ec4899", PortScan: "#22c55e",
  BruteForce: "#fb923c", WebAttack: "#a78bfa", Botnet: "#22d3ee",
  Exploits: "#f43f5e", Fuzzers: "#eab308", Generic: "#14b8a6",
  Shellcode: "#dc2626", Backdoor: "#7c3aed", Analysis: "#0ea5e9", Worms: "#84cc16"
};

let chartTraffic, chartVector, chartDonut, chartMitre, chartFeature;

// ---------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------
const VIEWS = ["dashboard", "logs", "alerts", "model"];
const TITLES = {
  dashboard: "Live Threat Dashboard",
  logs: "Network Traffic Logs",
  alerts: "Alert History & Analytics",
  model: "CIC-IDS2017 ML Model"
};

function showView(name) {
  VIEWS.forEach(v => {
    document.getElementById("view-" + v).style.display = (v === name) ? "block" : "none";
  });
  document.querySelectorAll(".nav-item").forEach(el => {
    el.classList.toggle("active", el.dataset.view === name);
  });
  document.getElementById("pageTitle").textContent = TITLES[name];

  if (name === "dashboard") renderDashboard();
  if (name === "logs") renderLogsTable();
  if (name === "alerts") renderAlerts();
  if (name === "model") loadModelView();
}

// ---------------------------------------------------------------
// Toast notifications
// ---------------------------------------------------------------
function showToast(message, sub) {
  const host = document.getElementById("toastHost");
  const el = document.createElement("div");
  el.className = "toast";

  const mainLine = document.createElement("div");
  mainLine.textContent = message;
  el.appendChild(mainLine);

  if (sub) {
    const subLine = document.createElement("div");
    subLine.className = "toast-sub";
    subLine.textContent = sub;
    el.appendChild(subLine);
  }

  host.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

// ---------------------------------------------------------------
// Traffic simulation
// ---------------------------------------------------------------
async function simulate(attackType, opts) {
  opts = opts || {};
  const count = opts.count || (attackType === "Normal" ? 15 : 12);
  try {
    const res = await fetch(`${API_BASE}/simulate?attack_type=${encodeURIComponent(attackType)}&count=${count}`, {
      method: "POST"
    });
    if (!res.ok) {
      if (res.status >= 500) {
        throw new Error(`Server error (HTTP ${res.status}) - the backend may be restarting or out of memory. Try again in a moment.`);
      }
      let detail = "";
      try { detail = (await res.json()).detail || ""; } catch (e) {}
      throw new Error(detail || `Request failed (HTTP ${res.status})`);
    }
    const data = await res.json();

    allLogs = data.entries.concat(allLogs).slice(0, 500);
    totalFlowsEver += data.injected;

    const threats = data.entries.filter(e => e.severity !== "benign").length;
    if (!opts.silent) {
      showToast(`Injected ${data.injected} flows (${attackType})`, `${threats} threat(s) detected`);
    }

    const nowLabel = new Date().toLocaleTimeString();
    trafficSeries.labels.push(nowLabel);
    trafficSeries.total.push(data.injected);
    trafficSeries.attacks.push(threats);
    if (trafficSeries.labels.length > MAX_SERIES_POINTS) {
      trafficSeries.labels.shift();
      trafficSeries.total.shift();
      trafficSeries.attacks.shift();
    }

    const activeView = VIEWS.find(v => document.getElementById("view-" + v).style.display !== "none");
    if (activeView === "dashboard") renderDashboard();
    if (activeView === "logs") renderLogsTable();
    if (activeView === "alerts") renderAlerts();
  } catch (err) {
    if (!opts.silent) showToast("Simulation failed", String(err.message || err));
  }
}

// Keep the dashboard feeling alive with a small background trickle of
// normal traffic, independent of manual button clicks.
setInterval(() => simulate("Normal", { count: 4, silent: true }), 7000);

// ---------------------------------------------------------------
// Dashboard view
// ---------------------------------------------------------------
function renderDashboard() {
  const threats = allLogs.filter(l => l.severity !== "benign");
  const critical = threats.filter(l => l.severity === "critical").length;
  const total = allLogs.length || 1;
  const anomalyIndex = Math.round((threats.length / total) * 1000) / 10;

  document.getElementById("kpiFlowsRate").textContent =
    trafficSeries.total.length ? (trafficSeries.total.reduce((a, b) => a + b, 0) / trafficSeries.total.length).toFixed(1) : "0.0";
  document.getElementById("kpiThreats").textContent = threats.length;
  document.getElementById("kpiThreatsSub").textContent = `${critical} critical`;
  document.getElementById("kpiAnomaly").textContent = anomalyIndex.toFixed(1);
  document.getElementById("kpiAccuracy").textContent = modelPerf ? (modelPerf.accuracy * 100).toFixed(1) + "%" : "–";
  document.getElementById("kpiTotalFlows").textContent = totalFlowsEver;

  renderTrafficLineChart();
  renderVectorBarChart();
  renderLiveFeed();

  if (!modelPerf) fetchModelPerformance().then(() => {
    document.getElementById("kpiAccuracy").textContent = modelPerf ? (modelPerf.accuracy * 100).toFixed(1) + "%" : "–";
  });
}

function renderTrafficLineChart() {
  const ctx = document.getElementById("trafficLineChart");
  const data = {
    labels: trafficSeries.labels,
    datasets: [
      {
        label: "Total flows",
        data: trafficSeries.total,
        borderColor: "#ef4444",
        backgroundColor: "rgba(239,68,68,0.12)",
        fill: true, tension: 0.35, pointRadius: 0
      },
      {
        label: "Attack flows",
        data: trafficSeries.attacks,
        borderColor: "#22d3ee",
        backgroundColor: "rgba(34,211,238,0.08)",
        fill: true, tension: 0.35, pointRadius: 0
      }
    ]
  };
  if (chartTraffic) { chartTraffic.data = data; chartTraffic.update(); return; }
  chartTraffic = new Chart(ctx, {
    type: "line",
    data,
    options: {
      responsive: true,
      scales: {
        x: { ticks: { color: "#5b6478", maxTicksLimit: 6 }, grid: { color: "rgba(148,163,184,0.06)" } },
        y: { beginAtZero: true, ticks: { color: "#5b6478" }, grid: { color: "rgba(148,163,184,0.06)" } }
      },
      plugins: { legend: { labels: { color: "#8b96ab" } } }
    }
  });
}

function renderVectorBarChart() {
  const counts = {};
  allLogs.forEach(l => {
    if (l.severity === "benign") return;
    counts[l.label] = (counts[l.label] || 0) + 1;
  });
  const labels = Object.keys(BUCKET_COLORS).filter(k => counts[k]);
  const values = labels.map(l => counts[l]);
  const colors = labels.map(l => BUCKET_COLORS[l]);

  const ctx = document.getElementById("vectorBarChart");
  const data = { labels, datasets: [{ data: values, backgroundColor: colors, borderRadius: 4 }] };
  if (chartVector) { chartVector.data = data; chartVector.update(); return; }
  chartVector = new Chart(ctx, {
    type: "bar",
    data,
    options: {
      indexAxis: "y",
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { color: "#5b6478" }, grid: { color: "rgba(148,163,184,0.06)" } },
        y: { ticks: { color: "#8b96ab" }, grid: { display: false } }
      }
    }
  });
}

function severityBadge(sev) {
  const cls = { critical: "badge-critical", high: "badge-high", medium: "badge-medium", benign: "badge-benign" }[sev] || "badge-medium";
  return `<span class="badge ${cls}">${sev}</span>`;
}

function renderLiveFeed() {
  const host = document.getElementById("liveFeed");
  host.innerHTML = allLogs.slice(0, 15).map(l => `
    <div class="feed-row">
      <span class="feed-time">${l.time.split(" ")[1] || l.time}</span>
      ${severityBadge(l.severity)}
      <span class="feed-src">${l.label} &nbsp; ${l.source} → ${l.dest}</span>
      <span class="feed-conf">${(l.confidence * 100).toFixed(0)}%</span>
    </div>
  `).join("") || `<p class="note-text">No traffic yet - click a TRAFFIC SIM button above to inject flows.</p>`;
}

// ---------------------------------------------------------------
// Traffic Logs view
// ---------------------------------------------------------------
function populateAttackFilterOptions() {
  const select = document.getElementById("logsAttackFilter");
  const current = select.value;
  const labels = Array.from(new Set(allLogs.map(l => l.label))).sort();
  select.innerHTML = `<option value="all">Attack: all</option>` +
    labels.map(l => `<option value="${l}">${l}</option>`).join("");
  select.value = labels.includes(current) ? current : "all";
}

function renderLogsTable() {
  populateAttackFilterOptions();

  const search = document.getElementById("logsSearch").value.toLowerCase();
  const attackFilter = document.getElementById("logsAttackFilter").value;
  const severityFilter = document.getElementById("logsSeverityFilter").value;
  const protoFilter = document.getElementById("logsProtoFilter").value;

  const filtered = allLogs.filter(l => {
    if (attackFilter !== "all" && l.label !== attackFilter) return false;
    if (severityFilter !== "all" && l.severity !== severityFilter) return false;
    if (protoFilter !== "all" && l.proto !== protoFilter) return false;
    if (search) {
      const hay = `${l.source} ${l.dest} ${l.label}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  const tbody = document.querySelector("#logsTable tbody");
  tbody.innerHTML = filtered.slice(0, 200).map(l => `
    <tr>
      <td>${l.time}</td>
      <td>${l.source} → ${l.dest}</td>
      <td>${l.proto}:${l.port}</td>
      <td>${l.label}</td>
      <td>${severityBadge(l.severity)}</td>
      <td>${(l.confidence * 100).toFixed(0)}%</td>
      <td><button class="inspect-link" onclick='inspectEntry(${JSON.stringify(JSON.stringify(l))})'>inspect</button></td>
    </tr>
  `).join("") || `<tr><td colspan="7" class="note-text">No matching flows.</td></tr>`;
}

let currentInspectEntry = null;

function inspectEntry(jsonStr) {
  currentInspectEntry = JSON.parse(jsonStr);
  openInspectPanel(currentInspectEntry);
}

function closeInspect() {
  document.getElementById("inspectOverlay").style.display = "none";
  currentInspectEntry = null;
}

function openInspectPanel(entry) {
  document.getElementById("inspectLabel").textContent = entry.label || "Unknown";
  document.getElementById("inspectSeverityBadge").innerHTML = severityBadge(entry.severity || "medium");

  const confidencePct = Math.round((entry.confidence || 0) * 100);
  document.getElementById("inspectConfidence").textContent = confidencePct + "%";
  document.getElementById("inspectConfidenceBar").style.width = confidencePct + "%";

  const topHost = document.getElementById("inspectTopPredictions");
  if (entry.top_predictions && entry.top_predictions.length) {
    topHost.innerHTML = entry.top_predictions.map(p => `
      <div class="top-pred-row"><span>${p.label}</span><span class="top-pred-value">${(p.probability * 100).toFixed(1)}%</span></div>
    `).join("");
  } else {
    topHost.innerHTML = "";
  }

  document.getElementById("inspectSource").textContent = entry.source || "–";
  document.getElementById("inspectDest").textContent = entry.dest || "–";
  document.getElementById("inspectProto").textContent = entry.proto && entry.port ? `${entry.proto} / ${entry.port}` : "–";
  document.getElementById("inspectDuration").textContent = entry.flow_duration_ms !== undefined ? `${entry.flow_duration_ms} ms` : "–";
  document.getElementById("inspectPackets").textContent = entry.total_packets !== undefined ? entry.total_packets : "–";
  document.getElementById("inspectRate").textContent = entry.flow_packets_per_sec !== undefined ? `${entry.flow_packets_per_sec}/s` : "–";
  document.getElementById("inspectMitre").textContent = entry.mitre && entry.mitre !== "-" ? entry.mitre : "None (benign)";

  // Detection Basis: describes what the system actually is - a
  // supervised Random Forest classifier - not a signature or
  // statistical-anomaly-baseline system.
  const treeCount = modelInfo ? modelInfo.n_estimators : "60+";
  document.getElementById("inspectBasis").textContent =
    `Random Forest classifier (${treeCount} trees, ${modelInfo ? modelInfo.num_features : 78} flow features) predicted "${entry.label}" with ${confidencePct}% confidence.` +
    (entry.true_label ? ` True label (simulator ground truth): ${entry.true_label}.` : "");

  // Reset AI analysis section for the new entry
  document.getElementById("inspectAiTitle").textContent = "AI Threat Analysis";
  document.getElementById("inspectAiBody").innerHTML =
    `<p class="note-text">Click Analyze to generate an AI-powered root cause report and remediation plan.</p>`;
  document.getElementById("inspectAnalyzeBtn").disabled = false;

  document.getElementById("inspectOverlay").style.display = "flex";
}

async function runAiAnalysis() {
  if (!currentInspectEntry) return;
  const btn = document.getElementById("inspectAnalyzeBtn");
  const body = document.getElementById("inspectAiBody");
  btn.disabled = true;
  btn.textContent = "Analyzing…";
  body.innerHTML = `<p class="note-text">Contacting the AI model…</p>`;

  try {
    const res = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentInspectEntry)
    });
    if (!res.ok) {
      let detail = "";
      try { detail = (await res.json()).detail || ""; } catch (e) {}
      throw new Error(detail || `Request failed (HTTP ${res.status})`);
    }
    const data = await res.json();
    document.getElementById("inspectAiTitle").textContent = `${(data.model || "AI").toUpperCase()} AI Threat Analysis`;
    // AI output is untrusted content - render through marked then
    // sanitize with DOMPurify before inserting, same lesson as the
    // earlier toast/error-message fix: never trust raw text into innerHTML.
    const rawHtml = marked.parse(data.analysis || "");
    body.innerHTML = DOMPurify.sanitize(rawHtml);
  } catch (err) {
    body.innerHTML = `<p class="note-text">Analysis failed: ${(err.message || err).toString().replace(/[<>&]/g, c => ({"<":"&lt;",">":"&gt;","&":"&amp;"}[c]))}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "✨ Analyze";
  }
}

async function uploadTrafficCsv(event) {
  const file = event.target.files[0];
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch(`${API_BASE}/detect/csv`, { method: "POST", body: formData });
    if (!res.ok) {
      if (res.status >= 500) {
        throw new Error(`Server error (HTTP ${res.status}) - the backend may be restarting or out of memory. Try again in a moment.`);
      }
      let detail = "";
      try { detail = (await res.json()).detail || ""; } catch (e) {}
      throw new Error(detail || `Request failed (HTTP ${res.status})`);
    }
    const data = await res.json();

    // The uploaded CSV's own IPs (if any) aren't part of what /detect/csv
    // returns - it only knows row index and the extracted flow features.
    // Source/dest below are placeholders for display, same as the
    // simulator - see the backend comment in main.py for why this
    // dataset has none. Everything else (severity, mitre, flow
    // details, top predictions) now comes straight from the backend.
    const now = new Date().toLocaleString();
    const newEntries = data.results.map(r => ({
      time: now,
      source: "uploaded row " + r.row,
      dest: "-",
      proto: "-",
      port: "-",
      label: r.prediction,
      severity: r.severity,
      confidence: r.confidence,
      mitre: r.mitre,
      flow_duration_ms: r.flow_duration_ms,
      total_packets: r.total_packets,
      flow_bytes_per_sec: r.flow_bytes_per_sec,
      flow_packets_per_sec: r.flow_packets_per_sec,
      syn_flag_ratio: r.syn_flag_ratio,
      top_predictions: r.top_predictions
    }));

    allLogs = newEntries.concat(allLogs).slice(0, 500);
    totalFlowsEver += newEntries.length;
    showToast(`Analyzed ${data.total_records} rows`, `${data.attacks_detected} flagged as attacks`);
    renderLogsTable();
  } catch (err) {
    showToast("Upload failed", String(err.message || err));
  } finally {
    event.target.value = "";
  }
}

// ---------------------------------------------------------------
// Alert History view
// ---------------------------------------------------------------
function renderAlerts() {
  const alerts = allLogs.filter(l => l.severity !== "benign");
  document.getElementById("alertsTotal").textContent = `${alerts.length} total alerts recorded`;

  const sevCounts = { critical: 0, high: 0, medium: 0 };
  alerts.forEach(a => { if (sevCounts[a.severity] !== undefined) sevCounts[a.severity]++; });

  const donutCtx = document.getElementById("severityDonut");
  const donutData = {
    labels: ["critical", "high", "medium"],
    datasets: [{ data: [sevCounts.critical, sevCounts.high, sevCounts.medium], backgroundColor: ["#ef4444", "#fb923c", "#facc15"], borderWidth: 0 }]
  };
  if (chartDonut) { chartDonut.data = donutData; chartDonut.update(); }
  else {
    chartDonut = new Chart(donutCtx, {
      type: "doughnut",
      data: donutData,
      options: { plugins: { legend: { position: "bottom", labels: { color: "#8b96ab" } } }, cutout: "65%" }
    });
  }

  const mitreCounts = {};
  alerts.forEach(a => { if (a.mitre && a.mitre !== "-") mitreCounts[a.mitre] = (mitreCounts[a.mitre] || 0) + 1; });
  const mitreLabels = Object.keys(mitreCounts);
  const mitreValues = mitreLabels.map(k => mitreCounts[k]);

  const mitreCtx = document.getElementById("mitreBarChart");
  const mitreData = { labels: mitreLabels, datasets: [{ data: mitreValues, backgroundColor: "#22d3ee", borderRadius: 4 }] };
  if (chartMitre) { chartMitre.data = mitreData; chartMitre.update(); }
  else {
    chartMitre = new Chart(mitreCtx, {
      type: "bar",
      data: mitreData,
      options: {
        indexAxis: "y",
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { color: "#5b6478" }, grid: { color: "rgba(148,163,184,0.06)" } },
          y: { ticks: { color: "#8b96ab", font: { size: 10 } }, grid: { display: false } }
        }
      }
    });
  }

  const tbody = document.querySelector("#alertsTable tbody");
  tbody.innerHTML = alerts.slice(0, 200).map(a => `
    <tr>
      <td>${a.time}</td>
      <td>${a.label}</td>
      <td>${severityBadge(a.severity)}</td>
      <td>${a.source} → ${a.dest}</td>
      <td>${a.mitre}</td>
      <td><button class="inspect-link" onclick='inspectEntry(${JSON.stringify(JSON.stringify(a))})'>inspect</button></td>
    </tr>
  `).join("") || `<tr><td colspan="6" class="note-text">No alerts yet.</td></tr>`;
}

function exportAlertsCsv() {
  const alerts = allLogs.filter(l => l.severity !== "benign");
  const header = "time,attack,severity,source,dest,confidence,mitre\n";
  const rows = alerts.map(a =>
    [a.time, a.label, a.severity, a.source, a.dest, a.confidence, `"${a.mitre}"`].join(",")
  ).join("\n");
  const blob = new Blob([header + rows], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "alert_report.csv";
  link.click();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------
// ML Model view
// ---------------------------------------------------------------
function renderConfusionMatrix(labels, matrix) {
  const host = document.getElementById("confusionMatrixHost");
  const header = `<tr><th></th>${labels.map(l => `<th>Pred ${l}</th>`).join("")}</tr>`;
  const rows = matrix.map((row, i) => `
    <tr>
      <th>Actual ${labels[i]}</th>
      ${row.map((val, j) => `<td class="${i === j ? 'cell-correct' : (val > 0 ? 'cell-wrong' : '')}">${val}</td>`).join("")}
    </tr>
  `).join("");
  host.innerHTML = `<table class="confusion-table"><thead>${header}</thead><tbody>${rows}</tbody></table>`;
}

async function fetchModelPerformance() {
  try {
    const res = await fetch(`${API_BASE}/model/performance`);
    if (res.ok) modelPerf = await res.json();
  } catch (e) { /* holdout file may not be deployed - views degrade gracefully */ }
}

async function loadModelView() {
  if (!modelInfo) {
    try {
      const res = await fetch(`${API_BASE}/model/info`);
      if (res.ok) modelInfo = await res.json();
    } catch (e) {}
  }
  if (modelInfo) {
    document.getElementById("modelTitle").textContent = `${modelInfo.algorithm} (${modelInfo.n_estimators} estimators)`;
    document.getElementById("modelSub").textContent = `${modelInfo.dataset} · v2.0 · ${modelInfo.num_features} features · ${modelInfo.num_classes}-class`;
  }

  if (!modelPerf) await fetchModelPerformance();
  if (modelPerf) {
    document.getElementById("mAccuracy").textContent = (modelPerf.accuracy * 100).toFixed(2) + "%";
    document.getElementById("mPrecision").textContent = (modelPerf.precision * 100).toFixed(2) + "% (macro)";
    document.getElementById("mRecall").textContent = (modelPerf.recall * 100).toFixed(2) + "% (macro)";
    document.getElementById("mF1").textContent = (modelPerf.f1_score * 100).toFixed(2) + "% (macro)";

    renderConfusionMatrix(modelPerf.confusion_matrix.labels, modelPerf.confusion_matrix.matrix);

    const tbody = document.querySelector("#perTypeTable tbody");
    tbody.innerHTML = Object.entries(modelPerf.per_class).map(([cls, s]) => `
      <tr>
        <td>${cls}</td>
        <td>${(s.precision * 100).toFixed(2)}%</td>
        <td>${(s.recall * 100).toFixed(2)}%</td>
        <td>${(s.f1_score * 100).toFixed(2)}%</td>
        <td>${s.support}</td>
      </tr>
    `).join("");
  } else {
    document.querySelector("#perTypeTable tbody").innerHTML =
      `<tr><td colspan="5" class="note-text">test_holdout.csv not found next to the model - run model/train_model.py first.</td></tr>`;
  }

  if (!featureImportance) {
    try {
      const res = await fetch(`${API_BASE}/model/feature-importance?top_n=10`);
      if (res.ok) featureImportance = (await res.json()).features;
    } catch (e) {}
  }
  if (featureImportance) {
    const ctx = document.getElementById("featureImportanceChart");
    const data = {
      labels: featureImportance.map(f => f.name).reverse(),
      datasets: [{ data: featureImportance.map(f => f.importance).reverse(), backgroundColor: "#22d3ee", borderRadius: 4 }]
    };
    if (chartFeature) { chartFeature.data = data; chartFeature.update(); }
    else {
      chartFeature = new Chart(ctx, {
        type: "bar",
        data,
        options: {
          indexAxis: "y",
          plugins: { legend: { display: false } },
          scales: {
            x: { beginAtZero: true, ticks: { color: "#5b6478" }, grid: { color: "rgba(148,163,184,0.06)" } },
            y: { ticks: { color: "#8b96ab", font: { size: 10 } }, grid: { display: false } }
          }
        }
      });
    }
  }
}

// ---------------------------------------------------------------
// Boot
// ---------------------------------------------------------------
const SIM_ICONS = {
  Normal: "\ud83d\udcc8", DoS: "\u26a1", DDoS: "\ud83c\udf10", PortScan: "\ud83d\udef0",
  BruteForce: "\ud83d\udd11", WebAttack: "\ud83e\udde8", Botnet: "\ud83e\udd16",
  Exploits: "\ud83d\udca5", Fuzzers: "\ud83c\udfb2", Generic: "\ud83d\udd10",
  Shellcode: "\ud83d\udc1a", Backdoor: "\ud83d\udeaa", Analysis: "\ud83d\udd0d", Worms: "\ud83d\udc1b"
};

async function populateSimDropdown() {
  if (!modelInfo) {
    try {
      const res = await fetch(`${API_BASE}/model/info`);
      if (res.ok) modelInfo = await res.json();
    } catch (e) { return; }
  }
  if (!modelInfo || !modelInfo.classes) return;

  const select = document.getElementById("simTypeSelect");
  const attackClasses = modelInfo.classes.filter(c => c !== "Normal").sort();
  select.innerHTML = `<option value="Normal">${SIM_ICONS.Normal} Normal</option>` +
    attackClasses.map(c => `<option value="${c}">${SIM_ICONS[c] || "\u26a0"} ${c}</option>`).join("");
}

async function boot() {
  try {
    const res = await fetch(`${API_BASE}/logs/traffic`);
    if (res.ok) {
      const data = await res.json();
      allLogs = data.logs;
      totalFlowsEver = allLogs.length;
    }
  } catch (e) {}

  await populateSimDropdown();
  await fetchModelPerformance();
  showView("dashboard");
}

boot();
