let trafficChart = null;
let attackTypesChart = null;

// Empty string = same origin as whatever served this page. Since the
// backend now serves this dashboard directly (see the StaticFiles
// mount in main.py), this works automatically both locally
// (http://localhost:8000/) and on Render (https://your-app.onrender.com/)
// with no editing needed after each deploy.
//
// Only hardcode a different URL here if you're serving this frontend
// from somewhere else than the backend itself (e.g. a separate static
// host) - in that case set it back to the full backend URL.
const API_BASE = "";

// Show selected file name
const fileInput = document.getElementById("csvFile");
const fileInfo = document.getElementById("fileInfo");

fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
        fileInfo.textContent = `Selected file: ${fileInput.files[0].name}`;
    } else {
        fileInfo.textContent = "No file selected";
    }
});


async function analyzeAll() {
  const fileInput = document.getElementById("csvFile");
  const status = document.getElementById("status");

  if (!fileInput.files.length) {
    status.textContent = "Please select a CSV file.";
    return;
  }

  const file = fileInput.files[0];
  status.textContent = "Analyzing...";

  try {
    // ---------- Summary ----------
    let formData = new FormData();
    formData.append("file", file);
    let attackForm = new FormData();
    attackForm.append("file", file);
    loadAttackTypes(attackForm);



    const summaryRes = await fetch(`${API_BASE}/detect/summary`, {
      method: "POST",
      body: formData
    });

    const summary = await summaryRes.json();

    document.getElementById("summary").style.display = "block";
    document.getElementById("totalRecords").textContent = summary.total_records;
    document.getElementById("attacksDetected").textContent = summary.attacks_detected;
    document.getElementById("benignDetected").textContent = summary.benign_detected;
    document.getElementById("attackRatio").textContent =
      (summary.attack_ratio * 100).toFixed(2) + "%";
      updateSOCAlert(summary.attack_ratio);
      renderTrafficChart(summary.benign_detected, summary.attacks_detected);

      // ---------- Threat Intelligence ----------
      const intelSection = document.getElementById("threatIntel");
      intelSection.style.display = "block";

      document.getElementById("riskLevel").textContent = summary.risk_level;
      document.getElementById("analysisText").textContent = summary.analysis;

      const list = document.getElementById("recommendationsList");
      list.innerHTML = "";

      summary.recommendations.forEach(item => {
        const li = document.createElement("li");
        li.textContent = item;
        list.appendChild(li);
      });

    // ---------- Evaluation Metrics ----------
    formData = new FormData();
    formData.append("file", file);

    const evalRes = await fetch(`${API_BASE}/detect/evaluate`, {
      method: "POST",
      body: formData
    });

    const evalData = await evalRes.json();

    document.getElementById("metrics").style.display = "block";
    document.getElementById("accuracy").textContent = evalData.metrics.accuracy;
    document.getElementById("precision").textContent = evalData.metrics.precision;
    document.getElementById("recall").textContent = evalData.metrics.recall;
    document.getElementById("f1").textContent = evalData.metrics.f1_score;


    // ---------- Confusion Matrix ----------
    formData = new FormData();
    formData.append("file", file);

    const confRes = await fetch(`${API_BASE}/stats/confusion`, {
      method: "POST",
      body: formData
    });

    const conf = await confRes.json();

    document.getElementById("confusion").style.display = "block";
    document.getElementById("tn").textContent = conf.true_negative;
    document.getElementById("fp").textContent = conf.false_positive;
    document.getElementById("fn").textContent = conf.false_negative;
    document.getElementById("tp").textContent = conf.true_positive;


    // ---------- System Stats ----------
    loadStats();

    status.textContent = "Analysis complete ✔";

  } catch (err) {
    console.error(err);
    status.textContent = "Error during analysis";
  }

  
  loadHistory();

}

async function loadStats() {
  try {
    const res = await fetch(`${API_BASE}/stats/summary`);
    const stats = await res.json();

    document.getElementById("statScans").textContent = stats.total_scans;
    document.getElementById("statRecords").textContent = stats.total_records_processed;
    document.getElementById("statAttacks").textContent = stats.total_attacks_detected;
    document.getElementById("statRatio").textContent =
      (stats.average_attack_ratio * 100).toFixed(2) + "%";
  } catch (err) {
    console.error("Failed to load stats", err);
  }
}

// Load system stats on page open
loadStats();

function updateSOCAlert(attackRatio) {
  const alertBox = document.getElementById("socAlert");
  const title = document.getElementById("alertTitle");
  const message = document.getElementById("alertMessage");

  // Reset classes
  alertBox.classList.remove("normal", "warning", "critical");

  if (attackRatio < 0.05) {
    alertBox.classList.add("normal");
    title.textContent = "System Status: NORMAL";
    message.textContent = "Network traffic is within safe limits.";
  }
  else if (attackRatio < 0.20) {
    alertBox.classList.add("warning");
    title.textContent = "System Status: SUSPICIOUS";
    message.textContent = "Elevated attack activity detected. Monitor closely.";
  }
  else {
    alertBox.classList.add("critical");
    title.textContent = "System Status: CRITICAL";
    message.textContent = "High attack volume detected! Immediate investigation required.";
  }
}

async function loadAttackTypes(formData) {
  try {
    const res = await fetch(`${API_BASE}/stats/attack-types`, {
      method: "POST",
      body: formData
    });

    const data = await res.json();

    const section = document.getElementById("attackTypesSection");
    const tbody = document.querySelector("#attackTable tbody");

    tbody.innerHTML = "";

    const types = data.attack_types;

    if (!types || Object.keys(types).length === 0) {
      section.style.display = "none";
      return;
    }

    section.style.display = "block";

    // Sort by count descending
    const sorted = Object.entries(types).sort((a, b) => b[1] - a[1]);

    sorted.forEach(([type, count]) => {
      const row = document.createElement("tr");
      row.innerHTML = `<td>${type}</td><td>${count}</td>`;
      tbody.appendChild(row);
    });
    renderAttackTypesChart(types);

  } catch (err) {
    console.error("Failed to load attack types", err);
  }
}

// Render attack types pie chart
function renderTrafficChart(benign, attacks) {
  const ctx = document.getElementById("trafficChart").getContext("2d");

  document.getElementById("chartsSection").style.display = "block";

  if (trafficChart) {
    trafficChart.destroy();
  }

  trafficChart = new Chart(ctx, {
    type: "pie",
    data: {
      labels: ["Benign", "Attack"],
      datasets: [{
        data: [benign, attacks],
        backgroundColor: ["#22c55e", "#ef4444"]
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          labels: {
            color: "#e5e7eb"
          }
        }
      }
    }
  });
}

function renderAttackTypesChart(types) {
  const canvas = document.getElementById("attackTypesChart");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");

  if (attackTypesChart) {
    attackTypesChart.destroy();
  }

  const labels = Object.keys(types);
  const values = Object.values(types);

  attackTypesChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Attack Count",
        data: values,
        backgroundColor: "#ef4444"
      }]
    },
    options: {
      responsive: true
    }
  });
}

// ---------- Live Monitoring ----------
async function liveMonitor() {
  try {
    const res = await fetch(`${API_BASE}/stats/summary`);
    const stats = await res.json();

    // Update stats
    document.getElementById("statScans").textContent = stats.total_scans;
    document.getElementById("statRecords").textContent = stats.total_records_processed;
    document.getElementById("statAttacks").textContent = stats.total_attacks_detected;
    document.getElementById("statRatio").textContent =
      (stats.average_attack_ratio * 100).toFixed(2) + "%";

    // Update SOC alert based on average ratio
    updateSOCAlert(stats.average_attack_ratio);

    // Update timestamp
    const now = new Date().toLocaleTimeString();
    document.getElementById("lastUpdate").textContent = now;

  } catch (err) {
    console.error("Live monitor failed", err);
  }
}

// Start live monitoring
setInterval(liveMonitor, 5000);

liveMonitor();

async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/stats/history`);
    const data = await res.json();

    const tbody = document.querySelector("#historyTable tbody");
    tbody.innerHTML = "";

    const history = data.history;

    if (!history || history.length === 0) {
      tbody.innerHTML = "<tr><td colspan='4'>No scans yet</td></tr>";
      return;
    }

    history.reverse().forEach(item => {
      const row = document.createElement("tr");

      row.innerHTML = `
        <td>${item.time}</td>
        <td>${item.total_records}</td>
        <td>${item.attacks_detected}</td>
        <td>${(item.attack_ratio * 100).toFixed(2)}%</td>
      `;

      tbody.appendChild(row);
    });

  } catch (err) {
    console.error("Failed to load history", err);
  }
}


