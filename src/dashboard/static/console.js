/* ============================================================
   PhishBuster UK — SOC Console client
   Polls KPI + chart endpoints, renders stream, manages modal.
   ============================================================ */

(() => {
  const state = { hours: 24, filters: {} };
  const fmt = new Intl.NumberFormat("en-GB");

  const PALETTE = {
    phishing: "#ef4452",
    suspicious: "#e5a94d",
    benign: "#5ba986",
    unknown: "#5a6b79",
    amber: "#e5a94d",
    amberDim: "#a77a32",
    grid: "rgba(229,169,77,0.08)",
    ink: "#cfd6db",
    inkLo: "#8a9aa6",
  };

  /* ---------- clock ---------- */
  const clockEl = document.getElementById("clock");
  function tick() {
    const d = new Date();
    const fmtDate = new Intl.DateTimeFormat("en-GB", {
      timeZone: "Europe/London",
      weekday: "short", day: "2-digit", month: "short",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: false,
    }).format(d);
    clockEl.textContent = fmtDate + " UK";
  }
  setInterval(tick, 1000); tick();

  /* ---------- window switcher ---------- */
  document.querySelectorAll(".win").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".win").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.hours = parseInt(btn.dataset.hours, 10);
      refreshAll();
    });
  });

  document.getElementById("refresh-stream").addEventListener("click", refreshStream);
  document.getElementById("filter-verdict").addEventListener("change", e => {
    state.filters.verdict = e.target.value || null; refreshStream();
  });
  document.getElementById("filter-severity").addEventListener("change", e => {
    state.filters.severity = e.target.value || null; refreshStream();
  });

  /* ---------- KPI ---------- */
  async function refreshKPIs() {
    const r = await fetch(`/api/kpis?hours=${state.hours}`).then(r => r.json());
    const set = (id, v) => { document.getElementById(id).textContent = v; };
    set("kpi-phishing", fmt.format(r.confirmed_phishing));
    set("kpi-total", fmt.format(r.total_scanned));
    set("kpi-mttd", r.mttd_label);
    set("kpi-mttr", r.mttr_label);
    set("kpi-sla",  r.sla_adherence_pct == null ? "—" : r.sla_adherence_pct.toFixed(1) + "%");
    set("kpi-fp",   r.fp_rate_pct == null ? "—" : r.fp_rate_pct.toFixed(1) + "%");
    set("kpi-dwell", r.dwell_label);
    document.getElementById("gen-time").textContent =
      "generated " + new Date(r.generated_at).toLocaleTimeString("en-GB");
  }

  /* ---------- Stream ---------- */
  async function refreshStream() {
    const params = new URLSearchParams({ limit: "40" });
    if (state.filters.verdict) params.set("verdict", state.filters.verdict);
    if (state.filters.severity) params.set("severity", state.filters.severity);
    const data = await fetch(`/api/incidents?${params}`).then(r => r.json());
    const box = document.getElementById("incident-stream");
    if (!data.items.length) {
      box.innerHTML = `<div class="stream-empty">NO INCIDENTS IN WINDOW</div>`;
      return;
    }
    box.innerHTML = data.items.map(i => {
      const time = new Date(i.received_at).toLocaleString("en-GB", {
        timeZone: "Europe/London",
        hour: "2-digit", minute: "2-digit", day: "2-digit", month: "short",
      });
      const brandTag = i.brand ? `<span class="tag t-brand">${esc(i.brand)}</span>` : "";
      const fpTag = i.is_fp ? `<span class="tag t-fp">FP</span>` : "";
      return `
        <div class="stream-item ${i.verdict}" data-id="${i.id}">
          <div class="bar"></div>
          <div class="stream-time">${time}</div>
          <div class="stream-body">
            <p class="subject">${esc(i.subject || "(no subject)")}</p>
            <div class="from">${esc(i.from || "—")}</div>
          </div>
          <div class="stream-meta">
            <span class="tag t-${i.verdict}">${i.verdict}</span>
            <span class="tag t-${i.severity}">${i.severity}</span>
            ${brandTag}${fpTag}
          </div>
        </div>
      `;
    }).join("");
    box.querySelectorAll(".stream-item").forEach(el => {
      el.addEventListener("click", () => openIncident(el.dataset.id));
    });
  }

  /* ---------- Verdict donut ---------- */
  let donut;
  async function refreshVerdicts() {
    const r = await fetch(`/api/charts/verdicts?hours=${state.hours}`).then(r => r.json());
    const labels = ["phishing", "suspicious", "benign", "unknown"];
    const data = labels.map(l => r[l] || 0);
    const colors = labels.map(l => PALETTE[l] || PALETTE.inkLo);
    document.getElementById("donut-total").textContent = fmt.format(data.reduce((a, b) => a + b, 0));

    const legend = document.getElementById("verdict-legend");
    legend.innerHTML = labels.map((l, i) => `
      <li style="--swatch:${colors[i]}">${l} · ${fmt.format(data[i])}</li>
    `).join("");

    const ctx = document.getElementById("chart-verdicts");
    if (donut) donut.destroy();
    donut = new Chart(ctx, {
      type: "doughnut",
      data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: "#11212d", borderWidth: 2 }] },
      options: {
        cutout: "72%", responsive: true, maintainAspectRatio: true,
        plugins: { legend: { display: false }, tooltip: {
          backgroundColor: "#0c1822", borderColor: "#1e3a4e", borderWidth: 1,
          titleFont: { family: "IBM Plex Mono", size: 11 },
          bodyFont: { family: "IBM Plex Mono", size: 11 },
        }},
      },
    });
  }

  /* ---------- Brand chart ---------- */
  async function refreshBrands() {
    const data = await fetch("/api/charts/brands?hours=168").then(r => r.json());
    const box = document.getElementById("brand-chart");
    if (!data.length) {
      box.innerHTML = `<div class="stream-empty">NO IMPERSONATION DETECTED</div>`;
      return;
    }
    const max = Math.max(...data.map(d => d.count));
    box.innerHTML = data.map(d => {
      const pct = (d.count / max * 100).toFixed(1);
      return `
        <div class="brand-row">
          <span class="brand-name">${esc(d.brand)}</span>
          <div class="brand-bar"><span style="width:${pct}%"></span></div>
          <span class="brand-count">${fmt.format(d.count)}</span>
        </div>`;
    }).join("");
  }

  /* ---------- Detector chart ---------- */
  async function refreshDetectors() {
    const data = await fetch("/api/charts/detectors?hours=168").then(r => r.json());
    const box = document.getElementById("detector-chart");
    if (!data.length) { box.innerHTML = `<div class="stream-empty">NO DETECTIONS YET</div>`; return; }
    const max = Math.max(...data.map(d => d.total_weight));
    box.innerHTML = data.slice(0, 9).map((d, idx) => {
      const pct = (d.total_weight / max * 100).toFixed(1);
      return `
        <div class="bar-row rank-${Math.min(idx, 2)}">
          <span class="label">${esc(d.detector)}</span>
          <div class="track"><span style="width:${pct}%"></span></div>
          <span class="value">${d.total_weight.toFixed(2)}</span>
        </div>`;
    }).join("");
  }

  /* ---------- Timeline ---------- */
  let timelineChart;
  async function refreshTimeline() {
    const hours = Math.min(state.hours, 168);
    const data = await fetch(`/api/charts/timeline?hours=${hours}`).then(r => r.json());
    const labels = data.map(d => d.bucket.slice(-5));
    const totals = data.map(d => d.total);
    const phishing = data.map(d => d.phishing);
    const suspicious = data.map(d => d.suspicious);

    const ctx = document.getElementById("chart-timeline");
    if (timelineChart) timelineChart.destroy();
    timelineChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [
          { label: "Benign",     data: totals.map((t, i) => t - phishing[i] - suspicious[i]),
            backgroundColor: PALETTE.benign, stack: "a" },
          { label: "Suspicious", data: suspicious, backgroundColor: PALETTE.suspicious, stack: "a" },
          { label: "Phishing",   data: phishing,   backgroundColor: PALETTE.phishing,   stack: "a" },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        scales: {
          x: { stacked: true, grid: { color: PALETTE.grid }, ticks: { color: PALETTE.inkLo, font: { family: "IBM Plex Mono", size: 10 }, maxRotation: 0 } },
          y: { stacked: true, grid: { color: PALETTE.grid }, ticks: { color: PALETTE.inkLo, font: { family: "IBM Plex Mono", size: 10 } } },
        },
        plugins: {
          legend: { labels: { color: PALETTE.ink, font: { family: "IBM Plex Mono", size: 11 } } },
          tooltip: {
            backgroundColor: "#0c1822", borderColor: "#1e3a4e", borderWidth: 1,
            titleFont: { family: "IBM Plex Mono", size: 11 },
            bodyFont: { family: "IBM Plex Mono", size: 11 },
          },
        },
      },
    });
  }

  /* ---------- MITRE ---------- */
  async function refreshMitre() {
    const data = await fetch("/api/charts/mitre?hours=720").then(r => r.json());
    const box = document.getElementById("mitre-chart");
    if (!data.length) { box.innerHTML = `<div class="stream-empty">NO TECHNIQUES OBSERVED</div>`; return; }
    box.innerHTML = data.map(d => `
      <div class="mitre-cell">
        <div class="mitre-id">${esc(d.technique)}</div>
        <div class="mitre-name">${esc(d.name)}</div>
        <div class="mitre-count">${fmt.format(d.count)} incident${d.count === 1 ? "" : "s"}</div>
      </div>
    `).join("");
  }

  /* ---------- IOC velocity ---------- */
  async function refreshIoc() {
    const data = await fetch("/api/charts/ioc-velocity?hours=24").then(r => r.json());
    const box = document.getElementById("ioc-chart");
    if (!data.length) { box.innerHTML = `<div class="stream-empty">NO INDICATORS EMITTED</div>`; return; }
    const max = Math.max(...data.map(d => d.count));
    box.innerHTML = data.map((d, idx) => {
      const pct = (d.count / max * 100).toFixed(1);
      return `
        <div class="bar-row rank-${Math.min(idx, 2)}">
          <span class="label">${esc(d.type)}</span>
          <div class="track"><span style="width:${pct}%"></span></div>
          <span class="value">${fmt.format(d.count)}</span>
        </div>`;
    }).join("");
  }

  /* ---------- Modal drill-down ---------- */
  const modal = document.getElementById("modal");
  modal.querySelectorAll("[data-close]").forEach(el => el.addEventListener("click", closeModal));
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

  async function openIncident(id) {
    const body = document.getElementById("modal-body");
    body.innerHTML = `<div class="stream-empty">Loading…</div>`;
    modal.classList.add("open");
    try {
      const html = await fetch(`/incidents/${id}`).then(r => r.text());
      // Extract main content from the detail page
      const doc = new DOMParser().parseFromString(html, "text/html");
      const wrap = doc.querySelector(".detail-wrap");
      if (wrap) {
        const fpBtn = `<button class="fp-toggle" id="fp-toggle" data-id="${id}">Toggle false positive</button>`;
        body.innerHTML = wrap.innerHTML + fpBtn;
        body.querySelector(".back")?.remove();
        document.getElementById("modal-title").textContent =
          body.querySelector(".detail-head h1")?.textContent || `Incident #${id}`;
        document.getElementById("fp-toggle").addEventListener("click", () => toggleFp(id));
      } else {
        body.innerHTML = `<div class="stream-empty">Unable to load.</div>`;
      }
    } catch (e) {
      body.innerHTML = `<div class="stream-empty">Error loading incident.</div>`;
    }
  }
  function closeModal() { modal.classList.remove("open"); }

  async function toggleFp(id) {
    await fetch(`/api/incidents/${id}/false-positive`, { method: "POST" });
    closeModal();
    refreshStream();
    refreshKPIs();
  }

  /* ---------- escape helper ---------- */
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  /* ---------- orchestrate ---------- */
  function refreshAll() {
    refreshKPIs(); refreshStream(); refreshVerdicts();
    refreshBrands(); refreshDetectors(); refreshTimeline();
    refreshMitre(); refreshIoc();
  }
  refreshAll();
  setInterval(refreshKPIs,   30_000);
  setInterval(refreshStream, 30_000);
  setInterval(refreshVerdicts, 60_000);
  setInterval(refreshTimeline, 60_000);
})();
