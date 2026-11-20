/* ==========================================================================
   WEB-XPLOIT // CYBER COMMAND COCKPIT CONTROLLER v2.2.1
   Non-blocking Event Stream & Multi-Task Responsive Hub
   ========================================================================== */

window.__WIRED_INITIALIZED__ = true;

const $ = (id) => document.getElementById(id);

// Central Application State
const state = {
  activePage: "recon",
  target: {
    host: "localhost",
    port: 3306,
    service: "mysql",
    is_cdn: false,
    discoveredPorts: 0,
  },
  allAttacks: {},
  currentCategory: "all",
  terminalLines: [],
  activeFilter: "all",
  autoScroll: true,
  isBusy: false,
  downloads: {},
};

/* ==========================================================================
   APPLICATION ENTRYPOINT
   ========================================================================== */
function bootApp() {
  initWiredIntro();
  initNavigation();
  initTargetManagement();
  initScanner();
  initAttacksSuite();
  initDirMapper();
  initOriginResolver();
  initTerminal();
  initDownloadsExplorer();
  initSystemInfo();
  connectEventStream();
  updateTelemetry();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootApp);
} else {
  bootApp();
}

/* ==========================================================================
   1. TELEMETRY & HUD METRICS
   ========================================================================== */
function updateTelemetry() {
  const host = state.target.host || "localhost";
  
  if ($("hudTargetVal")) $("hudTargetVal").textContent = host;
  if ($("reconHostInput") && $("reconHostInput").value !== host) {
    $("reconHostInput").value = host;
  }
  if ($("dirmapUrlInput") && !$("dirmapUrlInput").value) {
    $("dirmapUrlInput").value = `http://${host}`;
  }
  if ($("originDomainInput") && !$("originDomainInput").value) {
    $("originDomainInput").value = host;
  }

  if ($("statTargetVal")) $("statTargetVal").textContent = host;
  if ($("statTargetStatus")) {
    $("statTargetStatus").textContent = state.isBusy ? "SCANNING / BUSY" : "ONLINE / READY";
    $("statTargetStatus").style.color = state.isBusy ? "var(--red)" : "var(--green)";
  }

  if ($("statCdnVal")) {
    $("statCdnVal").textContent = state.target.is_cdn ? "CLOUDFLARE WAF" : "DIRECT TARGET";
    $("statCdnVal").style.color = state.target.is_cdn ? "var(--amber)" : "var(--cyan)";
  }

  if ($("statPortsVal")) {
    $("statPortsVal").textContent = `${state.target.discoveredPorts} PORTS OPEN`;
  }

  if ($("statAttacksVal")) {
    $("statAttacksVal").textContent = "63 READY";
  }

  updateAttackTargetDisplay();
}

/* ==========================================================================
   2. WIRED LOADING BOOT ANIMATION
   ========================================================================== */
function initWiredIntro() {
  const loader = $("wiredLoader");
  const pBar = $("wiredProgressBar");
  const pPercent = $("wiredPercent");
  const pMsg = $("wiredStatusMsg");
  const bootLog = $("wiredBootLog");
  const btnSkip = $("btnSkipWired");
  const btnReplay = $("btnReplayWired");
  const btnReplayAbout = $("btnReplayIntroAbout");

  const bootMessages = [
    "> INITIATING WIRED PROTOCOL LINK (VERSION 2.2)...",
    "> ALLOCATING HEAP MEMORY BUFFERS: 0x00FF88 SECURE",
    "> MOUNTING KERNEL: DISPATCH TABLE (63 ATTACK MODULES)...",
    "> ESTABLISHING IP ROTATION HOOKS & HEADERS...",
    "> RESOLVING WIRED ROUTING NODE: LOCALHOST:5001",
    "> SYNAPSE COMPLETE: ALL MODULES SYNCHRONIZED.",
  ];

  let progress = 0;
  let logIdx = 0;
  let timer = null;

  function runSequence() {
    if (!loader) return;
    loader.classList.remove("fade-out");
    progress = 0;
    logIdx = 0;
    if (bootLog) bootLog.innerHTML = "";

    timer = setInterval(() => {
      progress += Math.floor(Math.random() * 10) + 6;
      if (progress > 100) progress = 100;

      if (pBar) pBar.style.width = progress + "%";
      if (pPercent) pPercent.textContent = progress + "%";

      if (progress >= 15 && logIdx === 0) appendBootLog(bootMessages[0]);
      if (progress >= 35 && logIdx === 1) appendBootLog(bootMessages[1]);
      if (progress >= 55 && logIdx === 2) appendBootLog(bootMessages[2]);
      if (progress >= 75 && logIdx === 3) appendBootLog(bootMessages[3]);
      if (progress >= 90 && logIdx === 4) appendBootLog(bootMessages[4]);
      if (progress >= 98 && logIdx === 5) {
        appendBootLog(bootMessages[5]);
        if (pMsg) pMsg.textContent = "ACCESS GRANTED. ENTERING THE WIRED...";
      }

      if (progress >= 100) {
        clearInterval(timer);
        setTimeout(() => {
          dismissLoader();
        }, 400);
      }
    }, 85);
  }

  function appendBootLog(msg) {
    if (!msg || !bootLog) return;
    const div = document.createElement("div");
    div.className = "log-item";
    div.textContent = msg;
    bootLog.appendChild(div);
    bootLog.scrollTop = bootLog.scrollHeight;
    logIdx++;
  }

  function dismissLoader() {
    if (timer) clearInterval(timer);
    if (loader) loader.classList.add("fade-out");
  }

  if (btnSkip) btnSkip.onclick = dismissLoader;
  if (btnReplay) btnReplay.onclick = runSequence;
  if (btnReplayAbout) btnReplayAbout.onclick = runSequence;

  runSequence();
}

/* ==========================================================================
   3. MULTI-PAGE NAVIGATION ROUTER
   ========================================================================== */
function initNavigation() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const page = tab.getAttribute("data-page");
      navigateToPage(page);
    });
  });
}

function navigateToPage(pageId) {
  state.activePage = pageId;

  document.querySelectorAll(".nav-tab").forEach((t) => {
    t.classList.toggle("active", t.getAttribute("data-page") === pageId);
  });

  document.querySelectorAll(".page-view").forEach((v) => {
    v.classList.toggle("active", v.id === `view-${pageId}`);
  });

  if (pageId === "attacks") {
    if (!Object.keys(state.allAttacks).length) {
      loadAttacksList();
    }
  } else if (pageId === "artifacts") {
    loadDownloadsList();
  } else if (pageId === "dirmap") {
    if ($("dirmapUrlInput") && !$("dirmapUrlInput").value) {
      $("dirmapUrlInput").value = `http://${state.target.host || "localhost"}`;
    }
  } else if (pageId === "origin") {
    if ($("originDomainInput") && !$("originDomainInput").value) {
      $("originDomainInput").value = state.target.host || "localhost";
    }
  }
}

/* ==========================================================================
   4. TARGET MANAGEMENT
   ========================================================================== */
function initTargetManagement() {
  const hostInput = $("reconHostInput");
  const btnSet = $("btnSetTarget");
  const targetChip = $("hudTargetChip");

  if (btnSet) {
    btnSet.onclick = () => {
      const val = (hostInput ? hostInput.value : "").trim();
      if (val) setTargetHost(val);
    };
  }

  if (hostInput) {
    hostInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        const val = (hostInput.value || "").trim();
        if (val) setTargetHost(val);
      }
    });
  }

  if (targetChip) {
    targetChip.onclick = () => {
      navigateToPage("recon");
      if (hostInput) {
        hostInput.focus();
        hostInput.select();
      }
    };
  }
}

function setTargetHost(h) {
  // Strip schemes if passed
  h = String(h).replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim();
  state.target.host = h;
  state.target.is_cdn = false;
  state.target.discoveredPorts = 0;
  updateTelemetry();
  appendTerminalLine(`[+] Active target set to: ${h}`, "info");
  renderDiscoveredServices([]);
}

function setHostPreset(h) {
  setTargetHost(h);
}

function updateAttackTargetDisplay() {
  const val = $("attackTargetHostVal");
  if (val) val.textContent = state.target.host || "none";
}

/* ==========================================================================
   5. RECON & PORT SCANNER
   ========================================================================== */
function initScanner() {
  const btnScan = $("btnStartScan");
  const btnOrigin = $("btnJumpOrigin");

  if (btnScan) {
    btnScan.onclick = async () => {
      const host = (state.target.host || "").trim();
      if (!host) {
        alert("Please specify a target hostname or IP.");
        return;
      }

      const profile = document.querySelector('input[name="scanProfile"]:checked')?.value || "all";
      setBusy(true, "PORT PROBE");
      btnScan.disabled = true;
      btnScan.textContent = "⏳ SCANNING PORTS...";
      appendTerminalLine(`[>] Initiating port scan on ${host} (profile: ${profile})...`, "info");

      try {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ host, profile }),
        });
        const data = await res.json();
        if (data.error) {
          appendTerminalLine(`[-] Scan error: ${data.error}`, "error");
          onTaskFinished();
        } else {
          appendTerminalLine(`[+] Port probe started in background...`, "success");
        }
      } catch (err) {
        appendTerminalLine(`[-] Failed to connect to scan server: ${err.message}`, "error");
        onTaskFinished();
      }
    };
  }

  if (btnOrigin) {
    btnOrigin.onclick = () => {
      navigateToPage("origin");
    };
  }

  renderDiscoveredServices([]);
}

function renderDiscoveredServices(targets, is_cdn = false) {
  const container = $("serviceCardsContainer");
  const badge = $("serviceCountBadge");
  const cdnAlert = $("cdnAlert");

  state.target.is_cdn = is_cdn;
  state.target.discoveredPorts = targets ? targets.length : 0;
  updateTelemetry();

  if (cdnAlert) {
    if (is_cdn) cdnAlert.classList.remove("hidden");
    else cdnAlert.classList.add("hidden");
  }

  if (badge) {
    badge.textContent = `${state.target.discoveredPorts} SERVICE${state.target.discoveredPorts === 1 ? '' : 'S'}`;
  }

  if (!container) return;

  if (!targets || !targets.length) {
    container.innerHTML = `
      <div class="empty-state">
        <span class="empty-icon">⟁</span>
        <p>Target Surface Standby: ${escapeHtml(state.target.host)}</p>
        <p class="sub-hint">Click "Probe & Scan Target" or "One-Click Full Auto Audit" to enumerate live attack vectors.</p>
        <div class="common-ports-preview">
          <div class="preview-grid">
            <div class="preview-port-chip"><strong>3306</strong><span>MySQL DB</span></div>
            <div class="preview-port-chip"><strong>80 / 443</strong><span>Web HTTP/S</span></div>
            <div class="preview-port-chip"><strong>22</strong><span>SSH Shell</span></div>
            <div class="preview-port-chip"><strong>6379</strong><span>Redis Cache</span></div>
            <div class="preview-port-chip"><strong>21</strong><span>FTP Server</span></div>
            <div class="preview-port-chip"><strong>5432</strong><span>PostgreSQL</span></div>
          </div>
        </div>
      </div>
    `;
    return;
  }

  container.innerHTML = "";
  targets.forEach((t) => {
    const card = document.createElement("div");
    card.className = "service-card";
    const ver = (t.version && t.version !== "Unknown") ? t.version : "Service online";
    const isWeb = t.service.toLowerCase().includes("http") || [80, 443, 8080, 8443, 8000, 5000].includes(t.port);

    const dirMapBtn = isWeb
      ? `<button class="btn btn-mini btn-outline" style="color: var(--cyan); border-color: var(--cyan);" onclick="window.quickDirMapService('${escapeHtml(t.service)}', ${t.port})">🔍 DIR MAP</button>`
      : "";

    card.innerHTML = `
      <div class="service-card-top">
        <span class="service-name">${escapeHtml(t.service.toUpperCase())}</span>
        <span class="service-port">PORT ${t.port}</span>
      </div>
      <div class="service-banner">${escapeHtml(ver)}</div>
      <div class="service-actions" style="display: flex; gap: 8px;">
        <button class="btn btn-mini btn-cyan" onclick="window.quickAttackService('${escapeHtml(t.service)}', ${t.port})">
          ⚔ ATTACK PORT
        </button>
        ${dirMapBtn}
      </div>
    `;
    container.appendChild(card);
  });
}

function quickDirMapService(service, port) {
  state.target.service = service;
  state.target.port = port;
  const scheme = (service.toLowerCase() === "https" || port === 443 || port === 8443) ? "https" : "http";
  const portSuffix = (port === 80 || port === 443) ? "" : `:${port}`;
  const targetUrl = `${scheme}://${state.target.host || "localhost"}${portSuffix}`;
  if ($("dirmapUrlInput")) $("dirmapUrlInput").value = targetUrl;
  navigateToPage("dirmap");
}

function quickAttackService(service, port) {
  state.target.service = service;
  state.target.port = port;
  navigateToPage("attacks");

  if (service.includes("http") || port === 80 || port === 443) {
    selectCategoryTab("web");
  } else if (service.includes("sql") || port === 3306 || port === 5432) {
    selectCategoryTab("db");
  } else if (service.includes("ssh") || service.includes("ftp")) {
    selectCategoryTab("auth");
  }
}

/* ==========================================================================
   6. EXPLOIT SUITE (63 ATTACK MODULES)
   ========================================================================== */
function initAttacksSuite() {
  const catTabs = document.querySelectorAll(".cat-tab");
  catTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const cat = tab.getAttribute("data-cat");
      selectCategoryTab(cat);
    });
  });

  const searchInput = $("attackSearchInput");
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      renderAttacksList();
    });
  }

  loadAttacksList();
}

function selectCategoryTab(cat) {
  state.currentCategory = cat;
  document.querySelectorAll(".cat-tab").forEach((t) => {
    t.classList.toggle("active", t.getAttribute("data-cat") === cat);
  });
  renderAttacksList();
}

async function loadAttacksList() {
  try {
    const res = await fetch("/api/all_attacks");
    const data = await res.json();
    state.allAttacks = data.categories || {};
    renderAttacksList();
  } catch (err) {
    appendTerminalLine(`[-] Failed to load exploit catalog: ${err.message}`, "error");
  }
}

function renderAttacksList() {
  const container = $("attacksCardsGrid");
  if (!container) return;

  const query = ($("attackSearchInput")?.value || "").toLowerCase().trim();
  container.innerHTML = "";

  let count = 0;
  Object.keys(state.allAttacks).forEach((catKey) => {
    if (state.currentCategory !== "all" && state.currentCategory !== catKey) return;

    const catObj = state.allAttacks[catKey];
    const items = catObj.items || catObj.attacks || [];
    items.forEach((item) => {
      const name = item.name || item.label || "";
      const id = item.id || item.value || "";
      const desc = item.desc || item.brief || "";

      if (query && !name.toLowerCase().includes(query) && !desc.toLowerCase().includes(query) && !id.toLowerCase().includes(query)) {
        return;
      }

      count++;
      const card = document.createElement("div");
      card.className = "attack-card";

      const sev = item.severity || "Exploit";
      const badgeClass = sev === "Critical" ? "badge-red" : sev === "High" ? "badge-amber" : "badge-cyan";

      card.innerHTML = `
        <div class="attack-card-header">
          <span class="attack-name">${escapeHtml(name)}</span>
          <span class="badge ${badgeClass}">${escapeHtml(sev)}</span>
        </div>
        <p class="attack-desc">${escapeHtml(desc || "Web-Xploit payload module")}</p>
        <div class="attack-meta">
          <span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-muted);">${escapeHtml(id)}</span>
          <button class="btn btn-mini btn-outline" onclick="window.openAttackModal('${escapeHtml(id)}', '${escapeHtml(name)}')">
            CONFIGURE & RUN ❯
          </button>
        </div>
      `;
      container.appendChild(card);
    });
  });

  if (count === 0) {
    container.innerHTML = '<p class="hint text-center" style="grid-column: 1/-1; padding: 30px;">No exploits match your search filter.</p>';
  }
}

let currentSelectedAttack = null;

function openAttackModal(attackId, attackName) {
  currentSelectedAttack = attackId;
  const modal = $("attackModal");
  if (!modal) return;

  if ($("modalAttackTitle")) $("modalAttackTitle").textContent = `LAUNCH EXPLOIT: ${attackName}`;
  if ($("modalTargetHost")) $("modalTargetHost").value = state.target.host || "localhost";
  if ($("modalTargetPort")) $("modalTargetPort").value = state.target.port || 3306;
  if ($("modalTargetService")) $("modalTargetService").value = state.target.service || "mysql";

  modal.classList.remove("hidden");
}

function closeAttackModal() {
  const modal = $("attackModal");
  if (modal) modal.classList.add("hidden");
  currentSelectedAttack = null;
}

async function executeModalAttack() {
  if (!currentSelectedAttack) return;

  const host = ($("modalTargetHost")?.value || state.target.host || "localhost").trim();
  const port = parseInt($("modalTargetPort")?.value || "0");
  const service = ($("modalTargetService")?.value || "http").trim();
  const httpPath = ($("modalHttpPath")?.value || "").trim();
  const customParam = ($("modalCustomParam")?.value || "").trim();

  closeAttackModal();
  setBusy(true, currentSelectedAttack.toUpperCase());
  appendTerminalLine(`\n[>] EXECUTING EXPLOIT: ${currentSelectedAttack} → ${host}:${port}`, "info");

  try {
    const res = await fetch("/api/attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        host,
        port,
        service,
        attack: currentSelectedAttack,
        config: {
          http_path: httpPath,
          http_params: customParam,
        },
      }),
    });
    const data = await res.json();
    if (data.error) {
      appendTerminalLine(`[-] Exploit execution failed: ${data.error}`, "error");
      onTaskFinished();
    } else {
      appendTerminalLine(`[+] Exploit worker running. Streaming live telemetry...`, "success");
    }
  } catch (err) {
    appendTerminalLine(`[-] Attack error: ${err.message}`, "error");
    onTaskFinished();
  }
}

/* ==========================================================================
   7. DIRECTORY MAPPER (SPIDER)
   ========================================================================== */
function initDirMapper() {
  const btnStart = $("btnStartDirMap");
  if (!btnStart) return;

  btnStart.onclick = async () => {
    let url = ($("dirmapUrlInput")?.value || "").trim();
    if (!url) {
      url = `http://${state.target.host || "localhost"}`;
      if ($("dirmapUrlInput")) $("dirmapUrlInput").value = url;
    }

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = `http://${url}`;
      if ($("dirmapUrlInput")) $("dirmapUrlInput").value = url;
    }

    const wordlist = $("dirmapWordlistSelect")?.value || "directories.txt";
    setBusy(true, "DIR MAP");
    btnStart.disabled = true;
    btnStart.textContent = "⏳ SCANNING ENDPOINTS...";

    const tbody = $("dirmapHitsBody");
    if (tbody) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-center" style="padding: 24px; color: var(--cyan);">🔍 Directory brute-force in progress... Streaming live hits...</td></tr>';
    }

    appendTerminalLine(`[>] Starting directory mapper on ${url} (wordlist: ${wordlist}) ...`, "info");

    try {
      const res = await fetch("/api/dir_map", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, wordlist }),
      });
      const data = await res.json();
      if (data.error) {
        appendTerminalLine(`[-] Dir mapper error: ${data.error}`, "error");
        onTaskFinished();
      } else {
        appendTerminalLine(`[+] Dir mapper initiated on ${data.url || url}. Probing attack surface...`, "info");
      }
    } catch (err) {
      appendTerminalLine(`[-] Failed to launch dir mapper: ${err.message}`, "error");
      onTaskFinished();
    }
  };
}

function appendSingleDirMapHit(hit) {
  const tbody = $("dirmapHitsBody");
  const countBadge = $("dirmapCountBadge");
  if (!tbody || !hit) return;

  // Clear initial placeholder row if present
  if (tbody.querySelector("td[colspan]")) {
    tbody.innerHTML = "";
  }

  const status = hit.status || 200;
  const tagClass = status >= 200 && status < 300 ? "ok" : status >= 300 && status < 400 ? "redirect" : status === 403 ? "warn" : "error";

  let displayPath = hit.path || "";
  if (!displayPath && hit.url) {
    try {
      const u = new URL(hit.url);
      displayPath = u.pathname + (u.search || "");
    } catch (e) {
      displayPath = hit.url;
    }
  }

  const displaySize = hit.length != null ? `${hit.length} B` : (hit.size != null ? `${hit.size} B` : "-");
  const directUrl = hit.url || hit.path || "#";
  const titleInfo = hit.title ? ` <span style="color:var(--text-dim);font-size:11px;">[${escapeHtml(hit.title)}]</span>` : "";
  const redirInfo = hit.redirect ? ` <span style="color:var(--cyan);font-size:11px;">${escapeHtml(hit.redirect)}</span>` : "";

  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td><span class="status-tag ${tagClass}">${status}</span></td>
    <td><strong>${escapeHtml(displayPath)}</strong>${titleInfo}${redirInfo}</td>
    <td>${displaySize}</td>
    <td><a href="${escapeHtml(directUrl)}" target="_blank" class="dock-link">OPEN ↗</a></td>
  `;
  tbody.appendChild(tr);

  const currentCount = tbody.querySelectorAll("tr").length;
  if (countBadge) countBadge.textContent = `${currentCount} FOUND`;
}

function renderDirMapHits(hits) {
  const tbody = $("dirmapHitsBody");
  const countBadge = $("dirmapCountBadge");
  if (!tbody) return;

  tbody.innerHTML = "";
  if (countBadge) countBadge.textContent = `${hits ? hits.length : 0} FOUND`;

  if (!hits || !hits.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="text-center" style="padding: 20px;">No endpoints discovered.</td></tr>';
    return;
  }

  hits.forEach((hit) => {
    const tr = document.createElement("tr");
    const status = hit.status || 200;
    const tagClass = status >= 200 && status < 300 ? "ok" : status >= 300 && status < 400 ? "redirect" : status === 403 ? "warn" : "error";

    let displayPath = hit.path || "";
    if (!displayPath && hit.url) {
      try {
        const u = new URL(hit.url);
        displayPath = u.pathname + (u.search || "");
      } catch (e) {
        displayPath = hit.url;
      }
    }
    const displaySize = hit.length != null ? `${hit.length} B` : (hit.size != null ? `${hit.size} B` : "-");
    const directUrl = hit.url || hit.path || "#";
    const titleInfo = hit.title ? ` <span style="color:var(--text-dim);font-size:11px;">[${escapeHtml(hit.title)}]</span>` : "";
    const redirInfo = hit.redirect ? ` <span style="color:var(--cyan);font-size:11px;">${escapeHtml(hit.redirect)}</span>` : "";

    tr.innerHTML = `
      <td><span class="status-tag ${tagClass}">${status}</span></td>
      <td><strong>${escapeHtml(displayPath)}</strong>${titleInfo}${redirInfo}</td>
      <td>${displaySize}</td>
      <td><a href="${escapeHtml(directUrl)}" target="_blank" class="dock-link">OPEN ↗</a></td>
    `;
    tbody.appendChild(tr);
  });
}

/* ==========================================================================
   8. CDN BYPASS & ORIGIN RESOLVER
   ========================================================================== */
function initOriginResolver() {
  const btnRun = $("btnStartOriginResolve");
  if (!btnRun) return;

  btnRun.onclick = async () => {
    let domain = ($("originDomainInput")?.value || state.target.host || "").trim();
    domain = domain.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0];
    if (!domain) {
      alert("Please provide a domain to bypass CDN.");
      return;
    }

    setBusy(true, "ORIGIN RESOLVER");
    btnRun.disabled = true;
    btnRun.textContent = "⏳ RESOLVING ORIGIN...";
    appendTerminalLine(`[>] Initiating CDN Origin Bypass against: ${domain}`, "info");

    try {
      const res = await fetch("/api/origin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      const data = await res.json();
      if (data.error) {
        appendTerminalLine(`[-] Origin resolver error: ${data.error}`, "error");
        onTaskFinished();
      }
    } catch (err) {
      appendTerminalLine(`[-] Origin bypass error: ${err.message}`, "error");
      onTaskFinished();
    }
  };
}

function renderOriginCandidates(candidates, edgeIp) {
  const container = $("originCandidatesContainer");
  if ($("originEdgeIpDisplay")) {
    $("originEdgeIpDisplay").textContent = edgeIp || "104.21.x.x (Proxied)";
  }

  if (!container) return;
  container.innerHTML = "";

  if (!candidates || !candidates.length) {
    container.innerHTML = '<p class="hint">No origin backend leaked via DNS history or subdomains.</p>';
    return;
  }

  const best = candidates[0];
  if ($("originRealIpDisplay")) {
    $("originRealIpDisplay").textContent = best.ip;
  }

  candidates.forEach((c) => {
    const div = document.createElement("div");
    div.className = "service-card";
    div.innerHTML = `
      <div class="service-card-top">
        <span class="service-name">${escapeHtml(c.method || "DNS Leak")}</span>
        <span class="service-port">${escapeHtml(c.ip)}</span>
      </div>
      <p class="sub-hint">${escapeHtml(c.domain || "")}</p>
      <button class="btn btn-mini btn-cyan mt-2" onclick="window.setOriginAsTarget('${escapeHtml(c.ip)}')">
        ✓ USE AS ATTACK TARGET
      </button>
    `;
    container.appendChild(div);
  });
}

function setOriginAsTarget(ip) {
  setTargetHost(ip);
  navigateToPage("recon");
  appendTerminalLine(`[✓] Target switched to real backend origin IP: ${ip}`, "success");
}

/* ==========================================================================
   9. LIVE CONSOLE & STREAMING
   ========================================================================== */
function initTerminal() {
  const cmdInput = $("terminalCommandInput");
  if (cmdInput) {
    cmdInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        const cmd = (cmdInput.value || "").trim();
        cmdInput.value = "";
        if (cmd) executeTerminalCommand(cmd);
      }
    });
  }

  document.querySelectorAll(".filter-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      state.activeFilter = pill.getAttribute("data-filter");
      renderTerminal();
    });
  });
}

function executeTerminalCommand(cmd) {
  appendTerminalLine(`web-xploit@wired:~$ ${cmd}`, "info");
  const parts = cmd.split(" ");
  const action = parts[0].toLowerCase();

  if (action === "help") {
    appendTerminalLine("Available commands:\n  target <host>     - Set active target\n  scan              - Run port scan\n  fullauto          - Launch One-Click Full Auto Audit\n  clear             - Clear terminal\n  downloads         - Open artifacts explorer", "system");
  } else if (action === "clear") {
    state.terminalLines = [];
    renderTerminal();
  } else if (action === "target" && parts[1]) {
    setTargetHost(parts[1]);
  } else if (action === "fullauto") {
    triggerFullAutoShortcut();
  } else if (action === "downloads") {
    navigateToPage("artifacts");
  } else {
    appendTerminalLine(`Unknown command: ${action}. Type 'help' for commands.`, "warn");
  }
}

function appendTerminalLine(text, level = "info") {
  const lineObj = {
    text: String(text),
    level,
    timestamp: new Date().toLocaleTimeString(),
  };

  state.terminalLines.push(lineObj);
  if (state.terminalLines.length > 500) {
    state.terminalLines.shift();
  }

  const reconOutput = $("reconTerminalOutput");
  const dirmapOutput = $("dirmapTerminalOutput");
  const originOutput = $("originTerminalOutput");
  const fullOutput = $("terminalOutput");

  [reconOutput, dirmapOutput, originOutput, fullOutput].forEach((container) => {
    if (!container) return;
    const div = document.createElement("div");
    div.className = `line ${level}`;
    div.textContent = text;
    container.appendChild(div);
    if (state.autoScroll) {
      container.scrollTop = container.scrollHeight;
    }
  });
}

function renderTerminal() {
  const fullOutput = $("terminalOutput");
  const reconOutput = $("reconTerminalOutput");
  const dirmapOutput = $("dirmapTerminalOutput");
  const originOutput = $("originTerminalOutput");

  [fullOutput, reconOutput, dirmapOutput, originOutput].forEach((container) => {
    if (!container) return;
    container.innerHTML = "";
    state.terminalLines.forEach((l) => {
      if (state.activeFilter !== "all" && l.level !== state.activeFilter) return;
      const div = document.createElement("div");
      div.className = `line ${l.level}`;
      div.textContent = l.text;
      container.appendChild(div);
    });
    if (state.autoScroll) {
      container.scrollTop = container.scrollHeight;
    }
  });
}

function triggerFullAutoShortcut() {
  const host = (state.target.host || "localhost").trim();
  const btnAuto = $("btnQuickFullAuto");
  if (btnAuto) {
    btnAuto.textContent = "⚡ RUNNING FULL AUTO AUDIT...";
    btnAuto.disabled = true;
  }

  setBusy(true, "FULL AUTO AUDIT");
  appendTerminalLine(`\n[⚡] LAUNCHING ONE-CLICK FULL AUTO AUDIT ON: ${host}`, "success");
  appendTerminalLine("[*] Running parallel port scans, SQLi fuzzing, web spider, & credential spray...", "info");

  fetch("/api/attack", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      host,
      attack: "full_auto",
    }),
  }).catch((err) => {
    appendTerminalLine(`[-] Failed to start full auto audit: ${err.message}`, "error");
    onTaskFinished();
  });
}

function setBusy(busy, label = "") {
  state.isBusy = busy;
  const statusDot = $("statusDot");
  const statusText = $("statusText");
  const bottomDot = $("bottomPulseDot");
  const bottomMsg = $("bottomDockMsg");

  if (busy) {
    if (statusDot) statusDot.style.background = "var(--red)";
    if (statusText) statusText.textContent = label || "BUSY";
    if (bottomDot) bottomDot.style.background = "var(--red)";
    if (bottomMsg) bottomMsg.textContent = `SYSTEM ACTIVE: ${label}`;
  } else {
    if (statusDot) statusDot.style.background = "var(--green)";
    if (statusText) statusText.textContent = "IDLE";
    if (bottomDot) bottomDot.style.background = "var(--green)";
    if (bottomMsg) bottomMsg.textContent = "SYSTEM IDLE // THE WIRED PROTOCOL STANDBY";
  }

  updateTelemetry();
}

function onTaskFinished() {
  setBusy(false);
  const btnScan = $("btnStartScan");
  if (btnScan) {
    btnScan.disabled = false;
    btnScan.textContent = "⟁ PROBE & SCAN TARGET";
  }

  const btnAuto = $("btnQuickFullAuto");
  if (btnAuto) {
    btnAuto.disabled = false;
    btnAuto.textContent = "⚡ ONE-CLICK FULL AUTO AUDIT";
  }

  const btnDir = $("btnStartDirMap");
  if (btnDir) {
    btnDir.disabled = false;
    btnDir.textContent = "🔍 LAUNCH DIRECTORY SPIDER";
  }

  const btnOrigin = $("btnStartOriginResolve");
  if (btnOrigin) {
    btnOrigin.disabled = false;
    btnOrigin.textContent = "🛡 DISCOVER REAL ORIGIN IP";
  }
}

/* ==========================================================================
   10. SSE REAL-TIME EVENT STREAM (SINGLETON)
   ========================================================================== */
function connectEventStream() {
  if (window.__wiredEventSource) {
    try {
      window.__wiredEventSource.close();
    } catch (e) {}
  }

  const source = new EventSource("/stream");
  window.__wiredEventSource = source;

  source.onopen = () => {
    appendTerminalLine("[✓] Connected to live kernel event stream.", "system");
  };

  source.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === "log" || data.line) {
        const line = data.line || data.msg || "";
        if (line === "__END__") {
          onTaskFinished();
          appendTerminalLine("[✓] Task execution completed.", "success");
          return;
        }
        appendTerminalLine(line, data.level || "info");
      } else if (data.type === "result") {
        if (data.kind === "scan") {
          onTaskFinished();
          renderDiscoveredServices(data.data.targets || [], data.data.is_cdn || false);
        } else if (data.kind === "dir_hit") {
          appendSingleDirMapHit(data.data);
        } else if (data.kind === "dir_map") {
          onTaskFinished();
          renderDirMapHits(data.data.hits || []);
        } else if (data.kind === "origin") {
          onTaskFinished();
          renderOriginCandidates(data.data.candidates || [], data.data.edge_ip || "");
        } else {
          onTaskFinished();
        }
      } else if (data.type === "end") {
        onTaskFinished();
      }
    } catch (e) {
      if (event.data && typeof event.data === "string") {
        appendTerminalLine(event.data, "info");
      }
    }
  };

  source.onerror = () => {
    // Native browser EventSource will automatically handle reconnection.
    // We do NOT create extra instances here to avoid socket exhaustion.
  };
}

/* ==========================================================================
   11. ARTIFACTS & DUMPS EXPLORER
   ========================================================================== */
let allDownloadsData = {};
let currentDownloadHost = "";
let currentDownloadSubdir = "all";

async function initDownloadsExplorer() {
  const hostSelect = $("dlHostSelect");
  const subtabs = document.querySelectorAll(".dl-subtab");
  const btnRefresh = $("btnRefreshDownloads");
  const btnCopyFile = $("btnCopyFileContent");
  const btnDlRaw = $("btnDownloadRawFile");

  if (btnRefresh) btnRefresh.onclick = loadDownloadsList;

  if (hostSelect) {
    hostSelect.onchange = () => {
      currentDownloadHost = hostSelect.value;
      renderDownloadsFiles();
    };
  }

  subtabs.forEach((tab) => {
    tab.onclick = () => {
      subtabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      currentDownloadSubdir = tab.getAttribute("data-sub");
      renderDownloadsFiles();
    };
  });

  if (btnCopyFile) {
    btnCopyFile.onclick = () => {
      const text = $("fileViewerCode").textContent;
      navigator.clipboard.writeText(text).then(() => {
        appendTerminalLine("[✓] File contents copied to clipboard.", "success");
      });
    };
  }

  if (btnDlRaw) {
    btnDlRaw.onclick = () => {
      const activePath = btnDlRaw.getAttribute("data-path");
      if (activePath) {
        window.open(`/api/download_raw?path=${encodeURIComponent(activePath)}`, "_blank");
      }
    };
  }

  await loadDownloadsList();
}

async function loadDownloadsList() {
  try {
    const res = await fetch("/api/downloads");
    const data = await res.json();
    allDownloadsData = data.downloads || {};

    const hostSelect = $("dlHostSelect");
    if (!hostSelect) return;

    hostSelect.innerHTML = "";
    const hosts = Object.keys(allDownloadsData);
    if (!hosts.length) {
      hostSelect.innerHTML = '<option value="">No targets found</option>';
      if ($("dlFilesList")) $("dlFilesList").innerHTML = '<p class="hint">No downloaded artifacts or dumps yet.</p>';
      return;
    }

    hosts.forEach((h) => {
      const opt = document.createElement("option");
      opt.value = h;
      opt.textContent = `${h} (${allDownloadsData[h].length} files)`;
      hostSelect.appendChild(opt);
    });

    if (hosts.includes(state.target.host)) {
      hostSelect.value = state.target.host;
    } else {
      hostSelect.value = hosts[0];
    }
    currentDownloadHost = hostSelect.value;
    renderDownloadsFiles();
  } catch (err) {}
}

function renderDownloadsFiles() {
  const container = $("dlFilesList");
  if (!container) return;
  container.innerHTML = "";

  const files = allDownloadsData[currentDownloadHost] || [];
  let filtered = files;
  if (currentDownloadSubdir !== "all") {
    filtered = files.filter((f) => f.subdir === currentDownloadSubdir);
  }

  if ($("dlFileCountBadge")) {
    $("dlFileCountBadge").textContent = `${filtered.length} FILE${filtered.length === 1 ? '' : 'S'}`;
  }

  if (!filtered.length) {
    container.innerHTML = '<p class="hint text-center" style="padding: 20px;">No files in this category.</p>';
    return;
  }

  filtered.forEach((file) => {
    const item = document.createElement("div");
    item.className = "dl-file-item";
    const kb = (file.size / 1024).toFixed(1);
    const icon = file.name.endsWith(".json") ? "📋" : file.name.endsWith(".log") ? "📄" : "⚡";

    item.innerHTML = `
      <div class="dl-file-meta">
        <span class="dl-file-icon">${icon}</span>
        <div>
          <div class="dl-file-name" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</div>
          <div class="dl-file-sub">${escapeHtml(file.subdir || 'root')} • ${kb} KB • ${escapeHtml(file.modified)}</div>
        </div>
      </div>
    `;
    item.onclick = () => {
      document.querySelectorAll(".dl-file-item").forEach((el) => el.classList.remove("active"));
      item.classList.add("active");
      viewDownloadFile(file);
    };
    container.appendChild(item);
  });

  if (filtered.length > 0) {
    container.firstElementChild.click();
  }
}

async function viewDownloadFile(file) {
  if ($("activeFileName")) $("activeFileName").textContent = file.name;
  if ($("activeFilePath")) $("activeFilePath").textContent = `downloads/${file.path}`;
  if ($("activeFileSize")) $("activeFileSize").textContent = `${(file.size / 1024).toFixed(1)} KB`;
  if ($("btnDownloadRawFile")) $("btnDownloadRawFile").setAttribute("data-path", file.path);
  if ($("fileViewerCode")) $("fileViewerCode").textContent = "Loading file content...";

  try {
    const res = await fetch(`/api/file_content?path=${encodeURIComponent(file.path)}`);
    const data = await res.json();
    if (data.error) {
      if ($("fileViewerCode")) $("fileViewerCode").textContent = `[Error loading file: ${data.error}]`;
      return;
    }

    let text = data.content || "";
    if (file.name.endsWith(".json")) {
      try {
        const parsed = JSON.parse(text);
        text = JSON.stringify(parsed, null, 2);
      } catch (e) {}
    }

    if ($("fileViewerCode")) $("fileViewerCode").textContent = text;
  } catch (err) {
    if ($("fileViewerCode")) $("fileViewerCode").textContent = `[Network error: ${err.message}]`;
  }
}

/* ==========================================================================
   12. SYSTEM INFO
   ========================================================================== */
async function initSystemInfo() {
  try {
    const res = await fetch("/api/system_info");
    const data = await res.json();
    if ($("sysInfoLoadedModules")) {
      $("sysInfoLoadedModules").textContent = `${data.loaded_modules || 63} Core Attack Modules`;
    }
  } catch (e) {}
}

function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/* ==========================================================================
   13. GLOBAL WINDOW BINDINGS (CRITICAL FOR INLINE ONCLICK HANDLERS)
   ========================================================================== */
window.navigateToPage = navigateToPage;
window.setTargetHost = setTargetHost;
window.setHostPreset = setHostPreset;
window.triggerFullAutoShortcut = triggerFullAutoShortcut;
window.quickAttackService = quickAttackService;
window.quickDirMapService = quickDirMapService;
window.selectCategoryTab = selectCategoryTab;
window.openAttackModal = openAttackModal;
window.closeAttackModal = closeAttackModal;
window.executeModalAttack = executeModalAttack;
window.setOriginAsTarget = setOriginAsTarget;
window.loadDownloadsList = loadDownloadsList;
window.viewDownloadFile = viewDownloadFile;
window.executeTerminalCommand = executeTerminalCommand;
