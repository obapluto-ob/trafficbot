"use strict";

const form = document.querySelector("#audit-form");
const input = document.querySelector("#site-url");
const button = document.querySelector("#submit-button");
const sessionButton = document.querySelector("#session-button");
const browserToggle = document.querySelector("#browser-mode");
const message = document.querySelector("#message");
const report = document.querySelector("#report");
const cookieToggle = document.querySelector("#cookie-toggle");
const cookiePanel = document.querySelector("#cookie-panel");
const cookieInput = document.querySelector("#cookie-input");
const cookieGetBtn = document.querySelector("#cookie-get-btn");
const cookieSessionBtn = document.querySelector("#cookie-session-btn");

function syncCookiePanelBtns() {
  const hasCookies = cookieInput.value.trim().length > 0;
  cookieGetBtn.hidden = hasCookies;
  cookieSessionBtn.hidden = !hasCookies;
}
cookieInput.addEventListener("input", syncCookiePanelBtns);
cookieSessionBtn.addEventListener("click", () => {
  const url = getUrl();
  if (!url) return;
  openSession(url);
});

cookieToggle.addEventListener("click", () => {
  const open = cookiePanel.hidden;
  cookiePanel.hidden = !open;
  cookieToggle.setAttribute("aria-expanded", String(open));
  const arrow = cookieToggle.querySelector(".cookie-arrow");
  if (arrow) arrow.textContent = open ? "\u25b4" : "\u25be";
});

// Auto-fill cookies from extension/bookmarklet via ?cookies= param or sessionStorage
const _qp = new URLSearchParams(location.search);
if (_qp.has("cookies")) {
  const val = decodeURIComponent(_qp.get("cookies"));
  cookieInput.value = val;
  const dom = _qp.get("domain");
  if (dom && !input.value.trim()) input.value = dom;
  cookiePanel.hidden = false;
  cookieToggle.setAttribute("aria-expanded", "true");
  const arrow = cookieToggle.querySelector(".cookie-arrow");
  if (arrow) arrow.textContent = "\u25b4";
  history.replaceState(null, "", "/");
  cookieInput.scrollIntoView({ behavior: "smooth", block: "nearest" });
  syncCookiePanelBtns();
} else if (_qp.has("ngrok-skip-browser-warning")) {
  history.replaceState(null, "", "/");
} else {
  const savedCookies = sessionStorage.getItem("ss_cookies");
  if (savedCookies) {
    cookieInput.value = savedCookies;
    const savedObjects = sessionStorage.getItem("ss_cookie_objects");
    if (savedObjects) { cookieInput.dataset.objects = savedObjects; sessionStorage.removeItem("ss_cookie_objects"); }
    else delete cookieInput.dataset.objects;
    cookiePanel.hidden = false;
    cookieToggle.setAttribute("aria-expanded", "true");
    const arrow = cookieToggle.querySelector(".cookie-arrow");
    if (arrow) arrow.textContent = "\u25b4";
    sessionStorage.removeItem("ss_cookies");
    const savedUrl = sessionStorage.getItem("ss_cookie_url");
    let launchUrl = null;
    if (savedUrl) {
      try {
        const u = new URL(savedUrl);
        if (!input.value.trim()) input.value = u.hostname;
        launchUrl = u.toString();
      } catch {}
      sessionStorage.removeItem("ss_cookie_url");
    }
    syncCookiePanelBtns();
    const autolaunch = sessionStorage.getItem("ss_autolaunch");
    if (autolaunch && launchUrl) {
      sessionStorage.removeItem("ss_autolaunch");
      setTimeout(() => openSession(launchUrl), 150);
    } else {
      cookieInput.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }
}

// Receive tokens from Chrome extension content script
window.addEventListener("ss_ext_cookies", (e) => {
  const { cookies, domain, cookieObjects } = typeof e.detail === "object" ? e.detail : { cookies: e.detail, domain: "", cookieObjects: null };
  cookieInput.value = cookies;
  if (cookieObjects) cookieInput.dataset.objects = JSON.stringify(cookieObjects);
  else delete cookieInput.dataset.objects;
  if (domain && !input.value.trim()) input.value = domain;
  cookiePanel.hidden = false;
  cookieToggle.setAttribute("aria-expanded", "true");
  const arrow = cookieToggle.querySelector(".cookie-arrow");
  if (arrow) arrow.textContent = "\u25b4";
  syncCookiePanelBtns();
  cookieInput.scrollIntoView({ behavior: "smooth", block: "nearest" });
});

// Receive cookies pushed from bookmarklet on another tab
try {
  const _bc = new BroadcastChannel("ss_cookies");
  _bc.onmessage = (e) => {
    cookieInput.value = e.data;
    cookiePanel.hidden = false;
    cookieToggle.setAttribute("aria-expanded", "true");
    cookieInput.scrollIntoView({ behavior: "smooth", block: "nearest" });
  };
} catch {}

// Fetch VNC token once for Watch Live links
let _vncToken = '';
fetch('/api/vnc-token').then(r => r.json()).then(d => { _vncToken = d.token || ''; }).catch(() => {});

function vncUrl() { return '/vnc' + (_vncToken ? '?t=' + encodeURIComponent(_vncToken) : ''); }

function showMessage(text) {
  message.textContent = text;
  message.hidden = false;
  message.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function getUrl() {
  const v = input.value.trim();
  if (!v) { showMessage("Enter a URL first."); input.focus(); return null; }
  return normalizeInputUrl(v);
}

function normalizeInputUrl(value) {
  const trimmed = value.trim();
  return /^[a-z][a-z\d+.-]*:/i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function renderReport(data) {
  const findings = data.checks.length
    ? `<ul class="findings">${data.checks.map((c) => `
      <li class="finding ${escapeHtml(c.severity)}">
        <span class="finding-icon" aria-hidden="true"></span>
        <div><h3>${escapeHtml(c.name)}</h3><p>${escapeHtml(c.detail)}</p></div>
      </li>`).join("")}</ul>`
    : '<p class="all-clear">No issues were flagged by these basic checks.</p>';

  const redirectHtml = data.redirectChain && data.redirectChain.length > 1
    ? `<div class="redirect-chain">
        <p class="eyebrow">Redirect chain (${data.redirectChain.length} hops)</p>
        <ol>${data.redirectChain.map((h) => `<li><span class="vlog-badge ${h.status < 400 ? "ok" : "warn"}">${escapeHtml(h.status)}</span> ${escapeHtml(h.url)}</li>`).join("")}</ol>
      </div>` : "";

  const ogHtml = data.openGraph ? `<div class="og-row">
    <span class="og-item ${data.openGraph.ogTitle ? "og-ok" : "og-miss"}" title="og:title">${data.openGraph.ogTitle ? "✓" : "✗"} og:title</span>
    <span class="og-item ${data.openGraph.ogDescription ? "og-ok" : "og-miss"}" title="og:description">${data.openGraph.ogDescription ? "✓" : "✗"} og:desc</span>
    <span class="og-item ${data.openGraph.ogImage ? "og-ok" : "og-miss"}" title="og:image">${data.openGraph.ogImage ? "✓" : "✗"} og:image</span>
    <span class="og-item ${data.openGraph.twitterCard ? "og-ok" : "og-miss"}" title="twitter:card">${data.openGraph.twitterCard ? "✓" : "✗"} tw:card</span>
    <span class="og-item ${data.hasRobotsTxt ? "og-ok" : "og-miss"}" title="robots.txt">${data.hasRobotsTxt ? "✓" : "✗"} robots.txt</span>
    <span class="og-item ${data.hasSitemapXml ? "og-ok" : "og-miss"}" title="sitemap.xml">${data.hasSitemapXml ? "✓" : "✗"} sitemap.xml</span>
  </div>` : "";

  report.innerHTML = `
    <div class="report-head">
      <div><p class="eyebrow">Audit report</p><h2>${escapeHtml(data.title || data.url)}</h2>
      <p>${escapeHtml(data.url)} · HTTP ${escapeHtml(data.status)}</p></div>
      <div class="report-stats">
        <span class="stat"><strong>${escapeHtml(data.responseTimeMs)} ms</strong> response</span>
        <span class="stat"><strong>${escapeHtml(data.linkCount)}</strong> HTML links</span>
        <span class="stat"><strong>${escapeHtml(data.imageCount)}</strong> HTML images</span>
        ${data.ssl ? `<span class="stat ssl-stat ${data.ssl.daysLeft <= 14 ? "ssl-warn" : data.ssl.daysLeft <= 30 ? "ssl-amber" : "ssl-ok"}"><strong>${escapeHtml(data.ssl.daysLeft)}d</strong> TLS · ${escapeHtml(data.ssl.protocol)}</span>` : ""}
      </div>
    </div>
    ${ogHtml}
    ${redirectHtml}
    ${findings}
    <p class="notice">${escapeHtml(data.notice)}</p>
    <div class="visit-controls">
      <label for="visit-count" class="visit-label">Simulate human visits</label>
      <input id="visit-count" type="number" min="1" max="100" value="3">
      <button id="visit-btn" class="verify-btn" type="button">Run visits →</button>
    </div>
    <div id="visit-log"></div>`;
  report.hidden = false;

  document.querySelector("#visit-btn").addEventListener("click", () => {
    const count = Math.min(Math.max(Number(document.querySelector("#visit-count").value) || 1, 1), 100);
    runVisits(data.url, count);
  });
}

function visitRowHtml(v) {
  if (v.error) {
    return `<div class="vlog-row vlog-error">
      <span class="vlog-num">[${String(v.visit).padStart(3, "0")}]</span>
      <span class="vlog-badge err">ERR</span>
      <span class="vlog-err">${escapeHtml(v.error)}</span>
      <span class="vlog-time">${v.responseTimeMs}ms</span>
    </div>`;
  }
  return `<div class="vlog-row">
    <span class="vlog-num">[${String(v.visit).padStart(3, "0")}]</span>
    <span class="vlog-badge ${v.status === 200 ? "ok" : "warn"}">${escapeHtml(v.status)}</span>
    <span class="vlog-time">${v.responseTimeMs}ms</span>
    <div class="vlog-details">
      <div class="vlog-line"><span class="vlog-key">IP route</span><span class="vlog-val">${escapeHtml(v.proxy)}</span></div>
      <div class="vlog-line"><span class="vlog-key">device</span><span class="vlog-val">${escapeHtml(v.ua)}</span></div>
      <div class="vlog-line"><span class="vlog-key">viewport</span><span class="vlog-val">${escapeHtml(v.viewport)}</span> <span class="vlog-key">locale</span><span class="vlog-val">${escapeHtml(v.locale)}</span> <span class="vlog-key">tz</span><span class="vlog-val">${escapeHtml(v.timezone)}</span></div>
      <div class="vlog-line"><span class="vlog-key">referrer</span><span class="vlog-val">${escapeHtml(v.referrer)}</span></div>
      <div class="vlog-line"><span class="vlog-key">scrolled</span><span class="vlog-val">${escapeHtml(v.scrollSteps)} steps</span> <span class="vlog-key">mouse moves</span><span class="vlog-val">${escapeHtml(v.mouseMoves)}</span> <span class="vlog-key">dwell</span><span class="vlog-val">${escapeHtml(v.dwellMs)}ms</span></div>
      ${v.subpageUrl ? `<div class="vlog-line"><span class="vlog-key">navigated to</span><span class="vlog-val">${escapeHtml(v.subpageUrl)}</span></div>` : ""}
    </div>
  </div>`;
}

function showAuditLog(container) {
  container.innerHTML = `
    <div class="vlog-header">
      <span class="vlog-title">// AUDIT LOG</span>
      <span class="vlog-meta" id="audit-log-meta">starting…</span>
    </div>
    <div class="vlog" id="audit-log-rows"></div>`;
  container.hidden = false;
}

function appendAuditLog(text, ok = true) {
  const rows = document.querySelector("#audit-log-rows");
  if (!rows) return;
  rows.insertAdjacentHTML("beforeend",
    `<div class="vlog-row"><span class="vlog-badge ${ok ? "ok" : "warn"}">${ok ? "OK" : "…"}</span> <span>${escapeHtml(text)}</span></div>`);
  rows.scrollTop = rows.scrollHeight;
}

async function runAudit(url, userAgent = "scout") {
  message.hidden = true;
  report.hidden = true;
  button.disabled = true;
  sessionButton.disabled = true;
  button.querySelector("span").textContent = userAgent === "browser" ? "Rendering..." : "Checking...";
  const cookies = cookieInput.value.trim() || null;

  showAuditLog(report);
  appendAuditLog(`Resolving ${url}`, false);

  try {
    const res = await fetch("/api/audit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url, userAgent, cookies }),
    });

    if (!res.ok) {
      const result = await res.json();
      throw new Error(result.error || "The audit could not be completed.");
    }

    // stream NDJSON lines
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    let finalResult = null;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        const msg = JSON.parse(line);
        if (msg.type === "log") {
          appendAuditLog(msg.text, msg.ok !== false);
          const meta = document.querySelector("#audit-log-meta");
          if (meta) meta.textContent = msg.text;
        } else if (msg.type === "result") {
          finalResult = msg.data;
        }
      }
    }

    if (!finalResult) throw new Error("The audit could not be completed.");
    // auto-switch to browser mode if JS-rendered or canvas app, and not already in browser mode
    if ((finalResult.likelyClientRendered || finalResult.isCanvasApp) && userAgent === "scout") {
      browserToggle.checked = true;
      return runAudit(url, "browser");
    }
    renderReport(finalResult);
  } catch (err) {
    showMessage(err.message || "The audit could not be completed.");
    report.hidden = true;
  } finally {
    button.disabled = false;
    sessionButton.disabled = false;
    button.querySelector("span").textContent = "Audit Page";
  }
}

async function runVisits(url, count) {
  const visitBtn = document.querySelector("#visit-btn");
  const logEl = document.querySelector("#visit-log");
  visitBtn.disabled = true;
  visitBtn.textContent = "Running…";

  logEl.innerHTML = `
    <div class="vlog-header">
      <span class="vlog-title">// VISIT LOG</span>
      <span class="vlog-meta" id="vlog-meta">0 / ${count} · launching…</span>
    </div>
    <div class="vlog-progress"><div class="vlog-bar" id="vlog-bar" style="width:0%"></div></div>
    <div class="vlog" id="vlog-rows"></div>`;

  const meta = document.querySelector("#vlog-meta");
  const bar = document.querySelector("#vlog-bar");
  const rows = document.querySelector("#vlog-rows");
  let done = 0, succeeded = 0;
  const allTimes = [];

  try {
    const res = await fetch("/api/visit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url, count }),
    });
    if (!res.ok) {
      const e = await res.json();
      throw new Error(e.error || "Visits could not be completed.");
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (true) {
      const { value, done: streamDone } = await reader.read();
      if (streamDone) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop(); // incomplete last line
      for (const line of lines) {
        if (!line.trim()) continue;
        const msg = JSON.parse(line);
        if (msg.type === "visit") {
          done++;
          if (!msg.error) { succeeded++; allTimes.push(msg.responseTimeMs); }
          rows.insertAdjacentHTML("beforeend", visitRowHtml(msg));
          bar.style.width = `${Math.round((done / count) * 100)}%`;
          meta.textContent = `${done} / ${count} · ${succeeded} ok`;
        } else if (msg.type === "error") {
          logEl.insertAdjacentHTML("beforeend", `<div class="vlog-pending" style="color:var(--red)">${escapeHtml(msg.error)}</div>`);
        } else if (msg.type === "done") {
          const avgMs = done > 0 ? Math.round(allTimes.reduce((a, b) => a + b, 0) / allTimes.length) : 0;
          const medMs = allTimes.length ? [...allTimes].sort((a, b) => a - b)[Math.floor(allTimes.length / 2)] : 0;
          meta.textContent = `${msg.count} visits · ${msg.succeeded} succeeded · avg ${avgMs}ms · median ${medMs}ms · unique IP per visit`;
          bar.style.width = "100%";
        }
      }
    }
  } catch (err) {
    logEl.insertAdjacentHTML("beforeend", `<div class="vlog-pending" style="color:var(--red)">${escapeHtml(err.message)}</div>`);
  } finally {
    visitBtn.disabled = false;
    visitBtn.textContent = "Run visits →";
  }
}

async function openSession(url) {
  const cookies = cookieInput.value.trim() || null;
  const cookieObjects = cookieInput.dataset.objects ? JSON.parse(cookieInput.dataset.objects) : null;
  if (!cookies) {
    cookiePanel.hidden = false;
    cookieToggle.setAttribute("aria-expanded", "true");
    const arrow = cookieToggle.querySelector(".cookie-arrow");
    if (arrow) arrow.textContent = "\u25b4";
    cookieInput.focus();
    showMessage("Paste your session cookies above, then click Open Session again.");
    cookieInput.scrollIntoView({ behavior: "smooth", block: "nearest" });
    return;
  }
  // If no URL typed, derive from cookie domain
  if (!url || url === "https://") {
    if (cookieObjects && cookieObjects.length) {
      const d = cookieObjects[0].domain.replace(/^\./, "");
      url = `https://${d}`;
    } else {
      showMessage("Enter a URL first."); input.focus(); return;
    }
  }
  message.hidden = true;
  report.innerHTML = "";
  report.hidden = true;
  sessionButton.disabled = true;
  button.disabled = true;
  sessionButton.querySelector("span:not(.btn-tag)").textContent = "Launching...";


  report.innerHTML = `
    <div class="vlog-header">
      <span class="vlog-title">// SESSION LOG</span>
      <span class="vlog-meta" id="audit-log-meta">connecting…</span>
    </div>
    <div class="vlog-session-info" id="session-info" hidden>
      <div class="session-info-row"><span class="vlog-key">target</span><span class="vlog-val" id="si-url">${escapeHtml(url)}</span></div>
      <div class="session-info-row"><span class="vlog-key">cookies</span><span class="vlog-val" id="si-cookies">${escapeHtml(cookies.split(";").length)} token(s) injected</span></div>
      <div class="session-info-row" id="si-proxy-row" hidden><span class="vlog-key">proxy</span><span class="vlog-val" id="si-proxy">—</span></div>
      <div class="session-info-row" id="si-status-row"><span class="vlog-key">status</span><span class="vlog-val" id="si-status">launching…</span></div>
    </div>
    <div class="vlog" id="audit-log-rows"></div>`;
  report.hidden = false;
  report.scrollIntoView({ behavior: "smooth", block: "start" });

  try {
    const res = await fetch("/api/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url, cookies, cookieObjects }),
    });

    if (!res.ok) {
      const e = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error(e.error || `HTTP ${res.status}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        const msg = JSON.parse(line);
        if (msg.type === "log") {
          appendAuditLog(msg.text, msg.ok !== false);
          const meta = document.querySelector("#audit-log-meta");
          if (meta) meta.textContent = msg.text;
          // extract proxy info from log line
          const proxyMatch = msg.text.match(/Proxy #\d+ \(([^)]+)\)/);
          if (proxyMatch) {
            const siProxy = document.querySelector("#si-proxy");
            const siProxyRow = document.querySelector("#si-proxy-row");
            if (siProxy) siProxy.textContent = proxyMatch[1];
            if (siProxyRow) siProxyRow.hidden = false;
          }
          document.querySelector("#session-info").hidden = false;
        } else if (msg.type === "ready") {
          const isLoginPage = msg.warning === "login_page";
          const pageTitle = msg.pageTitle ? ` — "${msg.pageTitle}"` : "";
          if (isLoginPage) {
            appendAuditLog(`⚠ Redirected to login page${pageTitle}. Cookies may be expired or missing key tokens.`, false);
          } else {
            appendAuditLog(`Browser open${pageTitle}. Close the window when done.`, true);
          }
          const meta = document.querySelector("#audit-log-meta");
          if (meta) meta.textContent = isLoginPage ? "⚠ login page" : "● session active";
          const siStatus = document.querySelector("#si-status");
          if (siStatus) siStatus.textContent = isLoginPage ? "⚠ redirected to login — cookies invalid" : "● active — browser window is open";
          if (msg.pageUrl) {
            const siUrl = document.querySelector("#si-url");
            if (siUrl) { siUrl.textContent = msg.pageUrl; siUrl.title = msg.pageUrl; }
          }
          document.querySelector("#session-info").hidden = false;
        } else if (msg.type === "closed") {
          appendAuditLog("Browser window closed. Session ended.", false);
          const meta = document.querySelector("#audit-log-meta");
          if (meta) meta.textContent = "session ended";
          const siStatus = document.querySelector("#si-status");
          if (siStatus) siStatus.textContent = "closed";
        }
      }
    }
  } catch (err) {
    showMessage(err.message || "Could not open session.");
    report.hidden = true;
  } finally {
    sessionButton.disabled = false;
    button.disabled = false;
    sessionButton.querySelector("span:not(.btn-tag)").textContent = "Open Session";
  }
}

sessionButton.addEventListener("click", () => {
  const url = getUrl();
  if (!url) return;
  openSession(url);
});

button.addEventListener("click", () => {
  const url = getUrl();
  if (!url) return;
  runAudit(url, browserToggle.checked ? "browser" : "scout");
});

input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); button.click(); }
});

form.addEventListener("submit", (e) => e.preventDefault());
