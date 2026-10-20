# TrafficBot

A local tool for auditing public webpages and opening authenticated browser sessions through US proxies — all from one web interface.

Three things it does:

1. **Audit a page** — one identified GET request; checks metadata, headings, image alt text, security headers, TLS, and Open Graph tags. Does not execute JavaScript; likely client-rendered pages are flagged.
2. **Open a session** — paste your cookies, pick a US proxy, and launch a real Chromium window already logged in. View it live through the built-in VNC tab.
3. **Simulate visits** — automated visits with randomised fingerprints, human-like mouse movement, scroll behaviour, and US proxy rotation.

---

## Requirements

- Node.js 20 or newer
- Python 3 with `pysocks` (`pip3 install pysocks`)
- Playwright Chromium browser (`npx playwright install chromium`)
- VNC stack: `xvfb`, `x11vnc`, `websockify`, `novnc`

### Install VNC stack (Debian / Ubuntu / Kali WSL)

```sh
sudo apt update
sudo apt install -y xvfb x11vnc websockify novnc
```

---

## Setup

```sh
git clone <repo-url>
cd trafficbot
npm install
npx playwright install chromium
cp .env.example .env
# Edit .env and add your SOCKS5 proxy URLs
```

---

## Run

**1. Start the VNC virtual display** (required for the session browser to render):

```sh
bash start-vnc.sh
```

This starts Xvfb on `:1`, x11vnc on port `5900`, and websockify on port `5999`. Run it once per terminal session. If the VNC screen goes blank, run it again.

**2. Start the server:**

```sh
npm start
```

Open <http://127.0.0.1:10000>.

---

## Features

### Page audit
Enter any public URL and click **Audit Page**. Results include:
- Page title, description, Open Graph tags
- Heading structure, image alt attributes
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- TLS certificate info
- Likely calls to action
- JavaScript-rendered page detection

### Authenticated session
1. Paste cookies in `name=value; name2=value2` format into the **Session cookies** box
2. Enter the target URL
3. Click **Open Session**
4. Wait for `● session active` in the log
5. Open the **VNC tab** to see and control the live browser:

```
http://127.0.0.1:10000/vnc?t=<your-VNC_TOKEN>
```

The `VNC_TOKEN` is printed to the terminal on first run and saved to `.env`.

> **Getting cookies**: Use the bundled Chrome extension (download from `/cookies`) — it captures all cookies including `httpOnly` ones that the browser DevTools cookie panel hides. For LinkedIn you need `li_at` and `JSESSIONID`; for most sites the extension captures everything automatically.

### Visit simulation
Automated visits with:
- Randomised US fingerprint (locale, timezone, viewport, user-agent)
- Human-like curved mouse movement and scroll
- US SOCKS5 proxy rotation (up to 3 proxies, never repeats back-to-back)
- Canvas, audio, and WebRTC fingerprint masking
- `navigator.webdriver` hidden, `window.chrome` present

### Screen share room (`/room`)
WebRTC peer-to-peer screen share between devices. SSE-based presence, cast request/accept/decline via toast notifications.

---

## Chrome extension

The extension captures cookies from any tab and sends them directly to the session panel.

**Install:**
- Windows: visit `/cookies` and click **Auto-Install** — creates a dedicated Chrome profile with the extension loaded
- Mac/Linux: visit `/cookies` and click **Auto-Install** — same, using a shell script
- Manual: download `extension.zip` from `/cookies`, unzip, load as unpacked extension in Chrome at `chrome://extensions`

After any change to extension source files, rebuild the zip:

```sh
zip -j public/extension.zip extension/manifest.json extension/background.js extension/content.js extension/popup.html extension/popup.js extension/icon.svg
```

---

## Proxy setup

The server expects up to three SOCKS5 proxy URLs in `.env`:

```
PROXY_URL_1=socks5://user:pass@host:port
PROXY_URL_2=socks5://user:pass@host:port
PROXY_URL_3=socks5://user:pass@host:port
```

Tested with [IPRoyal](https://iproyal.com) residential proxies (`country-us` parameter). Sessions without proxies fall back to a direct connection.

---

## Expose with ngrok

```sh
ngrok http 10000
```

> **Always use port 10000.** `ERR_NGROK_8012` means ngrok is pointed at the wrong port.

Update the extension's server URL in `extension/popup.js` to match your ngrok URL.

---

## Tests

```sh
npm test
```

9 unit tests covering BIP-39 key generation, IPv4 SSRF guard, URL validation, DNS pinning, and HTML checks. All pass with no dependencies beyond Node.js built-ins.

---

## Security and scope

- Audit only websites you own or have permission to check.
- One identified GET request per audit run; does not submit forms, evade bot protection, or run a load test.
- Requests limited to HTTP/HTTPS, public IPv4 only, 5 redirects, 10-second timeout, 1 MB body cap.
- API rate-limited to 5 requests per minute per client IP.
- Hostnames resolving to private/reserved IPv4 ranges are rejected (SSRF guard).
- IPv6-only targets are not supported.
- Checks are heuristic and informational — not a penetration test.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| VNC screen is blank | Run `bash start-vnc.sh` again |
| x11vnc fails with "Wayland detected" | `start-vnc.sh` already runs `unset WAYLAND_DISPLAY` — make sure you run it with `bash start-vnc.sh`, not `sh` |
| Session redirects to login page | Cookies are expired or missing key tokens (`li_at` for LinkedIn, etc.) — use the extension to recapture |
| `ERR_NGROK_8012` | ngrok must point to port `10000`, not `3000` |
| `u is not defined` in session | `startBridge` is missing `const u = new URL(proxyUrl)` — check server.js line ~370 |
| Proxy detected by site | All stealth flags are active; if still detected, the proxy IP itself may be flagged — rotate to a different session ID in the proxy URL |
