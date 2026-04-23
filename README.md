# 🌐 CORS & SOP Misconfiguration Lab
### BankAPI — A hands-on lab for understanding and exploiting CORS misconfigurations

**Keywords:** CORS, Same-Origin Policy, SOP, Web Security, Security Lab, CORS Bypass, XSS, Cross-Origin, Browser Security, API Security, Preflight, Private Network Access, Security Training

> **Target audience:** Junior security engineers learning web vulnerability classes systematically  
> **Prior knowledge required:** Basic HTTP (requests, headers, status codes)  
> **CORS/SOP prior knowledge:** None — Exercise 00 teaches it from scratch

---

## 🎯 Quick Summary

**CORS & SOP Misconfiguration Lab** is a **hands-on security training lab** featuring 9 real-world CORS vulnerabilities found in production APIs. Build a BankAPI from scratch, learn how each vulnerability works, exploit it with browser-based attacks, write the fixes, and verify with automated tests.

- ✅ **9 Exploitable Vulnerabilities** — Real production bugs
- ✅ **Browser + Test Coverage** — Learn both ways
- ✅ **Step-by-Step Guides** — Every bug documented
- ✅ **Docker Setup** — Runs anywhere in minutes
- ✅ **200 Points Scoring System** — Track your learning progress

---

## What You'll Learn

By the end of this lab you will be able to:

- Explain the Same-Origin Policy and what it does (and does not) protect
- Identify the 9 most common CORS misconfigurations in production APIs
- Exploit each misconfiguration from a real browser using attacker-controlled HTML pages
- Read and interpret CORS response headers to assess vulnerability
- Write correct, production-grade CORS middleware
- Understand Private Network Access (PNA) — the major 2024-2026 browser enforcement change

---

## The Lab Setup

Three servers. One internal network. One student.

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                      │
│  localhost:3000  → BankAPI (victim)     — the vulnerable bank API   │
│  localhost:3001  → reports.bank.local   — legitimate trusted origin  │
│  localhost:3002  → evil.attacker.local  — open this in your browser │
│                                                                      │
│  From your browser's perspective:                                    │
│    localhost:3002 → localhost:3000 is CROSS-ORIGIN (different port) │
│    This makes SOP apply — and CORS misconfigs exploitable           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

The attacker page (localhost:3002) serves browser exploit pages that make
real cross-origin requests to the bank API (localhost:3000). Your browser
enforces SOP between them — no `/etc/hosts` tricks needed.

---

## Quick Start

**Prerequisites:** Docker Desktop (or Docker Engine + Compose), Node.js 18+

```bash
# 1. Clone the repo
git clone https://github.com//cors-sop-lab
cd cors-sop-lab

# 2. Start all three servers
docker compose up --build

# Wait for all three containers to show "running":
#   cors-victim-api        → http://localhost:3000
#   cors-trusted-subdomain → http://localhost:3001
#   cors-attacker-page     → http://localhost:3002

# 3. Open the attacker page in Chrome or Firefox
open http://localhost:3002

# 4. In a separate terminal, install test runner dependencies
npm install

# 5. Run all tests (docker compose must be running)
npm test

# Or run one exercise at a time:
npm run test:00   # SOP fundamentals (observation)
npm run test:01   # Core misconfigurations
npm run test:02   # Bypass techniques
npm run test:03   # Preflight & advanced
```

---

## How the Lab Works

### The file you edit

All CORS logic is in one file: **`servers/victim-api/cors-config.js`**

Each route in `app.js` uses a different handler from this file. You read the
bug, understand it, fix the handler, and verify with tests. `app.js` never needs
to be touched.

The victim-api container uses **Node's `--watch` flag** — changes to
`cors-config.js` restart the server automatically. No `docker compose restart` needed.

### Two ways to see every exploit

**1. Browser pages** (the experience)
Open `http://localhost:3002` and navigate to each exploit page.
Watch real cross-origin requests fire, see the CORS headers in real time,
and capture flags in the browser output panel. This is what a real victim would experience.

**2. Jest tests** (the verification)
Tests run in Node.js (no browser SOP), so they can check HTTP headers precisely.
They prove the vulnerability mechanically and verify your fix is correct.

### Step-by-Step Exploitation Guide

For detailed exploitation steps for each of the 9 vulnerabilities, see **[EXPLOITATION_GUIDE.md](./EXPLOITATION_GUIDE.md)**.

### The two-phase pattern

Every exercise follows the same structure:

```
🔴 EXPLOIT TESTS   → PASS when vulnerable   → should FAIL after your fix
🟢 HARDENING TESTS → FAIL when vulnerable   → should PASS after your fix
```

Before fix:   🔴 PASS  |  🟢 FAIL  
After fix:    🔴 FAIL  |  🟢 PASS

---

## Exercises

### [Exercise 00 — SOP Fundamentals](./exercises/00-sop-fundamentals/challenge.md)
*Observation only. No flags. No code changes.*

Build the mental model before anything breaks. What is an origin? What does
SOP actually block? Where does CORS fit? What does a correct CORS implementation
look like? This exercise makes every subsequent bug comprehensible rather than mechanical.

```bash
npm run test:00
```

---

### [Exercise 01 — Core Misconfigurations](./exercises/01-core-misconfigs/challenge.md)
*3 flags. The bugs that appear in most production APIs.*

| # | Bug | Route |
|---|---|---|
| 1 | Wildcard origin | `GET /api/public` |
| 2 | Origin reflection + credentials | `GET /api/account` |
| 3 | Null origin trusted | `GET /api/profile` |

```bash
npm run test:01
```
Browser: `http://localhost:3002/01-origin-reflection.html` and `02-null-origin.html`

---

### [Exercise 02 — Bypass Techniques](./exercises/02-bypasses/challenge.md)
*3 flags. When allowlists look almost right.*

| # | Bug | Route |
|---|---|---|
| 4 | Prefix regex bypass (`startsWith`) | `GET /api/transfers` |
| 5 | Suffix regex bypass (`endsWith`) | `GET /api/statements` |
| 6 | Subdomain wildcard pivot | `GET /api/admin` |

```bash
npm run test:02
```
Browser: `http://localhost:3002/03-regex-bypass.html`

---

### [Exercise 03 — Preflight Abuse & Advanced](./exercises/03-preflight-advanced/challenge.md)
*3 flags. Browser negotiation mechanics and the 2026 attack surface.*

| # | Bug | Route |
|---|---|---|
| 7 | Preflight cached 24 hours (Max-Age: 86400) | `PUT /api/settings` |
| 8 | Unsafe methods allowed cross-origin (DELETE) | `DELETE /api/account` |
| 9 | Private Network Access header ungated (2026) | `GET /api/internal` |

```bash
npm run test:03
```
Browser: `http://localhost:3002/04-preflight-abuse.html`

---

## Scoring

| Flag | Exercise | Points |
|---|---|---|
| `CORS{wildcard_any_origin_reads_this}` | 01 | 10 |
| `CORS{origin_reflection_exploit}` | 01 | 15 |
| `CORS{null_origin_trusted}` | 01 | 15 |
| `CORS{regex_prefix_bypass}` | 02 | 15 |
| `CORS{regex_suffix_bypass}` | 02 | 15 |
| `CORS{subdomain_trust_pivot}` | 02 | 20 |
| `CORS{preflight_cache_abuse}` | 03 | 15 |
| `CORS{unsafe_methods_cors_exploit}` | 03 | 20 |
| `CORS{private_network_access_2026}` | 03 | 25 |
| All 🟢 hardening tests green | All | **+50 bonus** |
| **Total** | | **200** |

---

## Project Structure

```
cors-sop-lab/
├── docker-compose.yml
├── servers/
│   ├── victim-api/
│   │   ├── Dockerfile
│   │   ├── package.json
│   │   ├── cors-config.js     ← THE FILE YOU EDIT (all 9 bugs)
│   │   └── app.js             ← routes (do not edit)
│   ├── trusted-subdomain/
│   │   ├── Dockerfile
│   │   ├── package.json
│   │   └── app.js             ← reports.bank.local (pivot demo server)
│   └── attacker-page/
│       ├── Dockerfile
│       ├── package.json
│       ├── app.js             ← serves exploit HTML
│       └── public/
│           ├── 00-sop-demo.html
│           ├── 01-origin-reflection.html
│           ├── 02-null-origin.html
│           ├── 03-regex-bypass.html
│           └── 04-preflight-abuse.html
├── exercises/
│   ├── 00-sop-fundamentals/
│   │   ├── challenge.md
│   │   └── sop.test.js
│   ├── 01-core-misconfigs/
│   │   ├── challenge.md
│   │   └── misconfigs.test.js
│   ├── 02-bypasses/
│   │   ├── challenge.md
│   │   └── bypasses.test.js
│   └── 03-preflight-advanced/
│       ├── challenge.md
│       └── preflight.test.js
├── jest.setup.js
├── package.json
└── README.md
```

---

## Key Concepts Reference

### The correct CORS implementation (memorize this pattern)

```javascript
const ALLOWED_ORIGINS = ['https://trusted.example.com'];

function corsSecure(req, res, next) {
  const origin = req.headers.origin;

  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');             // critical for CDN caching
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '60'); // short cache — fast fix window

  if (req.headers['access-control-request-private-network'] &&
      origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
  }

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}
```

### CORS is NOT a server security control

CORS controls whether a *browser* lets JavaScript read a cross-origin response.
The server always processes the request — CORS never prevents that.

**If your API returns sensitive data, protect it with:**
- Session cookies / JWT authentication
- CSRF tokens for state-changing operations
- Rate limiting
- Input validation

CORS is the last line — it stops *data exfiltration* from the browser, not unauthorized requests.

### Preflight quick reference

| Request type | Preflight? | Why |
|---|---|---|
| `GET` with standard headers | ❌ No | Simple request |
| `POST` with `Content-Type: application/json` | ✅ Yes | Non-standard content type |
| `PUT`, `DELETE`, `PATCH` | ✅ Yes | Non-simple method |
| Any request with custom headers | ✅ Yes | e.g. `Authorization` |

### Browser PNA enforcement (2026 status)

| Browser | PNA enforcement |
|---|---|
| Chrome/Edge 98+ | ✅ Enforced by default |
| Firefox | 🔄 In progress (flag available) |
| Safari | ❌ Not yet implemented |

---

## Troubleshooting

**`docker compose up` fails:**
```bash
docker compose down --volumes  # clean up
docker compose up --build      # rebuild from scratch
```

**Tests fail with "Server not ready":**
```bash
# Check containers are running
docker compose ps

# Check victim-api logs
docker compose logs victim-api
```

**Changes to cors-config.js aren't taking effect:**
```bash
# The container uses node --watch. Check it restarted:
docker compose logs victim-api --tail=5
# You should see "Server restarted" after saving the file
```

**Browser shows CORS error even after fixing:**
Clear the preflight cache: DevTools → Network → right-click → "Clear browser cache" or use Incognito mode.

---

## Solutions

Solutions are maintained in a **private repository** — contact the lab author for instructor access.

---

## Further Reading

- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [PortSwigger Web Security Academy: CORS](https://portswigger.net/web-security/cors)
- [OWASP: Testing for CORS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [Chrome: Private Network Access](https://developer.chrome.com/blog/private-network-access-update/)
- [James Kettle: Exploiting CORS Misconfigurations for Bitcoins and Bounties](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
- [W3C: Fetch spec — CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol)

---

## License

MIT — use it in your courses, adapt it, fork it.

---

## GitHub Topics

When viewing this repo on GitHub, the following topics should be added for discoverability:
- `cors`
- `security-lab`
- `web-security`
- `cors-bypass`
- `same-origin-policy`
- `api-security`
- `security-training`
- `ctf`
- `vulnerability-research`
- `browser-security`

**To add topics:** Click "⚙️ About" section on the repo homepage → add the tags above.
