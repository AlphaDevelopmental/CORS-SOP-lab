# Exercise 02 — Bypass Techniques
## When allowlists look right but aren't

> **Difficulty:** ⭐⭐⭐☆☆  
> **Flags:** 3  
> **Browser page:** `http://localhost:3002/03-regex-bypass.html`  
> **File to edit:** `servers/victim-api/cors-config.js`

---

## Your Mission

The developer tried to fix the naive origin reflection from Exercise 01.
They wrote three different allowlist implementations — each with a subtle flaw.
Your job: find the gap in each pattern, confirm it's exploitable, and fix it.

---

## Bug #4 — Prefix Match Bypass

**File:** `cors-config.js` → `corsRegexPrefix()`  
**Route:** `GET /api/transfers`

```javascript
// What's in the code:
if (origin.startsWith('http://localhost:3001')) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}
```

The intent: only allow `localhost:3001`. The flaw: `startsWith` matches any
string that *begins* with the trusted value — including strings that continue past it.

### Bypasses

```
http://localhost:3001          ← legitimate (intended)
http://localhost:3001.evil.com ← bypass (starts with trusted string)
http://localhost:30010         ← bypass (starts with trusted string, different port)
http://localhost:3001xyz       ← bypass
```

An attacker who owns `localhost:3001.evil.com` (or any domain starting with
`localhost:3001`) passes the check automatically.

### Phase 1: Demonstrate the bypass with curl

```bash
# Bypass: origin starts with the trusted string, but continues
curl -v http://localhost:3000/api/transfers \
  -H "Origin: http://localhost:3001.evil.com" \
  -H "Cookie: session=BANK_SESSION_abc123xyz" 2>&1 | grep "Access-Control"
```

Is `http://localhost:3001.evil.com` reflected back in ACAO?

### Phase 2: Root cause analysis

Open `cors-config.js`. Read `corsRegexPrefix()`.

Answer these questions before touching the fix:
- What string is passed to `startsWith()`?
- What character immediately after the trusted string would make an evil domain pass?
- Why is prefix matching fundamentally wrong for origin validation?

### Phase 3: Fix

Replace the `startsWith()` check with strict equality:

```javascript
// Instead of:
if (origin.startsWith('http://localhost:3001')) { ... }

// Do this:
if (ALLOWED_ORIGINS.includes(origin)) { ... }
```

**Rule:** Origin validation must use strict equality (`===`) against an explicit
allowlist. Never prefix, suffix, or substring matching.

---

## Bug #5 — Suffix Match Bypass

**File:** `cors-config.js` → `corsRegexSuffix()`  
**Route:** `GET /api/statements`

```javascript
// What's in the code:
if (origin.endsWith('bank.local')) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}
```

The intent: allow any `*.bank.local` subdomain. The flaw: `endsWith` matches
any string ending in `bank.local` — including strings that have extra characters before it.

### Bypasses

```
http://reports.bank.local   ← legitimate (intended)
http://evilbank.local       ← bypass (ends with "bank.local")
http://notabank.local       ← bypass
http://xbank.local          ← bypass
```

A real-world attacker registers `evilbank.local` and gets access to financial statements.

### Phase 1: Demonstrate

```bash
curl -v http://localhost:3000/api/statements \
  -H "Origin: http://evilbank.local" \
  -H "Cookie: session=BANK_SESSION_abc123xyz" 2>&1 | grep "Access-Control"
```

### Phase 2: The correct regex pattern

If you genuinely need to allow multiple subdomains (not just a fixed list), use
a properly anchored regex:

```javascript
// Correctly anchored — requires a dot before bank.local
const SUBDOMAIN_REGEX = /^https?:\/\/([a-z0-9-]+\.)?bank\.local(:\d+)?$/;

// This allows:
//   http://bank.local
//   http://reports.bank.local
//   http://reports.bank.local:3001

// This blocks:
//   http://evilbank.local       ← no dot before "bank"
//   http://notabank.local       ← no dot before "bank"
//   http://reports.bank.local.evil.com  ← doesn't end at bank.local
```

The key elements:
- `^` — anchored at the start (prevents prefix pollution)
- `\.` — requires a literal dot before the domain (prevents `evilbank.local`)
- `$` — anchored at the end (prevents suffix pollution)

### Phase 3: Fix

Replace `endsWith()` with the properly anchored regex above, or switch to an explicit allowlist.

---

## Bug #6 — Subdomain Wildcard Trust Pivot

**File:** `cors-config.js` → `corsSubdomainWildcard()`  
**Route:** `GET /api/admin`

```javascript
// What's in the code:
const subdomainRegex = /^https?:\/\/[a-z0-9-]+\.bank\.local(:\d+)?$/;
if (subdomainRegex.test(origin) || origin === 'http://localhost:3001') {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}
```

The regex is correctly anchored this time. The bug is different: it trusts **all**
`*.bank.local` subdomains. If an attacker compromises *any* one of them — through XSS,
subdomain takeover, or a misconfigured third-party service — they inherit full trust
on the admin API.

### The Two-Step Pivot Attack

```
Step 1: Attacker compromises reports.bank.local
        Methods: XSS via unsanitised input, subdomain takeover of expired DNS,
                 vulnerable npm package on the subdomain's server, etc.

Step 2: From reports.bank.local, attacker makes credentialed request to /api/admin
        Browser sees: "reports.bank.local is in the ACAO allowlist → allow"
        Admin data flows to compromised subdomain → to attacker
```

### Phase 1: Observe the pivot in action

Open `http://localhost:3001/pivot-page` in your browser.

This page simulates a compromised `reports.bank.local`. Its JavaScript makes
a credentialed cross-origin fetch to `/api/admin` using its trusted-origin status.
Watch what happens.

Then try the server-side version:

```bash
curl http://localhost:3001/pivot
```

### Phase 2: Questions to answer

1. How many `*.bank.local` subdomains exist in this lab?
2. If each subdomain is a separate application, how many attack surfaces exist?
3. What's the blast radius if one subdomain has an XSS vulnerability?
4. Should `reports.bank.local` have access to `/api/admin`? Does it need to?

### Phase 3: Fix (two approaches)

**Option A — Explicit allowlist (preferred):**
Only list exactly the subdomains that legitimately need cross-origin admin access.

```javascript
const ADMIN_ALLOWED_ORIGINS = [
  // Only list origins that actually need admin API access
  // Ask: does reports.bank.local need /api/admin? Probably not.
];
if (ADMIN_ALLOWED_ORIGINS.includes(origin)) { ... }
```

**Option B — Reduce trust scope per route:**
Admin endpoints should have the most restrictive CORS. If no external origin
needs admin access, set no CORS headers at all — same-origin only.

---

## Flags

| # | Flag | Route |
|---|---|---|
| 4 | `CORS{regex_prefix_bypass}` | `GET /api/transfers` |
| 5 | `CORS{regex_suffix_bypass}` | `GET /api/statements` |
| 6 | `CORS{subdomain_trust_pivot}` | `GET /api/admin` |

---

## Pattern Recognition Cheat Sheet

When reviewing CORS config in the wild, grep for these anti-patterns:

```javascript
// 🔴 Dangerous patterns to look for:
origin.startsWith(...)           // prefix match — bypassable
origin.endsWith(...)             // suffix match — bypassable
origin.includes(...)             // substring match — bypassable
origin.match(/trusted\.com/)    // unanchored regex — bypassable
origin || '*'                    // fallback to wildcard — dangerous

// ✅ Safe patterns:
ALLOWED_ORIGINS.includes(origin)                    // strict equality list
/^https:\/\/trusted\.com$/.test(origin)            // fully anchored regex
origin === 'https://trusted.com'                    // exact equality
```

---

## Further Reading

- [PortSwigger: CORS allowlist bypass](https://portswigger.net/web-security/cors#errors-parsing-origin-headers)
- [James Kettle: Exploiting CORS Misconfigurations for Bitcoins and Bounties](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
- [Subdomain Takeover](https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers)
