# Exercise 03 — Preflight Abuse & Advanced Topics
## Timing attacks, CSRF via CORS, and the 2026 browser enforcement frontier

> **Difficulty:** ⭐⭐⭐⭐☆  
> **Flags:** 3  
> **Browser page:** `http://localhost:3002/04-preflight-abuse.html`  
> **File to edit:** `servers/victim-api/cors-config.js`

---

## Your Mission

The obvious misconfigurations are fixed. Now you're looking at bugs that require
deeper knowledge of how browsers negotiate CORS — and one that most developers
have never heard of in 2026.

---

## Bug #7 — Preflight Over-Cached (Max-Age: 86400)

**File:** `cors-config.js` → `corsPreflightCache()`  
**Route:** `PUT /api/settings`

```javascript
res.setHeader('Access-Control-Max-Age', '86400');
```

`Access-Control-Max-Age` tells browsers how long to cache the preflight result.
86400 seconds = 24 hours.

### Why This Matters: The Fix Window

Imagine this scenario:

```
09:00 AM — Attacker discovers CORS misconfiguration on PUT /api/settings
           They successfully send a PUT with a malicious payload.

09:05 AM — Security team patches the CORS config.

09:05 AM–09:00 AM+1 — Every browser that cached the 09:00 AM preflight
           still has the OLD permissive response cached.
           The "fixed" server isn't actually fixed for those browsers yet.

09:00 AM +1 day — Preflight cache finally expires. Fix takes effect.
```

The attacker has a 24-hour exploitation window *after* the fix is deployed.
During an active incident, this could be catastrophic.

### Browser Caps (2026 Reality)

Browsers impose their own caps regardless of what the server sends:

| Browser | Max-Age cap |
|---|---|
| Chrome 76+ | 7,200 seconds (2 hours) |
| Firefox | 86,400 seconds (24 hours) |
| Safari | 600 seconds (10 minutes) |

Chrome caps at 2 hours — but that's still too long during an active incident.
A conservative production value is 60–300 seconds.

### Phase 1: Observe the cached header

```bash
# Send a preflight and inspect Max-Age
curl -v -X OPTIONS http://localhost:3000/api/settings \
  -H "Origin: http://localhost:3001" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: Content-Type" 2>&1 | grep -i "max-age"
```

Open `http://localhost:3002/04-preflight-abuse.html` → click **"Send PUT"**.
In DevTools Network, find the OPTIONS preflight. Note the `Access-Control-Max-Age` value.

### Phase 2: Fix

In `cors-config.js` → `corsPreflightCache()`:

```javascript
// Before:
res.setHeader('Access-Control-Max-Age', '86400');

// After (development):
res.setHeader('Access-Control-Max-Age', '0');    // disable caching entirely

// After (production):
res.setHeader('Access-Control-Max-Age', '60');   // 60 seconds — short enough to fix quickly
```

**Rule:** Keep Max-Age short. 60 seconds is almost always sufficient.
Never set it to hours. During an incident, you want config changes to take
effect in under a minute.

---

## Bug #8 — Unsafe Methods Allowed Cross-Origin

**File:** `cors-config.js` → `corsUnsafeMethods()`  
**Route:** `DELETE /api/account`

```javascript
res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
```

Listing `DELETE`, `PUT`, and `PATCH` in `Allow-Methods` means cross-origin pages
can trigger state-changing operations — using the victim's own session cookie.

This is **CSRF delivered via a CORS misconfiguration**. Traditional CSRF tokens
don't help here because the server's own CORS config is what grants cross-origin
access.

### The Attack Chain

```
1. Attacker sends PUT preflight from trusted origin
2. Server responds: Allow-Methods: GET, POST, PUT, DELETE, PATCH
3. Browser: "DELETE is listed — real request is permitted"
4. Attacker sends: DELETE /api/account
                   Cookie: session=BANK_SESSION_abc123xyz  (browser adds automatically)
5. Account deleted. Server processed it. Victim has no idea.
```

### Phase 1: Observe

```bash
# Check what methods are listed
curl -v -X OPTIONS http://localhost:3000/api/account \
  -H "Origin: http://localhost:3001" \
  -H "Access-Control-Request-Method: DELETE" 2>&1 | grep -i "allow-methods"
```

### Phase 2: Execute the cross-origin DELETE

Open `http://localhost:3002/04-preflight-abuse.html` → click **"Send cross-origin DELETE"**.

### Phase 3: Fix

```javascript
// Before:
res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');

// After (only list what's genuinely needed cross-origin):
res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
```

**Rule:** Only list HTTP methods that actually need cross-origin access.
State-changing methods (DELETE, PUT, PATCH) should be same-origin only —
or require additional protection (CSRF tokens, re-authentication) if they
must be cross-origin.

---

## Bug #9 — Private Network Access (2026)

**File:** `cors-config.js` → `corsPrivateNetwork()`  
**Route:** `GET /api/internal`

```javascript
// What's in the code:
if (req.headers['access-control-request-private-network']) {
  res.setHeader('Access-Control-Allow-Private-Network', 'true');
}
res.setHeader('Access-Control-Allow-Origin', origin || '*');
```

### Background: What Is Private Network Access?

Chrome 98+ (2022, fully enforced by 2024) introduced **Private Network Access (PNA)**.

The problem it solves: malicious public websites could reach internal services
(localhost, 192.168.x.x, 10.x.x.x) using the victim's browser as a proxy.
This is sometimes called "localhost attacks" or "router exploitation."

```
evil.com → victim's browser → makes request to → http://localhost:3000/api/internal
                                                   (an internal service not meant to be public)
```

**How PNA works:**
When a public page tries to reach a private network address, Chrome sends an
automatic preflight with:

```
Access-Control-Request-Private-Network: true
```

The server must respond with:

```
Access-Control-Allow-Private-Network: true
```

Otherwise Chrome blocks the request. This means internal services must
explicitly opt in to being reachable from public websites.

**The bug:** If the server sends `Access-Control-Allow-Private-Network: true`
to **any** origin that asks — without checking if the origin is trusted —
it defeats PNA protection entirely. Any public website can now reach the
"private" API as if PNA didn't exist.

### Phase 1: Observe the misconfiguration

```bash
# Simulate the Chrome PNA preflight from an untrusted origin
curl -v -X OPTIONS http://localhost:3000/api/internal \
  -H "Origin: http://localhost:3002" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Private-Network: true" 2>&1 | grep -i "private-network\|allow-origin"
```

Does the server return `Access-Control-Allow-Private-Network: true` to our untrusted origin?

### Phase 2: Open the browser page

Open `http://localhost:3002/04-preflight-abuse.html`.

Click **"Send PNA preflight"** and then **"Fetch /api/internal"**.

Note: Chrome automatically adds the PNA preflight when it detects a public→private
request. In the lab, localhost:3002 → localhost:3000 may or may not trigger it
depending on Chrome's heuristics. The curl test above is the most reliable way
to verify the header behaviour.

### Phase 3: Fix

```javascript
// Before:
if (req.headers['access-control-request-private-network']) {
  res.setHeader('Access-Control-Allow-Private-Network', 'true');  // any origin gets this!
}

// After:
const origin = req.headers.origin || '';
if (req.headers['access-control-request-private-network'] &&
    ALLOWED_ORIGINS.includes(origin)) {
  res.setHeader('Access-Control-Allow-Private-Network', 'true');  // only trusted origins
}

// Also fix the origin reflection on this route
if (ALLOWED_ORIGINS.includes(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
}
```

**Rule:** Only grant `Access-Control-Allow-Private-Network` to explicitly trusted origins.
Never grant it to `*` or reflected origins.

---

## Flags

| # | Flag | Route |
|---|---|---|
| 7 | `CORS{preflight_cache_abuse}` | `PUT /api/settings` |
| 8 | `CORS{unsafe_methods_cors_exploit}` | `DELETE /api/account` |
| 9 | `CORS{private_network_access_2026}` | `GET /api/internal` |

---

## Final Hardening Checklist

After completing all three exercises, verify your `cors-config.js` against this list:

- [ ] No `*` wildcard — all origins are explicitly listed
- [ ] No origin reflection — incoming `Origin` validated against allowlist before echo
- [ ] `null` origin is never trusted
- [ ] All origin checks use strict equality or properly anchored regex
- [ ] `Vary: Origin` is set on every response that conditionally sets `ACAO`
- [ ] `Access-Control-Max-Age` is ≤ 300 seconds
- [ ] `Allow-Methods` lists only methods that need cross-origin access (no DELETE/PUT/PATCH)
- [ ] `Access-Control-Allow-Private-Network` only sent to trusted origins
- [ ] Admin routes have the most restrictive CORS (ideally: no cross-origin access)

---

## Further Reading

- [Chrome: Private Network Access](https://developer.chrome.com/blog/private-network-access-update/)
- [W3C: Private Network Access spec](https://wicg.github.io/private-network-access/)
- [PortSwigger: CORS preflight](https://portswigger.net/web-security/cors#the-pre-flight-check)
- [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#cors-headers)
- [MDN: Access-Control-Max-Age](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age)
