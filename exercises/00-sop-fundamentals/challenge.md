# Exercise 00 — Same-Origin Policy Fundamentals
## Read this before you touch any exploit

> **Type:** Observation only — no code changes, no flags  
> **Goal:** Build the mental model that every subsequent exercise breaks  
> **Time:** 30–45 minutes

---

## What You're Learning

Most CORS tutorials start with the exploit. This one doesn't.

Before you break the Same-Origin Policy, you need to understand exactly what
it protects, where it lives, and — critically — what it does *not* protect.
Getting that model wrong leads to both missed vulnerabilities and false fixes.

---

## Part 1: What Is an Origin?

An **origin** is defined as the exact combination of three things:

```
scheme :// host : port
  ↑          ↑     ↑
 http    localhost  3000
```

All three must match for two URLs to share an origin. If **any one differs**,
the browser treats them as **cross-origin** and applies SOP restrictions.

| URL A | URL B | Same origin? | Why |
|---|---|---|---|
| `http://localhost:3000` | `http://localhost:3000/api` | ✅ Yes | Only path differs |
| `http://localhost:3000` | `http://localhost:3001` | ❌ No | Port differs |
| `http://localhost:3000` | `https://localhost:3000` | ❌ No | Scheme differs |
| `http://localhost:3000` | `http://bank.local:3000` | ❌ No | Host differs |
| `http://bank.local` | `http://reports.bank.local` | ❌ No | Subdomain = different host |

> **Common misconception:** Subdomains of the same root domain are NOT same-origin.
> `reports.bank.local` and `bank.local` are cross-origin.

---

## Part 2: What Does SOP Protect?

SOP restricts what JavaScript can **do** with cross-origin responses. Specifically:

**SOP blocks:** JavaScript reading the response body or headers from a cross-origin request.

**SOP does NOT block:**
- The request being *sent* (the server receives it and processes it)
- Embedded resources: `<img src>`, `<script src>`, `<link href>`
- Form submissions (they navigate the page — no JS reads the response)
- Redirects

This is the most important thing to internalize:

> **CORS is about reading. Not sending. The server always processes the request.**

This has a big implication for your security model. If a bank's transfer endpoint
relies on CORS to prevent cross-origin requests — it's broken. The request still
goes through. Only the response read is blocked.

---

## Part 3: Where Does CORS Fit?

CORS is the browser's mechanism for a server to **selectively unlock** cross-origin reads.

Without CORS headers from the server, SOP blocks JavaScript from reading responses.
With the right CORS headers, the server opts specific origins into read access.

```
No CORS headers:
  Browser → Request → Server (processes it) → Response (browser BLOCKS JS read)

With CORS headers:
  Browser → Request → Server → Response
  Server adds:  Access-Control-Allow-Origin: http://trusted.com
  Browser sees: "This origin is allowed" → JS can read the response
```

CORS does not protect the server from receiving requests. It only controls
whether JavaScript in a specific browser context can read the response.

---

## Part 4: The Preflight

For "non-simple" requests, the browser sends a **preflight** OPTIONS request first:

```
Browser → OPTIONS /api/data
          Origin: http://attacker.local
          Access-Control-Request-Method: PUT
          Access-Control-Request-Headers: Authorization

Server  → 204 No Content
          Access-Control-Allow-Origin: http://trusted.local
          Access-Control-Allow-Methods: GET, PUT
          Access-Control-Max-Age: 60

(if origin matches) Browser → PUT /api/data  (the real request)
(if origin rejected) Browser blocks the real request entirely
```

**Simple requests** skip the preflight (GET/POST with standard headers).
This matters because many CORS bugs are exploitable with simple GET requests
that don't trigger a preflight at all.

**Simple request criteria:**
- Method: GET, HEAD, or POST
- Headers: only `Accept`, `Accept-Language`, `Content-Language`, `Content-Type`
- Content-Type: only `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`

---

## Part 5: Observation Exercises

Start all servers: `docker compose up`

### Observation A — SOP enforcing in the browser

Open `http://localhost:3002/00-sop-demo.html` in Chrome.

1. Click **"Run same-origin fetch"** — note the response is readable.
2. Click **"Run cross-origin fetch"** — note the browser error in the output panel.
3. Open DevTools → Network. Find both requests. Note that the cross-origin request
   **did** reach the server (you'll see it in the Network tab) — but JS couldn't read the response.

**Question:** What error does the browser show? Does the request appear in the
Network tab even though JS couldn't read the response?

---

### Observation B — CORS unlocking a specific origin

In your terminal:

```bash
# Request from trusted origin (localhost:3001) — should be allowed
curl -v http://localhost:3000/api/safe \
  -H "Origin: http://localhost:3001" 2>&1 | grep -E "< Access-Control|< Vary"

# Request from untrusted origin (localhost:3002) — should be blocked
curl -v http://localhost:3000/api/safe \
  -H "Origin: http://localhost:3002" 2>&1 | grep -E "< Access-Control|< Vary"
```

**Question:** What CORS headers appear for each? What's missing in the second response?
Why does the Vary: Origin header matter?

---

### Observation C — Preflight in DevTools

Open `http://localhost:3002/00-sop-demo.html`.
Click **"Send a PUT request"**.

In DevTools → Network, find:
1. The OPTIONS preflight request — inspect its request and response headers.
2. The PUT request that follows — compare its headers to the preflight.

**Question:** Which headers in the OPTIONS response tell the browser whether
to proceed? What does `Access-Control-Max-Age` control?

---

### Observation D — CORS is a browser mechanism

```bash
# curl does NOT enforce CORS — it always reads the response regardless of headers
curl -s http://localhost:3000/api/account \
  -H "Origin: http://evil-attacker.xyz" | jq .flag
```

You'll receive the data even though the Origin is untrusted.

**Question:** Why? What does this tell you about using CORS as a server-side
security control? If your API returns sensitive data, what *else* should you
use besides CORS to protect it?

---

## Key Takeaways

Before moving to Exercise 01, you should be able to answer:

1. What three components define an origin?
2. Does SOP block the request from being sent, or from being read?
3. When does a preflight fire? When does it not?
4. If curl can read a cross-origin response, is CORS "broken"?
5. What is `Vary: Origin` and why does it matter for caches?

---

## Run the Observation Tests

```bash
npm run test:00
```

All tests should pass without any changes to `cors-config.js`. If they don't,
the lab setup has a problem — check `docker compose logs victim-api`.

The Part 4 tests contain explanatory `console.log` output that reinforces the
concepts above. Read them carefully.

---

## Further Reading

- [MDN: Same-Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [PortSwigger: CORS](https://portswigger.net/web-security/cors)
- [HTML Living Standard: Origin](https://html.spec.whatwg.org/multipage/origin.html)
