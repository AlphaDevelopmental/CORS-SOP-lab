/**
 * cors-config.js — BankAPI CORS Configuration
 * ════════════════════════════════════════════
 * THIS IS THE FILE YOU WILL EDIT DURING THE LAB.
 *
 * Each route in app.js imports one handler from this file to set
 * its CORS headers. Every handler below contains an intentional bug.
 *
 * Your workflow for each exercise:
 *   1. Read the handler — identify what's wrong
 *   2. Open the browser exploit page — confirm the bug fires
 *   3. Run the Jest tests — 🔴 exploit tests pass, 🟢 hardening tests fail
 *   4. Fix the handler below
 *   5. Re-run tests — 🔴 exploit tests fail, 🟢 hardening tests pass
 *
 * ─── BUG REGISTRY ────────────────────────────────────────────────────────────
 *  #1  corsWildcard()          Wildcard origin + credentials
 *  #2  corsReflectOrigin()     Blind origin reflection
 *  #3  corsNullOrigin()        Trusting the null origin
 *  #4  corsRegexPrefix()       Prefix-only regex match
 *  #5  corsRegexSuffix()       Suffix-only regex match
 *  #6  corsSubdomainWildcard() All subdomains blindly trusted
 *  #7  corsPreflightCache()    Preflight result cached 24 hours
 *  #8  corsUnsafeMethods()     DELETE/PUT allowed cross-origin
 *  #9  corsPrivateNetwork()    Private Network Access header missing
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

// The only origins that should EVER be trusted by this API
const ALLOWED_ORIGINS = [
  'http://localhost:3001',   // trusted-subdomain (reports.bank.local)
];

// ─────────────────────────────────────────────────────────────────────────────
// BUG #1 — Wildcard + Credentials
// Route: GET /api/public
// ─────────────────────────────────────────────────────────────────────────────
//
// What's wrong:
//   Access-Control-Allow-Origin: * means ANY website can read this response.
//   When combined with Access-Control-Allow-Credentials: true, browsers
//   *should* block this (the spec forbids the combination) — but the API
//   is one header-typo away from leaking credentialed data to any origin.
//   Even without credentials, a wildcard exposes all response data publicly.
//
// Modern context (2026):
//   Chrome 94+ enforces the wildcard+credentials rejection strictly.
//   But many developers set * thinking it's safe, then later add credentials
//   without realising the implication. The misconfiguration is extremely common.
//
// Fix: Replace * with an explicit origin from ALLOWED_ORIGINS, or remove
//      Allow-Credentials entirely if the endpoint is truly public.
//
function corsWildcard(req, res, next) {
  // ⚠️  BUG #1: Wildcard allows any origin to read this response.
  //     Even without credentials, sensitive data is exposed to all websites.
  res.setHeader('Access-Control-Allow-Origin', '*');

  // ⚠️  If you uncomment the next line alongside the wildcard above,
  //     browsers will reject responses (spec violation) — but it's still
  //     a misconfiguration waiting to happen when * is later narrowed badly.
  // res.setHeader('Access-Control-Allow-Credentials', 'true');

  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG #2 — Blind Origin Reflection
// Route: GET /api/account
// ─────────────────────────────────────────────────────────────────────────────
//
// What's wrong:
//   The server reads whatever origin the browser sends and echoes it back
//   as Access-Control-Allow-Origin. This is equivalent to a wildcard —
//   but worse, because it also works with Allow-Credentials: true.
//   Any website can make a credentialed cross-origin request and read
//   the response, including session cookies and auth tokens.
//
// This is the bug in your original snippet. It is the #1 most common
// CORS vulnerability in production APIs (PortSwigger research, 2023-2025).
//
// Fix: Validate the incoming Origin against an explicit allowlist.
//      Only reflect it back if it matches.
//
function corsReflectOrigin(req, res, next) {
  const origin = req.headers.origin;

  // ⚠️  BUG #2: Reflecting whatever origin the client sends.
  //     An attacker at evil.attacker.local sends Origin: http://localhost:3002
  //     and receives Access-Control-Allow-Origin: http://localhost:3002 back.
  //     With Allow-Credentials: true, their cookies are included too.
  res.setHeader('Access-Control-Allow-Origin', origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG #3 — Null Origin Trusted
// Route: GET /api/profile
// ─────────────────────────────────────────────────────────────────────────────
//
// What's wrong:
//   Some servers explicitly trust the string "null" as an origin.
//   Browsers send Origin: null in several cases:
//     - Requests from sandboxed iframes (<iframe sandbox>)
//     - Requests from local files (file://)
//     - Redirected cross-origin requests (in some browsers)
//     - data: URIs
//
//   An attacker can host a sandboxed iframe that sends Origin: null and
//   bypasses all origin-based allowlists. The iframe can be embedded on
//   any malicious website.
//
// Fix: Never trust the null origin. Treat it as an untrusted origin.
//
function corsNullOrigin(req, res, next) {
  const origin = req.headers.origin;

  // ⚠️  BUG #3: Explicitly trusting the "null" origin.
  //     Attackers use sandboxed iframes to generate null-origin requests.
  if (origin === 'null' || !origin) {
    res.setHeader('Access-Control-Allow-Origin', 'null');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG #4 — Regex Prefix Bypass
// Route: GET /api/transfers
// ─────────────────────────────────────────────────────────────────────────────
//
// What's wrong:
//   The developer wanted to allow only origins starting with
//   "http://localhost:3001". They used startsWith() — but forgot that
//   an attacker can register a domain that *starts with* the trusted string.
//
//   Bypassed by: http://localhost:3001.evil.com
//                http://localhost:30010  (different port)
//
// Fix: Use strict equality against ALLOWED_ORIGINS, not prefix matching.
//
function corsRegexPrefix(req, res, next) {
  const origin = req.headers.origin || '';

  // ⚠️  BUG #4: Prefix match allows any origin that starts with the trusted string.
  //     http://localhost:3001.evil.com passes this check.
  if (origin.startsWith('http://localhost:3001')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG #5 — Regex Suffix Bypass
// Route: GET /api/statements
// ─────────────────────────────────────────────────────────────────────────────
//
// What's wrong:
//   The developer wanted to allow any *.bank.local subdomain using endsWith().
//   An attacker registers: http://evilbank.local — passes the check.
//   Or:                    http://notbank.local — also passes.
//
//   The correct approach is a regex anchored at both ends with a dot separator:
//   /^https?:\/\/([a-z0-9-]+\.)?bank\.local(:\d+)?$/
//
// Fix: Use a properly anchored regex or strict allowlist.
//
function corsRegexSuffix(req, res, next) {
  const origin = req.headers.origin || '';

  // ⚠️  BUG #5: Suffix match allows any origin ending in "bank.local".
  //     http://evilbank.local and http://notabank.local both pass.
  if (origin.endsWith('bank.local')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG #6 — Subdomain Wildcard Trust Pivot
// Route: GET /api/admin
// ─────────────────────────────────────────────────────────────────────────────
//
// What's wrong:
//   The API trusts ALL *.bank.local subdomains. If an attacker compromises
//   any one subdomain (e.g. a forgotten dev server, a third-party widget
//   hosted at assets.bank.local), they inherit full trust and can read
//   admin-level API responses with the victim's credentials.
//
//   This is the "trusted subdomain pivot" — a two-step attack:
//     1. Compromise reports.bank.local (XSS, subdomain takeover, etc.)
//     2. Use it to make credentialed requests to /api/admin
//
//   The trusted-subdomain server (localhost:3001) demonstrates step 2.
//   It has an endpoint that, when visited, makes a cross-origin fetch
//   to /api/admin and returns the response — as if compromised.
//
// Fix: Only trust specific, explicitly listed subdomains. Not *.
//
function corsSubdomainWildcard(req, res, next) {
  const origin = req.headers.origin || '';

  // ⚠️  BUG #6: Any bank.local subdomain is trusted.
  //     Attacker compromises reports.bank.local → reads /api/admin freely.
  const subdomainRegex = /^https?:\/\/[a-z0-9-]+\.bank\.local(:\d+)?$/;
  if (subdomainRegex.test(origin) || origin === 'http://localhost:3001') {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG #7 — Preflight Over-Cached
// Route: PUT /api/settings
// ─────────────────────────────────────────────────────────────────────────────
//
// What's wrong:
//   Access-Control-Max-Age: 86400 tells browsers to cache the preflight
//   response for 24 hours. If an admin tightens CORS policy mid-day,
//   browsers that already cached the permissive preflight will continue
//   using the old permissions until the cache expires.
//
//   In a real incident: you discover a CORS misconfiguration at 9am,
//   fix it at 9:05am — but anyone who hit the endpoint before the fix
//   has a 24-hour window where their browser still thinks the old policy
//   applies, and their cached preflight approvals still grant access.
//
// Modern context (2026):
//   Chrome caps Max-Age at 7200 seconds (2h) regardless of what the
//   server sends. Firefox caps at 86400. Safari caps at 600.
//   But even 2 hours is dangerously long for a live misconfiguration.
//
// Fix: Set Max-Age to a short value (0 during development, 60-300 in prod).
//
function corsPreflightCache(req, res, next) {
  const origin = req.headers.origin || '';

  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // ⚠️  BUG #7: 24-hour preflight cache. A fix to CORS policy won't
  //     take effect for browsers that already cached this response.
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG #8 — Unsafe Methods Allowed Cross-Origin
// Route: DELETE /api/account
// ─────────────────────────────────────────────────────────────────────────────
//
// What's wrong:
//   Access-Control-Allow-Methods includes DELETE, PUT, and PATCH.
//   This means cross-origin requests can trigger state-changing operations
//   on the server — not just read data, but delete accounts, transfer funds,
//   change settings — using the victim's own session cookies.
//
//   This is CSRF at the CORS layer. Traditional CSRF tokens don't help
//   if the server's own CORS config permits the cross-origin request.
//
// Fix: Only list methods that legitimately need cross-origin access.
//      State-changing methods (DELETE, PUT, PATCH) should be same-origin only,
//      or protected by both CORS AND CSRF tokens.
//
function corsUnsafeMethods(req, res, next) {
  const origin = req.headers.origin || '';

  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  // ⚠️  BUG #8: DELETE and PUT are listed as cross-origin-allowed methods.
  //     A malicious page on an allowed origin can delete accounts or
  //     transfer funds cross-origin using the victim's cookies.
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '60');

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG #9 — Private Network Access Header Missing (2026)
// Route: GET /api/internal
// ─────────────────────────────────────────────────────────────────────────────
//
// What's wrong:
//   Chrome 98+ (fully enforced by 2024) introduced Private Network Access (PNA).
//   When a PUBLIC website (e.g. https://evil.com) tries to fetch a PRIVATE
//   network resource (localhost, 192.168.x.x, 10.x.x.x), Chrome sends a
//   preflight with the header:
//
//     Access-Control-Request-Private-Network: true
//
//   The server must respond with:
//
//     Access-Control-Allow-Private-Network: true
//
//   ...otherwise Chrome blocks the request. This protects internal services
//   from being reached by malicious public websites.
//
//   The vulnerability: if the server DOES respond with this header without
//   also validating the origin, it opts internal endpoints into cross-origin
//   access from any public website — defeating PNA protection entirely.
//
// Modern context (2026):
//   PNA is now enforced by default in Chrome and Edge. Firefox support
//   is in progress. This is the most commonly misunderstood CORS header
//   in 2025-2026 because it's new and most developers haven't heard of it.
//
// Fix: Only respond with Access-Control-Allow-Private-Network: true
//      when the origin is explicitly trusted. Never send it to unknown origins.
//
function corsPrivateNetwork(req, res, next) {
  const origin = req.headers.origin || '';

  // ⚠️  BUG #9: Allow-Private-Network sent to any origin that asks.
  //     A public malicious website sends the preflight — and this server
  //     opts itself into being reachable cross-origin from anywhere.
  if (req.headers['access-control-request-private-network']) {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
  }

  // Also reflecting origin (compounding the damage)
  res.setHeader('Access-Control-Allow-Origin', origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// CORRECT IMPLEMENTATION (reference — do not modify)
// ─────────────────────────────────────────────────────────────────────────────
//
// This is what a correct CORS handler looks like. Used by /api/health
// and /api/safe — so students always have a working baseline to compare against.
//
function corsSecure(req, res, next) {
  const origin = req.headers.origin;

  // Strict allowlist — only reflect if origin is explicitly trusted
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin'); // critical: tells CDNs this response varies by origin
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '60');

  // PNA: only grant private network access to trusted origins
  if (req.headers['access-control-request-private-network'] &&
      origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
  }

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

module.exports = {
  corsWildcard,
  corsReflectOrigin,
  corsNullOrigin,
  corsRegexPrefix,
  corsRegexSuffix,
  corsSubdomainWildcard,
  corsPreflightCache,
  corsUnsafeMethods,
  corsPrivateNetwork,
  corsSecure,
  ALLOWED_ORIGINS,
};
