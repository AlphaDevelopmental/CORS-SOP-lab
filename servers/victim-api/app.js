/**
 * app.js — BankAPI Victim Server
 * ══════════════════════════════
 * The vulnerable bank API. Every route uses a different CORS handler
 * from cors-config.js — each one containing an intentional bug.
 *
 * Students never edit this file. They only edit cors-config.js.
 *
 * Port: 3000
 */

'use strict';

const express    = require('express');
const cookieParser = require('cookie-parser');
const {
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
} = require('./cors-config');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());

// ── Session cookie simulator ──────────────────────────────────────────────────
// Sets a mock session cookie on first visit. Subsequent cross-origin requests
// that include credentials will carry this cookie — demonstrating how CORS
// misconfigs leak credentialed sessions.
app.use((req, res, next) => {
  if (!req.cookies.session) {
    res.cookie('session', 'BANK_SESSION_abc123xyz', {
      httpOnly: true,
      sameSite: 'None',   // required for cross-origin cookie sending in 2026
      secure: false,      // false because we're on http:// in the lab
      path: '/',
    });
  }
  next();
});

// ─── SAFE BASELINE ───────────────────────────────────────────────────────────

/**
 * GET /api/health
 * Public. Correctly configured CORS. Used by Docker healthcheck and tests.
 */
app.get('/api/health', corsSecure, (req, res) => {
  res.json({ status: 'ok', server: 'BankAPI', port: PORT });
});

/**
 * GET /api/safe
 * Correctly configured endpoint — students compare this against the buggy ones.
 * Only ALLOWED_ORIGINS can read this cross-origin.
 */
app.get('/api/safe', corsSecure, (req, res) => {
  res.json({
    message: 'This endpoint is correctly configured.',
    origin_received: req.headers.origin || 'none',
    cors_policy: 'strict allowlist — only trusted origins can read this',
  });
});

// ─── EXERCISE 01: CORE MISCONFIGURATIONS ─────────────────────────────────────

/**
 * GET /api/public
 * Bug #1 — Wildcard origin
 * Any website can read this response.
 */
app.options('/api/public', corsWildcard);
app.get('/api/public', corsWildcard, (req, res) => {
  res.json({
    endpoint: '/api/public',
    bug: 1,
    description: 'Wildcard CORS — any origin can read this.',
    sensitive_data: 'PUBLIC_RATE: 4.2%',
    flag: 'CORS{wildcard_any_origin_reads_this}',
  });
});

/**
 * GET /api/account
 * Bug #2 — Origin reflection with credentials
 * Any origin is reflected back. Credentialed cross-origin reads succeed.
 */
app.options('/api/account', corsReflectOrigin);
app.get('/api/account', corsReflectOrigin, (req, res) => {
  res.json({
    endpoint: '/api/account',
    bug: 2,
    description: 'Origin reflection — your origin is trusted automatically.',
    user: 'Alice Johnson',
    account_number: 'GB29 NWBK 6016 1331 9268 19',
    balance: '$84,302.17',
    private_token: 'HACK_ME_2026_SECRET',
    session_cookie_present: !!req.cookies.session,
    flag: 'CORS{origin_reflection_exploit}',
  });
});

/**
 * GET /api/profile
 * Bug #3 — Null origin trusted
 * Sandboxed iframes generate null origin — bypasses all allowlists.
 */
app.options('/api/profile', corsNullOrigin);
app.get('/api/profile', corsNullOrigin, (req, res) => {
  res.json({
    endpoint: '/api/profile',
    bug: 3,
    description: 'Null origin trusted — sandboxed iframes bypass origin checks.',
    origin_received: req.headers.origin,
    user_id: 'usr_0x4f2a',
    email: 'alice@banklocal.com',
    phone: '+1-555-0199',
    flag: 'CORS{null_origin_trusted}',
  });
});

// ─── EXERCISE 02: BYPASS TECHNIQUES ──────────────────────────────────────────

/**
 * GET /api/transfers
 * Bug #4 — Prefix regex bypass
 * http://localhost:3001.evil.com passes the startsWith check.
 */
app.options('/api/transfers', corsRegexPrefix);
app.get('/api/transfers', corsRegexPrefix, (req, res) => {
  res.json({
    endpoint: '/api/transfers',
    bug: 4,
    description: 'Prefix match bypass — origin starts with trusted string.',
    origin_received: req.headers.origin,
    recent_transfers: [
      { to: 'Bob Smith',   amount: '$1,200', date: '2026-04-01' },
      { to: 'Carol Davis', amount: '$340',   date: '2026-04-10' },
    ],
    flag: 'CORS{regex_prefix_bypass}',
  });
});

/**
 * GET /api/statements
 * Bug #5 — Suffix regex bypass
 * http://evilbank.local passes the endsWith check.
 */
app.options('/api/statements', corsRegexSuffix);
app.get('/api/statements', corsRegexSuffix, (req, res) => {
  res.json({
    endpoint: '/api/statements',
    bug: 5,
    description: 'Suffix match bypass — origin ends with trusted string.',
    origin_received: req.headers.origin,
    statements: [
      { month: 'March 2026', closing_balance: '$84,302.17' },
      { month: 'February 2026', closing_balance: '$81,100.00' },
    ],
    flag: 'CORS{regex_suffix_bypass}',
  });
});

/**
 * GET /api/admin
 * Bug #6 — Subdomain wildcard pivot
 * Any *.bank.local is trusted. Compromise one subdomain → access admin API.
 */
app.options('/api/admin', corsSubdomainWildcard);
app.get('/api/admin', corsSubdomainWildcard, (req, res) => {
  res.json({
    endpoint: '/api/admin',
    bug: 6,
    description: 'Subdomain wildcard — any bank.local subdomain is trusted.',
    origin_received: req.headers.origin,
    admin_data: {
      total_users: 14820,
      flagged_accounts: 3,
      system_key: 'ADMIN_KEY_2026_PIVOT',
    },
    flag: 'CORS{subdomain_trust_pivot}',
  });
});

// ─── EXERCISE 03: PREFLIGHT & ADVANCED ───────────────────────────────────────

/**
 * PUT /api/settings
 * Bug #7 — Preflight cached 24 hours
 * Shows Max-Age abuse. Test suite checks the header value.
 */
app.options('/api/settings', corsPreflightCache);
app.put('/api/settings', corsPreflightCache, (req, res) => {
  res.json({
    endpoint: '/api/settings',
    bug: 7,
    description: 'Preflight Max-Age 86400 — cache persists for 24 hours.',
    updated: req.body,
    flag: 'CORS{preflight_cache_abuse}',
  });
});

/**
 * DELETE /api/account
 * Bug #8 — Unsafe methods allowed cross-origin
 * DELETE listed in Allow-Methods. Cross-origin state mutation succeeds.
 */
app.options('/api/account', corsUnsafeMethods);
app.delete('/api/account', corsUnsafeMethods, (req, res) => {
  res.json({
    endpoint: '/api/account',
    bug: 8,
    description: 'DELETE allowed cross-origin — CSRF via CORS.',
    action: 'Account deletion triggered cross-origin.',
    flag: 'CORS{unsafe_methods_cors_exploit}',
  });
});

/**
 * GET /api/internal
 * Bug #9 — Private Network Access header granted without origin check
 * Any public origin that sends the PNA preflight header gets access.
 */
app.options('/api/internal', corsPrivateNetwork);
app.get('/api/internal', corsPrivateNetwork, (req, res) => {
  res.json({
    endpoint: '/api/internal',
    bug: 9,
    description: 'PNA header granted without origin validation (2026 attack surface).',
    internal_config: {
      db_host: '10.0.0.5',
      admin_panel: 'http://10.0.0.1/admin',
      api_key: 'INTERNAL_2026_KEY',
    },
    flag: 'CORS{private_network_access_2026}',
  });
});

// ─── 404 FALLBACK ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found', path: req.path });
});

// ─── START ────────────────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n🏦  BankAPI (victim) running on http://localhost:${PORT}`);
    console.log(`    Edit servers/victim-api/cors-config.js to fix the bugs.\n`);
  });
}

module.exports = app;
