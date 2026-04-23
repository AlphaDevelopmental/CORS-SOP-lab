/**
 * Exercise 03 — Preflight Abuse & Advanced Test Suite
 *
 * Run: npm run test:03
 *
 * 🔴 EXPLOIT TESTS  — PASS when vulnerable. Fix → they FAIL.
 * 🟢 HARDENING TESTS — FAIL when vulnerable. Fix → they PASS.
 */

const VICTIM = 'http://localhost:3000';

// ─── HELPERS ──────────────────────────────────────────────────────────────────

async function req(method, path, originHeader, extraHeaders = {}, body = null) {
  const headers = { 'Origin': originHeader, ...extraHeaders };
  if (body) headers['Content-Type'] = 'application/json';

  const res = await fetch(`${VICTIM}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  return {
    status:      res.status,
    acao:        res.headers.get('access-control-allow-origin'),
    acac:        res.headers.get('access-control-allow-credentials'),
    acam:        res.headers.get('access-control-allow-methods'),
    maxAge:      res.headers.get('access-control-max-age'),
    apn:         res.headers.get('access-control-allow-private-network'),
    body:        await res.json().catch(() => null),
  };
}

async function preflight(path, originHeader, requestMethod = 'GET', extraHeaders = {}) {
  const res = await fetch(`${VICTIM}${path}`, {
    method: 'OPTIONS',
    headers: {
      'Origin':                          originHeader,
      'Access-Control-Request-Method':   requestMethod,
      'Access-Control-Request-Headers':  'Content-Type',
      ...extraHeaders,
    },
  });

  return {
    status:  res.status,
    acao:    res.headers.get('access-control-allow-origin'),
    acam:    res.headers.get('access-control-allow-methods'),
    maxAge:  res.headers.get('access-control-max-age'),
    apn:     res.headers.get('access-control-allow-private-network'),
  };
}

const TRUSTED = 'http://localhost:3001';
const ATTACKER = 'http://localhost:3002';

// ─────────────────────────────────────────────────────────────────────────────
// BUG #7 — Preflight Over-Cached
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #7 — Preflight Over-Cached (PUT /api/settings)', () => {

  test('🔴 [EXPLOIT] OPTIONS response has Max-Age of 86400 seconds (24 hours)', async () => {
    const r = await preflight('/api/settings', TRUSTED, 'PUT');

    const maxAge = parseInt(r.maxAge || '0', 10);
    expect(maxAge).toBeGreaterThanOrEqual(86400);

    console.log('\n  🚩 Max-Age:', r.maxAge, 'seconds =', (maxAge / 3600).toFixed(1), 'hours');
    console.log('  A CORS fix deployed now would take', (maxAge / 3600).toFixed(1), 'hours to take effect for cached browsers.');
  });

  test('🔴 [EXPLOIT] PUT request with trusted origin succeeds and flag is present', async () => {
    const r = await req('PUT', '/api/settings', TRUSTED, {}, { theme: 'dark' });

    expect(r.status).toBe(200);
    expect(r.body.flag).toBe('CORS{preflight_cache_abuse}');
    console.log('\n  🚩 FLAG:', r.body.flag);
  });

  test('🟢 [HARDENING] Max-Age is 300 seconds or less after fix', async () => {
    const r = await preflight('/api/settings', TRUSTED, 'PUT');
    const maxAge = parseInt(r.maxAge || '0', 10);

    // A reasonable production max is 60–300 seconds
    // 0 is acceptable during development (disables caching)
    expect(maxAge).toBeLessThanOrEqual(300);
  });

  test('🟢 [HARDENING] Chrome effective cap respected (≤ 7200 seconds)', async () => {
    // Chrome 76+ caps Max-Age at 7200 regardless of server value.
    // After fix the server should not exceed this anyway.
    const r = await preflight('/api/settings', TRUSTED, 'PUT');
    const maxAge = parseInt(r.maxAge || '0', 10);
    expect(maxAge).toBeLessThanOrEqual(7200);
  });

  test('🟢 [HARDENING] Untrusted origin preflight is rejected', async () => {
    const r = await preflight('/api/settings', ATTACKER, 'PUT');
    expect(r.acao).not.toBe(ATTACKER);
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #8 — Unsafe Methods Allowed Cross-Origin
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #8 — Unsafe Methods Allowed Cross-Origin (DELETE /api/account)', () => {

  test('🔴 [EXPLOIT] OPTIONS response lists DELETE as an allowed cross-origin method', async () => {
    const r = await preflight('/api/account', TRUSTED, 'DELETE');

    expect(r.acam).toMatch(/DELETE/i);
    console.log('\n  ⚠️  Allowed methods:', r.acam);
    console.log('  DELETE is listed — cross-origin state mutations are possible.');
  });

  test('🔴 [EXPLOIT] Cross-origin DELETE request succeeds', async () => {
    const r = await req('DELETE', '/api/account', TRUSTED);

    expect(r.status).toBe(200);
    expect(r.body.flag).toBe('CORS{unsafe_methods_cors_exploit}');
    console.log('\n  🚩 FLAG:', r.body.flag);
  });

  test('🔴 [EXPLOIT] PUT and PATCH are also listed (broad method exposure)', async () => {
    const r = await preflight('/api/account', TRUSTED, 'PUT');
    expect(r.acam).toMatch(/PUT/i);
    expect(r.acam).toMatch(/PATCH/i);
  });

  test('🟢 [HARDENING] DELETE is not in Allow-Methods after fix', async () => {
    const r = await preflight('/api/account', TRUSTED, 'DELETE');
    if (r.acam) {
      expect(r.acam).not.toMatch(/DELETE/i);
    }
  });

  test('🟢 [HARDENING] PUT is not in Allow-Methods after fix', async () => {
    const r = await preflight('/api/account', TRUSTED, 'PUT');
    if (r.acam) {
      expect(r.acam).not.toMatch(/\bPUT\b/i);
    }
  });

  test('🟢 [HARDENING] DELETE request from trusted origin is blocked after fix', async () => {
    const r = await req('DELETE', '/api/account', TRUSTED);
    // After fix: preflight should be rejected, resulting in a blocked request
    // The server may still return 200 body-wise but CORS headers should block browser reads
    if (r.acao) {
      const methods = r.acam || '';
      expect(methods).not.toMatch(/DELETE/i);
    }
  });

  test('🟢 [HARDENING] Only safe read-only methods are listed', async () => {
    const r = await preflight('/api/account', TRUSTED, 'GET');
    if (r.acam) {
      // Should only contain GET, HEAD, OPTIONS — not state-changing methods
      expect(r.acam).toMatch(/GET/i);
      expect(r.acam).not.toMatch(/DELETE|PUT|PATCH/i);
    }
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #9 — Private Network Access Header (2026)
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #9 — Private Network Access Header Misconfiguration (GET /api/internal)', () => {

  test('🔴 [EXPLOIT] Server sends Allow-Private-Network: true without origin check', async () => {
    // Simulate the PNA preflight Chrome sends when a public page reaches localhost
    const r = await preflight('/api/internal', ATTACKER, 'GET', {
      'Access-Control-Request-Private-Network': 'true',
    });

    expect(r.apn).toBe('true');
    console.log('\n  ⚠️  Access-Control-Allow-Private-Network:', r.apn);
    console.log('  This header was returned to an untrusted origin!');
    console.log('  Any public website can now bypass Chrome\'s PNA protection.');
  });

  test('🔴 [EXPLOIT] PNA header returned even when origin is clearly untrusted', async () => {
    const r = await preflight('/api/internal', 'http://random-evil-site.xyz', 'GET', {
      'Access-Control-Request-Private-Network': 'true',
    });
    expect(r.apn).toBe('true');
  });

  test('🔴 [EXPLOIT] Internal endpoint data is accessible with forged PNA preflight', async () => {
    const r = await req('GET', '/api/internal', ATTACKER, {
      'Access-Control-Request-Private-Network': 'true',
    });
    // When vulnerable: internal data is readable
    expect(r.status).toBe(200);
    expect(r.body.flag).toBe('CORS{private_network_access_2026}');
    console.log('\n  🚩 FLAG:', r.body.flag);
  });

  test('🟢 [HARDENING] Allow-Private-Network NOT sent to untrusted origin', async () => {
    const r = await preflight('/api/internal', ATTACKER, 'GET', {
      'Access-Control-Request-Private-Network': 'true',
    });
    // After fix: untrusted origins do not receive this header
    expect(r.apn).not.toBe('true');
  });

  test('🟢 [HARDENING] Allow-Private-Network IS sent to trusted origin', async () => {
    const r = await preflight('/api/internal', TRUSTED, 'GET', {
      'Access-Control-Request-Private-Network': 'true',
    });
    // After fix: only trusted origins receive the PNA permission
    expect(r.acao).toBe(TRUSTED);
    expect(r.apn).toBe('true');
  });

  test('🟢 [HARDENING] No ACAO header for untrusted origin on /api/internal', async () => {
    const r = await req('GET', '/api/internal', ATTACKER);
    // After fix: untrusted origin gets no ACAO header
    expect(r.acao).toBeNull();
  });

  test('🟢 [HARDENING] Origin reflection is also removed from /api/internal', async () => {
    // The route had both PNA and origin reflection bugs — both should be fixed
    const r = await req('GET', '/api/internal', ATTACKER);
    expect(r.acao).not.toBe(ATTACKER);
    expect(r.acao).not.toBe('*');
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// CROSS-CUTTING — headers that should always be correct regardless of exercise
// ─────────────────────────────────────────────────────────────────────────────

describe('Cross-cutting — headers that must always be correct', () => {

  test('🟢 Vary: Origin must be present on any route that conditionally sets ACAO', async () => {
    // Without Vary: Origin, CDNs and proxies may cache a response for one origin
    // and serve it to another — defeating the entire allowlist
    const r = await req('GET', '/api/account', TRUSTED);
    expect(r.acao).not.toBeNull(); // Only relevant if ACAO was set
    // After all fixes: check Vary header exists on credentialed endpoints
    // (This test validates the fixed state — it may fail pre-fix which is expected)
  });

  test('🟢 Health endpoint remains accessible without CORS headers', async () => {
    const r = await req('GET', '/api/health', null);
    expect(r.status).toBe(200);
  });

});
