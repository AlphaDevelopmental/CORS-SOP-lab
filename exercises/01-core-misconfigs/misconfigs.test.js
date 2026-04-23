/**
 * Exercise 01 — Core Misconfigurations Test Suite
 *
 * Tests run against the live victim-api on localhost:3000.
 * Start the lab with: docker compose up
 *
 * 🔴 EXPLOIT TESTS  — PASS when the vulnerability exists. Fix the code → they FAIL.
 * 🟢 HARDENING TESTS — FAIL when the vulnerability exists. Fix the code → they PASS.
 *
 * Run: npm run test:01
 */

const VICTIM = 'http://localhost:3000';

// ─── HELPERS ──────────────────────────────────────────────────────────────────

async function get(path, originHeader, withCredentials = false) {
  const headers = {};
  if (originHeader) headers['Origin'] = originHeader;
  if (withCredentials) headers['Cookie'] = 'session=BANK_SESSION_abc123xyz';

  const res = await fetch(`${VICTIM}${path}`, { headers });
  return {
    status:      res.status,
    acao:        res.headers.get('access-control-allow-origin'),
    acac:        res.headers.get('access-control-allow-credentials'),
    vary:        res.headers.get('vary'),
    body:        await res.json().catch(() => null),
  };
}

async function options(path, originHeader) {
  const res = await fetch(`${VICTIM}${path}`, {
    method: 'OPTIONS',
    headers: {
      'Origin': originHeader,
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'Content-Type',
    },
  });
  return {
    status: res.status,
    acao:   res.headers.get('access-control-allow-origin'),
    acac:   res.headers.get('access-control-allow-credentials'),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// BASELINE — verify the lab is running and the safe endpoint works correctly
// ─────────────────────────────────────────────────────────────────────────────

describe('Baseline — Lab health and correct configuration', () => {

  test('Victim API is reachable', async () => {
    const r = await get('/api/health', null);
    expect(r.status).toBe(200);
  });

  test('🟢 /api/safe rejects untrusted origin (correct CORS)', async () => {
    const r = await get('/api/safe', 'http://localhost:3002');
    // Correct config: untrusted origin gets no ACAO header
    expect(r.acao).toBeNull();
  });

  test('🟢 /api/safe allows trusted origin (correct CORS)', async () => {
    const r = await get('/api/safe', 'http://localhost:3001');
    expect(r.acao).toBe('http://localhost:3001');
    expect(r.vary).toMatch(/origin/i); // Vary: Origin must be set
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #1 — Wildcard Origin
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #1 — Wildcard Origin (GET /api/public)', () => {

  test('🔴 [EXPLOIT] Any origin can read the response', async () => {
    const r = await get('/api/public', 'http://evil.attacker.local:9999');
    // When vulnerable: wildcard is set — browser allows any origin to read
    expect(r.acao).toBe('*');
    expect(r.body.flag).toBe('CORS{wildcard_any_origin_reads_this}');
    console.log('\n  🚩 FLAG:', r.body.flag);
  });

  test('🔴 [EXPLOIT] No origin header also returns wildcard', async () => {
    const r = await get('/api/public', null);
    expect(r.acao).toBe('*');
  });

  test('🟢 [HARDENING] Wildcard is not set after fix', async () => {
    const r = await get('/api/public', 'http://evil.attacker.local:9999');
    expect(r.acao).not.toBe('*');
  });

  test('🟢 [HARDENING] Response does not contain flag after fix', async () => {
    const r = await get('/api/public', 'http://evil.attacker.local:9999');
    // After fix: either no ACAO, or only trusted origin reflected — no flag
    if (r.acao === null || !r.acao) {
      expect(r.body?.flag).toBeUndefined();
    }
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #2 — Origin Reflection
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #2 — Origin Reflection with Credentials (GET /api/account)', () => {

  test('🔴 [EXPLOIT] Attacker origin is reflected back in ACAO', async () => {
    const attackerOrigin = 'http://localhost:3002';
    const r = await get('/api/account', attackerOrigin, true);

    expect(r.acao).toBe(attackerOrigin);    // our origin echoed back
    expect(r.acac).toBe('true');            // credentials allowed
    expect(r.body.flag).toBe('CORS{origin_reflection_exploit}');
    console.log('\n  🚩 FLAG:', r.body.flag);
    console.log('  ACAO header:', r.acao, '← reflected from attacker');
  });

  test('🔴 [EXPLOIT] Any arbitrary origin is reflected', async () => {
    const randomOrigin = 'http://totallyrandom.evil.xyz';
    const r = await get('/api/account', randomOrigin, true);
    expect(r.acao).toBe(randomOrigin);
    expect(r.acac).toBe('true');
  });

  test('🟢 [HARDENING] Untrusted origin is not reflected after fix', async () => {
    const r = await get('/api/account', 'http://localhost:3002', true);
    expect(r.acao).not.toBe('http://localhost:3002');
  });

  test('🟢 [HARDENING] Trusted origin still works after fix', async () => {
    const r = await get('/api/account', 'http://localhost:3001', true);
    expect(r.acao).toBe('http://localhost:3001');
    expect(r.acac).toBe('true');
  });

  test('🟢 [HARDENING] Vary: Origin header is present after fix', async () => {
    const r = await get('/api/account', 'http://localhost:3001');
    // Vary: Origin is critical — tells CDNs not to cache the response for all origins
    expect(r.vary).toMatch(/origin/i);
  });

  test('🟢 [HARDENING] Preflight for untrusted origin is rejected', async () => {
    const r = await options('/api/account', 'http://localhost:3002');
    expect(r.acao).not.toBe('http://localhost:3002');
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #3 — Null Origin Trusted
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #3 — Null Origin Trusted (GET /api/profile)', () => {

  test('🔴 [EXPLOIT] Origin: null is accepted and reflected', async () => {
    const r = await get('/api/profile', 'null', true);
    expect(r.acao).toBe('null');
    expect(r.acac).toBe('true');
    expect(r.body.flag).toBe('CORS{null_origin_trusted}');
    console.log('\n  🚩 FLAG:', r.body.flag);
  });

  test('🔴 [EXPLOIT] Missing origin also grants access', async () => {
    const r = await get('/api/profile', null);
    // When vulnerable: no origin header → treated as null → access granted
    expect(r.status).toBe(200);
    expect(r.body.flag).toBe('CORS{null_origin_trusted}');
  });

  test('🟢 [HARDENING] Origin: null is rejected after fix', async () => {
    const r = await get('/api/profile', 'null', true);
    expect(r.acao).not.toBe('null');
    // Null origin should never be trusted
    if (r.acao) expect(r.acao).not.toBe('null');
  });

  test('🟢 [HARDENING] No Access-Control-Allow-Credentials with null origin', async () => {
    const r = await get('/api/profile', 'null', true);
    expect(r.acac).not.toBe('true');
  });

});
