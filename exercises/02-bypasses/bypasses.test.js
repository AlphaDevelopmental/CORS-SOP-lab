/**
 * Exercise 02 — Bypass Techniques Test Suite
 *
 * Run: npm run test:02
 *
 * 🔴 EXPLOIT TESTS  — PASS when vulnerable. Fix → they FAIL.
 * 🟢 HARDENING TESTS — FAIL when vulnerable. Fix → they PASS.
 */

const VICTIM = 'http://localhost:3000';

async function get(path, originHeader, withCredentials = false) {
  const headers = {};
  if (originHeader) headers['Origin'] = originHeader;
  if (withCredentials) headers['Cookie'] = 'session=BANK_SESSION_abc123xyz';
  const res = await fetch(`${VICTIM}${path}`, { headers });
  return {
    status: res.status,
    acao:   res.headers.get('access-control-allow-origin'),
    acac:   res.headers.get('access-control-allow-credentials'),
    body:   await res.json().catch(() => null),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG #4 — Prefix Match Bypass
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #4 — Regex Prefix Bypass (GET /api/transfers)', () => {

  test('🔴 [EXPLOIT] Origin starting with trusted string passes prefix check', async () => {
    // http://localhost:3001.evil.com starts with 'http://localhost:3001'
    const bypassOrigin = 'http://localhost:3001.evil.com';
    const r = await get('/api/transfers', bypassOrigin, true);

    expect(r.acao).toBe(bypassOrigin);   // bypass succeeded — origin reflected
    expect(r.acac).toBe('true');
    expect(r.body.flag).toBe('CORS{regex_prefix_bypass}');
    console.log('\n  🚩 FLAG:', r.body.flag);
    console.log('  Bypass origin:', bypassOrigin);
  });

  test('🔴 [EXPLOIT] Extended port number also bypasses prefix check', async () => {
    // http://localhost:30010 also starts with http://localhost:3001
    const bypassOrigin = 'http://localhost:30010';
    const r = await get('/api/transfers', bypassOrigin, true);
    expect(r.acao).toBe(bypassOrigin);
  });

  test('🟢 [HARDENING] Prefix-bypass origin is rejected after fix', async () => {
    const r = await get('/api/transfers', 'http://localhost:3001.evil.com', true);
    expect(r.acao).not.toBe('http://localhost:3001.evil.com');
  });

  test('🟢 [HARDENING] Legitimate trusted origin still works after fix', async () => {
    const r = await get('/api/transfers', 'http://localhost:3001', true);
    expect(r.acao).toBe('http://localhost:3001');
    expect(r.acac).toBe('true');
  });

  test('🟢 [HARDENING] Untrusted origin with similar prefix is rejected', async () => {
    const r = await get('/api/transfers', 'http://localhost:3001xyz.evil.com', true);
    expect(r.acao).not.toMatch(/localhost:3001xyz/);
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #5 — Suffix Match Bypass
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #5 — Regex Suffix Bypass (GET /api/statements)', () => {

  test('🔴 [EXPLOIT] Origin ending with "bank.local" passes suffix check', async () => {
    const bypassOrigin = 'http://evilbank.local';
    const r = await get('/api/statements', bypassOrigin, true);

    expect(r.acao).toBe(bypassOrigin);
    expect(r.acac).toBe('true');
    expect(r.body.flag).toBe('CORS{regex_suffix_bypass}');
    console.log('\n  🚩 FLAG:', r.body.flag);
    console.log('  Bypass origin:', bypassOrigin);
  });

  test('🔴 [EXPLOIT] Any domain ending in "bank.local" passes', async () => {
    const bypassOrigin = 'http://notabank.local';
    const r = await get('/api/statements', bypassOrigin, true);
    expect(r.acao).toBe(bypassOrigin);
  });

  test('🟢 [HARDENING] Suffix-bypass origin is rejected after fix', async () => {
    const r = await get('/api/statements', 'http://evilbank.local', true);
    expect(r.acao).not.toBe('http://evilbank.local');
  });

  test('🟢 [HARDENING] Legitimate subdomain still works after fix', async () => {
    const r = await get('/api/statements', 'http://localhost:3001', true);
    expect(r.acao).toBe('http://localhost:3001');
  });

  test('🟢 [HARDENING] Suffix bypass with different prefix is rejected', async () => {
    const r = await get('/api/statements', 'http://totally-not-a.bank.local', true);
    // After fix: only explicitly allowed origins should pass
    expect(r.acao).not.toBe('http://totally-not-a.bank.local');
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #6 — Subdomain Wildcard Trust Pivot
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #6 — Subdomain Wildcard Trust Pivot (GET /api/admin)', () => {

  test('🔴 [EXPLOIT] Trusted subdomain origin (localhost:3001) reads admin data', async () => {
    // The trusted subdomain is localhost:3001 — simulates reports.bank.local
    // If it were compromised, it could make this exact request
    const r = await get('/api/admin', 'http://localhost:3001', true);

    expect(r.acao).toBe('http://localhost:3001');
    expect(r.acac).toBe('true');
    expect(r.body.flag).toBe('CORS{subdomain_trust_pivot}');
    console.log('\n  🚩 FLAG:', r.body.flag);
    console.log('  Pivot: compromised reports.bank.local reads admin data');
  });

  test('🔴 [EXPLOIT] Any *.bank.local pattern passes wildcard regex', async () => {
    // Any subdomain matching /^https?:\/\/[a-z0-9-]+\.bank\.local/ is trusted
    // In a real attack: attacker takes over forgotten-dev.bank.local
    const pivotOrigin = 'http://forgotten-dev.bank.local';
    const r = await get('/api/admin', pivotOrigin, true);
    expect(r.acao).toBe(pivotOrigin);
    expect(r.body.flag).toBe('CORS{subdomain_trust_pivot}');
  });

  test('🟢 [HARDENING] Non-allowlisted subdomain rejected after fix', async () => {
    const r = await get('/api/admin', 'http://forgotten-dev.bank.local', true);
    expect(r.acao).not.toBe('http://forgotten-dev.bank.local');
  });

  test('🟢 [HARDENING] Untrusted origin completely rejected', async () => {
    const r = await get('/api/admin', 'http://localhost:3002', true);
    expect(r.acao).toBeNull();
    expect(r.status).toBe(200); // server still returns 200 — just no ACAO header
  });

  test('🟢 [HARDENING] Admin endpoint requires explicit origin allowlist entry', async () => {
    // After fix: admin route should have a very strict allowlist
    // Only explicitly named origins — no wildcards or regex patterns
    const r = await get('/api/admin', 'http://localhost:3001', true);
    // localhost:3001 may or may not be in the post-fix allowlist
    // The key is that wildcard subdomains no longer pass
    const randomSub = await get('/api/admin', 'http://random.bank.local', true);
    expect(randomSub.acao).not.toBe('http://random.bank.local');
  });

});
