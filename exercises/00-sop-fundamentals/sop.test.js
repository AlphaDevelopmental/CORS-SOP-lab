/**
 * Exercise 00 — SOP Fundamentals Test Suite
 *
 * No exploit/harden pattern here — these are observation tests.
 * They verify your understanding of what SOP enforces and what CORS unlocks.
 * All tests should PASS without any code changes.
 *
 * Run: npm run test:00
 *
 * Read each test name as a statement of fact about how browsers work.
 * If a test fails, it means the lab is misconfigured — not that you
 * need to fix cors-config.js.
 */

const VICTIM = 'http://localhost:3000';

async function get(path, originHeader) {
  const headers = {};
  if (originHeader) headers['Origin'] = originHeader;
  const res = await fetch(`${VICTIM}${path}`, { headers });
  return {
    status: res.status,
    acao:   res.headers.get('access-control-allow-origin'),
    acac:   res.headers.get('access-control-allow-credentials'),
    vary:   res.headers.get('vary'),
    body:   await res.json().catch(() => null),
  };
}

async function options(path, origin) {
  const res = await fetch(`${VICTIM}${path}`, {
    method: 'OPTIONS',
    headers: {
      'Origin':                         origin,
      'Access-Control-Request-Method':  'GET',
      'Access-Control-Request-Headers': 'Content-Type',
    },
  });
  return {
    status:  res.status,
    acao:    res.headers.get('access-control-allow-origin'),
    acam:    res.headers.get('access-control-allow-methods'),
    maxAge:  res.headers.get('access-control-max-age'),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// PART 1: The API is reachable
// ─────────────────────────────────────────────────────────────────────────────

describe('Part 1 — Lab Setup Verification', () => {

  test('Victim API is running on port 3000', async () => {
    const r = await get('/api/health', null);
    expect(r.status).toBe(200);
    expect(r.body.status).toBe('ok');
  });

  test('API returns JSON responses', async () => {
    const r = await get('/api/health', null);
    expect(r.body).toBeDefined();
    expect(typeof r.body).toBe('object');
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// PART 2: What CORS headers look like when correct
// ─────────────────────────────────────────────────────────────────────────────

describe('Part 2 — Correct CORS in Action (/api/safe)', () => {

  test('Trusted origin (localhost:3001) receives ACAO header', async () => {
    const r = await get('/api/safe', 'http://localhost:3001');
    // The server explicitly allows localhost:3001
    expect(r.acao).toBe('http://localhost:3001');
  });

  test('Trusted origin also receives Allow-Credentials: true', async () => {
    const r = await get('/api/safe', 'http://localhost:3001');
    expect(r.acac).toBe('true');
  });

  test('Vary: Origin header is set (critical for CDN cache correctness)', async () => {
    // Without Vary: Origin, a CDN might cache the response for one origin
    // and return it to a different origin — defeating the allowlist entirely
    const r = await get('/api/safe', 'http://localhost:3001');
    expect(r.vary).toMatch(/origin/i);
  });

  test('Untrusted origin (localhost:3002) receives NO ACAO header', async () => {
    const r = await get('/api/safe', 'http://localhost:3002');
    // Without ACAO, the browser blocks the JavaScript from reading the response
    expect(r.acao).toBeNull();
  });

  test('No origin header → no ACAO header (server-to-server or direct calls)', async () => {
    const r = await get('/api/safe', null);
    // Direct requests (curl, server-to-server) send no Origin — no CORS needed
    expect(r.acao).toBeNull();
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// PART 3: Preflight mechanics
// ─────────────────────────────────────────────────────────────────────────────

describe('Part 3 — Preflight Mechanics', () => {

  test('OPTIONS preflight returns 204 No Content', async () => {
    const r = await options('/api/safe', 'http://localhost:3001');
    expect(r.status).toBe(204);
  });

  test('Preflight response includes Allow-Methods', async () => {
    const r = await options('/api/safe', 'http://localhost:3001');
    expect(r.acam).toBeDefined();
    expect(r.acam).toMatch(/GET/i);
  });

  test('Preflight response includes Max-Age', async () => {
    const r = await options('/api/safe', 'http://localhost:3001');
    // A configured Max-Age means the browser caches the preflight result
    expect(r.maxAge).toBeDefined();
  });

  test('Preflight for untrusted origin does not return ACAO', async () => {
    const r = await options('/api/safe', 'http://localhost:3002');
    expect(r.acao).toBeNull();
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// PART 4: What the tests do NOT test (important limitations to understand)
// ─────────────────────────────────────────────────────────────────────────────

describe('Part 4 — Understanding Test Limitations', () => {

  /**
   * IMPORTANT: These tests run in Node.js via fetch(), not in a browser.
   *
   * Node.js fetch does NOT enforce the Same-Origin Policy. It will happily
   * read responses regardless of CORS headers — because SOP is a browser
   * security feature, not a network feature.
   *
   * What this means:
   *   - Our tests can SEND any Origin header and READ any response.
   *   - We are testing what HEADERS the server sends — not whether the browser
   *     would actually block the read.
   *   - The browser exploit pages (localhost:3002) are what demonstrate the
   *     real browser behaviour.
   *
   * This is why the lab has BOTH:
   *   - Jest tests: prove the vulnerability exists by checking headers
   *   - Browser pages: show what a real victim would experience
   */

  test('Node fetch can read cross-origin responses (SOP is browser-only)', async () => {
    // This always works — Node has no SOP. We're just checking headers.
    const r = await get('/api/safe', 'http://localhost:3002');
    // We can read the response even though ACAO is null
    expect(r.status).toBe(200);
    expect(r.body).toBeDefined();
    // But the ACAO header is null — a browser would block the read
    expect(r.acao).toBeNull();
    console.log('\n  ℹ️  Node can read this, but a browser at localhost:3002 cannot.');
    console.log('     The ACAO header is:', r.acao, '← null means browser blocks it.');
  });

  test('CORS is enforced by the BROWSER — the server always processes the request', async () => {
    // Even for a "blocked" cross-origin request, the server runs the handler
    // and returns a response. The browser just refuses to let JS read it.
    // This is why CORS alone is NOT a server-side security mechanism —
    // the request hits the server regardless. Use auth/sessions for real protection.
    const r = await get('/api/account', 'http://localhost:3002');
    // Server processed the request and returned data
    expect(r.status).toBe(200);
    // But CORS headers determine if the browser lets JS read it
    console.log('\n  ℹ️  The server processed the request regardless of origin.');
    console.log('     CORS headers control browser read access, not server execution.');
  });

});
