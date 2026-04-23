/**
 * app.js — Attacker Page Server (evil.attacker.local)
 * ════════════════════════════════════════════════════
 * Serves the browser-based exploit HTML pages.
 * Open http://localhost:3002 in your browser.
 *
 * This server is intentionally minimal — it just serves static HTML.
 * The actual exploits run as JavaScript inside the browser pages.
 *
 * Port: 3002
 */

'use strict';

const express = require('express');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3002;

// Serve exploit pages from ./public/
app.use(express.static(path.join(__dirname, 'public')));

// Index — lists all available exploit pages
app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CORS/SOP Lab — Attacker Pages</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Courier New', monospace;
      background: #0a0e1a;
      color: #e0e6f0;
      min-height: 100vh;
      padding: 2rem;
    }
    header {
      border-bottom: 1px solid #ff3c3c44;
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
    }
    h1 { color: #ff3c3c; font-size: 1.6rem; letter-spacing: 0.05em; }
    .subtitle { color: #6272a4; margin-top: 0.4rem; font-size: 0.9rem; }
    .warning {
      background: #1e0a0a;
      border: 1px solid #ff3c3c66;
      border-left: 4px solid #ff3c3c;
      padding: 0.8rem 1.2rem;
      border-radius: 4px;
      margin-bottom: 2rem;
      font-size: 0.85rem;
      color: #ffaaaa;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
      gap: 1rem;
    }
    .card {
      background: #111827;
      border: 1px solid #1f2d3d;
      border-radius: 8px;
      padding: 1.2rem;
      text-decoration: none;
      color: inherit;
      transition: border-color 0.15s;
      display: block;
    }
    .card:hover { border-color: #ff3c3c88; }
    .card-header {
      display: flex;
      align-items: center;
      gap: 0.8rem;
      margin-bottom: 0.6rem;
    }
    .bug-badge {
      background: #ff3c3c22;
      border: 1px solid #ff3c3c44;
      color: #ff6b6b;
      font-size: 0.7rem;
      padding: 0.2rem 0.5rem;
      border-radius: 3px;
      white-space: nowrap;
    }
    .card h3 { font-size: 0.95rem; color: #cdd6f4; }
    .card p { font-size: 0.8rem; color: #6272a4; margin-top: 0.4rem; line-height: 1.5; }
    .ex-label {
      font-size: 0.7rem;
      color: #f1fa8c;
      background: #f1fa8c11;
      border: 1px solid #f1fa8c33;
      padding: 0.15rem 0.5rem;
      border-radius: 3px;
    }
    footer { margin-top: 3rem; color: #44475a; font-size: 0.75rem; }
  </style>
</head>
<body>
  <header>
    <h1>☠️  CORS/SOP Lab — Attacker Origin</h1>
    <div class="subtitle">http://localhost:3002 → attacking http://localhost:3000</div>
  </header>

  <div class="warning">
    ⚠️ This is a controlled lab environment. These pages make real cross-origin 
    requests to the victim API on localhost:3000. Open DevTools → Network tab 
    to watch the requests and response headers in real time.
  </div>

  <div class="grid">
    <a class="card" href="/01-origin-reflection.html">
      <div class="card-header">
        <span class="ex-label">Ex 01</span>
        <span class="bug-badge">Bug #2</span>
        <h3>Origin Reflection</h3>
      </div>
      <p>The server mirrors back whatever origin you send. Any site can read credentialed responses.</p>
    </a>

    <a class="card" href="/02-null-origin.html">
      <div class="card-header">
        <span class="ex-label">Ex 01</span>
        <span class="bug-badge">Bug #3</span>
        <h3>Null Origin via Sandboxed iframe</h3>
      </div>
      <p>A sandboxed iframe generates Origin: null. Watch it bypass all origin allowlists.</p>
    </a>

    <a class="card" href="/03-regex-bypass.html">
      <div class="card-header">
        <span class="ex-label">Ex 02</span>
        <span class="bug-badge">Bugs #4 #5 #6</span>
        <h3>Regex & Subdomain Bypasses</h3>
      </div>
      <p>Prefix match, suffix match, and wildcard subdomain trust. Three ways to fool a regex allowlist.</p>
    </a>

    <a class="card" href="/04-preflight-abuse.html">
      <div class="card-header">
        <span class="ex-label">Ex 03</span>
        <span class="bug-badge">Bugs #7 #8 #9</span>
        <h3>Preflight Abuse & PNA</h3>
      </div>
      <p>Inspect OPTIONS negotiations, cache timing attacks, unsafe method escalation, and Private Network Access headers.</p>
    </a>

    <a class="card" href="/00-sop-demo.html">
      <div class="card-header">
        <span class="ex-label">Ex 00</span>
        <span class="bug-badge">Fundamentals</span>
        <h3>SOP Fundamentals Demo</h3>
      </div>
      <p>Watch the Same-Origin Policy working correctly before anything breaks. Side-by-side: blocked vs allowed.</p>
    </a>
  </div>

  <footer>
    CORS/SOP Lab — for educational use only. All exploits run against localhost.
  </footer>
</body>
</html>`);
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', server: 'attacker-page', port: PORT });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n💀  Attacker Page running on http://localhost:${PORT}`);
    console.log(`    Open this URL in your browser to run live exploits.\n`);
  });
}

module.exports = app;
