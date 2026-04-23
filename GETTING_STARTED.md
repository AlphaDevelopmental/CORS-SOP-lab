# Getting Started with CORS & SOP Lab

A comprehensive guide to get you up and running with the lab in minutes.

## Prerequisites

Before you start, make sure you have:

- **Docker Desktop** or **Docker Engine + Docker Compose** (v2.0+)
  - [Install Docker Desktop](https://www.docker.com/products/docker-desktop)
- **Node.js 18+**
  - [Download Node.js](https://nodejs.org)
- **Git**
  - [Install Git](https://git-scm.com)
- **Web Browser** (Chrome, Firefox, Safari, or Edge)
  - Any modern browser supporting ES6

Check your versions:
```bash
docker --version
docker compose version
node --version
npm --version
git --version
```

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/AlphaDevelopmental/CORS-SOP-lab.git
cd CORS-SOP-lab
```

### 2. Start the Lab Services

From the project root, start all three servers:

```bash
docker compose up --build
```

Wait for all services to be healthy. You should see:
```
✔ cors-victim-api       Running
✔ cors-trusted-subdomain Running
✔ cors-attacker-page    Running
```

The servers are now available at:
- **Victim API**: http://localhost:3000
- **Trusted Subdomain**: http://localhost:3001
- **Attacker Page**: http://localhost:3002

### 3. Install Test Dependencies

In a **new terminal** (keep docker compose running), install dependencies:

```bash
npm install
```

### 4. Verify the Setup

Run all tests to confirm everything is working:

```bash
npm test
```

You should see test output with some passing and some failing (the vulnerabilities).

## First Steps

### Step 1: Open the Attacker Page in Your Browser

Navigate to: **http://localhost:3002**

You'll see links to different exploit pages. This is where you'll observe the vulnerabilities in action.

### Step 2: Run Exercise 00 (Understanding Fundamentals)

In your terminal:

```bash
npm run test:00
```

This teaches you about the Same-Origin Policy before any exploitation.

### Step 3: Follow the Exploitation Guide

Open [EXPLOITATION_GUIDE.md](./EXPLOITATION_GUIDE.md) for step-by-step instructions on exploiting each vulnerability.

## Understanding the Lab Structure

```
CORS-SOP-lab/
├── servers/
│   ├── victim-api/          ← THE API YOU'LL FIX
│   ├── trusted-subdomain/   ← Legitimate trusted service
│   └── attacker-page/       ← Where browser exploits run
├── exercises/
│   ├── 00-sop-fundamentals/ ← Start here (observation only)
│   ├── 01-core-misconfigs/  ← 3 flags (wildcard, reflection, null)
│   ├── 02-bypasses/         ← 3 flags (regex tricks)
│   └── 03-preflight-advanced/ ← 3 flags (cache, methods, PNA)
├── README.md                 ← Full documentation
└── EXPLOITATION_GUIDE.md     ← Step-by-step exploitation
```

## Key Files to Know

| File | Purpose |
|------|---------|
| `servers/victim-api/cors-config.js` | **YOU EDIT THIS** — All CORS handlers |
| `exercises/*/challenge.md` | Detailed explanation of each bug |
| `exercises/*/*.test.js` | Automated tests (exploit + hardening) |
| `servers/attacker-page/public/*.html` | Browser exploit pages |

## Running Tests

```bash
# Run all tests
npm test

# Run specific exercise
npm run test:00   # SOP fundamentals
npm run test:01   # Core misconfigurations
npm run test:02   # Bypass techniques
npm run test:03   # Preflight & advanced

# Run specific test by name
npm run test:01 -- --testNamePattern="Bug #1"
```

## Working Through a Vulnerability

For each of the 9 bugs, follow this pattern:

1. **Understand**: Read `exercises/XX-*/challenge.md`
2. **Observe**: Open the browser exploit page at `http://localhost:3002/YY-*.html`
3. **Test**: Run the test suite to see 🔴 exploit tests pass
4. **Fix**: Edit `servers/victim-api/cors-config.js`
5. **Verify**: Re-run tests — 🔴 should fail, 🟢 should pass

## Example: Bug #1 (Wildcard Origin)

```bash
# 1. Read the challenge
cat exercises/01-core-misconfigs/challenge.md

# 2. See it in browser
open http://localhost:3002/01-origin-reflection.html

# 3. See tests fail
npm run test:01 -- --testNamePattern="Bug #1"

# 4. Edit the file
nano servers/victim-api/cors-config.js
# Find corsWildcard() and fix it

# 5. Watch server restart automatically (check logs)
docker compose logs victim-api --tail 5

# 6. Verify the fix
npm run test:01 -- --testNamePattern="Bug #1"
# 🔴 exploit tests should FAIL (bug is fixed)
# 🟢 hardening tests should PASS (security is good)
```

## Troubleshooting

### Docker containers won't start
```bash
docker compose down --volumes
docker compose up --build
```

### Tests fail with "Server not ready"
```bash
# Check container status
docker compose ps

# Check victim-api logs
docker compose logs victim-api
```

### Changes to cors-config.js aren't taking effect
The container uses `node --watch` for auto-restart. Check the logs:
```bash
docker compose logs victim-api --tail 5
# You should see "Server restarted" message
```

### Browser shows CORS error even after fixing
Clear the preflight cache:
- DevTools → Network → right-click → "Clear browser cache"
- Or use an Incognito/Private window

### Port 3000/3001/3002 already in use
Change the ports in `docker-compose.yml`:
```yaml
services:
  victim-api:
    ports:
      - "3000:3000"  ← Change left side to unused port
```

## Getting Help

1. **Check the README**: Comprehensive documentation
2. **Read EXPLOITATION_GUIDE.md**: Step-by-step walkthroughs
3. **Review challenge.md files**: Detailed explanations per bug
4. **Check logs**: `docker compose logs victim-api`
5. **Open an issue**: [GitHub Issues](https://github.com/AlphaDevelopmental/CORS-SOP-lab/issues)

## What You'll Learn

By completing this lab, you will be able to:

✅ Explain the Same-Origin Policy and its limitations  
✅ Identify the 9 most common CORS misconfigurations  
✅ Exploit CORS bugs from a real browser  
✅ Read and interpret CORS response headers  
✅ Write secure, production-grade CORS middleware  
✅ Understand Private Network Access (PNA) security  
✅ Defend APIs against CORS-based attacks  

## Next Steps

1. Run `npm run test:00` to understand SOP
2. Complete `npm run test:01` to `npm run test:03`
3. Exploit each vulnerability in your browser
4. Fix all bugs and get all tests passing
5. Aim for the 50-point bonus by passing all hardening tests

Good luck! 🚀

---

## 🔙 Navigation & Links

**← [Back to README](./README.md)**  
**← [Back to Index](./INDEX.md)**  
**🌐 [AlphaDevelopmental Portfolio](https://alphadevelopmental.netlify.app/)**
