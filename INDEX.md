# Repository Index & Navigation

This file helps you navigate the CORS & SOP Lab repository and find what you need quickly.

## 📚 Documentation Files

| File | Purpose | Audience |
|------|---------|----------|
| **README.md** | Main documentation | Everyone (start here) |
| **GETTING_STARTED.md** | Setup and first steps | New users |
| **EXPLOITATION_GUIDE.md** | Step-by-step vulnerability exploitation | Learners |
| **ABOUT_CREATOR.md** | About AlphaDevelopmental & philosophy | Everyone |
| **CONTRIBUTING.md** | How to contribute | Contributors |
| **CODE_OF_CONDUCT.md** | Community standards | Everyone |
| **LICENSE** | MIT License | Legal |

## 🎓 Learning Path

### For Complete Beginners
1. Start: Read [README.md](README.md) — understand what this lab teaches
2. Setup: Follow [GETTING_STARTED.md](GETTING_STARTED.md) — get lab running
3. Learn: Run `npm run test:00` — understand SOP fundamentals
4. Exploit: Work through [EXPLOITATION_GUIDE.md](EXPLOITATION_GUIDE.md)

### For Security Professionals
1. Review: [README.md](README.md#scoring) — quick overview of 9 bugs
2. Setup: [GETTING_STARTED.md](GETTING_STARTED.md) — 5 min setup
3. Exploit: Direct to [EXPLOITATION_GUIDE.md](EXPLOITATION_GUIDE.md)
4. Verify: Run tests, check your score

### For Instructors
1. Review [README.md](README.md) for course fit
2. Check [exercises/](exercises/) directory for lesson structure
3. See [CONTRIBUTING.md](CONTRIBUTING.md) for extending the lab
4. Students follow [GETTING_STARTED.md](GETTING_STARTED.md)

## 📂 Project Structure

```
cors-sop-lab/
│
├── 📖 DOCUMENTATION
│   ├── README.md                 ← Start here
│   ├── GETTING_STARTED.md        ← Setup guide
│   ├── EXPLOITATION_GUIDE.md     ← How to exploit each bug
│   ├── CONTRIBUTING.md           ← Contribution guidelines
│   ├── CODE_OF_CONDUCT.md        ← Community standards
│   ├── LICENSE                   ← MIT License
│   └── INDEX.md                  ← This file
│
├── 🐳 DOCKER SETUP
│   └── docker-compose.yml        ← 3 services configuration
│
├── 🧪 TEST FRAMEWORK
│   ├── jest.setup.js             ← Jest configuration
│   ├── package.json              ← Dependencies and scripts
│   └── package-lock.json         ← Lock file
│
├── 🎯 EXERCISES (Learning modules)
│   ├── 00-sop-fundamentals/
│   │   ├── challenge.md          ← SOP explanation
│   │   └── sop.test.js           ← Observation tests
│   │
│   ├── 01-core-misconfigs/
│   │   ├── challenge.md          ← Bug explanations
│   │   └── misconfigs.test.js    ← Exploit & hardening tests
│   │
│   ├── 02-bypasses/
│   │   ├── challenge.md          ← Bypass techniques
│   │   └── bypasses.test.js      ← Regex bypass tests
│   │
│   └── 03-preflight-advanced/
│       ├── challenge.md          ← Preflight & PNA
│       └── preflight.test.js     ← Advanced attack tests
│
├── 🖥️ SERVERS (Vulnerable application)
│   ├── victim-api/
│   │   ├── cors-config.js        ← 🎯 YOU EDIT THIS
│   │   ├── app.js                ← Routes (read-only)
│   │   ├── package.json
│   │   └── Dockerfile
│   │
│   ├── attacker-page/
│   │   ├── public/
│   │   │   ├── 00-sop-demo.html
│   │   │   ├── 01-origin-reflection.html
│   │   │   ├── 02-null-origin.html
│   │   │   ├── 03-regex-bypass.html
│   │   │   └── 04-preflight-abuse.html
│   │   ├── app.js
│   │   └── Dockerfile
│   │
│   └── trusted-subdomain/
│       ├── app.js
│       └── Dockerfile
│
└── 🔧 GITHUB CONFIG
    └── .github/
        ├── ISSUE_TEMPLATE/
        │   ├── bug_report.md
        │   └── feature_request.md
        └── pull_request_template.md
```

## 🚀 Quick Commands

```bash
# Setup
docker compose up --build
npm install

# Run tests
npm test                    # All tests
npm run test:00            # Exercise 00
npm run test:01            # Exercise 01
npm run test:02            # Exercise 02
npm run test:03            # Exercise 03

# Specific test
npm run test:01 -- --testNamePattern="Bug #1"

# View logs
docker compose logs victim-api --tail 20
```

## 🐛 The 9 Vulnerabilities

### Exercise 01: Core Misconfigurations (3 bugs)
- **Bug #1**: Wildcard origin (`GET /api/public`)
- **Bug #2**: Origin reflection + credentials (`GET /api/account`)
- **Bug #3**: Null origin trusted (`GET /api/profile`)

### Exercise 02: Bypass Techniques (3 bugs)
- **Bug #4**: Prefix regex bypass (`GET /api/transfers`)
- **Bug #5**: Suffix regex bypass (`GET /api/statements`)
- **Bug #6**: Subdomain wildcard pivot (`GET /api/admin`)

### Exercise 03: Preflight & Advanced (3 bugs)
- **Bug #7**: Preflight cached 24 hours (`PUT /api/settings`)
- **Bug #8**: Unsafe methods allowed (`DELETE /api/account`)
- **Bug #9**: Private Network Access ungated (`GET /api/internal`)

See [EXPLOITATION_GUIDE.md](EXPLOITATION_GUIDE.md) for details on each.

## 📍 Key Files to Edit

**ONLY FILE YOU NEED TO EDIT:**
```
servers/victim-api/cors-config.js
```

Contains all 9 vulnerable CORS handlers. Each exercise focuses on fixing specific handlers.

## 🌐 Browser Endpoints

| URL | Purpose |
|-----|---------|
| `http://localhost:3000` | Victim API (backend) |
| `http://localhost:3001` | Trusted subdomain |
| `http://localhost:3002` | Attacker page (browser exploits) |
| `http://localhost:3002/00-sop-demo.html` | SOP demonstration |
| `http://localhost:3002/01-origin-reflection.html` | Bug #1-3 exploits |
| `http://localhost:3002/03-regex-bypass.html` | Bug #4-6 exploits |
| `http://localhost:3002/04-preflight-abuse.html` | Bug #7-9 exploits |

## 📊 Scoring System

| Bug | Points | Type |
|-----|--------|------|
| Bug #1-3 | 10-15 | Core |
| Bug #4-6 | 15-20 | Bypass |
| Bug #7-9 | 15-25 | Advanced |
| All hardening tests green | +50 | Bonus |
| **Total** | **200** | |

## 🔍 Searching This Repository

| Looking for... | File |
|---|---|
| How to get started | [GETTING_STARTED.md](GETTING_STARTED.md) |
| How each bug works | [exercises/*/challenge.md](exercises/) |
| How to exploit | [EXPLOITATION_GUIDE.md](EXPLOITATION_GUIDE.md) |
| Main API logic | [servers/victim-api/cors-config.js](servers/victim-api/cors-config.js) |
| Browser exploits | [servers/attacker-page/public/](servers/attacker-page/public/) |
| Tests | [exercises/*/\*.test.js](exercises/) |
| Contribution guide | [CONTRIBUTING.md](CONTRIBUTING.md) |

## ✅ Checklist for Completion

- [ ] Setup lab (`docker compose up --build`)
- [ ] Install dependencies (`npm install`)
- [ ] Run Exercise 00 (`npm run test:00`)
- [ ] Read EXPLOITATION_GUIDE.md
- [ ] Fix Bug #1-3 in Exercise 01
- [ ] Fix Bug #4-6 in Exercise 02
- [ ] Fix Bug #7-9 in Exercise 03
- [ ] All tests passing (`npm test`)
- [ ] All hardening tests green
- [ ] Score: 200/200

## 🆘 Troubleshooting

| Issue | Solution |
|-------|----------|
| Containers won't start | `docker compose down --volumes && docker compose up --build` |
| Tests fail "Server not ready" | `docker compose logs victim-api` |
| Changes not taking effect | Check server auto-restart in logs |
| Port already in use | Change ports in `docker-compose.yml` |
| CORS error in browser | Clear cache or use Incognito mode |

See [GETTING_STARTED.md#troubleshooting](GETTING_STARTED.md#troubleshooting) for more.

## 🤝 Contributing

Want to improve the lab? See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📞 Support

1. Check [GETTING_STARTED.md](GETTING_STARTED.md)
2. Read relevant [exercises/*/challenge.md](exercises/)
3. See [EXPLOITATION_GUIDE.md](EXPLOITATION_GUIDE.md)
4. Open an [issue](https://github.com/AlphaDevelopmental/CORS-SOP-lab/issues)

---

## 🔗 Created By

**[AlphaDevelopmental](https://alphadevelopmental.netlify.app/)** — Developer & Ethical Hacker

This lab is part of my educational mission to teach real-world security concepts through hands-on learning. For more projects and resources, visit my portfolio.

---

**Happy learning!** 🎓 Start with [GETTING_STARTED.md](GETTING_STARTED.md)  
**🌐 [Visit AlphaDevelopmental Portfolio](https://alphadevelopmental.netlify.app/)**
