# Contributing to CORS & SOP Misconfiguration Lab

Thank you for your interest in contributing! This lab is designed to help junior security engineers learn CORS and SOP vulnerabilities.

## How to Contribute

### Reporting Issues
- Found a bug? Please open an issue with:
  - Clear description of the problem
  - Steps to reproduce
  - Expected vs actual behavior
  - Your environment (OS, Node version, Docker version)

### Improving Documentation
- Better explanations needed? 
- Typos or clarity issues?
- Please submit a pull request with improvements

### Adding New Vulnerabilities
- CORS misconfigs you think are missing?
- New browser attack vectors?
- Open a discussion first, then submit a PR with:
  - Updated `cors-config.js` with the vulnerable handler
  - Updated test file with exploit and hardening tests
  - Updated `EXPLOITATION_GUIDE.md` with steps
  - Updated `challenge.md` with explanation

### Code Standards
- Keep code readable and well-commented
- Follow existing patterns in `cors-config.js`
- Ensure all tests pass: `npm test`
- Include both exploit (🔴) and hardening (🟢) test cases

## Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make changes and test: `npm test`
4. Commit with clear messages: `git commit -m "feat: add new CORS vulnerability"`
5. Push to your fork: `git push origin feature/your-feature`
6. Open a pull request with description of changes

## Testing

```bash
# Run all tests
npm test

# Run specific exercise
npm run test:01

# Run specific test pattern
npm run test:01 -- --testNamePattern="Bug #1"
```

## Questions?

- Check the [EXPLOITATION_GUIDE.md](./EXPLOITATION_GUIDE.md) for detailed walkthroughs
- Review exercise challenge files in `exercises/*/challenge.md`
- See the README for core concepts

## Code of Conduct

- Be respectful and constructive
- No harassment or discrimination
- Focus on learning and improvement

---

## 🔙 Navigation

**← [Back to README](./README.md)**  
**← [Back to Index](./INDEX.md)**  
**🌐 [AlphaDevelopmental Portfolio](https://alphadevelopmental.netlify.app/)**

Thank you for helping make this lab better! 🙏
