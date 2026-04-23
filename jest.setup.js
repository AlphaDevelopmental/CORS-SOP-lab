/**
 * jest.setup.js — Global test setup
 * Waits for the victim-api container to be healthy before running tests.
 * Run `docker compose up` before `npm test`.
 */
async function waitForServer(url, retries = 20, delay = 500) {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch (_) {}
    await new Promise((r) => setTimeout(r, delay));
  }
  throw new Error(`Server at ${url} did not become ready in time. Run: docker compose up`);
}

module.exports = async function () {
  await waitForServer('http://localhost:3000/api/health');
};
