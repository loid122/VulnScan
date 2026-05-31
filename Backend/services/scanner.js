const { crawlPage } = require('./crawler');
const { testSQLi } = require('./sqli_test');
const { testXSS } = require('./xss_test');
const { testCommandInjection } = require('./cmdi_test');

async function saveFindings(findings, scanId, saveFinding) {
  for (const finding of findings) {
    console.log(`  ✓ ${finding.type} (confidence: ${finding.confidence})`);
    await Promise.resolve(saveFinding({ ...finding, scanId }));
  }
}

function getPageKey(point) {
  try {
    const u = new URL(point.url);
    u.hash = '';
    u.search = '';
    return `${u.origin}${u.pathname}`;
  } catch {
    return point.url.split('?')[0].split('#')[0];
  }
}

async function runScan(scanId, targetUrl, saveFinding, cookie = '') {
  const sessionCookie = (cookie || '').trim();

  console.log(`\n========== SCAN ${scanId} ==========`);
  console.log(`Target: ${targetUrl}`);
  if (sessionCookie) console.log('Using session cookies');

  const injectionPoints = await crawlPage(targetUrl, sessionCookie);

  console.log(`\nFound ${injectionPoints.length} injection points:`);
  injectionPoints.forEach((point, idx) => {
    console.log(`${idx + 1}. [${point.type}] ${point.method} ${point.url} → param: "${point.param}"`);
  });

  // Pages where any vulnerability has already been found – skip all further tests
  const pageHasVuln = new Set();

  // ---------- SQLi ----------
  for (const point of injectionPoints) {
    const pageKey = getPageKey(point);
    if (pageHasVuln.has(pageKey)) {
      console.log(`\n--- Skipping SQLi for ${point.method} ${point.url} (param: ${point.param}) – vulnerability already found on this page ---`);
      continue;
    }

    console.log(`\n--- SQLi Testing: ${point.method} ${point.url} (param: ${point.param}) ---`);
    const findings = await testSQLi(point, sessionCookie);
    console.log(`SQLi findings: ${findings.length}`);
    await saveFindings(findings, scanId, saveFinding);

    if (findings.length > 0) {
      pageHasVuln.add(pageKey);
      console.log('  → Page marked as vulnerable, skipping all further tests for this page.');
    }
  }

  // ---------- Stored XSS ----------
  console.log(`\n========== XSS TYPE: STORED ==========`);
  for (const point of injectionPoints) {
    const pageKey = getPageKey(point);
    if (pageHasVuln.has(pageKey)) {
      console.log(`\n--- Skipping stored XSS for ${point.method} ${point.url} (param: ${point.param}) – vulnerability already found on this page ---`);
      continue;
    }

    console.log(`\n--- Testing: ${point.method} ${point.url} (param: ${point.param}) [stored] ---`);
    const findings = await testXSS(point, sessionCookie, 'stored');
    console.log(`XSS findings (stored): ${findings.length}`);
    await saveFindings(findings, scanId, saveFinding);

    if (findings.length > 0) {
      pageHasVuln.add(pageKey);
      console.log('  → Page marked as vulnerable, skipping all further tests for this page.');
    }
  }

  // ---------- Reflected XSS ----------
  console.log(`\n========== XSS TYPE: REFLECTED ==========`);
  for (const point of injectionPoints) {
    const pageKey = getPageKey(point);
    if (pageHasVuln.has(pageKey)) {
      console.log(`\n--- Skipping reflected XSS for ${point.method} ${point.url} (param: ${point.param}) – vulnerability already found on this page ---`);
      continue;
    }

    console.log(`\n--- Testing: ${point.method} ${point.url} (param: ${point.param}) [reflected] ---`);
    const findings = await testXSS(point, sessionCookie, 'reflected');
    console.log(`XSS findings (reflected): ${findings.length}`);
    await saveFindings(findings, scanId, saveFinding);

    if (findings.length > 0) {
      pageHasVuln.add(pageKey);
      console.log('  → Page marked as vulnerable, skipping all further tests for this page.');
    }
  }

  // ---------- Command Injection ----------
  console.log(`\n========== COMMAND INJECTION TEST ==========`);
  for (const point of injectionPoints) {
    const pageKey = getPageKey(point);
    if (pageHasVuln.has(pageKey)) {
      console.log(`\n--- Skipping command injection for ${point.method} ${point.url} (param: ${point.param}) – vulnerability already found on this page ---`);
      continue;
    }

    console.log(`\n--- Testing: ${point.method} ${point.url} (param: ${point.param}) [command injection] ---`);
    const findings = await testCommandInjection(point, sessionCookie);
    console.log(`Command injection findings: ${findings.length}`);
    await saveFindings(findings, scanId, saveFinding);

    if (findings.length > 0) {
      pageHasVuln.add(pageKey);
      console.log('  → Page marked as vulnerable, skipping all further tests for this page.');
    }
  }

  console.log(`\n========== SCAN COMPLETED ==========`);
}

module.exports = { runScan };