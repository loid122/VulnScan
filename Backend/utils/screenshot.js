const puppeteer = require('puppeteer');

function stripHash(url) {
  const u = new URL(url);
  u.hash = '';
  return u.href;
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

  const host = new URL(url).hostname;
  await page.setCookie(
    ...cookies.map(c => ({
      name: c.name,
      value: c.value,
      domain: host,
      path: '/',
    }))
  );
}

// Simple timeout replacement for waitForTimeout
const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

async function takeScreenshot(point, payload, cookie = '') {
  let browser;
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });

    const page = await browser.newPage();
    await applyCookies(page, cookie, point.url);

    const baseUrl = stripHash(point.url);

    if (point.type === 'query') {
      const u = new URL(baseUrl);
      u.searchParams.set(point.param, payload);
      await page.goto(u.href, { waitUntil: 'domcontentloaded', timeout: 15000 });
    } else if (point.type === 'form') {
      await page.goto(baseUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
      await page.evaluate((data) => {
        const form = document.querySelector('form');
        if (!form) return;

        for (const [name, value] of Object.entries(data)) {
          const el = form.querySelector(`[name="${name}"]`);
          if (el) el.value = value;
        }

        const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
        if (submitBtn) submitBtn.click();
        else if (typeof form.requestSubmit === 'function') form.requestSubmit();
        else form.submit();
      }, { ...(point.otherParams || {}), [point.param]: payload });
    }

    // Wait for the page to settle (replaces waitForTimeout)
    await wait(1500);

    return await page.screenshot({ encoding: 'base64' });
  } catch (err) {
    console.error('Screenshot error:', err.message);
    return null;
  } finally {
    if (browser) await browser.close();
  }
}

module.exports = { takeScreenshot };
