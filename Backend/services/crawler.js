const puppeteer = require('puppeteer');
const cheerio = require('cheerio');
const { URL } = require('url');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// General functions for error handling

function safeResolve(href, base) {
  try {
    return new URL(href, base).href;
  } catch {
    return null;
  }
}

function isSameHost(rawUrl, host) {
  try {
    return new URL(rawUrl).hostname === host;
  } catch {
    return false;
  }
}

function normalizeUrl(rawUrl) {
  try {
    return new URL(rawUrl).href;
  } catch {
    return rawUrl;
  }
}

function addUnique(points, point) {
  if (!points.some((p) => p._key === point._key)) points.push(point);
}

// Find the points from a captured request and save them
function parseCapturedParams(capturedRequest) {
  const params = {};
  if (!capturedRequest) return params;

  const { postData = '', url = '' } = capturedRequest;

  if (postData) {
    try {
      const json = JSON.parse(postData);
      if (json && typeof json === 'object' && !Array.isArray(json)) return json;
    } catch {}

    try {
      const sp = new URLSearchParams(postData);
      for (const [k, v] of sp.entries()) params[k] = v;
      if (Object.keys(params).length) return params;
    } catch {}
  }

  try {
    const u = new URL(url);
    for (const [k, v] of u.searchParams.entries()) params[k] = v;
  } catch {}

  return params;
}

// Using a blacklist of parameter names to skip ( mostly just helper buttons )
function shouldSkipParam(name, type) {
  const lowerName = (name || '').toLowerCase();
  const lowerType = (type || '').toLowerCase();

  // Skip based on HTML input type
  if (['submit', 'button', 'reset', 'file'].includes(lowerType)) {
    return true;
  }

  // Skip common token / helper names
  if (['user_token', 'csrf', 'token', 'nonce', 'login', 'submit', 'captcha'].some(k => lowerName.includes(k))) {
    return true;
  }

  // Skip button-like names (e.g., btnSign, btnClear)
  if (/^btn/i.test(lowerName)) {
    return true;
  }

  return false;
}

// Support for DVWA cookie login parser
function parseCookieHeader(cookieHeader, baseUrl) {
  const raw = (cookieHeader || '').trim();
  if (!raw) return [];

  const host = new URL(baseUrl).hostname;

  return raw
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((part) => {
      const idx = part.indexOf('=');
      if (idx === -1) return null;

      const name = part.slice(0, idx).trim();
      const value = part.slice(idx + 1).trim();

      if (!name) return null;

      return {
        name,
        value,
        domain: host,
        path: '/',
      };
    })
    .filter(Boolean);
}

async function applyCookies(page, cookieHeader, baseUrl) {
  const cookies = parseCookieHeader(cookieHeader, baseUrl);
  if (!cookies.length) return;

  await page.setCookie(...cookies);
  console.log(`Crawler: set ${cookies.length} cookie(s)`);
}

// Checking if there is a dropdown box in the page 
function getElementValue($el) {
  const tag = ($el[0]?.tagName || '').toLowerCase();

  if (tag === 'select') {
    const selected = $el.find('option[selected]').first();
    if (selected.length) return selected.attr('value') ?? selected.text().trim() ?? '';
    const first = $el.find('option').first();
    if (first.length) return first.attr('value') ?? first.text().trim() ?? '';
    return '';
  }

  if (tag === 'textarea') {
    const text = $el.text();
    if (text && text.trim()) return text.trim();
    const val = $el.val();
    return val == null ? '' : String(val);
  }

  const val = $el.val();
  if (val != null && String(val).length) return String(val);

  const attrVal = $el.attr('value');
  return attrVal == null ? '' : String(attrVal);
}


// Main function to start crawling to find injection points
async function crawlPage(startUrl, cookie = '') {
  const targetHost = new URL(startUrl).hostname;
  const visitedUrls = new Set();
  const queuedUrls = new Set();
  const injectionPoints = [];
  const maxPages = 25;

  let browser;
  // WE use puppeteer library to launch a headless browser to take screenshots and to execute things
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1365, height: 900 });

    if (cookie) {
      await applyCookies(page, cookie, startUrl);
    }


    // Another function to find the static injection points
    async function extractStaticInjectionPoints() {
      const currentUrl = page.url();
      const html = await page.content();
      const $ = cheerio.load(html);
      const parsedUrl = new URL(currentUrl);   

      $('form').each((i, form) => {
        const rawAction = $(form).attr('action') || currentUrl;
        const fullAction = safeResolve(rawAction, currentUrl);
        if (!fullAction || !isSameHost(fullAction, targetHost)) return;

        const actionUrl = new URL(fullAction);
        actionUrl.hash = '';
        const cleanAction = actionUrl.href;

        const method = ($(form).attr('method') || 'GET').toUpperCase();


        const allInputs = [];
        $(form).find('input, textarea, select').each((j, el) => {
          const $el = $(el);
          const name = $el.attr('name') || $el.attr('id');
          if (!name) return;

          const tag = ($el[0]?.tagName || '').toLowerCase();
          const type = ($el.attr('type') || tag || 'text').toLowerCase();

          allInputs.push({
            name,
            type,
            value: getElementValue($el),
            skip: shouldSkipParam(name, type),   
          });
        });

        const injectableInputs = allInputs.filter(inp => !inp.skip);

        for (const input of injectableInputs) {
          const key = `${cleanAction}|${method}|${input.name}`;
          const otherParams = {};

          for (const other of allInputs) {
            if (other.name !== input.name) {
              otherParams[other.name] = other.value || 'test';
            }
          }

          addUnique(injectionPoints, {
            _key: key,
            type: 'form',
            url: cleanAction,
            method,
            param: input.name,
            fieldType: input.type,
            payloadValue: input.value || '',
            otherParams,
          });
        }
      });

      // 2. Regular query string parameters
      if (parsedUrl.search) {
        const allParams = {};
        parsedUrl.searchParams.forEach((v, k) => {
          allParams[k] = v;
        });

        for (const key of parsedUrl.searchParams.keys()) {
          if (shouldSkipParam(key, 'query')) continue;
          const base = parsedUrl.origin + parsedUrl.pathname;
          addUnique(injectionPoints, {
            _key: `${base}|GET|${key}`,
            type: 'query',
            url: base,
            method: 'GET',
            param: key,
            allParams,
          });
        }
      }

      // 3. Hash fragment query parameters (for SPAs)
      const fragment = parsedUrl.hash;
      if (fragment && fragment.includes('?')) {
        const queryPart = fragment.substring(fragment.indexOf('?') + 1);
        const hashSearchParams = new URLSearchParams(queryPart);
        const baseWithFragment = parsedUrl.origin + parsedUrl.pathname + fragment.split('?')[0];

        hashSearchParams.forEach((value, key) => {
          if (shouldSkipParam(key, 'query')) return;
          const allParams = {};
          hashSearchParams.forEach((v, k) => { allParams[k] = v; });
          addUnique(injectionPoints, {
            _key: `${baseWithFragment}|GET|${key}`,
            type: 'query',
            url: baseWithFragment,
            method: 'GET',
            param: key,
            allParams,
          });
        });
      }
    }


    // Sometimes the request being sent from frontend maybe to another page , this is to capture that
    async function discoverFormEndpoint(formIndex) {
      const selector = `form:nth-of-type(${formIndex + 1})`;

      const exists = await page.waitForSelector(selector, { timeout: 3000 }).catch(() => null);
      if (!exists) return null;

      const formInfo = await page.$eval(selector, (form) => {
        const method = (form.getAttribute('method') || 'GET').toUpperCase();
        const action = form.getAttribute('action') || document.location.href;

        const fields = Array.from(form.querySelectorAll('input, textarea, select'))
          .map((field) => {
            const tag = field.tagName.toLowerCase();
            const type = (field.getAttribute('type') || tag || 'text').toLowerCase();
            const name = field.getAttribute('name') || field.getAttribute('id') || '';

            let value = '';
            if (tag === 'select') {
              const selected = field.querySelector('option[selected]');
              if (selected) {
                value = selected.value ?? selected.textContent ?? '';
              } else if (field.options && field.options.length) {
                value = field.options[0].value ?? field.options[0].textContent ?? '';
              }
            } else if (tag === 'textarea') {
              value = field.value ?? field.textContent ?? '';
            } else {
              value = field.value ?? field.getAttribute('value') ?? '';
            }

            return { name, tag, type, value };
          })
          .filter((f) => f.name && !['submit', 'button', 'reset', 'file'].includes(f.type));

        return { method, action, fields };
      });

      if (!formInfo) return null;

      const resolvedAction = safeResolve(formInfo.action, page.url());
      if (!resolvedAction || !isSameHost(resolvedAction, targetHost)) return null;

      const actionUrl = new URL(resolvedAction);
      actionUrl.hash = '';
      const cleanAction = actionUrl.href;

      // Generate a unique marker to identify the request triggered by this form
      const marker = `__SCANNER_MARKER_${Date.now()}_${Math.random().toString(36).slice(2, 10)}__`;

      // Wait for a request that contains the marker, navigation or XHR/fetch
      const requestPromise = page
        .waitForRequest(
          (request) => {
            try {
              const url = request.url();
              const postData = request.postData() || '';
              const body = postData;
              const fullUrl = url;

              // Check if the marker appears anywhere in URL or body
              if (fullUrl.includes(marker) || body.includes(marker)) {
                return true;
              }
              return false;
            } catch {
              return false;
            }
          },
          { timeout: 5000 }
        )
        .catch(() => null);

      // Fill all fields with the marker and submit
      await page.evaluate(({ selector, fields, marker }) => {
        const form = document.querySelector(selector);
        if (!form) return;

        const setControlValue = (control, value) => {
          const tag = control.tagName.toLowerCase();
          const type = (control.getAttribute('type') || tag || 'text').toLowerCase();

          if (tag === 'select') {
            const options = Array.from(control.options || []);
            const matched = options.find((o) => o.value === value) || options[0];
            if (matched) control.value = matched.value;
          } else if (tag === 'textarea') {
            control.value = value;
          } else if (type === 'checkbox') {
            control.checked = true;
            control.value = value;
          } else if (type === 'radio') {
            control.checked = true;
            control.value = value;
          } else {
            control.value = value;
          }

          control.dispatchEvent(new Event('input', { bubbles: true }));
          control.dispatchEvent(new Event('change', { bubbles: true }));
        };

        for (const field of fields) {
          const control = form.elements.namedItem(field.name);
          if (!control) continue;

          if (typeof RadioNodeList !== 'undefined' && control instanceof RadioNodeList) {
            const items = Array.from(control);
            for (const item of items) {
              if (item.tagName && item.tagName.toLowerCase() === 'input' && item.type === 'radio') {
                item.checked = true;
                item.dispatchEvent(new Event('change', { bubbles: true }));
                break;
              }
            }
            continue;
          }

          setControlValue(control, marker);
        }

        const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
        if (submitBtn) {
          submitBtn.click();
        } else if (typeof form.requestSubmit === 'function') {
          form.requestSubmit();
        } else {
          form.submit();
        }
      }, { selector, fields: formInfo.fields, marker });

      const captured = await requestPromise;
      if (!captured) return null;

      return {
        url: captured.url(),
        method: captured.method(),
        postData: captured.postData() || '',
      };
    }
    async function processAllForms() {
      const formCount = await page.$$eval('form', (forms) => forms.length).catch(() => 0);
      if (!formCount) return;

      await extractStaticInjectionPoints();

      for (let i = 0; i < formCount; i++) {
        const endpoint = await discoverFormEndpoint(i);
        if (!endpoint) continue;

        const parsedParams = parseCapturedParams(endpoint);
        for (const param of Object.keys(parsedParams)) {
          if (shouldSkipParam(param, 'dynamic')) continue;

          const key = `${endpoint.url}|${endpoint.method}|${param}`;
          const otherParams = { ...parsedParams };
          delete otherParams[param];

          addUnique(injectionPoints, {
            _key: key,
            type: 'form',
            url: endpoint.url,
            method: endpoint.method,
            param,
            fieldType: 'unknown',
            payloadValue: parsedParams[param] ?? '',
            otherParams,
          });
        }
      }
    }

    async function getInternalLinks() {
      const html = await page.content();
      const $ = cheerio.load(html);
      const links = new Set();
      const currentUrl = page.url();

      $('a[href]').each((i, a) => {
        const href = $(a).attr('href');
        if (!href) return;

        const resolved = safeResolve(href, currentUrl);
        if (!resolved || !isSameHost(resolved, targetHost)) return;

        try {
          const u = new URL(resolved);
          if (u.pathname.startsWith('/redirect')) return;
        } catch {}

        links.add(resolved);
      });

      return [...links];
    }

    async function loadPage(url) {
      try {
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
      } catch {}

      await page.waitForNetworkIdle({ idleTime: 500, timeout: 3000 }).catch(() => null);
      await sleep(800);

      const finalUrl = page.url();
      if (!isSameHost(finalUrl, targetHost)) return null;

      if (finalUrl.includes('/login.php')) {
        console.log('Crawler: redirected to login.php. Session is missing or invalid.');
        return null;
      }

      return finalUrl;
    }

    console.log(`Loading: ${startUrl}`);
    const loadedUrl = await loadPage(startUrl);

    if (!loadedUrl) {
      return [];
    }

    console.log(`  After load, current URL: ${page.url()}`);

    const isDirectVulnPage = loadedUrl.includes('/vulnerabilities/');

    if (isDirectVulnPage) {
      await extractStaticInjectionPoints();
      await processAllForms();
    } else {
      const queue = [loadedUrl];
      queuedUrls.add(normalizeUrl(loadedUrl));

      while (queue.length && visitedUrls.size < maxPages) {
        const next = queue.shift();
        const normalized = normalizeUrl(next);
        if (visitedUrls.has(normalized)) continue;

        console.log(`Visiting: ${next}`);
        const loaded = await loadPage(next);
        if (!loaded) continue;

        visitedUrls.add(normalized);
        await extractStaticInjectionPoints();
        await processAllForms();

        const links = await getInternalLinks();
        for (const link of links) {
          const n = normalizeUrl(link);
          if (!visitedUrls.has(n) && !queuedUrls.has(n)) {
            queuedUrls.add(n);
            queue.push(link);
          }
        }
      }
    }

    console.log(`Total unique injection points: ${injectionPoints.length}`);
    return injectionPoints.map(({ _key, ...point }) => point);
  } catch (err) {
    console.error(`Crawl error: ${err.message}`);
    return [];
  } finally {
    if (browser) await browser.close();
  }
}

module.exports = { crawlPage };