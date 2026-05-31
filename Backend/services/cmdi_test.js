const axios = require('axios');
const { takeScreenshot } = require('../utils/screenshot');

const BASE_MARKER = 'CMD_MARKER';

const CMD_PAYLOADS = [
  { str: `127.0.0.1; echo ${BASE_MARKER}`, type: 'unix' },
  { str: `127.0.0.1|echo ${BASE_MARKER}`, type: 'unix' },
  { str: `127.0.0.1\`echo ${BASE_MARKER}\``, type: 'unix' },
  { str: `127.0.0.1&&echo ${BASE_MARKER}`, type: 'unix' },
  { str: `127.0.0.1 || echo ${BASE_MARKER}`, type: 'unix' },
];

function generateMarker(point, payloadIndex) {
  return `CMD_${point.param}_${Date.now()}_${payloadIndex}`;
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

async function testCommandInjection(point, cookie = '') {
  const findings = [];

  // Clean URL – remove any hash fragment, it's irrelevant for the HTTP request
  const cleanUrl = point.url.split('#')[0];

  for (let i = 0; i < CMD_PAYLOADS.length; i++) {
    const marker = generateMarker(point, i);
    const payload = CMD_PAYLOADS[i].str.replace(BASE_MARKER, marker);

    let config;
    let testUrl;
    let encodedData = '';     // <-- define here so it's available everywhere
    let requestInfo = '';

    if (point.type === 'query') {
      testUrl = buildUrlWithParam(cleanUrl, point.param, payload);
      config = { method: 'GET', url: testUrl };
      requestInfo = `GET ${testUrl}`;
    } else if (point.type === 'form') {
      testUrl = cleanUrl;
      const data = { ...(point.otherParams || {}) };
      data[point.param] = payload;
      encodedData = new URLSearchParams(data).toString();

      config = {
        method: point.method,
        url: cleanUrl,
        data: encodedData,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      };
      requestInfo = `POST ${cleanUrl}\nBody: ${encodedData}`;
    } else {
      continue;
    }

    if (cookie) {
      if (!config.headers) config.headers = {};
      config.headers['Cookie'] = cookie;
    }

    // DEBUG
    if (i === 0) {
      console.log(`  [DEBUG] ${config.method} ${config.url}`);
      console.log(`  [DEBUG] Data:`, config.data);
    }

    try {
      const resp = await axios({
        ...config,
        timeout: 20000,
        validateStatus: () => true,
      });

      const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);

      if (i === 0) {
        console.log(`  [DEBUG] Status: ${resp.status}`);
        console.log(`  [DEBUG] Response length: ${body.length}`);
        // Search for marker and log snippet if found
        if (body.includes(marker)) {
          const pos = body.indexOf(marker);
          console.log(`  [DEBUG] Marker FOUND at position ${pos}: ${body.substring(Math.max(0, pos - 50), pos + marker.length + 50)}`);
        } else {
          console.log(`  [DEBUG] Marker NOT found.`);
        }
      }

      if (body.includes(marker)) {
        const snippet = body.substring(
          Math.max(0, body.indexOf(marker) - 100),
          body.indexOf(marker) + marker.length + 200
        );

        let screenshot = null;
        try {
          screenshot = await takeScreenshot(point, payload, cookie);
        } catch (e) {
          console.error('Screenshot failed:', e.message);
        }

        findings.push({
          type: 'Command_Injection',
          url: cleanUrl,
          method: config.method,
          param: point.param,
          payload,
          request: requestInfo,
          responseSnippet: snippet,
          screenshot,
          confidence: 'high',
        });
        break;
      }
    } catch (err) {
      // Only log the error; no more reference to encodedData
      console.log(`  [DEBUG] Request error: ${err.message}`);
    }
  }

  return findings;
}

module.exports = { testCommandInjection };