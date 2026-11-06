const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const http = require('node:http');
const { createRequire } = require('node:module');
const { once } = require('node:events');
const { join } = require('node:path');
const { test } = require('node:test');
const { runInNewContext } = require('node:vm');

const axiosRequire = createRequire(require.resolve('axios'));
const follow = axiosRequire('follow-redirects');

async function listen(t, handler) {
  const server = http.createServer(handler);
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections();
  }));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return `http://127.0.0.1:${server.address().port}`;
}

function request(url, options = {}, body) {
  return new Promise((resolve, reject) => {
    const req = follow.http.request(url, options, async (res) => {
      try {
        let data = '';
        for await (const chunk of res) data += chunk;
        resolve(JSON.parse(data));
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
    req.setTimeout(3000, () => req.destroy(new Error('redirect test timed out')));
    req.end(body);
  });
}

function echo(req, res) {
  req.resume();
  req.on('end', () => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ headers: req.headers, method: req.method }));
  });
}

function headers(form, host) {
  const entries = [
    ['Host', host],
    ['aUtHoRiZaTiOn', 'Bearer test-token'],
    ['Proxy-Authorization', 'Basic test-proxy'],
    ['Cookie', 'session=test-session'],
    ['X-API-Key', 'test-api-key'],
    ['X-Harmless', 'preserved'],
  ];
  return form === 'array' ? entries.flat() : Object.fromEntries(entries);
}

test('all lockfile copies require follow-redirects 1.16.2 or newer', () => {
  for (const file of ['package-lock.json', 'client/package-lock.json']) {
    const lockfile = JSON.parse(readFileSync(join(__dirname, '../..', file)));
    const packages = Object.entries(lockfile.packages).filter(([path]) =>
      path.endsWith('/follow-redirects'));
    if (file === 'package-lock.json') assert.ok(packages.length > 0);
    for (const [path, { version }] of packages) {
      const [major, minor, patch] = version.split('.').map(Number);
      assert.ok(
        major > 1 || (major === 1 && (minor > 16 || (minor === 16 && patch >= 2))),
        `${file}: vulnerable ${path}@${version}`,
      );
    }
  }
});

for (const form of ['array', 'object']) {
  for (const destination of ['cross origin', 'same origin']) {
    test(`${form} headers match sensitive regex characters literally on ${destination} redirects`, {
      timeout: 5000,
    }, async (t) => {
      const target = destination === 'cross origin' ? await listen(t, echo) : null;
      let original;
      const origin = await listen(t, (req, res) => {
        if (req.url === '/destination') return echo(req, res);
        original = req.headers;
        req.resume();
        res.writeHead(302, { Location: `${target || ''}/destination` });
        res.end();
      });
      const entries = [
        ['X-Api^Key', 'test-caret-credential'],
        ['X-Token|Secret', 'test-pipe-credential'],
        ['X-Control-Key', 'test-control-credential'],
        ['Authorization', 'Bearer test-token'],
        ['X-Token', 'preserve-token-header'],
        ['Secret', 'preserve-secret-header'],
        ['X-Harmless', 'preserved'],
      ];
      const result = await request(origin, {
        headers: form === 'array' ? entries.flat() : Object.fromEntries(entries),
        sensitiveHeaders: ['x-aPI^kEY', 'x-tOKEN|sECRET', 'X-Control-Key'],
      });
      for (const [name, value] of entries) {
        const key = name.toLowerCase();
        assert.equal(original[key], value, `${name} must reach the initial origin`);
        const sensitive = ['x-api^key', 'x-token|secret', 'x-control-key', 'authorization']
          .includes(key);
        assert.equal(
          result.headers[key],
          destination === 'cross origin' && sensitive ? undefined : value,
          `${name} must be matched literally`,
        );
      }
    });
  }

  for (const realm of ['same realm', 'cross realm']) {
    test(`${form} headers strip credentials across origins with ${realm} sensitiveHeaders`, {
      timeout: 5000,
    }, async (t) => {
      const target = await listen(t, echo);
      let original;
      const origin = await listen(t, (req, res) => {
        original = req.headers;
        req.resume();
        res.writeHead(302, { Location: `${target}/destination` });
        res.end();
      });
      const sensitiveHeaders = realm === 'cross realm'
        ? runInNewContext("['X-API-Key']")
        : ['X-API-Key'];
      const result = await request(origin, {
        headers: headers(form, new URL(origin).host),
        sensitiveHeaders,
      });
      assert.equal(original.authorization, 'Bearer test-token');
      assert.equal(original['x-api-key'], 'test-api-key');
      for (const name of ['authorization', 'proxy-authorization', 'cookie', 'x-api-key']) {
        assert.equal(result.headers[name], undefined, `${name} leaked`);
      }
      assert.equal(result.headers['x-harmless'], 'preserved');
      assert.equal(result.headers.host, new URL(target).host);
    });
  }

  test(`${form} headers preserve credentials on same-origin redirects`, {
    timeout: 5000,
  }, async (t) => {
    const origin = await listen(t, (req, res) => {
      if (req.url === '/destination') return echo(req, res);
      req.resume();
      res.writeHead(302, { Location: '/destination' });
      res.end();
    });
    const result = await request(origin, {
      headers: headers(form, new URL(origin).host),
      sensitiveHeaders: ['X-API-Key'],
    });
    assert.equal(result.headers.authorization, 'Bearer test-token');
    assert.equal(result.headers['proxy-authorization'], 'Basic test-proxy');
    assert.equal(result.headers.cookie, 'session=test-session');
    assert.equal(result.headers['x-api-key'], 'test-api-key');
    assert.equal(result.headers['x-harmless'], 'preserved');
  });

  test(`${form} headers remove content headers when a redirect converts POST to GET`, {
    timeout: 5000,
  }, async (t) => {
    const target = await listen(t, echo);
    const origin = await listen(t, (req, res) => {
      req.resume();
      req.on('end', () => {
        res.writeHead(302, { Location: target });
        res.end();
      });
    });
    const entries = [
      ['Content-Length', '7'],
      ['Content-Type', 'text/plain'],
      ['X-Harmless', 'preserved'],
    ];
    const result = await request(origin, {
      method: 'POST',
      headers: form === 'array' ? entries.flat() : Object.fromEntries(entries),
    }, 'payload');
    assert.equal(result.method, 'GET');
    assert.equal(result.headers['content-length'], undefined);
    assert.equal(result.headers['content-type'], undefined);
    assert.equal(result.headers['x-harmless'], 'preserved');
  });
}

test('Axios still follows redirects and strips built-in credentials', {
  timeout: 5000,
}, async (t) => {
  const target = await listen(t, echo);
  const origin = await listen(t, (req, res) => {
    req.resume();
    res.writeHead(302, { Location: target });
    res.end();
  });
  const axios = require('axios');
  const { data } = await axios.get(origin, {
    proxy: false,
    timeout: 3000,
    headers: {
      Authorization: 'Bearer test-token',
      Cookie: 'session=test-session',
      'X-Harmless': 'preserved',
    },
  });
  assert.equal(data.headers.authorization, undefined);
  assert.equal(data.headers.cookie, undefined);
  assert.equal(data.headers['x-harmless'], 'preserved');
});
