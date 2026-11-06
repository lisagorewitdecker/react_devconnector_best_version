const assert = require('node:assert/strict');
const { once } = require('node:events');
const { readFileSync } = require('node:fs');
const http = require('node:http');
const { createRequire } = require('node:module');
const { join } = require('node:path');
const { test } = require('node:test');

const expressRequire = createRequire(require.resolve('express'));
const bodyParserRequire = createRequire(expressRequire.resolve('body-parser'));

test('both lockfiles require patched qs versions', () => {
  for (const file of ['package-lock.json', 'client/package-lock.json']) {
    const lockfile = JSON.parse(readFileSync(join(__dirname, '../..', file)));
    const packages = Object.entries(lockfile.packages).filter(([path]) =>
      path.endsWith('/qs'));
    if (file === 'package-lock.json') assert.ok(packages.length > 0);
    for (const [path, { version }] of packages) {
      const [major, minor, patch] = version.split('.').map(Number);
      assert.ok(
        major > 6 || (major === 6 && (minor > 16 || (minor === 16 && patch >= 1))),
        `${file}: vulnerable ${path}@${version}`,
      );
    }
  }
});

for (const [label, consumerRequire] of [
  ['Express', expressRequire],
  ['body-parser', bodyParserRequire],
]) {
  const qs = consumerRequire('qs');
  for (const encodeValuesOnly of [false, true]) {
    test(`${label} safely serializes non-callable toString values with encodeValuesOnly=${encodeValuesOnly}`, () => {
      const options = { arrayFormat: 'comma', encodeValuesOnly };
      for (const toString of ['blocked', null, 123, false, {}, []]) {
        const input = JSON.parse(JSON.stringify({ items: [{ toString }] }));
        const before = JSON.stringify(input);
        assert.equal(
          qs.stringify(input, options),
          'items=%5Bobject%20Object%5D',
        );
        assert.equal(JSON.stringify(input), before, 'input must not be mutated');
      }
      assert.equal(
        qs.stringify({ items: [Object.create(null)] }, options),
        'items=%5Bobject%20Object%5D',
      );
      assert.equal(
        qs.stringify({ items: [[{ toString: 'blocked' }]] }, options),
        'items=%5Bobject%20Object%5D',
      );
      const parsed = qs.parse('items[0][toString]=blocked', { allowPrototypes: true });
      assert.equal(parsed.items[0].toString, 'blocked');
      assert.equal(qs.stringify(parsed, options), 'items=%5Bobject%20Object%5D');
    });
  }

  test(`${label} preserves ordinary serialization, coercion and parsing`, () => {
    const options = { arrayFormat: 'comma' };
    assert.equal(qs.stringify({ items: ['a', 'b', 3] }, options), 'items=a%2Cb%2C3');
    assert.equal(
      qs.stringify({ items: ['a', 'b'] }, { ...options, encodeValuesOnly: true }),
      'items=a,b',
    );
    assert.equal(qs.stringify({ items: [null, undefined, 'a'] }, options), 'items=%2C%2Ca');
    assert.equal(
      qs.stringify({ items: [{ toString: () => 'custom' }] }, options),
      'items=custom',
    );
    assert.equal(
      qs.stringify({ items: [{ toString: null, valueOf: () => 42 }] }, options),
      'items=42',
    );
    assert.equal(qs.stringify({ items: ['a', 'b'] }), 'items%5B0%5D=a&items%5B1%5D=b');
    assert.deepEqual(qs.parse('user[name]=Ada&tags[]=js&tags[]=node'), {
      user: { name: 'Ada' },
      tags: ['js', 'node'],
    });
    assert.deepEqual(qs.parse('items=a,b', { comma: true }), { items: ['a', 'b'] });
    assert.equal(qs.stringify({ user: { name: 'Ada' } }), 'user%5Bname%5D=Ada');
  });
}

test('Express retains nested query and URL-encoded form parsing', {
  timeout: 5000,
}, async (t) => {
  const express = require('express');
  const app = express();
  app.use(express.urlencoded({ extended: true, limit: '10kb' }));
  app.post('/probe', (req, res) => res.json({ query: req.query, body: req.body }));
  const server = app.listen(0, '127.0.0.1');
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections();
  }));
  await once(server, 'listening');
  const result = await new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port: server.address().port,
      method: 'POST',
      path: '/probe?filter[name]=Ada&tags[]=js&tags[]=node',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }, async (res) => {
      try {
        assert.equal(res.statusCode, 200);
        let body = '';
        for await (const chunk of res) body += chunk;
        resolve(JSON.parse(body));
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
    req.setTimeout(3000, () => req.destroy(new Error('form request timed out')));
    req.end('user[name]=Ada&roles[]=reader&roles[]=writer');
  });
  assert.deepEqual(result, {
    query: { filter: { name: 'Ada' }, tags: ['js', 'node'] },
    body: { user: { name: 'Ada' }, roles: ['reader', 'writer'] },
  });
});
