const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');

test('both lockfiles exclude body-parser versions affected by GHSA-27r3-jxmh-p828', () => {
  for (const file of ['package-lock.json', 'client/package-lock.json']) {
    const lockfile = JSON.parse(readFileSync(join(__dirname, '../..', file)));
    const packages = Object.entries(lockfile.packages).filter(([path]) =>
      path.endsWith('/body-parser'));
    if (file === 'package-lock.json') assert.ok(packages.length > 0);
    for (const [path, { version }] of packages) {
      const [major, minor, patch] = version.split('.').map(Number);
      assert.ok(
        major > 2 ||
        (major === 2 && minor >= 4) ||
        (major === 1 && (minor > 20 || (minor === 20 && patch >= 9))),
        `${file}: vulnerable ${path}@${version}`,
      );
    }
  }
});

for (const encoding of ['gzip', 'deflate']) {
  test(`Express survives trailing bytes after a ${encoding} request and drains pending input`, () => {
    // An unhandled decoder error must fail the child, not crash the test runner.
    const result = spawnSync(process.execPath, ['--eval', `
      const assert = require('node:assert/strict');
      const { createHash } = require('node:crypto');
      const { once } = require('node:events');
      const http = require('node:http');
      const express = require('express');
      const zlib = require('node:zlib');
      const encoding = ${JSON.stringify(encoding)};
      const parser = express.json({ limit: '10kb' });
      const app = express();
      const compressed = encoding === 'gzip'
        ? zlib.gzipSync('{"value":"ok"}')
        : zlib.deflateSync('{"value":"ok"}');
      const first = Buffer.concat([compressed, Buffer.from([0])]);
      const trailing = Buffer.alloc(100 * 1024, 0x58);
      const expectedHash = createHash('sha256').update(first).update(trailing).digest('hex');
      let client;
      app.post('/probe', (req, res, next) => {
        const hash = createHash('sha256');
        req.pipe(hash);
        const finished = once(hash, 'finish');
        parser(req, res, (error) => {
          if (error) return next(error);
          // Deliver the final bytes only after parsing finished successfully.
          client.end(trailing);
          finished.then(() => {
            assert.equal(req.complete, true);
            assert.equal(hash.read().toString('hex'), expectedHash);
            res.json(req.body);
          }).catch(next);
        });
      });
      app.post('/normal', parser, (req, res) => res.json(req.body));
      app.use((error, req, res, next) => {
        res.status(error.status || 500).json({ type: error.type });
      });
      const server = app.listen(0, '127.0.0.1', async () => {
        const port = server.address().port;
        function send(path, body, headers = {}) {
          return new Promise((resolve, reject) => {
            const req = http.request({
              hostname: '127.0.0.1', port, path, method: 'POST', agent: false,
              headers: { 'Content-Type': 'application/json', ...headers },
            }, async (res) => {
              try {
                let data = '';
                for await (const chunk of res) data += chunk;
                resolve({ status: res.statusCode, body: JSON.parse(data) });
              } catch (error) { reject(error); }
            });
            req.on('error', reject);
            req.setTimeout(3000, () => req.destroy(new Error('request did not finish')));
            if (path === '/probe') { client = req; req.write(first); }
            else req.end(body);
          });
        }
        try {
          const result = await send('/probe', null, {
            'Content-Encoding': encoding,
            'Content-Length': first.length + trailing.length,
          });
          assert.deepEqual(result, { status: 200, body: { value: 'ok' } });
          // Give late decoder errors a chance to surface, then prove the server remains usable.
          await new Promise(resolve => setTimeout(resolve, 100));
          assert.deepEqual(await send('/normal', '{"plain":true}'), {
            status: 200, body: { plain: true },
          });
          assert.deepEqual(await send('/normal', compressed, { 'Content-Encoding': encoding }), {
            status: 200, body: { value: 'ok' },
          });
          assert.equal((await send('/normal', '{invalid')).status, 400);
          const oversized = Buffer.from(JSON.stringify({ value: 'x'.repeat(11 * 1024) }));
          const packed = encoding === 'gzip'
            ? zlib.gzipSync(oversized) : zlib.deflateSync(oversized);
          assert.deepEqual(await send('/normal', packed, { 'Content-Encoding': encoding }), {
            status: 413, body: { type: 'entity.too.large' },
          });
        } catch (error) {
          console.error(error);
          process.exitCode = 1;
        } finally {
          server.close();
          server.closeAllConnections();
        }
      });
    `], {
      cwd: join(__dirname, '../..'),
      encoding: 'utf8',
      timeout: 10_000,
    });
    assert.ifError(result.error);
    assert.equal(result.signal, null, result.stderr);
    assert.equal(result.status, 0, result.stderr);
  });
}
