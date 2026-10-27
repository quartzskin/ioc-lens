import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { enrich } from '../src/enrich.js';
import { openCache } from '../src/cache.js';
import { toJson, toMarkdown } from '../src/export.js';
import { heuristics } from '../src/providers/heuristics.js';

function counting(ttl = 60) {
  const p = {
    name: 'counting',
    ttl,
    supports: () => true,
    calls: 0,
    async lookup(_i, { now }) {
      p.calls++;
      return [{ name: 'n', value: p.calls, source: 'counting', observedAt: now, confidence: 'low' }];
    },
  };
  return p;
}

test('cache serves within TTL and refetches after expiry', async () => {
  const cache = openCache();
  const p = counting();
  let t = 1_000_000;
  const opts = { providers: [p], cache, now: () => new Date(t) };

  await enrich('example.com', opts);
  const second = await enrich('EXAMPLE.com', opts);
  assert.equal(p.calls, 1);
  assert.equal(second.facts[0].cached, true);

  t += 61_000;
  await enrich('example.com', opts);
  assert.equal(p.calls, 2);
  cache.close();
});

test('ttl 0 bypasses the cache; purge removes expired rows', async () => {
  const cache = openCache();
  const p = counting(0);
  await enrich('example.com', { providers: [p], cache });
  await enrich('example.com', { providers: [p], cache });
  assert.equal(p.calls, 2);

  cache.set('x', 'y', [], 1, 0);
  assert.equal(cache.purgeExpired(5000), 1);
  cache.close();
});

test('a failing provider is reported without losing other facts', async () => {
  const bad = { name: 'bad', ttl: 0, supports: () => true, lookup: async () => { throw new Error('boom'); } };
  const r = await enrich('8.8.8.8', { providers: [heuristics, bad] });
  assert.equal(r.errors[0].provider, 'bad');
  assert.ok(r.facts.length > 0);
});

test('invalid input yields an error entry', async () => {
  const r = await enrich('not an ioc', { providers: [heuristics] });
  assert.ok(r.error);
  assert.deepEqual(r.facts, []);
});

test('exports', async () => {
  const results = [
    await enrich('hxxp://a[.]example[.]com/', { providers: [heuristics] }),
    await enrich('???', { providers: [heuristics] }),
  ];
  assert.equal(JSON.parse(toJson(results))[0].type, 'url');
  const md = toMarkdown(results);
  assert.match(md, /## http:\/\/a\.example\.com\/ \(url\)/);
  assert.match(md, /\| host \| a\.example\.com \| heuristics \| high \|/);
  assert.match(md, /Skipped: not a recognised indicator/);
});

test('cli: offline run, bad input exit code, no network by default', () => {
  const run = (...a) =>
    spawnSync(process.execPath, ['bin/ioc-lens.js', '--no-cache', ...a], { encoding: 'utf8' });

  const good = run('--mock', '192.0.2.1');
  assert.equal(good.status, 0);
  const out = JSON.parse(good.stdout);
  assert.deepEqual(new Set(out[0].facts.map((f) => f.source)), new Set(['heuristics', 'mock']));

  const bad = run('1.2.3.999');
  assert.equal(bad.status, 1);
  assert.equal(run('--format', 'xml', '1.1.1.1').status, 2);
  assert.equal(run('--doh', 'http://x', '1.1.1.1').status, 2);
  assert.equal(run('--bogus').status, 2);
});
