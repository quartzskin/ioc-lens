import { test } from 'node:test';
import assert from 'node:assert/strict';
import { heuristics, entropy, classifyIPv4, classifyIPv6 } from '../src/providers/heuristics.js';
import { createMock } from '../src/providers/mock.js';
import { createDoh } from '../src/providers/doh.js';

const get = (facts, name) => facts.find((f) => f.name === name)?.value;

test('address classification', () => {
  assert.equal(classifyIPv4('10.1.2.3'), 'private');
  assert.equal(classifyIPv4('172.31.0.1'), 'private');
  assert.equal(classifyIPv4('172.32.0.1'), 'public');
  assert.equal(classifyIPv4('127.0.0.1'), 'loopback');
  assert.equal(classifyIPv4('100.64.0.1'), 'shared-address-space');
  assert.equal(classifyIPv4('8.8.8.8'), 'public');
  assert.equal(classifyIPv6('::1'), 'loopback');
  assert.equal(classifyIPv6('fd00::1'), 'private');
  assert.equal(classifyIPv6('fe80::1'), 'link-local');
  assert.equal(classifyIPv6('2606:4700::1111'), 'public');
});

test('entropy', () => {
  assert.equal(entropy(''), 0);
  assert.equal(entropy('aaaa'), 0);
  assert.equal(entropy('abcd'), 2);
});

test('heuristics on domains, urls and hashes', async () => {
  const d = await heuristics.lookup({ type: 'domain', value: 'xk3j9qz7vb2mw4lp.top' });
  assert.equal(get(d, 'tld'), 'top');
  assert.equal(get(d, 'algorithmic_looking'), true);

  const plain = await heuristics.lookup({ type: 'domain', value: 'example.com' });
  assert.equal(get(plain, 'algorithmic_looking'), undefined);

  const u = await heuristics.lookup({ type: 'url', value: 'http://user:pw@10.0.0.5:8080/x' });
  assert.equal(get(u, 'embedded_credentials'), true);
  assert.equal(get(u, 'host_address_class'), 'private');
  assert.equal(get(u, 'port'), 8080);

  const h = await heuristics.lookup({ type: 'md5', value: 'd41d8cd98f00b204e9800998ecf8427e' });
  assert.equal(get(h, 'known_value'), 'hash of empty input');
});

test('mock provider returns fixture rows with provenance', async () => {
  const mock = createMock();
  const facts = await mock.lookup({ type: 'domain', value: 'example.com' }, { now: 'T' });
  assert.deepEqual(facts, [
    { name: 'reputation', value: 'benign', source: 'mock', observedAt: 'T', confidence: 'medium' },
  ]);
  assert.deepEqual(await mock.lookup({ type: 'domain', value: 'unknown.test' }), []);
});

function fakeFetch(answers, calls = []) {
  return async (url) => {
    calls.push(url);
    const u = new URL(url);
    const body = answers[`${u.searchParams.get('name')}/${u.searchParams.get('type')}`] ?? { Status: 0 };
    return { ok: true, status: 200, json: async () => body };
  };
}

test('doh resolves a domain through the injected fetch only', async () => {
  const calls = [];
  const doh = createDoh({
    fetchImpl: fakeFetch(
      {
        'example.com/A': { Status: 0, Answer: [{ type: 1, data: '93.184.216.34' }] },
        'example.com/MX': { Status: 0, Answer: [{ type: 15, data: '0 mail.example.com.' }] },
      },
      calls,
    ),
  });
  const facts = await doh.lookup({ type: 'url', value: 'https://example.com/path?q=1' });
  assert.equal(get(facts, 'dns_A'), '93.184.216.34');
  assert.equal(get(facts, 'dns_MX'), '0 mail.example.com');
  assert.equal(calls.length, 4);
  assert.ok(calls.every((c) => c.startsWith('https://cloudflare-dns.com/dns-query?name=example.com')));
});

test('doh does PTR for ips and reports NXDOMAIN', async () => {
  const doh = createDoh({
    fetchImpl: fakeFetch({
      '4.3.2.1.in-addr.arpa/PTR': { Status: 0, Answer: [{ type: 12, data: 'host.example.net.' }] },
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa/PTR': { Status: 3 },
    }),
  });
  assert.equal(get(await doh.lookup({ type: 'ipv4', value: '1.2.3.4' }), 'dns_PTR'), 'host.example.net');
  assert.equal(get(await doh.lookup({ type: 'ipv6', value: '::1' }), 'dns_PTR'), 'NXDOMAIN');
});

test('doh surfaces HTTP errors and does not support hashes', async () => {
  const doh = createDoh({ fetchImpl: async () => ({ ok: false, status: 503 }) });
  await assert.rejects(doh.lookup({ type: 'domain', value: 'example.com' }), /HTTP 503/);
  assert.equal(doh.supports({ type: 'sha256' }), false);
});
