import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIndicator } from '../src/indicator.js';

const ok = (input) => {
  const r = parseIndicator(input);
  assert.ok(r.ok, `${input} should parse`);
  return r;
};

test('detects and normalizes types', () => {
  assert.deepEqual(ok('8.8.8.8').type, 'ipv4');
  assert.equal(ok('2001:DB8:0:0:0:0:0:1').value, '2001:db8::1');
  assert.equal(ok('[::1]').type, 'ipv6');
  assert.equal(ok('Example.COM.').value, 'example.com');
  assert.equal(ok('D41D8CD98F00B204E9800998ECF8427E').type, 'md5');
  assert.equal(ok('da39a3ee5e6b4b0d3255bfef95601890afd80709').type, 'sha1');
  assert.equal(ok('E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855').type, 'sha256');
  assert.equal(ok('HTTP://Example.com:80/a#frag').value, 'http://example.com/a');
});

test('refangs common defanging styles', () => {
  assert.equal(ok('hxxp://evil[.]example[.]com/x').value, 'http://evil.example.com/x');
  assert.equal(ok('hxxps[:]//evil(.)example{.}com').value, 'https://evil.example.com/');
  assert.equal(ok('1[.]2[.]3[.]4').value, '1.2.3.4');
  assert.equal(ok('evil[dot]com').value, 'evil.com');
});

test('rejects malformed input', () => {
  const bad = [
    '', '   ', null, undefined, 42,
    '256.1.1.1', '1.2.3', '1.2.3.4.5', '01.2.3.4',
    'localhost', 'a..com', '-bad.com', 'bad-.com', 'foo.123', 'exa mple.com',
    ':::', '12345::6789::1',
    'abcdef', 'g41d8cd98f00b204e9800998ecf8427e',
    'http://', 'http://exa mple.com', 'javascript://alert(1)', 'ftp://[::1', 'http://256.1.1.1',
    'a'.repeat(64) + '.com',
  ];
  for (const b of bad) assert.equal(parseIndicator(b).ok, false, `${String(b)} should be rejected`);
});

test('overlong domain is rejected', () => {
  assert.equal(parseIndicator(('a'.repeat(60) + '.').repeat(5) + 'com').ok, false);
});
