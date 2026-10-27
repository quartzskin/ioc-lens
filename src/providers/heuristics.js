import { hostOf } from '../indicator.js';

const SOURCE = 'heuristics';
const RISKY_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'icu', 'tk', 'gq', 'cf', 'ml', 'work', 'country']);
const EMPTY_HASHES = {
  md5: 'd41d8cd98f00b204e9800998ecf8427e',
  sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
};

export function entropy(s) {
  if (!s) return 0;
  const counts = new Map();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function classifyIPv4(ip) {
  const [a, b, c] = ip.split('.').map(Number);
  if (a === 0) return 'unspecified';
  if (a === 10) return 'private';
  if (a === 127) return 'loopback';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 192 && b === 168) return 'private';
  if (a === 169 && b === 254) return 'link-local';
  if (a === 100 && b >= 64 && b <= 127) return 'shared-address-space';
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) {
    return 'documentation';
  }
  if (a >= 224 && a <= 239) return 'multicast';
  if (a >= 240) return 'reserved';
  return 'public';
}

export function classifyIPv6(ip) {
  if (ip === '::') return 'unspecified';
  if (ip === '::1') return 'loopback';
  const first = parseInt(ip.split(':')[0] || '0', 16);
  if ((first & 0xfe00) === 0xfc00) return 'private';
  if ((first & 0xffc0) === 0xfe80) return 'link-local';
  if ((first & 0xff00) === 0xff00) return 'multicast';
  if (first === 0x2001 && ip.startsWith('2001:db8:')) return 'documentation';
  return 'public';
}

function fact(name, value, confidence, observedAt) {
  return { name, value, source: SOURCE, observedAt, confidence };
}

function domainFacts(domain, now) {
  const labels = domain.split('.');
  const tld = labels[labels.length - 1];
  const facts = [fact('tld', tld, 'high', now), fact('label_count', labels.length, 'high', now)];
  if (RISKY_TLDS.has(tld)) {
    facts.push(fact('tld_note', 'TLD is frequently abused in commodity phishing/spam; not evidence on its own', 'low', now));
  }
  if (labels.some((l) => l.startsWith('xn--'))) {
    facts.push(fact('punycode', true, 'high', now));
  }
  const sld = labels[labels.length - 2];
  const h = entropy(sld);
  facts.push(fact('sld_entropy', Number(h.toFixed(2)), 'high', now));
  if (sld.length >= 12 && h > 3.5) {
    facts.push(fact('algorithmic_looking', true, 'low', now));
  }
  return facts;
}

export const heuristics = {
  name: SOURCE,
  ttl: 0,
  online: false,
  supports: () => true,
  async lookup(indicator, { now = new Date().toISOString() } = {}) {
    const { type, value } = indicator;
    if (type === 'ipv4') return [fact('address_class', classifyIPv4(value), 'high', now)];
    if (type === 'ipv6') return [fact('address_class', classifyIPv6(value), 'high', now)];
    if (type === 'domain') return domainFacts(value, now);
    if (type === 'url') {
      const u = new URL(value);
      const facts = [fact('scheme', u.protocol.slice(0, -1), 'high', now)];
      const host = hostOf(indicator);
      facts.push(fact('host', host, 'high', now));
      if (u.username || u.password) {
        facts.push(fact('embedded_credentials', true, 'medium', now));
      }
      if (u.port) facts.push(fact('port', Number(u.port), 'high', now));
      if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
        facts.push(fact('host_address_class', classifyIPv4(host), 'high', now));
      } else if (!host.includes(':')) {
        facts.push(...domainFacts(host, now).filter((f) => f.name === 'tld' || f.name === 'punycode'));
      }
      return facts;
    }
    const facts = [fact('hash_type', type, 'high', now)];
    if (EMPTY_HASHES[type] === value) {
      facts.push(fact('known_value', 'hash of empty input', 'high', now));
    }
    return facts;
  },
};
