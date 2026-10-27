import { hostOf } from '../indicator.js';
import net from 'node:net';

const DEFAULT_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const RR_TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 28: 'AAAA' };

function ptrName(ip) {
  if (net.isIPv4(ip)) return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  return expandV6(ip).split('').reverse().join('.') + '.ip6.arpa';
}

function expandV6(ip) {
  const [head, tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const fill = Array(8 - h.length - t.length).fill('0');
  return [...h, ...fill, ...t].map((g) => g.padStart(4, '0')).join('');
}

export function createDoh({ endpoint = DEFAULT_ENDPOINT, fetchImpl = fetch, timeoutMs = 8000 } = {}) {
  async function query(name, type) {
    const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${type}`;
    const res = await fetchImpl(url, {
      headers: { accept: 'application/dns-json' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`resolver returned HTTP ${res.status}`);
    return res.json();
  }

  return {
    name: 'doh',
    ttl: 15 * 60,
    online: true,
    supports: (i) => ['domain', 'url', 'ipv4', 'ipv6'].includes(i.type),
    async lookup(indicator, { now = new Date().toISOString() } = {}) {
      const host = hostOf(indicator);
      const isIp = net.isIP(host) !== 0;
      const jobs = isIp ? [[ptrName(host), 'PTR']] : ['A', 'AAAA', 'NS', 'MX'].map((t) => [host, t]);
      const facts = [];
      for (const [name, type] of jobs) {
        const body = await query(name, type);
        if (body.Status === 3) {
          facts.push({ name: `dns_${type}`, value: 'NXDOMAIN', source: 'doh', observedAt: now, confidence: 'medium' });
          continue;
        }
        const wanted = (body.Answer ?? []).filter((a) => RR_TYPES[a.type] === type);
        for (const a of wanted) {
          facts.push({
            name: `dns_${type}`,
            value: String(a.data).replace(/\.$/, ''),
            source: 'doh',
            observedAt: now,
            confidence: 'medium',
          });
        }
      }
      return facts;
    },
  };
}
