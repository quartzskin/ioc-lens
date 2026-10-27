import net from 'node:net';

const HASH_LENGTHS = { 32: 'md5', 40: 'sha1', 64: 'sha256' };
const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

export function refang(input) {
  return String(input)
    .trim()
    .replace(/^(h)(?:xx|tt)p(s?)(?=\[?:|:)/i, (_, h, s) => `${h}ttp${s}`)
    .replace(/^fxp(?=:)/i, 'ftp')
    .replace(/\[:\]|\(:\)/g, ':')
    .replace(/\[:\/\/\]/g, '://')
    .replace(/\[\/\/\]/g, '//')
    .replace(/[[({]\s*(?:\.|dot)\s*[\])}]/gi, '.')
    .replace(/[[({]\s*(?:@|at)\s*[\])}]/gi, '@');
}

function normalizeIPv4(s) {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  for (const p of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255) return null;
  }
  return s;
}

function normalizeIPv6(s) {
  const bare = s.replace(/^\[|\]$/g, '');
  if (!net.isIPv6(bare)) return null;
  try {
    return new URL(`http://[${bare}]`).hostname.slice(1, -1);
  } catch {
    return null;
  }
}

function normalizeDomain(s) {
  const d = s.toLowerCase().replace(/\.$/, '');
  if (d.length > 253) return null;
  const labels = d.split('.');
  if (labels.length < 2) return null;
  for (const l of labels) {
    if (!/^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/.test(l)) return null;
  }
  const tld = labels[labels.length - 1];
  if (!/^([a-z]{2,63}|xn--[a-z0-9-]+)$/.test(tld)) return null;
  return d;
}

function normalizeHost(h) {
  if (h.startsWith('[')) return normalizeIPv6(h);
  return normalizeIPv4(h) ?? normalizeDomain(h);
}

function normalizeUrl(s) {
  if (!/^(https?|ftp):\/\//i.test(s) || /\s/.test(s)) return null;
  let u;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  const host = u.hostname;
  if (!host || !normalizeHost(host)) return null;
  u.hash = '';
  return u.href;
}

export function parseIndicator(input) {
  if (typeof input !== 'string' || !input.trim()) {
    return { ok: false, input: String(input), error: 'empty input' };
  }
  const raw = refang(input);

  if (SCHEME.test(raw)) {
    const value = normalizeUrl(raw);
    if (!value) return { ok: false, input, error: 'invalid or unsupported URL' };
    return { ok: true, input, type: 'url', value };
  }

  if (/^[0-9a-f]+$/i.test(raw) && HASH_LENGTHS[raw.length]) {
    return { ok: true, input, type: HASH_LENGTHS[raw.length], value: raw.toLowerCase() };
  }

  const v4 = normalizeIPv4(raw);
  if (v4) return { ok: true, input, type: 'ipv4', value: v4 };

  if (raw.includes(':')) {
    const v6 = normalizeIPv6(raw);
    if (v6) return { ok: true, input, type: 'ipv6', value: v6 };
  }

  const domain = normalizeDomain(raw);
  if (domain) return { ok: true, input, type: 'domain', value: domain };

  return { ok: false, input, error: 'not a recognised indicator' };
}

export function hostOf(indicator) {
  if (indicator.type === 'url') {
    const h = new URL(indicator.value).hostname;
    return h.startsWith('[') ? h.slice(1, -1) : h;
  }
  return indicator.value;
}
