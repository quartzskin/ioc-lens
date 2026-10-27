import { parseIndicator } from './indicator.js';

export async function enrich(input, { providers, cache, ttl, now = () => new Date() }) {
  const parsed = parseIndicator(input);
  if (!parsed.ok) return { input, error: parsed.error, facts: [], errors: [] };

  const indicator = { type: parsed.type, value: parsed.value };
  const facts = [];
  const errors = [];

  for (const p of providers) {
    if (!p.supports(indicator)) continue;
    const ttlSeconds = ttl ?? p.ttl;
    const cached = cache && ttlSeconds > 0 ? cache.get(p.name, indicator.value, now().getTime()) : null;
    if (cached) {
      facts.push(...cached.map((f) => ({ ...f, cached: true })));
      continue;
    }
    try {
      const got = await p.lookup(indicator, { now: now().toISOString() });
      facts.push(...got);
      if (cache && ttlSeconds > 0) cache.set(p.name, indicator.value, got, ttlSeconds, now().getTime());
    } catch (err) {
      errors.push({ provider: p.name, message: err.cause?.message ?? err.message });
    }
  }

  return { input, ...indicator, enrichedAt: now().toISOString(), facts, errors };
}
