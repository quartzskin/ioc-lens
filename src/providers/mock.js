import { readFileSync } from 'node:fs';

const BUILTIN = {
  'example.com': [{ name: 'reputation', value: 'benign', confidence: 'medium' }],
  '192.0.2.1': [{ name: 'reputation', value: 'malicious', confidence: 'low' }],
  'd41d8cd98f00b204e9800998ecf8427e': [{ name: 'reputation', value: 'benign', confidence: 'medium' }],
};

// Fixture format: { "<normalized indicator>": [{ name, value, confidence }] }
export function createMock(path) {
  const table = path ? JSON.parse(readFileSync(path, 'utf8')) : BUILTIN;
  return {
    name: 'mock',
    ttl: 0,
    online: false,
    supports: () => true,
    async lookup(indicator, { now = new Date().toISOString() } = {}) {
      const rows = table[indicator.value] ?? [];
      return rows.map((r) => ({
        name: r.name,
        value: r.value,
        source: 'mock',
        observedAt: now,
        confidence: r.confidence ?? 'low',
      }));
    },
  };
}
