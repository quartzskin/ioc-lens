import { DatabaseSync } from 'node:sqlite';

export function openCache(path = ':memory:') {
  const db = new DatabaseSync(path);
  db.exec(`
    CREATE TABLE IF NOT EXISTS lookups (
      provider   TEXT NOT NULL,
      value      TEXT NOT NULL,
      fetched_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      facts      TEXT NOT NULL,
      PRIMARY KEY (provider, value)
    )
  `);
  const get = db.prepare('SELECT facts FROM lookups WHERE provider = ? AND value = ? AND expires_at > ?');
  const put = db.prepare('INSERT OR REPLACE INTO lookups VALUES (?, ?, ?, ?, ?)');
  const purge = db.prepare('DELETE FROM lookups WHERE expires_at <= ?');

  return {
    get(provider, value, nowMs = Date.now()) {
      const row = get.get(provider, value, nowMs);
      return row ? JSON.parse(row.facts) : null;
    },
    set(provider, value, facts, ttlSeconds, nowMs = Date.now()) {
      put.run(provider, value, nowMs, nowMs + ttlSeconds * 1000, JSON.stringify(facts));
    },
    purgeExpired(nowMs = Date.now()) {
      return Number(purge.run(nowMs).changes);
    },
    close() {
      db.close();
    },
  };
}
