#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { readFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { enrich } from '../src/enrich.js';
import { openCache } from '../src/cache.js';
import { heuristics } from '../src/providers/heuristics.js';
import { createMock } from '../src/providers/mock.js';
import { createDoh } from '../src/providers/doh.js';
import { toJson, toMarkdown } from '../src/export.js';

const USAGE = `usage: ioc-lens [options] <indicator...>
       ioc-lens [options] -        read indicators from stdin, one per line

  --online          allow DNS-over-HTTPS lookups (sends the host name to the resolver)
  --doh <url>       resolver endpoint (default Cloudflare)
  --mock            add the mock provider (built-in sample data)
  --mock-file <f>   add the mock provider with a JSON fixture
  --format <fmt>    json (default) or md
  --db <path>       cache file (default ~/.ioc-lens/cache.db)
  --ttl <seconds>   override provider cache TTL
  --no-cache        do not read or write the cache
  -h, --help
`;

function fail(msg) {
  console.error(`ioc-lens: ${msg}`);
  process.exit(2);
}

let args;
try {
  args = parseArgs({
    allowPositionals: true,
    options: {
      online: { type: 'boolean' },
      doh: { type: 'string' },
      mock: { type: 'boolean' },
      'mock-file': { type: 'string' },
      format: { type: 'string', default: 'json' },
      db: { type: 'string' },
      ttl: { type: 'string' },
      'no-cache': { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
    strict: true,
  });
} catch (err) {
  fail(err.message);
}
const { values, positionals } = args;

if (values.help || positionals.length === 0) {
  process.stdout.write(USAGE);
  process.exit(values.help ? 0 : 2);
}
if (!['json', 'md'].includes(values.format)) fail('--format must be json or md');
if (values.doh && !values.online) fail('--doh needs --online');

let ttl;
if (values.ttl !== undefined) {
  ttl = Number(values.ttl);
  if (!Number.isFinite(ttl) || ttl < 0) fail('--ttl must be a non-negative number');
}

let inputs = positionals;
if (positionals.length === 1 && positionals[0] === '-') {
  inputs = readFileSync(0, 'utf8').split(/\r?\n/).filter((l) => l.trim());
}

const providers = [heuristics];
try {
  if (values.mock || values['mock-file']) providers.push(createMock(values['mock-file']));
} catch (err) {
  fail(`cannot load mock fixture: ${err.message}`);
}
if (values.online) providers.push(createDoh({ endpoint: values.doh }));

let cache = null;
if (!values['no-cache']) {
  const path = values.db ?? join(homedir(), '.ioc-lens', 'cache.db');
  mkdirSync(dirname(path), { recursive: true });
  cache = openCache(path);
  cache.purgeExpired();
}

const results = [];
for (const input of inputs) results.push(await enrich(input, { providers, cache, ttl }));
cache?.close();

console.log(values.format === 'md' ? toMarkdown(results) : toJson(results));
process.exit(results.some((r) => r.error) ? 1 : 0);
