# ioc-lens

Small CLI that takes indicators (IPs, domains, URLs, file hashes), normalizes them, and collects facts about them from a few providers. Every fact carries its source, a timestamp and a confidence label (low / medium / high). Output is JSON or Markdown.

No npm dependencies. Needs a Node version with `node:sqlite` (24+; developed on 26).

## Usage

    node bin/ioc-lens.js 8.8.8.8 'hxxps://evil[.]example[.]com/login' d41d8cd98f00b204e9800998ecf8427e
    node bin/ioc-lens.js --format md example.com
    node bin/ioc-lens.js --online example.com
    printf '1.2.3.4\nexample.org\n' | node bin/ioc-lens.js -

Options: `--online`, `--doh <url>`, `--mock`, `--mock-file <json>`, `--format json|md`, `--db <path>`, `--ttl <seconds>`, `--no-cache`. Exit code is 1 if any input was not a valid indicator, 2 for bad arguments.

Detected: IPv4, IPv6, domains, http/https/ftp URLs, MD5/SHA-1/SHA-256. Defanged forms (`hxxp`, `[.]`, `(.)`, `[dot]`, `[:]`, `[://]`) are refanged first. Domains are lowercased, IPv6 is compressed, URL fragments are dropped.

## Providers

- `heuristics` (always on, offline): address class (private, loopback, link-local, documentation, ...), TLD, label entropy, punycode, embedded URL credentials, hash type, hashes of empty input.
- `mock`: returns canned facts from a built-in table or a JSON fixture `{ "<indicator>": [{ "name", "value", "confidence" }] }`. For tests and demos.
- `doh` (only with `--online`): DNS-over-HTTPS lookups against Cloudflare's JSON endpoint, no key. A/AAAA/NS/MX for domains and URL hosts, PTR for IPs. Results are cached for 15 minutes in SQLite (`~/.ioc-lens/cache.db` by default).

A provider is an object with `name`, `ttl`, `supports(indicator)` and `async lookup(indicator, { now })` returning facts; see `src/providers/mock.js` for the smallest one.

## Network behaviour

URLs are never requested. For a URL only the host name is looked up, and only with `--online`. Online mode sends the host name to the resolver, so don't use it for names you consider sensitive.

## Limits

- DoH is the only online source, and it only tells you what a name resolves to. There is no reputation, WHOIS, or passive DNS provider.
- Heuristics are crude. The TLD list and the entropy threshold are guesses and are labelled low confidence. No public suffix list, so `co.uk` style names treat `co` as the second-level label.
- Defang handling covers common patterns, not everything seen in reports. Emails, CIDR ranges and CVE ids are not recognised.
- Resolver rate limits are not tracked; a failed lookup is reported and not cached.
- Tested on Windows only so far; CI runs on Linux.

## Tests

    node --test
