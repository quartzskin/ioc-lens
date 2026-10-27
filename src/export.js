export function toJson(results) {
  return JSON.stringify(results, null, 2);
}

const cell = (v) => String(v).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

export function toMarkdown(results) {
  const out = ['# IOC enrichment', ''];
  for (const r of results) {
    if (r.error) {
      out.push(`## ${cell(r.input)}`, '', `Skipped: ${r.error}`, '');
      continue;
    }
    out.push(`## ${r.value} (${r.type})`, '');
    if (r.facts.length) {
      out.push('| Fact | Value | Source | Confidence | Observed |', '| --- | --- | --- | --- | --- |');
      for (const f of r.facts) {
        const src = f.cached ? `${f.source} (cached)` : f.source;
        out.push(`| ${f.name} | ${cell(f.value)} | ${src} | ${f.confidence} | ${f.observedAt} |`);
      }
      out.push('');
    } else {
      out.push('No facts from the enabled providers.', '');
    }
    for (const e of r.errors) out.push(`Provider ${e.provider} failed: ${cell(e.message)}`, '');
  }
  return out.join('\n');
}
