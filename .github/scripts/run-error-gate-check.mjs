#!/usr/bin/env node
// Negative control for run-error-gate.mjs: a clean fixture passes, and every condition the gate must refuse is refused.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const gate = path.join(path.dirname(fileURLToPath(import.meta.url)), 'run-error-gate.mjs');
const seen = { file: 'src/A.php', line: 'while ($a) {', occurrence: 1, mutant: 'M: while (!$a) {' };
const quiet = { file: 'src/A.php', line: 'while ($b) {', occurrence: 1, mutant: 'M: while (!$b) {' };
const SRC = '<?php\nwhile ($a) {\n}\n  while ($b) {\n}\n';

function run(over = {}) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'run-error-gate-'));
  const c = { src: SRC, list1: [seen], list2: [], survivors: [], ledger: [{ ...seen, reason: 'r' }, { ...quiet, reason: 'r' }], ...over };
  fs.mkdirSync(path.join(d, 'src'));
  if (c.src !== null) fs.writeFileSync(path.join(d, 'src/A.php'), c.src);
  for (const [n, list, survivors] of [[1, c.list1, c.survivors], [2, c.list2, []]]) {
    const a = path.join(d, `reports/shard-${n}`);
    fs.mkdirSync(a, { recursive: true });
    if (list !== null) fs.writeFileSync(path.join(a, `run-errors-${n}.json`), JSON.stringify(list));
    if (!(c.noReport === n)) fs.writeFileSync(path.join(a, `shard-${n}.json`), JSON.stringify({ survivors }));
  }
  fs.writeFileSync(path.join(d, 'ledger.json'), JSON.stringify(c.ledger));
  const r = spawnSync('node', [gate, `--reports=${d}/reports`, `--ledger=${d}/ledger.json`, `--src=${d}`, '--shards=2'], { encoding: 'utf8' });
  fs.rmSync(d, { recursive: true, force: true });
  return r;
}

const refuses = {
  'changed source line': [{ src: SRC.replace('while ($b) {', 'while ($c) {') }, 'STALE'],
  'source file gone': [{ src: null }, 'STALE'],
  'occurrence past the last match': [{ ledger: [{ ...seen, reason: 'r' }, { ...quiet, occurrence: 2, reason: 'r' }] }, 'STALE'],
  'unlisted errored mutant': [{ list2: [{ ...quiet, mutant: 'M: other' }] }, 'UNPROVEN'],
  'no reason': [{ ledger: [{ ...seen }, { ...quiet, reason: 'r' }] }, 'without a reason'],
  'blank reason': [{ ledger: [{ ...seen, reason: ' ' }, { ...quiet, reason: 'r' }] }, 'without a reason'],
  'count above the multiplicity': [{ list2: [seen] }, 'covers 1, the run has 2'],
  'count below the multiplicity': [{ ledger: [{ ...seen, multiplicity: 2, reason: 'r' }, { ...quiet, reason: 'r' }] }, 'covers 2, the run has 1'],
  'listed mutant survived': [{ survivors: [quiet] }, 'SURVIVED'],
  'missing run-error list': [{ list2: null }, 'no run-error list'],
  'missing shard report': [{ noReport: 2 }, 'no report'],
  'entry listed twice': [{ ledger: [{ ...seen, reason: 'r' }, { ...seen, reason: 'r' }, { ...quiet, reason: 'r' }] }, 'listed twice'],
};

let bad = 0;
const ok = run();
if (ok.status !== 0 || !ok.stdout.includes('1 listed entries with zero occurrences') || !ok.stdout.includes(`  src/A.php | while ($b) {`)) {
  console.error(`clean fixture must pass and list its zero-occurrence entry: status ${ok.status}\n${ok.stdout}${ok.stderr}`);
  bad++;
}
for (const [name, [over, text]] of Object.entries(refuses)) {
  const r = run(over);
  if (r.status !== 1 || !r.stderr.includes(text)) { console.error(`NOT refused as expected: ${name}: status ${r.status}\n${r.stdout}${r.stderr}`); bad++; }
  else console.log(`refused: ${name}`);
}
console.log(bad ? `${bad} control(s) failed` : `all ${Object.keys(refuses).length + 1} controls hold`);
process.exit(bad ? 1 : 0);
