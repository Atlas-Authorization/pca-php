#!/usr/bin/env node
// The PHP run-error gate. An ERRORED mutant's test process died (PHP fatal error, memory exhaustion, signal) and a TIMED-OUT one
// hit the Infection timeout, with no test deciding either, yet Infection counts both as detected, so each must be listed in
// mutation-run-errors.json with a proof that the mutant itself loops or allocates without bound (or why it dies).
// A listed entry may have 0 occurrences in a run: on unchanged tests, listed mutants were seen to land in killed or timed out
// instead (causes inferred: time-to-memory-limit against the timeout, and Infection's time-based test order). Every failure
// below stays exact. The survivor check (mutation-merge.mjs) does not read this ledger and is unaffected.
import fs from 'node:fs';
import path from 'node:path';

const arg = (n) => process.argv.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);
const [reports, ledger, src, want] = [arg('reports'), arg('ledger'), arg('src'), Number(arg('shards'))];
const key = (m) => [m.file, m.line, m.occurrence || 1, m.mutant].join(' | ');

const lists = new Map(), shardReports = new Map(), killedKeys = new Set();
// A shard's infection-baseline.json holds its sources and every mutant of this run with its bucket. The key is built exactly as
// php-survivors.py builds a record's key (trimmed source line, occurrence of that text, '<Mutator>: <first changed line>').
const addKilled = (b) => {
  for (const m of b.mutants ?? []) {
    if (m.bucket !== 'killed') continue;
    const src = (b.sources?.[m.file] ?? '').split('\n');
    const line = (src[m.line - 1] ?? '').trim();
    const occ = src.slice(0, m.line).filter((l) => l.trim() === line).length;
    const plus = m.diff.split('\n').filter((l) => l.startsWith('+') && !l.startsWith('+++')).map((l) => l.slice(1).trim());
    killedKeys.add(key({ file: 'src/' + m.file, line, occurrence: occ, mutant: (m.mutator + ': ' + (plus[0] ?? '(line removed)')).slice(0, 240) }));
  }
};
const walk = (d) => {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) { walk(p); continue; }
    if (e.name === 'infection-baseline.json') { addKilled(JSON.parse(fs.readFileSync(p, 'utf8'))); continue; }
    const m = /^(run-errors|shard)-(\d+)\.json$/.exec(e.name);
    if (m) (m[1] === 'shard' ? shardReports : lists).set(Number(m[2]), JSON.parse(fs.readFileSync(p, 'utf8')));
  }
};
walk(reports);

// a zero-occurrence entry means nothing unless every shard really ran: a missing shard fails the whole gate
let incomplete = false;
for (let n = 1; n <= want; n++) {
  if (!lists.has(n)) { console.error(`::error::shard ${n}: no run-error list (a missing list is a failure)`); incomplete = true; }
  if (!shardReports.has(n)) { console.error(`::error::shard ${n}: no report (a missing report is a failure)`); incomplete = true; }
}
if (lists.size !== want || shardReports.size !== want) { console.error(`::error::expected ${want} shards, have ${lists.size} lists and ${shardReports.size} reports`); incomplete = true; }
for (const [n, r] of shardReports) {
  const c = r.counts ?? {};
  if (!['killed', 'escaped', 'error', 'timeOut', 'notCovered'].some((k) => c[k] > 0)) { console.error(`::error::shard ${n}: its report counts no mutant at all`); incomplete = true; }
}
if (incomplete) process.exit(1);

const got = [...lists.values()].flat();
const have = new Map(), ev = new Map();
for (const m of got) {
  have.set(key(m), (have.get(key(m)) || 0) + 1);
  if (!ev.has(key(m))) ev.set(key(m), (m.evidence || '').slice(-300).replace(/\s+/g, ' '));
}
const survived = new Set([...shardReports.values()].flatMap((r) => r.survivors ?? []).map(key));
const led = JSON.parse(fs.readFileSync(ledger, 'utf8'));
const fileLines = new Map();
const countOf = (file, line) => {
  const f = path.join(src, file);
  if (!fileLines.has(f)) fileLines.set(f, fs.existsSync(f) ? fs.readFileSync(f, 'utf8').split(/\r?\n/).map((l) => l.trim()) : []);
  return fileLines.get(f).filter((l) => l === line.trim()).length;
};

let bad = 0;
const fail = (s) => { console.error(`::error::${s}`); bad++; };
const used = new Set(), zero = [];
for (const e of led) {
  const k = key(e);
  if (used.has(k)) fail(`run-error ledger entry listed twice: ${k}`);
  used.add(k);
  if (typeof e.reason !== 'string' || !e.reason.trim()) fail(`run-error ledger entry without a reason: ${k}`);
  if (countOf(e.file, e.line) < (e.occurrence || 1)) fail(`STALE run-error ledger entry, the source line changed or is gone: ${k}`);
  if (survived.has(k)) fail(`a listed mutant SURVIVED: ${k}`);
  const n = have.get(k) || 0, m = e.multiplicity || 1;
  if (n === 0) {
    // 0 occurrences passes only when this exact mutant was KILLED in this run (a test decided it); a survivor, an uncovered or a
    // vanished mutant means the entry is stale
    if (killedKeys.has(k)) zero.push(k);
    else fail(`STALE run-error ledger entry: no errored or timed-out occurrence and the mutant was not killed in this run (survived, not covered, or gone): ${k}`);
  }
  else if (n !== m) fail(`run-error ledger entry covers ${m}, the run has ${n}: ${k}`);
}
for (const [k, n] of have) if (!used.has(k)) fail(`UNPROVEN run error (x${n}), no test decided it: ${k} :: ${ev.get(k)}`);
console.log(`${zero.length} listed entries with zero occurrences in this run, each killed this time:`);
for (const k of zero) console.log(`::notice::killed this run, entry no longer needed: ${k}`);
console.log(`${got.length} errored or timed-out mutant(s) over ${want} shards, ${led.length} ledger entries, ${zero.length} with zero occurrences, ${bad} problem(s)`);
process.exit(bad ? 1 : 0);
