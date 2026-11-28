#!/usr/bin/env python3
"""Measured cost of one shard's mutants, for the next shard plan (mutation-plan.py / mutation-cost.json).

  python3 infection-cost.py --log infection-out/log.json --shard <k> --out cost-<k>.json

Per file: mutants run, the PHPUnit run time each one reported ("Time: mm:ss.mmm" in its process output; a run that died or
timed out reports none and is counted under `untimed`), and the per-bucket split. A process also pays its PHP / PHPUnit start
(not in that time), so the plan adds a per-mutant start cost on top.
"""
import collections, json, re, sys

def opt(name):
    return sys.argv[sys.argv.index(name) + 1]

TIME = re.compile(r'Time: (?:(\d+):)?(\d+):(\d+(?:\.\d+)?)')
log = json.load(open(opt('--log')))
files = collections.defaultdict(lambda: {'mutants': 0, 'seconds': 0.0, 'untimed': 0, 'buckets': collections.Counter()})
for bucket, ms in log.items():
    if bucket == 'stats' or not isinstance(ms, list):
        continue
    for m in ms:
        f = files[re.sub(r'^(?:.*/)?src/', 'src/', m['mutator']['originalFilePath'].replace('\\', '/'))]
        f['mutants'] += 1
        f['buckets'][bucket] += 1
        t = TIME.findall(m.get('processOutput') or '')
        if t and bucket != 'uncovered':
            h, mi, s = t[-1]
            f['seconds'] += int(h or 0) * 3600 + int(mi) * 60 + float(s)
        elif bucket != 'uncovered':
            f['untimed'] += 1
out = {'shard': int(opt('--shard')), 'files': {k: dict(v, seconds=round(v['seconds'], 1)) for k, v in sorted(files.items())}}
json.dump(out, open(opt('--out'), 'w'), indent=1)
print(f"cost: {sum(v['mutants'] for v in files.values())} mutants, {sum(v['seconds'] for v in files.values()) / 60:.1f} min of PHPUnit time, "
      f"{sum(v['untimed'] for v in files.values())} untimed")
