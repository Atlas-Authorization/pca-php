#!/usr/bin/env python3
"""Regenerate the generated block of the shard matrix in mutation.yml from the measured mutation cost of every src/ file.

  python3 mutation-plan.py <src dir> <mutation.yml> <mutation-cost.json>          rewrite the block (and SHARDS / the job name)
  python3 mutation-plan.py --check <src dir> <mutation.yml> <mutation-cost.json>  fail when the file is not what the rewrite writes

Files named by a hand-written entry (outside the block: the native-library shards) are left where they are. Every other file of
src/ is packed by cost (mutation-cost.json: thread-minutes per file, measured or estimated) into shards of at most `budget`; a
file over the budget is cut into ceil(1.25 cost / budget) line slices (infection-slice.py: cuts at method ends), one shard each.
Greedy first-fit, largest first, deterministic. A file missing from the cost table fails the plan (measure or estimate it).
"""
import json, math, pathlib, re, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from importlib import import_module
cuts = import_module('infection-slice').cuts

BEGIN, END = '          # BEGIN generated plan (scripts/mutation-plan.py)\n', '          # END generated plan\n'

def main(argv):
    check = argv[0] == '--check'
    src, wf, ct = (pathlib.Path(a) for a in argv[check:3 + check])
    text = wf.read_text()
    table = json.loads(ct.read_text())
    cost, budget = {**table['estimated'], **table['measured']}, table['budget']
    a, b = text.index(BEGIN), text.index(END)
    outside = text[:a] + text[b + len(END):]
    entry = re.compile(r"^ +- \{ shard: (\d+), files: '([^']*)'", re.M)
    hand = {f for m in entry.finditer(outside) for f in m.group(2).split(',')}
    last = max((int(m.group(1)) for m in entry.finditer(outside)), default=0)
    todo = sorted(f for f in (p.relative_to(src.parent).as_posix() for p in src.glob('**/*.php')) if f not in hand)
    missing = [f for f in todo if f not in cost]
    if missing:
        sys.exit(f'no cost for {missing} in {ct} (measure or estimate them)')
    bins = []  # [cost, [files], slice-or-None]
    for f in todo:
        if cost[f] > budget:
            # equal-line slices of a file whose cost is not spread evenly over its lines: 25% headroom per slice
            n = math.ceil(cost[f] * 1.25 / budget)
            cuts((src.parent / f).read_text().split('\n'), n)  # every slice must be non-empty
            bins += [[cost[f] / n, [f], f'{k}/{n}'] for k in range(1, n + 1)]
    for f in sorted((f for f in todo if cost[f] <= budget), key=lambda f: (-cost[f], f)):
        x = next((x for x in bins if x[2] is None and x[0] + cost[f] <= budget), None)
        if x is None:
            x = [0, [], None]
            bins.append(x)
        x[0] += cost[f]
        x[1].append(f)
    block = BEGIN
    for i, (c, fs, sl) in enumerate(sorted(bins, key=lambda x: (sorted(x[1])[0], int((x[2] or '0/1').split('/')[0]))), last + 1):
        block += f"          - {{ shard: {i}, files: '{','.join(sorted(fs))}'{f", slice: '{sl}'" if sl else ''} }}\n"
    total = last + len(bins)
    if total > 256:
        sys.exit(f'{total} shards: a GitHub matrix runs at most 256 jobs (raise the budget or make the covering tests faster)')
    new = text[:a] + block + text[b:]
    new = re.sub(r"SHARDS: '\d+'", f"SHARDS: '{total}'", new, count=1)
    new = re.sub(r"shard \$\{\{ matrix.shard \}\}/\d+ \(", f"shard ${{{{ matrix.shard }}}}/{total} (", new, count=1)
    if check:
        if new != text:
            sys.exit('mutation.yml is not what mutation-plan.py generates')
        print(f'plan ok: {total} shards')
        return
    wf.write_text(new)
    print(f'{len(bins)} generated shard(s), {total} in all, largest {max(x[0] for x in bins):.0f} of budget {budget}')

main(sys.argv[1:])
