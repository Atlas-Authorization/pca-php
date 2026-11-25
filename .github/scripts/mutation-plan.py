#!/usr/bin/env python3
"""Regenerate the generated block of the shard matrix in mutation.yml so every file of src/ is planned.

  python3 mutation-plan.py <src dir> <mutation.yml>          rewrite the block (and SHARDS / the job name)
  python3 mutation-plan.py --check <src dir> <mutation.yml>  fail when the file is not what the rewrite would write

Files named by a hand-written entry (outside the block) are left where they are; every other file of src/ is packed, largest
first, into shards of at most CAP lines (a single file over CAP is cut into ceil(lines/CAP) line slices, one shard each, as the hand-written Actions.php entries are) (greedy, deterministic), numbered after the last hand-written shard.
"""
import re, sys, pathlib

CAP = 1500  # ~20 s of mutation per line is the measured p80 of the 0.5.1 shards: 1500 lines + ~9 min of setup stays under 40 min
BEGIN, END = '          # BEGIN generated plan (scripts/mutation-plan.py)\n', '          # END generated plan\n'

def main(argv):
    check = argv[0] == '--check'
    src, wf = (pathlib.Path(a) for a in argv[check:2 + check])
    text = wf.read_text()
    a, b = text.index(BEGIN), text.index(END)
    outside = text[:a] + text[b + len(END):]
    entry = re.compile(r"^ +- \{ shard: (\d+), files: '([^']*)'", re.M)
    hand = {f for m in entry.finditer(outside) for f in m.group(2).split(',')}
    last = max(int(m.group(1)) for m in entry.finditer(outside))
    todo = sorted(f for f in (p.relative_to(src.parent).as_posix() for p in src.glob('**/*.php')) if f not in hand)
    lines = {f: (src.parent / f).read_text().count('\n') + 1 for f in todo}
    bins = []  # [lines, [files], slice-or-None]
    big = [f for f in todo if lines[f] > CAP]
    for f in big:
        n = -(-lines[f] // CAP)
        bins += [[lines[f] // n, [f], f'{k}/{n}'] for k in range(1, n + 1)]
    todo = [f for f in todo if f not in big]
    for f in sorted(todo, key=lambda f: (-lines[f], f)):
        fit = [x for x in bins if x[2] is None and x[0] + lines[f] <= CAP]
        x = min(fit, key=lambda x: x[0]) if fit else None
        if x is None: x = [0, [], None]; bins.append(x)
        x[0] += lines[f]; x[1].append(f)
    block = BEGIN
    for i, (n, fs, sl) in enumerate(sorted(bins, key=lambda x: (sorted(x[1])[0], x[2] or '')), last + 1):
        block += f"          - {{ shard: {i}, files: '{','.join(sorted(fs))}'{f", slice: '{sl}'" if sl else ''} }}\n"
    total = last + len(bins)
    new = text[:a] + block + text[b:]
    new = re.sub(r"SHARDS: '\d+'", f"SHARDS: '{total}'", new, count=1)
    new = re.sub(r"shard \$\{\{ matrix.shard \}\}/\d+ \(", f"shard ${{{{ matrix.shard }}}}/{total} (", new, count=1)
    if check:
        if new != text: sys.exit('mutation.yml is not what mutation-plan.py generates')
        print(f'plan ok: {total} shards'); return
    wf.write_text(new); print(f'{len(bins)} generated shard(s), {total} in all')

main(sys.argv[1:])
