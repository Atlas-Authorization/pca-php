#!/usr/bin/env python3
"""Line slice k/n of one source file, cut only at method-closing lines ("    }"), so no node spans two slices.

  python3 infection-slice.py <src/File.php> <k/n> <base-dir>
     Writes <base-dir>/<path under src> = the file with exactly the slice's lines altered (a trailing comment): committed as the
     git base, `infection --git-diff-lines --git-diff-base=HEAD` mutates exactly that slice.

cuts(lines, n) is also what mutation-plan.py runs to check that every planned file can be cut into n non-empty slices.
"""
import os, sys

def cuts(lines, n):
    """n + 1 strictly increasing cut points (0 .. len), each inner one a method end, each nearest to an equal line split."""
    ends = [i + 1 for i, l in enumerate(lines) if l == '    }' and i + 1 < len(lines)]
    out = [0]
    for j in range(1, n):
        cand = [e for e in ends if e > out[-1]]
        cand = cand[:len(cand) - (n - 1 - j)]  # every later cut still needs a method end of its own
        if not cand:
            raise ValueError(f'{n} slices need {n - 1} method ends, the file has {len(ends)}')
        out.append(min(cand, key=lambda e: (abs(e - len(lines) * j / n), e)))
    return out + [len(lines)]

if __name__ == '__main__':
    f, (k, n), base = sys.argv[1], map(int, sys.argv[2].split('/')), sys.argv[3]
    L = open(f, encoding='utf-8').read().split('\n')
    c = cuts(L, n)
    a, b = c[k - 1], c[k]
    p = os.path.join(base, os.path.relpath(f, 'src'))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, 'w', encoding='utf-8').write('\n'.join(l + ' // slice' if a < i <= b else l for i, l in enumerate(L, 1)))
    print(f'slice {k}/{n} of {f}: lines {a + 1}..{b} of {len(L)}')
