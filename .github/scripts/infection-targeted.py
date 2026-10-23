#!/usr/bin/env python3
"""Infection results of one shard, full or TARGETED (a re-run of only the earlier survivors and the changed lines).

  plan:   python3 infection-targeted.py plan --baseline <infection-baseline.json> --src <src dir> --files <src/A.php,...>
                                             --base-dir <dir> --carried <carried.json>
     Prints the number of target lines. Target lines (current line numbers) = every line of the shard's files that is not
     an unchanged copy of a baseline line (edited, added, next to a deletion) + the line of every baseline survivor
     (escaped / uncovered). For each file with a target line, <base-dir>/<File>.php is the CURRENT file with every target
     line altered (a trailing comment): committed as the git base, it makes `infection --git-diff-lines --git-diff-base=HEAD`
     mutate exactly the target lines (Infection mutates the added / modified lines of `git diff <base>`), with the usual
     coverage-based test selection. Every other baseline mutant (on unchanged lines that are not targets) is written to
     --carried with its line moved to the current source, and keeps its result.
  finish: python3 infection-targeted.py finish [--log <infection-out/log.json>] [--carried <carried.json>] --src <src dir>
                                               --files <...> --summary <summary.json> --baseline <infection-baseline.json>
     summary.json = the shard's complete result (carried + new; a mutant Infection reported again wins) in the format
     php-survivors.py reads ({stats, escaped, uncovered, killed, timeouted, errored, syntaxErrors, ignored}: {file, line,
     mutator, diff}); infection-baseline.json = the shard's sources and every mutant with its bucket, for the next run."""
import difflib, json, os, sys

BUCKETS = {"escaped": "escapedCount", "uncovered": "notCoveredCount", "killed": "killedCount", "timeouted": "timeOutCount",
           "errored": "errorCount", "syntaxErrors": "syntaxErrorCount", "ignored": "ignoredCount"}
SURVIVED = ("escaped", "uncovered")

def opt(name, required=True):
    if name in sys.argv:
        return sys.argv[sys.argv.index(name) + 1]
    if required:
        sys.exit(f"infection-targeted.py: {name} is required")
    return None

def changed(diff):
    """The -/+ lines of an Infection diff (its identity without context lines)."""
    return tuple(l.rstrip() for l in diff.split("\n") if l[:1] in "+-" and not l.startswith(("+++", "---")))

def key(m):
    return (m["file"], m["line"], m["mutator"], changed(m["diff"]))

def minus_count(diff):
    return max(1, sum(1 for l in diff.split("\n") if l.startswith("-") and not l.startswith("---")))

cmd = sys.argv[1]
src = opt("--src")
files = [os.path.basename(f) for f in opt("--files").split(",") if f]
cur = {f: open(os.path.join(src, f), encoding="utf-8").read().split("\n") for f in files}

if cmd == "plan":
    base = json.load(open(opt("--baseline")))
    outdir = opt("--base-dir")
    os.makedirs(outdir, exist_ok=True)
    carried, ntarget = [], 0
    for f in files:
        lines = cur[f]
        old = base.get("sources", {}).get(f)
        same = {}
        target = set()
        if old is None:
            target = set(range(1, len(lines) + 1))
        else:
            old = old.split("\n")
            for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, old, lines, autojunk=False).get_opcodes():
                if tag == "equal":
                    same.update({o + 1: c + 1 for o, c in zip(range(i1, i2), range(j1, j2))})
                elif tag == "delete":
                    target.update({j1, j1 + 1})
                else:
                    target.update(range(j1 + 1, j2 + 1))
        mine = [m for m in base.get("mutants", []) if m["file"] == f]
        for m in mine:
            if m["bucket"] in SURVIVED and m["line"] in same:
                target.add(same[m["line"]])
        target = {x for x in target if 1 <= x <= len(lines)}
        for m in mine:
            span = [same.get(m["line"] + i) for i in range(minus_count(m["diff"]))]
            if all(x is not None and x not in target for x in span):
                carried.append(dict(m, line=span[0]))
        if target:
            ntarget += len(target)
            alt = [l + " //~infection-target" if i in target else l for i, l in enumerate(lines, 1)]
            open(os.path.join(outdir, f), "w", encoding="utf-8").write("\n".join(alt))
        print(f"{f}: {len(target)} target line(s), {sum(1 for m in carried if m['file'] == f)} mutant(s) carried", file=sys.stderr)
    json.dump(carried, open(opt("--carried"), "w"))
    print(ntarget)
elif cmd == "finish":
    new = []
    log = opt("--log", False)
    stats = {}
    if log and os.path.exists(log):
        d = json.load(open(log))
        stats = d.get("stats", {})
        for b in BUCKETS:
            for m in d.get(b) or []:
                new.append({"file": os.path.basename(m["mutator"]["originalFilePath"]), "line": m["mutator"]["originalStartLine"],
                            "mutator": m["mutator"]["mutatorName"], "diff": m["diff"], "bucket": b})
    car = opt("--carried", False)
    seen = {key(m) for m in new}
    allm = new + [m for m in (json.load(open(car)) if car and os.path.exists(car) else []) if key(m) not in seen]
    allm = [m for m in allm if m["file"] in cur]
    allm.sort(key=lambda m: (m["file"], m["line"], m["mutator"], m["diff"]))
    out = {"stats": {v: sum(1 for m in allm if m["bucket"] == b) for b, v in BUCKETS.items()}}
    out["stats"]["skippedCount"] = stats.get("skippedCount", 0)
    out["stats"]["totalMutantsCount"] = len(allm)
    for b in BUCKETS:
        out[b] = [{k: m[k] for k in ("file", "line", "mutator", "diff")} for m in allm if m["bucket"] == b]
    json.dump(out, open(opt("--summary"), "w"), indent=1)
    json.dump({"files": files, "sources": {f: "\n".join(cur[f]) for f in files}, "mutants": allm}, open(opt("--baseline"), "w"))
    print(f"{len(allm)} mutant(s) ({len(allm) - len(new)} carried, {len(new)} run now): {out['stats']}")
else:
    sys.exit("infection-targeted.py plan|finish ...")
