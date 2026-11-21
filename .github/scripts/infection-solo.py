#!/usr/bin/env python3
"""Solo second pass for every ERRORED and TIMED-OUT mutant of a shard (a dead PHPUnit process or a timeout is not a kill).

  plan:  python3 infection-solo.py plan --log infection-out/log.json --src src --base-dir <dir> --config infection.json5
     Prints the number of lines holding an errored or timed-out mutant. For each such file, <base-dir>/<path under src> is the
     current file with those lines altered (a trailing comment): committed as the git base, `infection --git-diff-lines` mutates
     only them. Writes infection.solo.json5: the config with its logs under infection-out/solo-*.
     The workflow runs that pass with ONE thread (one mutant, one PHPUnit process), a raised memory_limit, a watchdog trigger well
     below it, and a hard wall-clock limit on the whole process group.
  merge: python3 infection-solo.py merge --log infection-out/log.json --solo infection-out/solo-log.json --report infection-out/solo-report.json
     Each first-pass errored or timed-out mutant takes the bucket the solo pass gave it (same file, line, mutator and diff): KILLED
     (a test failed, a guard throw included), escaped/uncovered (the survivor ledger applies), or errored/timed out again (the
     run-error ledger needs a proof). A mutant the solo pass did not report keeps its first-pass bucket: a dead process never
     becomes a kill. The merged log replaces --log; --report lists both results of every re-run mutant.
"""
import json, os, re, sys

BUCKETS = ("escaped", "uncovered", "killed", "timeouted", "errored", "syntaxErrors", "ignored")
DEAD = ("errored", "timeouted")

def opt(name):
    return sys.argv[sys.argv.index(name) + 1]

def key(m):
    return (m["mutator"]["originalFilePath"], m["mutator"]["originalStartLine"], m["mutator"]["mutatorName"], m["diff"])

def rel(path):
    return re.sub(r"^(?:.*/)?src/", "", path)

cmd = sys.argv[1]
log = json.load(open(opt("--log")))
if cmd == "plan":
    src, out = opt("--src"), opt("--base-dir")
    lines = {}
    for b in DEAD:
        for m in log.get(b) or []:
            lines.setdefault(rel(m["mutator"]["originalFilePath"]), set()).add(m["mutator"]["originalStartLine"])
    for f, ls in lines.items():
        cur = open(os.path.join(src, f), encoding="utf-8").read().split("\n")
        p = os.path.join(out, f)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w", encoding="utf-8").write("\n".join(l + " //~infection-solo" if i in ls else l for i, l in enumerate(cur, 1)))
    cfg = open(opt("--config"), encoding="utf-8").read()
    cfg = cfg.replace("infection-out/log.", "infection-out/solo-log.")
    assert "solo-log.json" in cfg, "the config's json log path was not found"
    open("infection.solo.json5", "w", encoding="utf-8").write(cfg)
    print(sum(len(v) for v in lines.values()))
elif cmd == "merge":
    sl = json.load(open(opt("--solo")))
    second = {key(m): b for b in BUCKETS for m in sl.get(b) or []}
    out = {b: [m for m in log.get(b) or [] if b not in DEAD] for b in BUCKETS}
    report, moved = [], 0
    for first in DEAD:
        for m in log.get(first) or []:
            b = second.get(key(m), first)
            moved += b != first
            out[b].append(m)
            report.append({"file": rel(m["mutator"]["originalFilePath"]), "line": m["mutator"]["originalStartLine"],
                           "mutator": m["mutator"]["mutatorName"], "first": first, "solo": second.get(key(m), "not re-run")})
    out["stats"] = dict(log.get("stats", {}))
    out["stats"]["skippedCount"] = out["stats"].get("skippedCount", 0) + sl.get("stats", {}).get("skippedCount", 0)
    json.dump(out, open(opt("--log"), "w"))
    json.dump(report, open(opt("--report"), "w"), indent=1)
    kept = sum(1 for r in report if r["solo"] in ("not re-run", "errored", "timeouted"))
    print(f"solo: {len(report)} dead-process or timed-out mutants re-run alone, {moved} changed bucket "
          f"({sum(1 for r in report if r['solo'] == 'killed')} killed), {kept} still dead or not re-run")
else:
    sys.exit("infection-solo.py plan|merge ...")
