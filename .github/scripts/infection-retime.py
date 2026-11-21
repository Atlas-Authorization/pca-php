#!/usr/bin/env python3
"""Second chance for TIMED-OUT mutants at twice the Infection timeout (only a second timeout counts).

  plan:  python3 infection-retime.py plan --log infection-out/log.json --src src --base-dir <dir> --config infection.json5
     Prints the number of lines holding a timed-out mutant. For each such file, <base-dir>/<path under src> is the current file
     with those lines altered (a trailing comment): committed as the git base, `infection --git-diff-lines` mutates only them.
     Writes infection.retime.json5: the config with the timeout doubled and its logs under infection-out/retime-*.
  merge: python3 infection-retime.py merge --log infection-out/log.json --retime infection-out/retime-log.json
     Each first-pass timed-out mutant takes the bucket the second pass gave it (same file, line, mutator and diff); every
     other first-pass result stays. The merged log replaces --log; the second pass's time-skipped count is added.
"""
import json, os, re, sys

BUCKETS = ("escaped", "uncovered", "killed", "timeouted", "errored", "syntaxErrors", "ignored")

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
    for m in log.get("timeouted") or []:
        lines.setdefault(rel(m["mutator"]["originalFilePath"]), set()).add(m["mutator"]["originalStartLine"])
    for f, ls in lines.items():
        cur = open(os.path.join(src, f), encoding="utf-8").read().split("\n")
        p = os.path.join(out, f)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w", encoding="utf-8").write("\n".join(l + " //~infection-retime" if i in ls else l for i, l in enumerate(cur, 1)))
    cfg = open(opt("--config"), encoding="utf-8").read()
    t = re.search(r'"timeout":\s*(\d+)', cfg)
    cfg = cfg.replace(t.group(0), f'"timeout": {2 * int(t.group(1))}').replace("infection-out/log.", "infection-out/retime-log.")
    assert "retime-log.json" in cfg, "the config's json log path was not found"
    open("infection.retime.json5", "w", encoding="utf-8").write(cfg)
    print(sum(len(v) for v in lines.values()))
elif cmd == "merge":
    rt = json.load(open(opt("--retime")))
    second = {key(m): b for b in BUCKETS for m in rt.get(b) or []}
    out = {b: [m for m in log.get(b) or [] if b != "timeouted"] for b in BUCKETS}
    moved = 0
    for m in log.get("timeouted") or []:
        b = second.get(key(m), "timeouted")
        moved += b != "timeouted"
        out[b].append(m)
    out["stats"] = dict(log.get("stats", {}))
    out["stats"]["skippedCount"] = out["stats"].get("skippedCount", 0) + rt.get("stats", {}).get("skippedCount", 0)
    json.dump(out, open(opt("--log"), "w"))
    print(f"retime: {len(log.get('timeouted') or [])} first-pass timeouts, {moved} decided at twice the limit, "
          f"{len(out['timeouted'])} still timed out")
else:
    sys.exit("infection-retime.py plan|merge ...")
