#!/usr/bin/env python3
"""Validate work/out_XX.jsonl against work/chunk_XX.jsonl and append in order.

Stops at the first chunk that is incomplete or invalid, so progress.json
always points at a contiguous, fully classified prefix.
"""
import json, os, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.environ.get("WORK_DIR", "/home/user/cvework")
KEYS = ["cve_id", "classification", "confidence", "needs_review", "vulnerable_component",
        "attacker_input", "entry_path", "processing_side", "protocol",
        "documented_web_path", "alternative_path", "reason"]
LABELS = {"SERVER_WEB_REQUEST", "INFRA_ENDPOINT"}
CONF = {"high", "medium", "low"}
SIDES = {"server", "client", "local", "protocol_layer", "hardware", "unknown"}


def check(o):
    assert set(o) == set(KEYS), f"keys {sorted(set(o) ^ set(KEYS))}"
    assert o["classification"] in LABELS
    assert o["confidence"] in CONF
    assert o["processing_side"] in SIDES
    assert isinstance(o["needs_review"], bool) and isinstance(o["documented_web_path"], bool)
    assert o["alternative_path"] is None or isinstance(o["alternative_path"], str)


def main():
    chunks = sorted(f for f in os.listdir(WORK) if f.startswith("chunk_"))
    prog_path = os.path.join(REPO, "results/progress.json")
    with open(prog_path) as fh:
        prog = json.load(fh)
    appended = 0
    for c in chunks:
        want = [json.loads(l)["cve_id"] for l in open(os.path.join(WORK, c))]
        out = os.path.join(WORK, c.replace("chunk_", "out_"))
        if not os.path.exists(out):
            print(f"{c}: missing output, stopping"); break
        got = {}
        bad = []
        for n, line in enumerate(open(out), 1):
            if not line.strip():
                continue
            try:
                o = json.loads(line); check(o)
                got[o["cve_id"]] = o
            except Exception as e:
                bad.append(f"line {n}: {e}")
        missing = [w for w in want if w not in got]
        if missing or bad:
            print(f"{c}: {len(missing)} missing, {len(bad)} invalid; first missing {missing[:3]} {bad[:3]}; stopping")
            break
        with open(os.path.join(REPO, "results/classifications.jsonl"), "a") as fh:
            for w in want:
                fh.write(json.dumps({k: got[w][k] for k in KEYS}) + "\n")
        prog["last_completed_cve_id"] = want[-1]
        prog["completed"] += len(want)
        appended += len(want)
        os.rename(out, out + ".merged")
        print(f"{c}: merged {len(want)} ({want[0]} .. {want[-1]})")
    with open(prog_path, "w") as fh:
        json.dump(prog, fh, indent=1)
    print(f"appended {appended}; completed {prog['completed']} / {prog['total_published']}")
    sys.exit(0 if appended else 1)


if __name__ == "__main__":
    main()
