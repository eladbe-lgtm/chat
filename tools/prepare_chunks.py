#!/usr/bin/env python3
"""Build per-agent input chunks of the next unclassified CVEs.

Usage: prepare_chunks.py N_AGENTS CHUNK_SIZE
Reads results/progress.json, takes the next N_AGENTS*CHUNK_SIZE published CVEs
(CVE ID order, REJECTED skipped) and writes work/chunk_XX.jsonl, one CVE_DATA
record per line.
"""
import json, os, re, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CVES = os.environ.get("CVE_DIR", "/home/user/cveproject/cvelistv5/cves")
WORK = os.environ.get("WORK_DIR", "/home/user/cvework")
INDEX = os.path.join(WORK, "published_index.txt")


def key(cve_id):
    _, y, n = cve_id.split("-")
    return int(y), int(n)


def build_index():
    ids = []
    for root, _, fs in os.walk(CVES):
        for f in fs:
            if re.match(r"CVE-\d+-\d+\.json$", f):
                p = os.path.join(root, f)
                with open(p) as fh:
                    if json.load(fh)["cveMetadata"]["state"] != "REJECTED":
                        ids.append((f[:-5], p))
    ids.sort(key=lambda x: key(x[0]))
    with open(INDEX, "w") as fh:
        fh.write("\n".join(f"{i}\t{p}" for i, p in ids))


def trim(s, n):
    return s if len(s) <= n else s[:n] + "..."


def extract(path):
    with open(path) as fh:
        d = json.load(fh)
    conts = [d["containers"].get("cna", {})] + d["containers"].get("adp", [])
    desc = [x["value"] for c in conts for x in c.get("descriptions", [])
            if x.get("lang", "").startswith("en")]
    affected = []
    for c in conts:
        for a in c.get("affected", []):
            vers = [v.get("version") for v in a.get("versions", [])][:4]
            affected.append(f"{a.get('vendor')} / {a.get('product')} {vers}")
    cwe = sorted({x.get("description") or x.get("cweId") for c in conts
                  for pt in c.get("problemTypes", []) for x in pt.get("descriptions", [])
                  if (x.get("description") or x.get("cweId")) not in (None, "n/a")})
    cvss = [v["vectorString"] for c in conts for m in c.get("metrics", [])
            for v in m.values() if isinstance(v, dict) and "vectorString" in v]
    refs = [r["url"] for r in d["containers"].get("cna", {}).get("references", [])]
    return {
        "cve_id": d["cveMetadata"]["cveId"],
        "description": trim(" | ".join(dict.fromkeys(desc)), 2000),
        "affected": affected[:6],
        "problem_types": cwe[:5],
        "cvss": list(dict.fromkeys(cvss))[:3],
        "references": refs[:6],
    }


def main():
    n_agents, size = int(sys.argv[1]), int(sys.argv[2])
    os.makedirs(WORK, exist_ok=True)
    if not os.path.exists(INDEX):
        build_index()
    with open(INDEX) as fh:
        index = [l.split("\t") for l in fh.read().splitlines()]
    with open(os.path.join(REPO, "results/progress.json")) as fh:
        last = json.load(fh)["last_completed_cve_id"]
    start = next(i for i, (c, _) in enumerate(index) if key(c) > key(last))
    for f in os.listdir(WORK):
        if f.startswith(("chunk_", "out_")):
            os.remove(os.path.join(WORK, f))
    for a in range(n_agents):
        part = index[start + a * size: start + (a + 1) * size]
        if not part:
            break
        with open(os.path.join(WORK, f"chunk_{a:02d}.jsonl"), "w") as fh:
            for _, p in part:
                fh.write(json.dumps(extract(p)) + "\n")
        print(f"chunk_{a:02d}: {part[0][0]} .. {part[-1][0]} ({len(part)})")
    print(f"remaining after this round: {max(0, len(index) - start - n_agents * size)}")


if __name__ == "__main__":
    main()
