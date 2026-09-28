#!/usr/bin/env python3
"""Allocate the next N input chunks of SIZE CVEs each, without disturbing
in-flight chunks. Tracks a high-water mark (last assigned CVE ID) in
work/assigned_hwm.txt so chunks never overlap. Chunk files get a numeric
index one past the current maximum. Prints each new chunk's id and range.

Usage: next_chunk.py N SIZE
"""
import json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prepare_chunks as pc  # reuse key(), extract(), INDEX, WORK

WORK = pc.WORK
HWM = os.path.join(WORK, "assigned_hwm.txt")


def main():
    n, size = int(sys.argv[1]), int(sys.argv[2])
    index = [l.split("\t") for l in open(pc.INDEX).read().splitlines()]
    hwm = open(HWM).read().strip()
    start = next((i for i, (c, _) in enumerate(index) if pc.key(c) > pc.key(hwm)),
                 len(index))
    existing = [int(re.search(r"chunk_(\d+)\.jsonl$", f).group(1))
                for f in os.listdir(WORK) if re.match(r"chunk_\d+\.jsonl$", f)]
    seq = (max(existing) + 1) if existing else 0
    pos = start
    for _ in range(n):
        part = index[pos:pos + size]
        if not part:
            break
        name = f"chunk_{seq:04d}.jsonl"
        with open(os.path.join(WORK, name), "w") as fh:
            for _, p in part:
                fh.write(json.dumps(pc.extract(p)) + "\n")
        print(f"{name}: {part[0][0]} .. {part[-1][0]} ({len(part)})")
        with open(HWM, "w") as fh:
            fh.write(part[-1][0])
        seq += 1
        pos += size
    print(f"unassigned remaining: {max(0, len(index) - pos)}")


if __name__ == "__main__":
    main()
