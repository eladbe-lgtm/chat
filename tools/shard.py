#!/usr/bin/env python3
"""Split the monolithic results/classifications.jsonl into fixed-size shard
files under results/parts/, each well under GitHub's 100 MB blob limit.

Shard k holds lines [k*SIZE, (k+1)*SIZE). Only the final (partial) shard
changes as new classifications are appended, so earlier shards stay
byte-identical between runs and git stores them once. Concatenating the
shards in name order reproduces classifications.jsonl exactly.

Usage: shard.py [SIZE]   (default 25000 lines/shard)
"""
import os, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "results/classifications.jsonl")
PARTS = os.path.join(REPO, "results/parts")


def main():
    size = int(sys.argv[1]) if len(sys.argv) > 1 else 25000
    os.makedirs(PARTS, exist_ok=True)
    with open(SRC) as fh:
        lines = fh.readlines()
    total = len(lines)
    nshards = (total + size - 1) // size
    for k in range(nshards):
        chunk = lines[k * size:(k + 1) * size]
        with open(os.path.join(PARTS, f"part-{k + 1:05d}.jsonl"), "w") as fh:
            fh.writelines(chunk)
    # Remove any stale shards beyond the current count.
    for f in os.listdir(PARTS):
        if f.startswith("part-") and f.endswith(".jsonl"):
            k = int(f[5:10])
            if k > nshards:
                os.remove(os.path.join(PARTS, f))
    print(f"{total} lines -> {nshards} shards of {size} in results/parts/")


if __name__ == "__main__":
    main()
