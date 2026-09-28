# CVE classification results

Each line is one CVE classified as `SERVER_WEB_REQUEST` or `INFRA_ENDPOINT`
per `prompts/classification_prompt.md`, in CVE-ID order.

The full JSONL deliverable is sharded into `results/parts/part-NNNNN.jsonl`
(25,000 lines each) to stay under GitHub's 100 MB per-file limit.
Reassemble the single file with:

    cat results/parts/part-*.jsonl > classifications.jsonl

`progress.json` records the resume checkpoint (`last_completed_cve_id`) and
counts. Shards are regenerated from the running file with `tools/shard.py`.
