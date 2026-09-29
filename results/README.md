# CVE classification results

`classifications.jsonl.gz` is the full dataset: one gzip-compressed JSON Lines
file containing all 380,265 published CVEs from MITRE's cvelistV5, one JSON
object per line, in CVE-ID order.

## Use it

```bash
gunzip -k classifications.jsonl.gz          # -> classifications.jsonl (207 MB, 380,265 lines)
# or stream without unpacking:
gunzip -c classifications.jsonl.gz | head -1
```

The file is stored gzipped (8 MB) because the uncompressed JSONL is 207 MB,
above GitHub's 100 MB per-file limit. Decompressing reproduces it exactly.

## Schema

Each line has exactly these 12 keys:

`cve_id`, `classification`, `confidence`, `needs_review`, `vulnerable_component`,
`attacker_input`, `entry_path`, `processing_side`, `protocol`,
`documented_web_path`, `alternative_path`, `reason`

- `classification`: `SERVER_WEB_REQUEST` | `INFRA_ENDPOINT`
- `confidence`: `high` | `medium` | `low`
- `processing_side`: `server` | `client` | `local` | `protocol_layer` | `hardware` | `unknown`
- `needs_review`, `documented_web_path`: booleans
- `alternative_path`: string or null

`progress.json` is the run checkpoint (last completed CVE ID and total count).
