# Web-triggerable CVE sets — validation & export

Built by joining each CVE's CWE(s) to the web-triggerability label in
`cwe_web_triggerable.tsv` (a CVE takes the **highest** tier among its CWEs),
then cross-checking against the per-CVE `classification` in
`classifications.jsonl.gz`.

## Validation: does a web-capable CWE imply we tagged the CVE SERVER_WEB_REQUEST?

| CWE web-tier of the CVE | SERVER_WEB_REQUEST | INFRA_ENDPOINT | % SWR |
|---|--:|--:|--:|
| yes         | 93,292 | 30,051 | 75.6% |
| conditional | 12,893 | 54,876 | 19.0% |
| no          |    138 |  2,920 |  4.5% |
| (no CWE id) | 70,886 | 115,209 | 38.1% |

**Not all `yes`-CWE CVEs are SERVER_WEB_REQUEST** — 75.6% are; the other
30,051 were classified INFRA_ENDPOINT. That is expected and correct: a
web-*capable* weakness class still occurs in non-web contexts (client-side
XSS, local path traversal, CLI OS-command injection, an upload over a
non-web channel, or a sparse record with no documented HTTP path). The
per-CVE label reflects the actual documented exploitation mechanism, which
is the stricter and more accurate signal. Those 30,051 exceptions are listed
in `web_yes_but_infra.tsv` (cve_id, cwes, processing_side, reason).

## Deliverables

Each line is the original 12-key classification record plus two fields:
`cwes` (the CVE's CWE ids) and `cwe_web_tier` (yes/conditional).

- **`web_yes.jsonl.gz`** — 93,292 CVEs that have a `yes`-tier CWE **and** are
  classified SERVER_WEB_REQUEST. (The validated web-triggerable set.)
- **`web_yes_and_conditional.jsonl.gz`** — 106,185 CVEs: the 93,292 above
  **plus** 12,893 CVEs whose top CWE is `conditional` and which we reviewed
  (via the per-CVE classification) as SERVER_WEB_REQUEST.

Reassemble either with:
```bash
gunzip -c web_yes.jsonl.gz | wc -l    # 93292
```
