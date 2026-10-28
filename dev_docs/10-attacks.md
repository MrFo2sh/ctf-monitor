# Attack classifier — `proxy/src/attacks.js`

## Purpose

`attacks.js` tags a request with the web-exploitation techniques it looks like: SQL injection, XSS, template injection, path traversal, command injection, shells, XXE, SSRF, open-redirect probes, deserialization payloads, and known scanner tools. It is detection only, in the spirit of a WAF rule set, and it never blocks anything. The output feeds the `attack:<class>` flags, the severity bump in `server.js`, the `web-attack` alerts in `store.js`, and the per-class counters on the Students page.

## Where it sits

| | |
|---|---|
| Required by | `proxy/src/server.js` (`classify()` and `worstLevel()` in `onEvent()`, lines 211-219) |
| Requires | nothing — it is a pure module with no dependencies |
| Consumers of its output | `store.js` (`s.attacks`, `attackTotals`, `alertFor()` builds the `web-attack` alert from `label`, `where`, `sample`, `level`); `db.js` (`requests.attacks` column, JSON); `query.js` (`attack = "sqli"` searches that JSON); the dashboard (class chips) |

## Data it owns

### `CLASSES` — one entry per attack class (lines 6-24)

| Field | Meaning |
|---|---|
| `cls` | Short key used everywhere else: `sqli`, `nosqli`, `xss`, `ssti`, `lfi`, `cmdi`, `shell`, `xxe`, `ssrf`, `redirect`, `deser`, `scanner`. |
| `level` | `low` / `medium` / `high` / `critical`. Drives severity and alert level. |
| `label` | Human text for alerts ("SQL injection"). |
| `re` | Array of regexes tried in order against the decoded URL, body and Referer. Present on every class except `scanner`. |
| `ua` | Single regex tried against the raw User-Agent only. Present on `scanner` only. |

The class levels as shipped:

| cls | level | what the patterns look for |
|---|---|---|
| `sqli` | high | `' OR '`, `UNION SELECT`, `SELECT ... FROM`, `sleep(`, `benchmark(`, `waitfor delay`, `information_schema`, `; DROP`, `or 1=1`, `'--` |
| `nosqli` | medium | `$ne`, `$gt`, `$regex`, `$where` ... as JSON keys or `[$ne]` form keys |
| `xss` | medium | `<script`, `onerror=`, `javascript:`, `<img src=` / `onload`, `alert(`, `prompt(`, `document.cookie` |
| `ssti` | high | `{{7*7}}`, `{{config}}`, `${7*7}`, `<%= %>`, `#{...}` |
| `lfi` | high | two or more `../` (raw or encoded), `/etc/passwd`, `c:\windows\`, `/proc/self/environ`, `php://filter`, `expect://` |
| `cmdi` | high | `; cat`, `| ls`, `&& id`, `$(whoami)`, backticks, `${IFS}` |
| `shell` | critical | `/dev/tcp/`, `nc -e`, `bash -i`, `socat ... exec`, `<?php`, `system($_GET`, `.php?cmd=` |
| `xxe` | high | `<!DOCTYPE ... [<!ENTITY`, `<!ENTITY x SYSTEM` |
| `ssrf` | high | URLs to `127.x`, `localhost`, `0.0.0.0`, `169.254.169.254`, `10.x`, `192.168.x`, `[::1]`; `gopher://`, `dict://`, `file://` |
| `redirect` | low | `?next=`, `?url=`, `?redirect=` ... pointing at an external host |
| `deser` | high | Java `rO0AB` (base64 of `AC ED 00 05`), PHP `O:4:"User":2:{`, hex `aced0005` |
| `scanner` | medium | User-Agent of sqlmap, nikto, nuclei, gobuster, ffuf, nmap, burp, zap, hydra, **python-requests, go-http-client, curl, wget** ... |

### A hit (what `classify()` returns, one object per class)

| Field | Meaning |
|---|---|
| `cls`, `level`, `label` | Copied from the class. |
| `where` | `'url'`, `'body'`, `'referer'` or `'user-agent'` — the first place the class matched. |
| `sample` | Up to 120 chars of the decoded text around the match (20 before, 20 after), or the first 80 chars of the UA. Shown in alerts and in the student detail samples. |

### `LEVEL_RANK` (line 75)

`{ info: 0, low: 1, medium: 2, high: 3, critical: 4 }` — the ordering used by `worstLevel()`.

## Walkthrough

### The class table

```js
// lines 6-11 (excerpt)
const CLASSES = [
  { cls: 'sqli', level: 'high', label: 'SQL injection', re: [
    /('|%27|")\s*(or|and)\s*('|%27|"|\d)/i, /\b(union)\b[\s/*]+(all\s+)?select\b/i, /\b(select|insert|update|delete)\b.{0,40}\b(from|into|set|where)\b/i,
    /\bsleep\s*\(\s*\d/i, /\bbenchmark\s*\(/i, /\bwaitfor\s+delay\b/i, /\binformation_schema\b/i, /(;|--|#)\s*(drop|alter|truncate)\b/i, /\bor\s+1\s*=\s*1\b/i, /'\s*--/,
  ] },
  { cls: 'nosqli', level: 'medium', label: 'NoSQL injection', re: [/\$(ne|gt|lt|gte|lte|regex|where|exists|in|nin)\b/, /\[\$(ne|gt|regex|where)\]/] },
```

Things to know about the patterns in general:

- Most carry the `i` flag; the NoSQL and deserialization ones are deliberately case-sensitive (`$ne`, `rO0AB` are exact tokens).
- `%27` appears in the SQLi pattern even though input is decoded first: `decode()` stops after two rounds, so triple-encoded or malformed input can still reach the regex with `%27` intact.
- `[\s/*]+` between `UNION` and `SELECT` catches the classic `UNION/**/SELECT` comment trick.
- The scanner UA list (line 23) includes `curl/` and `wget/` and `python-requests/`. That is intentional for a CTF (students should use a browser or at least spoof the UA), but it means every `curl` request is a `medium` scanner hit and therefore at least `warn` severity. Remove those alternatives if your CTF expects command-line tools.
- Patterns are tested against text that was decoded **once or twice**, so `%3Cscript%3E` and `%253Cscript%253E` both match `<\s*script\b`.

```js
// lines 20-23 (excerpt)
  { cls: 'ssrf', level: 'high', label: 'Server-side request forgery', re: [/(^|[=\s"'])https?:\/\/(127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|\[::1\])/i, /\b(gopher|dict|file):\/\//i] },
  { cls: 'redirect', level: 'low', label: 'Open redirect probe', re: [/[?&](next|url|redirect|return|goto|dest|continue)=(https?:)?\/\/(?!127\.0\.0\.1)[a-z0-9.-]+/i] },
  { cls: 'deser', level: 'high', label: 'Deserialization payload', re: [/rO0AB/, /O:\d+:"[a-z_\\]+":\d+:\{/i, /\baced0005\b/i] },
  { cls: 'scanner', level: 'medium', label: 'Scanner / fuzzing tool', ua: /\b(sqlmap|nikto|nuclei|gobuster|dirbuster|dirb|ffuf|wfuzz|nmap|masscan|zgrab|acunetix|nessus|openvas|w3af|arachni|burpsuite|zap|hydra|python-requests\/|go-http-client|curl\/|wget\/)\b/i },
];
```

- SSRF requires the URL to be at the start of the text or preceded by `=`, whitespace or a quote — i.e. it must be a *value*, so `/proxy?target=http://127.0.0.1` matches but `/docs/http-localhost-guide` does not.
- The redirect pattern uses a negative lookahead `(?!127\.0\.0\.1)` so a redirect back to the local test host is not a probe; it also requires the parameter name to be one of the usual redirect names.

### `decode` — URL-decoding up to twice

```js
// lines 26-38
function decode(s) {
  let out = String(s || '');
  for (let i = 0; i < 2; i++) {
    try {
      const d = decodeURIComponent(out.replace(/\+/g, ' '));
      if (d === out) break;
      out = d;
    } catch {
      break;
    }
  }
  return out;
}
```

- `null`/`undefined` become `''` so callers can pass missing headers.
- `+` is turned into a space before decoding (form-encoding convention). This also happens to a literal `+` in a path, which is harmless for detection.
- Two rounds handle double encoding (`%252e` → `%2e` → `.`), which the test `double URL encoding is decoded before matching` checks. A third level is not attempted.
- `decodeURIComponent` throws `URIError` on malformed sequences (`%zz`, a lone `%`). The `catch` keeps the last successfully decoded string instead of failing the whole request, and the loop stops — the raw text is still scanned, which is why some patterns also list encoded forms.
- The early `break` when decoding changes nothing avoids a pointless second pass on plain text.

### `classify` — set-up

```js
// lines 43-50
function classify({ url, bodyText, ua, referer }) {
  const hits = [];
  const seen = new Set();
  const places = [
    ['url', decode(url)],
    ['body', decode(String(bodyText || '').slice(0, 8192))],
    ['referer', decode(referer)],
  ];
```

- `places` fixes the **search order**: URL first, then body, then Referer. The first place that matches a class is the one reported in `where`.
- The body is cut to 8192 characters *before* decoding. `server.js` already passes at most 8192 bytes (`x.reqBuf.toString('utf8', 0, 8192)`), so a payload hidden deep inside a large upload is not seen; this is a deliberate cost bound.
- `seen` guarantees one hit per class per request, regardless of how many places or patterns match.

### `classify` — the scan loop

```js
// lines 51-73
  for (const c of CLASSES) {
    if (c.ua) {
      const m = c.ua.exec(String(ua || ''));
      if (m) hits.push({ cls: c.cls, level: c.level, label: c.label, where: 'user-agent', sample: String(ua).slice(0, 80) });
      continue;
    }
    for (const [where, text] of places) {
      if (!text || seen.has(c.cls)) continue;
      // a Referer naturally contains the site's own URL (localhost / 127.0.0.1 while testing): never an SSRF or redirect probe
      if (where === 'referer' && (c.cls === 'ssrf' || c.cls === 'redirect')) continue;
      for (const re of c.re) {
        const m = re.exec(text);
        if (m) {
          const start = Math.max(0, m.index - 20);
          hits.push({ cls: c.cls, level: c.level, label: c.label, where, sample: text.slice(start, m.index + m[0].length + 20).slice(0, 120) });
          seen.add(c.cls);
          break;
        }
      }
    }
  }
  return hits;
}
```

- UA classes take a separate path: the User-Agent is tested raw (not decoded), only once, and the loop `continue`s so the `places` are never scanned for that class. The sample is the first 80 chars of the UA.
- For regex classes, `if (!text || seen.has(c.cls)) continue;` skips empty places and stops scanning further places once the class has matched. Combined with `break` after the first matching pattern, the cost per class is bounded by "all patterns on at most one place where it matches, all patterns on the places before it".
- **The Referer exception.** Browsers send the page the student is on as `Referer`, which during local testing is `http://localhost:8888/...` or `http://127.0.0.1:8888/?next=...`. Those strings match the SSRF and redirect patterns, so for `where === 'referer'` those two classes are skipped entirely. Every other class is still checked in the Referer, so a payload that was in the previous page's query string (`' OR 1=1--`) is still caught; the test `a Referer pointing at the site itself (localhost while testing) is not an SSRF or redirect probe` covers both sides.
- The sample window is 20 characters either side of the match, capped at 120 characters total. It is taken from the *decoded* text, which is what you want to read in an alert. The sample can contain secrets (a password with `'` in it); `server.js` masks `ev.path` and `ev.body` but not `attacks[].sample`. Keep that in mind if alerts are exported.
- Output order is the `CLASSES` order, not severity order; `worstLevel()` exists for that reason.
- `m.index` is the position in the decoded text, so `start` is correct for the slice; the regexes are not global, so `exec` always starts at 0.

### `worstLevel`

```js
// lines 75-78
const LEVEL_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function worstLevel(hits) {
  return hits.reduce((w, h) => (LEVEL_RANK[h.level] > LEVEL_RANK[w] ? h.level : w), 'info');
}
```

- Starts at `'info'`, so an empty list yields `'info'` (test: `worstLevel([])` is `'info'`).
- An unknown level string makes `LEVEL_RANK[h.level]` `undefined`; `undefined > n` is `false`, so unknown levels are ignored rather than crashing.

### How `server.js` uses the result (for context)

```js
// server.js lines 211-219
  const attacks = blockedReq ? [] : classify({ url: x.url, bodyText: x.reqBuf.length ? x.reqBuf.toString('utf8', 0, 8192) : '', ua: x.req.headers['user-agent'], referer: x.req.headers.referer });
  const flags = verdict.flags.concat(attacks.map((a) => `attack:${a.cls}`));
  let severity = verdict.severity;
  if (attacks.length && severity !== 'critical') {
    const w = worstLevel(attacks);
    if (w === 'critical') severity = 'critical';
    else if (w === 'high' && severity !== 'high') severity = 'high';
    else if (severity === 'ok' || severity === 'notice') severity = 'warn';
  }
```

- Blocked requests (student banned by the organizer) are not classified.
- `url` is the **raw** `req.url` (query string included, not yet masked); masking happens afterwards for `ev.path`.
- Severity mapping: a `critical` class (shell) makes the event `critical`; a `high` class makes it `high` unless it already is; `medium`/`low` classes raise `ok`/`notice` to `warn` but leave `warn`/`high` alone.
- The hits are stored verbatim on `ev.attacks`, which is how `store.js` and `db.js` see `level`, `label`, `where` and `sample`.

### Export

```js
// line 80
module.exports = { classify, worstLevel, CLASSES, LEVEL_RANK };
```

`CLASSES` and `LEVEL_RANK` are exported so a UI or a test can list the classes; nothing in `src/` imports them today.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `server.js` `onEvent()` | `classify({url, bodyText, ua, referer})` with the raw URL, the first 8 KB of the request body, and two headers. |
| out | `server.js` | `[{cls, level, label, where, sample}]`; `worstLevel(hits)` for the severity bump; `attack:<cls>` flags. |
| out | `store.js` | `ev.attacks` → `s.attacks[cls]++`, `attackTotals[cls]++`, `web-attack` alert (level = worst of the *fresh* hits, message from `label`/`where`/`sample`). |
| out | `db.js` | `ev.attacks` serialised to `requests.attacks` as JSON; `studentDetail()` aggregates `count` and up to 25 samples per class. |
| out | `query.js` | `attack = "sqli"` compiles to `attacks LIKE '%"sqli"%'`, which matches the `"cls":"sqli"` text in that JSON. |

## Changing it safely

| Likely change | Where | Notes |
|---|---|---|
| Add a class | Append to `CLASSES` (lines 6-24) with `cls`, `level`, `label`, `re` | Also add the key to the help text in `query.js` `FIELDS.attack.help`. Prefer the end of the array if ordering of hits in alerts does not matter. |
| Tune a pattern / reduce false positives | The `re` array of that class | Write the probe in `attacks.test.js` first. Remember input is decoded up to twice and `+` becomes space. |
| Stop flagging curl/wget/python as scanners | Remove `curl\/`, `wget\/`, `python-requests\/`, `go-http-client` from the `ua` regex on line 23 | Changes severity of every CLI request from `warn` to `ok`. |
| Scan a new place (e.g. a custom header, cookies) | Add `[name, decode(...)]` to `places` (lines 46-50) and pass it in from `server.js` line 211 | Decide whether the Referer exception should apply there too. |
| Change the severity mapping | Not here — `server.js` lines 214-219; alert level is in `store.js alertFor()` line 191 | |

Tests (`proxy/test/attacks.test.js`):

- `normal traffic is not flagged`
- `classic injection probes are classified` — one probe per class except shell/xxe/redirect/deser
- `a Referer pointing at the site itself (localhost while testing) is not an SSRF or redirect probe`
- `double URL encoding is decoded before matching`
- `scanner user agents are flagged from the UA header`
- `one hit per class, with a short sample and a worst level`

Run: `cd D:\SIEMs\ctf-watch\proxy; node --test test/attacks.test.js`

## Exercises

1. **See the sample window.** Classify `/search?q=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<script>alert(1)</script>bbbbbbbbbbbbbbbbbbbbbbbbbbbb` and print `hits[0].sample`. Confirm it is 20 chars of `a` + the match + 20 chars of `b`, and that `where` is `url`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node -e "const {classify}=require('./src/attacks');console.log(classify({url:'/search?q='+'a'.repeat(30)+'<script>alert(1)</script>'+'b'.repeat(30)}))"`
2. **Add a class.** Append `{ cls: 'log4shell', level: 'critical', label: 'JNDI lookup', re: [/\$\{jndi:/i] }` to `CLASSES`, then add a test asserting `classes({ ua: '${jndi:ldap://x/a}' })` is `[]` (UA is not scanned by regex classes) and `classes({ url: '/?x=${jndi:ldap://x/a}' })` includes `log4shell`. Note that `${jndi:...}` does not match the SSTI pattern `\$\{\s*\d+\s*[*+]\s*\d+\s*\}` because that one needs an arithmetic expression.
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node --test test/attacks.test.js`
3. **Prove the Referer exception is class-specific.** Run `classify({ url: '/', referer: 'http://127.0.0.1:8888/?next=http://evil.io&q=<script>' })` and confirm the result has one `xss` hit with `where: 'referer'` and no `redirect`/`ssrf`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node -e "const {classify}=require('./src/attacks');console.log(classify({url:'/',referer:'http://127.0.0.1:8888/?next=http://evil.io&q=<script>'}).map(h=>h.cls+'@'+h.where))"`

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `classify` | `({url, bodyText, ua, referer}) => Array<{cls, level, label, where, sample}>` | One hit per matching class; empty array for clean traffic. |
| `worstLevel` | `(hits) => 'info' \| 'low' \| 'medium' \| 'high' \| 'critical'` | Highest `level` among the hits, `'info'` for none. |
| `CLASSES` | `Array<{cls, level, label, re?: RegExp[], ua?: RegExp}>` | The rule table, in scan order. |
| `LEVEL_RANK` | `{info:0, low:1, medium:2, high:3, critical:4}` | Level ordering. |

## Update: issue 8 fixed (in the caller)

`classify()` itself is unchanged, but `pipeline.js` now feeds it a body where the values of sensitive fields are masked (`mask.maskBodyText`), a URL masked with `maskUrl`, and runs every returned `sample` through `maskText`. Samples shown in alerts and detail pages can no longer contain a password or a token. The golden replay confirms classification results did not change.
