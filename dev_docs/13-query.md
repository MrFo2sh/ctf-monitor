# Query language — `proxy/src/query.js`

## Purpose

`query.js` implements the small search language used on the dashboard's Query tab (`student = "alice" AND status >= 400`). It tokenizes the text, parses it into an AST with the usual `NOT > AND > OR` precedence, and compiles the AST into a parameterised `SELECT` over the `requests` table — column names come only from its own `FIELDS` table and every user value becomes a `?` parameter, so no user text is ever concatenated into SQL. The same file is served to the browser as `/query.js`, where `validate()` powers live linting (error position and length) and `FIELDS`/`OPS_BY_TYPE` power autocomplete.

## Where it sits

| | |
|---|---|
| Required by | `dashboard.js` (`compile()` and `QueryError` for `POST /api/query`; the raw file is read from disk and served at `GET /query.js`, lines 114-125); `proxy/public/app.html` (`<script src="/query.js">` at line 501, then `window.CtfQuery` at line 846); `db.test.js` (`compile()` to drive `runSql`) |
| Requires | nothing. It must stay dependency-free and free of Node-only APIs because it also runs in the browser. |
| Downstream | `db.js runSql(sql, params, limit)` executes the output and appends `LIMIT`. |

## Data it owns

### `FIELDS` — the only names a query may use (lines 12-32)

| field | column | type | help text (shown in the editor) |
|---|---|---|---|
| `ts` | `ts` | time | time of the request: "-10m", "-2h", "-1d" or an ISO date |
| `student` | `student` | text | student name as shown on the dashboard |
| `raw` | `raw_name` | text | name before any rename by the organizer |
| `ip` | `ip` | text | client ip address |
| `method` | `method` | text | GET, POST, PUT, DELETE... |
| `path` | `path` | text | request path with query string (secrets masked) |
| `endpoint` | `endpoint` | text | name of the matched IDOR endpoint rule |
| `id` | `object_id` | text | object id taken from the request |
| `status` | `status` | num | HTTP status code |
| `size` | `size` | num | response size in bytes |
| `latency` | `latency` | num | response time in milliseconds |
| `severity` | `severity` | text | ok, notice, warn, high, critical |
| `flag` | `flags` | list | idor-attempt, idor-success, enumeration, burst-errors, blocked, attack:<class> |
| `attack` | `attacks` | list | attack class: sqli, xss, ssti, lfi, cmdi, shell, xxe, ssrf, nosqli, redirect, deser, scanner |
| `owner` | `owner` | text | who the requested object belongs to |
| `ua` | `ua` | text | user agent |
| `source` | `source` | text | how the student was identified: name, ip-match, session, jwt, login, ip |
| `ctf` | `ctf_id` | num | CTF record number (mentioning it searches outside the current CTF) |
| `player` | `player_id` | num | player number (same person across CTFs) |

Field types decide which operators are legal and how values are compiled:

| type | storage | operators (`OPS_BY_TYPE`, line 33) | compiled as |
|---|---|---|---|
| `text` | TEXT | `= != ~ !~ in` | `col = ?`, `col LIKE ? ESCAPE '\'` for `~` |
| `num` | INTEGER/REAL | `= != > >= < <= in` | `col op ?` with the value coerced to a number |
| `time` | INTEGER ms | `> >= < <= = !=` | `col op ?` with the value converted by `timeValue()` |
| `list` | TEXT holding a JSON array | `= != ~ !~ in` | `col LIKE '%"value"%'` for `=`; plain substring LIKE for `~` |

### Tokens (produced by `tokenize()`)

| field | meaning |
|---|---|
| `t` | kind: `(`, `)`, `,`, `op`, `str`, `num`, `ident`, `AND`, `OR`, `NOT`, `IN` |
| `v` | value: operator string, unquoted string, number, or identifier text (absent for punctuation/keywords) |
| `pos`, `len` | character offset and length in the source, for error highlighting |
| `text` | the raw matched text (quotes included for strings) |

### AST nodes (produced by `parse()`)

| node | shape |
|---|---|
| `and` / `or` | `{type, left, right}` |
| `not` | `{type, expr}` |
| `cmp` | `{type: 'cmp', field, op, value, pos, len, opPos, opLen}` — `pos/len` cover the field name, `opPos/opLen` the operator |
| `in` | `{type: 'in', field, values: [...], pos, len}` |

### `QueryError`

`{message, pos, len}` — `pos` is `null` when unknown, `len` defaults to 1. `dashboard.js` returns these as HTTP 400 `{error, pos, len}`; the editor underlines `[pos, pos+len)`.

## Walkthrough

### Header comment and `FIELDS`

```js
// lines 1-10
'use strict';
// Tiny query language for the request log, compiled to parameterised SQL (never string-built).
// Also loaded by the dashboard in the browser (served as /query.js) for live linting and autocomplete.
//
//   student = "alice" AND status >= 400
//   (path ~ "/api/orders" OR endpoint = "orders") AND NOT flag ~ "idor"
//   ts > "-10m" AND method in ("POST", "PUT")
//
// Operators: = != > >= < <= ~ (contains) !~ in    Logic: AND OR NOT ( )
// Values: "string" or 'string', number, list ("a","b"). ts accepts "-10m" "-2h" "-1d" or ISO dates.
```

The `FIELDS` object (lines 12-32, tabulated above) is the whitelist. A name that is not a key here is rejected at parse time with `unknown field`, and that is the whole SQL-injection defence for column names: the compiler emits `f.col`, never the user's word. `ctf` is special-cased in `compile()`.

```js
// line 33
const OPS_BY_TYPE = { text: ['=', '!=', '~', '!~', 'in'], num: ['=', '!=', '>', '>=', '<', '<=', 'in'], time: ['>', '>=', '<', '<=', '=', '!='], list: ['=', '!=', '~', '!~', 'in'] };
```

`OPS_BY_TYPE` is used for **error messages and autocomplete only**. The parser accepts any operator token syntactically; the type checks live in `compileNode()` (`~` on `num`/`time`, anything but `=`/`!=`/`~`/`!~` on `list`). Note that `time` has no `in` entry in this table, yet `compileNode` does handle `in` for time fields (line 182) — the table under-reports what works.

### `QueryError`

```js
// lines 35-41
class QueryError extends Error {
  constructor(message, pos, len) {
    super(message);
    this.pos = pos == null ? null : pos;
    this.len = len || 1;
  }
}
```

Only `QueryError`s are turned into 400 responses and editor underlines; any other exception becomes a 500 (`dashboard.js` line 240) or a position-less lint error (`validate()`).

### `tokenize()` — the regex

```js
// lines 43-46
function tokenize(input) {
  const tokens = [];
  const re = /\s*(?:(\()|(\))|(,)|(>=|<=|!=|!~|=|>|<|~)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(-?\d+(?:\.\d+)?)|([A-Za-z_][A-Za-z0-9_]*))/y;
  let pos = 0;
```

Piece by piece:

| part | group | matches |
|---|---|---|
| `\s*` | – | any leading whitespace, consumed with the token (so a token's `pos` must be corrected afterwards) |
| `(\()` | 1 | opening parenthesis |
| `(\))` | 2 | closing parenthesis |
| `(,)` | 3 | list separator |
| `(>=\|<=\|!=\|!~\|=\|>\|<\|~)` | 4 | operator. Two-character forms are listed **first** so `>=` is not read as `>` followed by `=`. |
| `("(?:[^"\\]\|\\.)*"\|'(?:[^'\\]\|\\.)*')` | 5 | a double- or single-quoted string; inside, either a char that is not the quote or a backslash, or a backslash followed by any char (so `\"` and `\\` are allowed) |
| `(-?\d+(?:\.\d+)?)` | 6 | integer or decimal, optional leading minus. No exponent form. |
| `([A-Za-z_][A-Za-z0-9_]*)` | 7 | a word: field name or keyword |
| flag `y` | – | **sticky**: the match must start exactly at `re.lastIndex`. This is what makes the regex a lexer — it cannot skip ahead over an unknown character. |

Because every alternative requires at least one character, `m[0]` is never empty or whitespace-only when there *is* a match.

### `tokenize()` — the loop and errors

```js
// lines 47-58
  while (pos < input.length) {
    re.lastIndex = pos;
    const m = re.exec(input);
    if (!m || (m[0].trim() === '' && m.index + m[0].length === pos)) {
      if (/^\s*$/.test(input.slice(pos))) break;
      const bad = pos + (input.slice(pos).match(/^\s*/) || [''])[0].length;
      const ch = input[bad];
      throw new QueryError(ch === '"' || ch === "'" ? 'unterminated string' : `unexpected character "${ch}"`, bad, ch === '"' || ch === "'" ? input.length - bad : 1);
    }
    const start = m.index + (m[0].length - m[0].trimStart().length);
    const text = m[0].trim();
    pos = m.index + m[0].length;
    const tok = { pos: start, len: text.length, text };
```

- Each iteration sets `lastIndex = pos` and asks for one token. The second half of the `if` (an empty match that did not advance) is defensive; in practice only `!m` happens.
- No match and only whitespace left → done. Otherwise the offending character is located after skipping whitespace (`bad`). If it is a quote, the string group failed to close: the error is `unterminated string` and its `len` runs to the end of the input, so the editor underlines the whole open string (test: `validate('student = "ali')` → `pos 10`). Any other character (`;`, `#`, `@`, `{`) gives `unexpected character` with `len 1` — this is what rejects `student = "a"; DROP TABLE requests` (test `unknown fields, bad operators and injection attempts are rejected`).
- `start` is `m.index` plus the length of the leading whitespace that `\s*` swallowed; `text` is the trimmed match. `pos` advances past the whole match including that whitespace.

```js
// lines 59-73
    const tok = { pos: start, len: text.length, text };
    if (m[1]) tokens.push({ ...tok, t: '(' });
    else if (m[2]) tokens.push({ ...tok, t: ')' });
    else if (m[3]) tokens.push({ ...tok, t: ',' });
    else if (m[4]) tokens.push({ ...tok, t: 'op', v: m[4] });
    else if (m[5]) tokens.push({ ...tok, t: 'str', v: m[5].slice(1, -1).replace(/\\(.)/g, '$1') });
    else if (m[6]) tokens.push({ ...tok, t: 'num', v: Number(m[6]) });
    else if (m[7]) {
      const w = m[7].toUpperCase();
      if (w === 'AND' || w === 'OR' || w === 'NOT' || w === 'IN') tokens.push({ ...tok, t: w });
      else tokens.push({ ...tok, t: 'ident', v: m[7] });
    }
  }
  return tokens;
}
```

- Strings: the surrounding quotes are stripped and `\x` becomes `x` (so `"a\"b"` → `a"b`, `"C:\\x"` → `C:\x`). There are no other escapes (`\n` is just `n`).
- Numbers are converted with `Number()` at lex time, so `status = 404` carries `404` (number) while `status = "404"` carries `"404"` (string) — the compiler coerces the latter.
- Keywords are case-insensitive (`and`, `And`, `AND`) and become their own token kinds; everything else is an `ident` keeping the original spelling (the parser lowercases it for lookup, so `Status` works, but the error message shows what the user typed).

### `parse()` — set-up

```js
// lines 75-87
function parse(input) {
  const src = String(input || '');
  const toks = tokenize(src.trim() === '' ? '' : src);
  let i = 0;
  const peek = () => toks[i];
  const next = () => toks[i++];
  const endPos = src.length;
  const at = (tok) => (tok ? tok.pos : endPos);
  const expect = (t, what) => {
    const tok = next();
    if (!tok || tok.t !== t) throw new QueryError(`expected ${what || t} but found ${tok ? `"${tok.text}"` : 'end of query'}`, at(tok), tok ? tok.len : 1);
    return tok;
  };
```

A classic recursive-descent parser over the token array with a single cursor `i`. `at(tok)` gives a position for errors even when the input ran out (`endPos`), which is how `student =` reports `pos 9` (test `validate() reports the position of the problem for the editor`).

### `parse()` — precedence climbing

```js
// lines 89-111
  function parseOr() {
    let left = parseAnd();
    while (peek() && peek().t === 'OR') {
      next();
      left = { type: 'or', left, right: parseAnd() };
    }
    return left;
  }
  function parseAnd() {
    let left = parseNot();
    while (peek() && peek().t === 'AND') {
      next();
      left = { type: 'and', left, right: parseNot() };
    }
    return left;
  }
  function parseNot() {
    if (peek() && peek().t === 'NOT') {
      next();
      return { type: 'not', expr: parseNot() };
    }
    return parsePrimary();
  }
```

Grammar, lowest precedence first:

```
or      := and ( OR and )*
and     := not ( AND not )*
not     := NOT not | primary
primary := '(' or ')' | ident op value | ident IN '(' value (',' value)* ')'
```

- Each level loops on its own keyword and builds **left-associative** trees: `a OR b OR c` → `or(or(a,b),c)`.
- Because `parseAnd` is called from inside `parseOr`, `AND` binds tighter than `OR`: `a OR b AND c` → `or(a, and(b,c))`. `NOT` binds tightest and is right-recursive, so `NOT NOT x` works.
- There is no implicit `AND`: two conditions side by side leave a token unconsumed, which the final check in `parse()` turns into `unexpected "status" - join conditions with AND / OR`.

### `parse()` — primaries, comparisons and `IN`

```js
// lines 112-126
  function parsePrimary() {
    const tok = peek();
    if (!tok) throw new QueryError('expected a field name (e.g. student, status, path)', endPos);
    if (tok.t === '(') {
      next();
      const e = parseOr();
      expect(')', '")"');
      return e;
    }
    if (tok.t !== 'ident') throw new QueryError(`expected a field name but found "${tok.text}"`, tok.pos, tok.len);
    next();
    const field = tok.v.toLowerCase();
    if (!FIELDS[field]) throw new QueryError(`unknown field "${tok.v}" (known: ${Object.keys(FIELDS).join(', ')})`, tok.pos, tok.len);
    const opTok = next();
    if (!opTok) throw new QueryError(`missing operator after "${field}" (${OPS_BY_TYPE[FIELDS[field].type].join(' ')})`, endPos);
```

- A parenthesised group just recurses into `parseOr` and demands the closing `)`; the AST keeps no node for the parentheses, the tree shape *is* the grouping.
- The field is validated here, at parse time, with the full list of known names in the message (test: `studnt = "alice"` → `pos 0, len 6, /unknown field/`).

```js
// lines 127-145
    if (opTok.t === 'IN') {
      expect('(', '"(" after in');
      const values = [];
      for (;;) {
        const v = next();
        if (!v || (v.t !== 'str' && v.t !== 'num')) throw new QueryError('in (...) expects a list of values like ("a", "b")', at(v), v ? v.len : 1);
        values.push(v.v);
        const sep = next();
        if (!sep) throw new QueryError('unterminated in (...) list, missing ")"', endPos);
        if (sep.t === ')') break;
        if (sep.t !== ',') throw new QueryError('expected "," or ")" in the in (...) list', sep.pos, sep.len);
      }
      return { type: 'in', field, values, pos: tok.pos, len: tok.len };
    }
    if (opTok.t !== 'op') throw new QueryError(`expected an operator after "${field}" (${OPS_BY_TYPE[FIELDS[field].type].join(' ')}) but found "${opTok.text}"`, opTok.pos, opTok.len);
    const v = next();
    if (!v || (v.t !== 'str' && v.t !== 'num')) throw new QueryError(`missing value after "${field} ${opTok.v}" (strings in quotes)`, at(v), v ? v.len : 1);
    return { type: 'cmp', field, op: opTok.v, value: v.v, pos: tok.pos, len: tok.len, opPos: opTok.pos, opLen: opTok.len };
  }
```

- `IN` is a keyword token, not an `op`, so it takes its own branch: `(`, then one or more `str`/`num` values separated by commas, then `)`. An empty list `in ()` is rejected because the first `next()` returns `)` which is neither `str` nor `num`.
- A plain comparison needs an `op` token and then **exactly one `str` or `num`**. A bare word as value (`student = alice`) is an `ident`, so the error is `missing value ... (strings in quotes)` — this is the hint users need most.
- Both node types record where the field name was (`pos`/`len`); `cmp` also records the operator's position so type errors can underline the operator rather than the field.

```js
// lines 147-151
  if (!toks.length) return null;
  const ast = parseOr();
  if (i < toks.length) throw new QueryError(`unexpected "${toks[i].text}" - join conditions with AND / OR`, toks[i].pos, toks[i].len);
  return ast;
}
```

An empty or whitespace-only query returns `null` (no AST), which `compile()` treats as "no condition". After a successful parse any leftover token is an error.

### `timeValue()`

```js
// lines 153-163
function timeValue(v, now, node) {
  if (typeof v === 'number') return v < 1e11 ? v * 1000 : v; // seconds vs ms
  const m = /^-(\d+)\s*([smhd])$/.exec(String(v).trim());
  if (m) {
    const mult = { s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2]];
    return now - Number(m[1]) * mult;
  }
  const t = Date.parse(v);
  if (Number.isNaN(t)) throw new QueryError(`bad time value "${v}" (use -10m, -2h, -1d or an ISO date)`, node && node.pos, node && node.len);
  return t;
}
```

Three accepted forms, all converted to epoch **milliseconds** (the `ts` column's unit):

1. A number: below `1e11` it is taken as seconds and multiplied by 1000 (`1e11` ms is March 1973, `1e11` s is the year 5138, so the threshold is unambiguous for any realistic value); otherwise it is already ms.
2. A relative string `-<n><unit>` with optional whitespace before the unit: `-10m`, `-2 h`, `-1d`, `-30s`. Computed against `now`, which `compile()` takes from its options so tests can pin it (`NOW` in `query.test.js`). Positive offsets (`+10m`) are not supported.
3. Anything `Date.parse` understands — ISO dates such as `2026-10-28` or `2026-10-28T12:00:00Z`. Note that a date-only string is parsed as **UTC midnight**.

Anything else (`"yesterday"`) throws with the field's position.

### `compileNode()` — boolean nodes and `IN`

```js
// lines 165-184
function compileNode(node, params, now) {
  switch (node.type) {
    case 'and':
      return `(${compileNode(node.left, params, now)} AND ${compileNode(node.right, params, now)})`;
    case 'or':
      return `(${compileNode(node.left, params, now)} OR ${compileNode(node.right, params, now)})`;
    case 'not':
      return `(NOT ${compileNode(node.expr, params, now)})`;
    case 'in': {
      const f = FIELDS[node.field];
      if (f.type === 'list') {
        const parts = node.values.map((v) => {
          params.push(`%"${String(v)}"%`);
          return `${f.col} LIKE ?`;
        });
        return `(${parts.join(' OR ')})`;
      }
      node.values.forEach((v) => params.push(f.type === 'time' ? timeValue(v, now, node) : v));
      return `${f.col} IN (${node.values.map(() => '?').join(', ')})`;
    }
```

- `params` is an array passed down and appended to **in evaluation order**; because `compileNode` compiles `left` before `right` (template literal evaluation is left-to-right), the `?` placeholders and the params line up.
- Every boolean node is fully parenthesised, so SQL precedence can never differ from the AST, at the cost of some redundant brackets.
- `IN` on a `list` field cannot use SQL `IN` (the column holds a JSON array as text), so it becomes an `OR` of `LIKE '%"value"%'` tests — "the array contains this exact quoted element". For the other types it is a normal `col IN (?, ?, ...)`, with time values converted.

### `compileNode()` — comparisons

```js
// lines 185-210
    case 'cmp': {
      const f = FIELDS[node.field];
      let { op, value } = node;
      if (f.type === 'time') value = timeValue(value, now, node);
      if (f.type === 'num' && typeof value !== 'number') {
        const n = Number(value);
        if (Number.isNaN(n)) throw new QueryError(`"${node.field}" expects a number`, node.pos, node.len);
        value = n;
      }
      if (op === '~' || op === '!~') {
        if (f.type === 'num' || f.type === 'time') throw new QueryError(`"${op}" cannot be used on "${node.field}" (${OPS_BY_TYPE[f.type].join(' ')})`, node.opPos, node.opLen);
        params.push(`%${String(value).replace(/[%_\\]/g, (c) => '\\' + c)}%`);
        return `${f.col} ${op === '~' ? 'LIKE' : 'NOT LIKE'} ? ESCAPE '\\'`;
      }
      if (f.type === 'list') {
        if (op !== '=' && op !== '!=') throw new QueryError(`"${node.field}" supports = != ~ !~ in`, node.opPos, node.opLen);
        params.push(`%"${String(value)}"%`);
        return `${f.col} ${op === '=' ? 'LIKE' : 'NOT LIKE'} ?`;
      }
      params.push(value);
      return `${f.col} ${op} ?`;
    }
    default:
      throw new QueryError('bad expression');
  }
}
```

Order of the checks matters:

1. **Time conversion** first, so `ts > "-10m"` becomes a number.
2. **Numeric coercion**: a quoted number on a `num` field (`status < "500"`) is converted; a non-numeric string is an error at the field (test `IN lists and numeric coercion`).
3. **`~` / `!~` (contains)**: refused on `num`/`time` with the error pointing at the operator (`status ~ 200` → `pos 7`). Otherwise the value is wrapped in `%...%` and the SQL `LIKE` wildcards inside the user's text are escaped with a backslash, with `ESCAPE '\'` declared in the SQL — so `path ~ "100%_x"` really searches for the literal characters (test `LIKE wildcards in user input are escaped`). SQLite `LIKE` is case-insensitive for ASCII, so `~` is a case-insensitive substring match.
   For `list` fields `~` is the same substring LIKE over the JSON text, without the quotes: `flag ~ "idor"` matches both `idor-attempt` and `idor-success`.
4. **`list` with `=` / `!=`**: the value is wrapped in `%"..."%` so it must match a whole JSON string element (`flag = "idor"` does **not** match `"idor-attempt"`). No `ESCAPE` clause here, so a `%` or `_` inside the value would act as a wildcard — flag and class names never contain those. `attack = "sqli"` works because the stored objects contain `"cls":"sqli"`, i.e. the quoted class name appears in the text. Other operators on lists are refused at the operator position (test: `flag > "x"` throws).
5. Everything else is a direct `col op ?`.

### `compile()`

```js
// lines 216-227
function compile(query, { ctfId, now = Date.now() } = {}) {
  const ast = parse(query);
  const params = [];
  const parts = [];
  if (ast) parts.push(compileNode(ast, params, now));
  if (ctfId && !/\bctf\b/i.test(query || '')) {
    parts.push('ctf_id = ?');
    params.push(ctfId);
  }
  const where = parts.length ? `WHERE ${parts.join(' AND ')}` : '';
  return { sql: `SELECT * FROM requests ${where} ORDER BY ts DESC`, params, where };
}
```

- The caller (dashboard) passes the CTF to scope to (`scopeCtf(body.ctf) || 0`); when it is truthy and the query text does **not** contain the word `ctf`, `ctf_id = ?` is appended with `AND`. Writing `ctf = 3` (or any `ctf ...` condition) therefore searches across CTFs explicitly (test `mentioning ctf disables the automatic ctf scope`). **Gotcha:** the check is a regex over the raw text, so a string value containing the word, e.g. `path ~ "/ctf/flag"`, also switches the automatic scope off.
- With no AST and a `ctfId`, the result is `WHERE ctf_id = ?` (test `empty query returns everything in the active ctf`); with neither, `where` is `''` and the whole table is selected.
- No `LIMIT` is emitted here — `db.runSql()` appends a capped one. `where` is returned separately for callers that want to reuse it (the dashboard echoes `sql`/`params` to the UI for transparency).

### `validate()`

```js
// lines 229-238
// Linting helper for the editor: { ok, error, pos, len }
function validate(query) {
  try {
    compile(query, { now: Date.now() });
    return { ok: true };
  } catch (err) {
    if (err instanceof QueryError) return { ok: false, error: err.message, pos: err.pos, len: err.len };
    return { ok: false, error: err.message, pos: null, len: 1 };
  }
}
```

Runs the full pipeline (so type errors from `compileNode` are caught too, not just syntax) without a `ctfId`, and never throws. The browser calls this on every keystroke; the server never calls it (it uses `compile()` and maps the exception itself).

### Dual export

```js
// lines 240-242
const api = { compile, parse, tokenize, validate, FIELDS, OPS_BY_TYPE, QueryError };
if (typeof module !== 'undefined' && module.exports) module.exports = api;
else if (typeof window !== 'undefined') window.CtfQuery = api;
```

- In Node (`require('./query')`) the first branch runs. In the browser there is no `module`, so the API is attached to `window.CtfQuery`.
- `dashboard.js` (lines 114-125) serves the file verbatim: it `fs.readFile`s `src/query.js` and sends it with `Content-Type: application/javascript` and `Cache-Control: no-cache`, behind the same login as the rest of the app. `app.html` loads it with `<script src="/query.js">` and uses `window.CtfQuery` for linting (`validate`), autocomplete (`FIELDS`, `OPS_BY_TYPE`) and showing the token under the cursor. One source file, two runtimes — which is why `'use strict'` plus plain ES2015 is all it uses.

## Worked example

Query: `(path ~ "/api/orders" OR endpoint = "orders") AND NOT flag = "idor-success"`, compiled with `{ ctfId: 7 }`. Values below are the real output of `tokenize`, `parse` and `compile`.

### Token list (14 tokens)

| # | pos | len | t | v |
|---|---|---|---|---|
| 0 | 0 | 1 | `(` | |
| 1 | 1 | 4 | `ident` | `path` |
| 2 | 6 | 1 | `op` | `~` |
| 3 | 8 | 13 | `str` | `/api/orders` (text is `"/api/orders"`, 13 chars with quotes) |
| 4 | 22 | 2 | `OR` | |
| 5 | 25 | 8 | `ident` | `endpoint` |
| 6 | 34 | 1 | `op` | `=` |
| 7 | 36 | 8 | `str` | `orders` |
| 8 | 44 | 1 | `)` | |
| 9 | 46 | 3 | `AND` | |
| 10 | 50 | 3 | `NOT` | |
| 11 | 54 | 4 | `ident` | `flag` |
| 12 | 59 | 1 | `op` | `=` |
| 13 | 61 | 14 | `str` | `idor-success` |

### AST

```
and
├─ or
│  ├─ cmp { field: "path",     op: "~", value: "/api/orders", pos: 1,  len: 4, opPos: 6,  opLen: 1 }
│  └─ cmp { field: "endpoint", op: "=", value: "orders",      pos: 25, len: 8, opPos: 34, opLen: 1 }
└─ not
   └─ cmp { field: "flag",     op: "=", value: "idor-success", pos: 54, len: 4, opPos: 59, opLen: 1 }
```

How it got there: `parseOr` → `parseAnd` → `parseNot` → `parsePrimary` sees `(`, recurses into `parseOr`, which builds the inner `or` from two `cmp`s and consumes `)`. Back in `parseAnd` the loop sees `AND`, calls `parseNot`, which sees `NOT`, recurses, and `parsePrimary` builds the `flag` comparison. `parseOr`'s loop sees no `OR`, so the outer node is the `and`. No tokens remain.

### Compiled SQL and params

```sql
SELECT * FROM requests
WHERE ((path LIKE ? ESCAPE '\' OR endpoint = ?) AND (NOT flags LIKE ?)) AND ctf_id = ?
ORDER BY ts DESC
```

`params = ["%/api/orders%", "orders", "%\"idor-success\"%", 7]`

- `path ~` → `LIKE ? ESCAPE '\'` with `%/api/orders%` (no wildcard characters to escape).
- `endpoint =` → plain `= ?`.
- `flag =` on a `list` field → `flags LIKE ?` with `%"idor-success"%` (quotes included so `idor-success` must be a whole element); the `NOT` node wraps it as `(NOT ...)`.
- `ctf_id = ?` appended because `ctfId` was given and the text does not mention `ctf`.
- `db.runSql()` then appends ` LIMIT 1000` (or the requested cap) before executing.

The test `OR / NOT / parentheses respect precedence` asserts exactly this `where` and params (without the `ctfId`).

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `dashboard.js` `POST /api/query` (line 236) | `compile(String(body.q), { ctfId: scopeCtf(body.ctf) \|\| 0 })`; `QueryError` instance check decides 400 vs 500 and `pos`/`len` are echoed. |
| in | `dashboard.js` `GET /query.js` (lines 114-125) | The raw source file, served to the browser. |
| in | `public/app.html` | `window.CtfQuery.validate/tokenize/FIELDS/OPS_BY_TYPE` for the editor. |
| in | `test/db.test.js` | `compile()` output fed to `db.runSql`. |
| out | `db.js runSql()` | `{sql, params}` — SQL with only `FIELDS` column names and `?` placeholders. |
| data contract | `db.js` schema | Every `col` in `FIELDS` must be a real column of `requests`; `flags`/`attacks` must stay JSON-array text for the `LIKE '%"x"%'` trick. |

## Changing it safely

| Likely change | Where | Notes |
|---|---|---|
| Expose a new column (e.g. `body`) | Add one line to `FIELDS` (lines 12-32) with `col`, `type`, `help` | Nothing else: the parser, compiler and editor all read `FIELDS`. The autocomplete *values* endpoint in `dashboard.js` has its own `COLS` whitelist; extend it if you want value suggestions. |
| New operator (e.g. `^` starts-with) | Group 4 of the tokenizer regex (line 45, longest forms first), `OPS_BY_TYPE` (line 33), and a branch in the `cmp` case (lines 194-205) | Keep user text in `params`; use `ESCAPE` if the operator maps to `LIKE`. |
| Positive relative times or `now` keyword | `timeValue()` (lines 153-163) | Keep returning ms. |
| Change the auto-scope rule (e.g. only when `ctf` is a *field*, not inside strings) | `compile()` line 221 — walk the AST for a `cmp`/`in` with `field === 'ctf'` instead of the regex | Update the help text of `ctf` in `FIELDS` and the test `mentioning ctf disables the automatic ctf scope`. |
| Add `LIMIT`/`ORDER BY` control | `compile()` line 226 and `db.runSql()` which appends `LIMIT` | Never interpolate user text; keep the limit numeric. |

Whatever you change, the file must still run in the browser: no `require`, no Node globals.

Tests (`proxy/test/query.test.js`):

- `simple comparison compiles to parameterised SQL`
- `OR / NOT / parentheses respect precedence` — the worked example
- `relative time values`
- `IN lists and numeric coercion`
- `mentioning ctf disables the automatic ctf scope`
- `empty query returns everything in the active ctf`
- `LIKE wildcards in user input are escaped`
- `validate() reports the position of the problem for the editor` — positions for unknown field, bad operator, missing AND, unterminated string, missing value
- `unknown fields, bad operators and injection attempts are rejected`

Plus `proxy/test/db.test.js` `requests are batched, flushed and queryable through the query language`, which runs compiled SQL against a real in-memory DB.

Run: `cd D:\SIEMs\ctf-watch\proxy; node --test test/query.test.js test/db.test.js`

## Exercises

1. **Inspect tokens and AST.** Print `tokenize()` and `parse()` for `ts > "-2h" AND method in ("POST", "PUT") OR NOT severity = "ok"` and confirm the top node is `or` (because `AND` binds tighter) and the `in` node's `values` are `["POST", "PUT"]`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node -e "const q=require('./src/query');const s='ts > \"-2h\" AND method in (\"POST\", \"PUT\") OR NOT severity = \"ok\"';console.log(q.tokenize(s).map(t=>t.t+':'+(t.v??'')).join(' '));console.log(JSON.stringify(q.parse(s),null,1))"`
2. **Add a `starts-with` operator.** Add `^` to the operator group of the regex and to `OPS_BY_TYPE.text`, and in the `cmp` case compile `^` to `col LIKE ? ESCAPE '\'` with the param `escaped + '%'` (no leading `%`). Write a test asserting `compile('path ^ "/api"', {now: 0})` yields `WHERE path LIKE ? ESCAPE '\'` and params `['/api%']`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node --test test/query.test.js`
3. **See the error positions the editor uses.** Run `validate()` on `status ~ 200`, `student = "ali`, `student = "alice" status = 200` and `flag > "x"` and map each `pos`/`len` back onto the string (print `' '.repeat(pos) + '^'.repeat(len)` under it).
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node -e "const {validate}=require('./src/query');for(const s of ['status ~ 200','student = \"ali','student = \"alice\" status = 200','flag > \"x\"']){const v=validate(s);console.log(s);console.log(' '.repeat(v.pos)+'^'.repeat(v.len),v.error)}"`

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `compile` | `(query: string, {ctfId?, now?} = {}) => {sql, params, where}` | Parse + compile to `SELECT * FROM requests WHERE ... ORDER BY ts DESC`; adds `ctf_id = ?` unless the text mentions `ctf`. Throws `QueryError`. |
| `parse` | `(query) => ast \| null` | Tokenize + recursive descent; `null` for an empty query. |
| `tokenize` | `(input) => token[]` | Sticky-regex lexer with positions. |
| `validate` | `(query) => {ok: true} \| {ok: false, error, pos, len}` | Non-throwing lint for the editor. |
| `FIELDS` | `{[name]: {col, type, help}}` | Field whitelist and metadata. |
| `OPS_BY_TYPE` | `{text, num, time, list: string[]}` | Operators per type, for messages and autocomplete. |
| `QueryError` | `new QueryError(message, pos, len)` | Error with editor position (`pos` may be `null`, `len` ≥ 1). |
