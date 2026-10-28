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

const FIELDS = {
  ts: { col: 'ts', type: 'time', help: 'time of the request: "-10m", "-2h", "-1d" or an ISO date' },
  student: { col: 'student', type: 'text', help: 'student name as shown on the dashboard' },
  raw: { col: 'raw_name', type: 'text', help: 'name before any rename by the organizer' },
  ip: { col: 'ip', type: 'text', help: 'client ip address' },
  method: { col: 'method', type: 'text', help: 'GET, POST, PUT, DELETE...' },
  path: { col: 'path', type: 'text', help: 'request path with query string (secrets masked)' },
  endpoint: { col: 'endpoint', type: 'text', help: 'name of the matched IDOR endpoint rule' },
  id: { col: 'object_id', type: 'text', help: 'object id taken from the request' },
  status: { col: 'status', type: 'num', help: 'HTTP status code' },
  size: { col: 'size', type: 'num', help: 'response size in bytes' },
  latency: { col: 'latency', type: 'num', help: 'response time in milliseconds' },
  severity: { col: 'severity', type: 'text', help: 'ok, notice, warn, high, critical' },
  flag: { col: 'flags', type: 'list', help: 'idor-attempt, idor-success, enumeration, burst-errors, blocked, attack:<class>' },
  attack: { col: 'attacks', type: 'list', help: 'attack class: sqli, xss, ssti, lfi, cmdi, shell, xxe, ssrf, nosqli, redirect, deser, scanner' },
  owner: { col: 'owner', type: 'text', help: 'who the requested object belongs to' },
  ua: { col: 'ua', type: 'text', help: 'user agent' },
  source: { col: 'source', type: 'text', help: 'how the student was identified: name, ip-match, session, jwt, login, ip' },
  ctf: { col: 'ctf_id', type: 'num', help: 'CTF record number (mentioning it searches outside the current CTF)' },
  player: { col: 'player_id', type: 'num', help: 'player number (same person across CTFs)' },
};
const OPS_BY_TYPE = { text: ['=', '!=', '~', '!~', 'in'], num: ['=', '!=', '>', '>=', '<', '<=', 'in'], time: ['>', '>=', '<', '<=', '=', '!='], list: ['=', '!=', '~', '!~', 'in'] };

class QueryError extends Error {
  constructor(message, pos, len) {
    super(message);
    this.pos = pos == null ? null : pos;
    this.len = len || 1;
  }
}

function tokenize(input) {
  const tokens = [];
  const re = /\s*(?:(\()|(\))|(,)|(>=|<=|!=|!~|=|>|<|~)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(-?\d+(?:\.\d+)?)|([A-Za-z_][A-Za-z0-9_]*))/y;
  let pos = 0;
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

  if (!toks.length) return null;
  const ast = parseOr();
  if (i < toks.length) throw new QueryError(`unexpected "${toks[i].text}" - join conditions with AND / OR`, toks[i].pos, toks[i].len);
  return ast;
}

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

/**
 * compile(query, { ctfId, now }) -> { sql, params, where }
 * ctfId scopes the query to one CTF unless the query itself mentions "ctf".
 */
// does the query itself filter on the ctf field? (decided on the parsed tree, not on the raw text,
// so a value like path ~ "/ctf/flag" does not switch the automatic scope off)
function mentionsCtf(node) {
  if (!node) return false;
  if (node.type === 'cmp' || node.type === 'in') return node.field === 'ctf';
  if (node.type === 'not') return mentionsCtf(node.expr);
  return mentionsCtf(node.left) || mentionsCtf(node.right);
}

function compile(query, { ctfId, now = Date.now() } = {}) {
  const ast = parse(query);
  const params = [];
  const parts = [];
  if (ast) parts.push(compileNode(ast, params, now));
  if (ctfId && !mentionsCtf(ast)) {
    parts.push('ctf_id = ?');
    params.push(ctfId);
  }
  const where = parts.length ? `WHERE ${parts.join(' AND ')}` : '';
  return { sql: `SELECT * FROM requests ${where} ORDER BY ts DESC`, params, where };
}

// Linting helper for the editor: { ok, error, pos, len }
/**
 * What the editor should offer at `caret`: a field, an operator, a value (for which field and
 * operator) or a logic word, plus the partial word being typed and where it starts.
 * A string is "open" only when the tokenizer says so (an unterminated quote before the caret),
 * never because a closing quote happens to be the last quote on the line.
 */
function contextAt(src, caret) {
  const before = src.slice(0, caret);
  let toks = [];
  let partial = '';
  let isOpenStr = false;
  try {
    toks = tokenize(before);
  } catch (err) {
    if (err instanceof QueryError && err.pos != null && /unterminated/.test(err.message)) {
      isOpenStr = true;
      partial = before.slice(err.pos);
      try {
        toks = tokenize(before.slice(0, err.pos));
      } catch {
        toks = [];
      }
    }
  }
  if (!isOpenStr) {
    const m = /([A-Za-z_][A-Za-z0-9_-]*|-?\d+(?:\.\d+)?)$/.exec(before);
    partial = m ? m[1] : '';
  }
  const lastTok = toks[toks.length - 1];
  const done = partial && !isOpenStr && lastTok && lastTok.pos + lastTok.len === caret ? toks.slice(0, -1) : toks;
  const last = done[done.length - 1];
  const prev = done[done.length - 2];
  const lastIdent = () => {
    const t = done.slice().reverse().find((x) => x.t === 'ident');
    return t ? t.v.toLowerCase() : undefined;
  };
  let kind = 'none';
  let field;
  let op;
  if (last && last.t === '(' && prev && prev.t === 'IN') {
    kind = 'value';
    field = lastIdent();
    op = 'in';
  } else if (!last || ['(', 'AND', 'OR', 'NOT'].includes(last.t)) kind = 'field';
  else if (last.t === 'ident') {
    kind = 'op';
    field = last.v.toLowerCase();
  } else if (last.t === 'op' && prev && prev.t === 'ident') {
    kind = 'value';
    field = prev.v.toLowerCase();
    op = last.v;
  } else if (last.t === 'IN' || last.t === ',') {
    kind = 'value';
    field = lastIdent();
    op = 'in';
  } else if (last.t === 'str' || last.t === 'num' || last.t === ')') kind = 'logic';
  return { kind, field, op, partial, isOpenStr, start: caret - partial.length };
}

function validate(query) {
  try {
    compile(query, { now: Date.now() });
    return { ok: true };
  } catch (err) {
    if (err instanceof QueryError) return { ok: false, error: err.message, pos: err.pos, len: err.len };
    return { ok: false, error: err.message, pos: null, len: 1 };
  }
}

const api = { compile, parse, tokenize, validate, contextAt, FIELDS, OPS_BY_TYPE, QueryError };
if (typeof module !== 'undefined' && module.exports) module.exports = api;
else if (typeof window !== 'undefined') window.CtfQuery = api;
