'use strict';
// Tiny query language for the request log, compiled to parameterised SQL (never string-built).
//
//   student = "alice" AND status >= 400
//   (path ~ "/api/orders" OR endpoint = "orders") AND NOT flag ~ "idor"
//   ts > "-10m" AND method in ("POST", "PUT")
//
// Fields: ts student ip method path endpoint id status size latency severity flag attack owner ua source raw ctf
// Operators: = != > >= < <= ~ (contains) !~ in    Logic: AND OR NOT ( )
// Values: "string" or 'string', number, list ("a","b"). ts accepts "-10m" "-2h" "-1d" or ISO dates.

const FIELDS = {
  ts: { col: 'ts', type: 'time' },
  student: { col: 'student', type: 'text' },
  raw: { col: 'raw_name', type: 'text' },
  ip: { col: 'ip', type: 'text' },
  method: { col: 'method', type: 'text' },
  path: { col: 'path', type: 'text' },
  endpoint: { col: 'endpoint', type: 'text' },
  id: { col: 'object_id', type: 'text' },
  status: { col: 'status', type: 'num' },
  size: { col: 'size', type: 'num' },
  latency: { col: 'latency', type: 'num' },
  severity: { col: 'severity', type: 'text' },
  flag: { col: 'flags', type: 'list' },
  attack: { col: 'attacks', type: 'list' },
  owner: { col: 'owner', type: 'text' },
  ua: { col: 'ua', type: 'text' },
  source: { col: 'source', type: 'text' },
  ctf: { col: 'ctf_id', type: 'num' },
  player: { col: 'player_id', type: 'num' },
};

class QueryError extends Error {}

function tokenize(input) {
  const tokens = [];
  const re = /\s*(?:(\()|(\))|(,)|(>=|<=|!=|!~|=|>|<|~)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(-?\d+(?:\.\d+)?)|([A-Za-z_][A-Za-z0-9_]*))/y;
  let pos = 0;
  while (pos < input.length) {
    re.lastIndex = pos;
    const m = re.exec(input);
    if (!m || m[0].trim() === '' && m.index + m[0].length === pos) {
      if (/^\s*$/.test(input.slice(pos))) break;
      throw new QueryError(`unexpected character at position ${pos}: "${input.slice(pos, pos + 10)}"`);
    }
    pos = m.index + m[0].length;
    if (m[1]) tokens.push({ t: '(' });
    else if (m[2]) tokens.push({ t: ')' });
    else if (m[3]) tokens.push({ t: ',' });
    else if (m[4]) tokens.push({ t: 'op', v: m[4] });
    else if (m[5]) tokens.push({ t: 'str', v: m[5].slice(1, -1).replace(/\\(.)/g, '$1') });
    else if (m[6]) tokens.push({ t: 'num', v: Number(m[6]) });
    else if (m[7]) {
      const w = m[7].toUpperCase();
      if (w === 'AND' || w === 'OR' || w === 'NOT' || w === 'IN') tokens.push({ t: w });
      else tokens.push({ t: 'ident', v: m[7] });
    }
  }
  return tokens;
}

function parse(input) {
  const toks = tokenize(String(input || '').trim());
  let i = 0;
  const peek = () => toks[i];
  const next = () => toks[i++];
  const expect = (t) => {
    const tok = next();
    if (!tok || tok.t !== t) throw new QueryError(`expected ${t} but found ${tok ? tok.t : 'end of query'}`);
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
    if (!tok) throw new QueryError('unexpected end of query');
    if (tok.t === '(') {
      next();
      const e = parseOr();
      expect(')');
      return e;
    }
    const field = expect('ident').v.toLowerCase();
    if (!FIELDS[field]) throw new QueryError(`unknown field "${field}" (known: ${Object.keys(FIELDS).join(', ')})`);
    const opTok = next();
    if (!opTok) throw new QueryError(`missing operator after "${field}"`);
    if (opTok.t === 'IN') {
      expect('(');
      const values = [];
      for (;;) {
        const v = next();
        if (!v || (v.t !== 'str' && v.t !== 'num')) throw new QueryError('IN expects a list of values');
        values.push(v.v);
        const sep = next();
        if (!sep) throw new QueryError('unterminated IN list');
        if (sep.t === ')') break;
        if (sep.t !== ',') throw new QueryError('expected , or ) in IN list');
      }
      return { type: 'in', field, values };
    }
    if (opTok.t !== 'op') throw new QueryError(`expected an operator after "${field}"`);
    const v = next();
    if (!v || (v.t !== 'str' && v.t !== 'num')) throw new QueryError(`missing value after "${field} ${opTok.v}"`);
    return { type: 'cmp', field, op: opTok.v, value: v.v };
  }

  if (!toks.length) return null;
  const ast = parseOr();
  if (i < toks.length) throw new QueryError(`unexpected token "${toks[i].v || toks[i].t}"`);
  return ast;
}

function timeValue(v, now) {
  if (typeof v === 'number') return v < 1e11 ? v * 1000 : v; // seconds vs ms
  const m = /^-(\d+)\s*([smhd])$/.exec(String(v).trim());
  if (m) {
    const mult = { s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2]];
    return now - Number(m[1]) * mult;
  }
  const t = Date.parse(v);
  if (Number.isNaN(t)) throw new QueryError(`bad time value "${v}" (use -10m, -2h, -1d or an ISO date)`);
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
      node.values.forEach((v) => params.push(f.type === 'time' ? timeValue(v, now) : v));
      return `${f.col} IN (${node.values.map(() => '?').join(', ')})`;
    }
    case 'cmp': {
      const f = FIELDS[node.field];
      let { op, value } = node;
      if (f.type === 'time') value = timeValue(value, now);
      if (f.type === 'num' && typeof value !== 'number') {
        const n = Number(value);
        if (Number.isNaN(n)) throw new QueryError(`"${node.field}" expects a number`);
        value = n;
      }
      if (op === '~' || op === '!~') {
        if (f.type === 'num' || f.type === 'time') throw new QueryError(`"~" cannot be used on "${node.field}"`);
        params.push(`%${String(value).replace(/[%_\\]/g, (c) => '\\' + c)}%`);
        return `${f.col} ${op === '~' ? 'LIKE' : 'NOT LIKE'} ? ESCAPE '\\'`;
      }
      if (f.type === 'list') {
        // flag = "idor-success"  -> exact element match inside the JSON array
        if (op !== '=' && op !== '!=') throw new QueryError(`"${node.field}" supports = != ~ !~ in`);
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

module.exports = { compile, parse, tokenize, FIELDS, QueryError };
