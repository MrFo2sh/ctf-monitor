'use strict';
// Web-exploitation attempt classifier (detection only, in the spirit of WAF rule sets).
// Looks at the decoded URL, request body, User-Agent and Referer and tags the request with attack classes.
// Classes with zero hits are simply absent, so the UI naturally hides them.

const CLASSES = [
  { cls: 'sqli', level: 'high', label: 'SQL injection', re: [
    /('|%27|")\s*(or|and)\s*('|%27|"|\d)/i, /\b(union)\b[\s/*]+(all\s+)?select\b/i, /\b(select|insert|update|delete)\b.{0,40}\b(from|into|set|where)\b/i,
    /\bsleep\s*\(\s*\d/i, /\bbenchmark\s*\(/i, /\bwaitfor\s+delay\b/i, /\binformation_schema\b/i, /(;|--|#)\s*(drop|alter|truncate)\b/i, /\bor\s+1\s*=\s*1\b/i, /'\s*--/,
  ] },
  { cls: 'nosqli', level: 'medium', label: 'NoSQL injection', re: [/\$(ne|gt|lt|gte|lte|regex|where|exists|in|nin)\b/, /\[\$(ne|gt|regex|where)\]/] },
  { cls: 'xss', level: 'medium', label: 'Cross-site scripting', re: [
    /<\s*script\b/i, /\bon(error|load|click|mouseover|focus|input)\s*=/i, /javascript\s*:/i, /<\s*(img|svg|iframe|object|embed|body)\b[^>]*\b(src|onload|onerror)\b/i, /\balert\s*\(|\bprompt\s*\(|document\.cookie/i,
  ] },
  { cls: 'ssti', level: 'high', label: 'Template injection', re: [/\{\{\s*[^}]*(\d+\s*[*+]\s*\d+|config|self|request|__class__|lipsum|cycler)[^}]*\}\}/i, /\$\{\s*\d+\s*[*+]\s*\d+\s*\}/, /<%=?\s*[^%]*%>/, /#\{\s*[^}]*\}/] },
  { cls: 'lfi', level: 'high', label: 'Path traversal / file include', re: [/(\.\.[\/\\]){2,}/, /(%2e%2e(%2f|%5c)){2,}/i, /\/etc\/(passwd|shadow|hosts)\b/i, /\bc:\\windows\\/i, /\/proc\/self\/(environ|cmdline)\b/i, /php:\/\/(filter|input)\b/i, /\bexpect:\/\//i] },
  { cls: 'cmdi', level: 'high', label: 'Command injection', re: [/(;|\||&&|\$\(|`)\s*(cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python|perl|powershell|cmd)\b/i, /\b(cat|ls|id|whoami|uname)\s*;\s*/i, /\$\{IFS\}/] },
  { cls: 'shell', level: 'critical', label: 'Reverse / web shell', re: [/\/dev\/tcp\//i, /\bnc\b.{0,20}\s-e\s/i, /\bbash\s+-i\b/i, /\bsocat\b.{0,30}\bexec\b/i, /<\?php\b/i, /\b(system|passthru|shell_exec|exec)\s*\(\s*\$_(get|post|request)\b/i, /\.(php[3-7]?|phtml|jsp|aspx?|cgi)\b.*(cmd|exec|shell)/i] },
  { cls: 'xxe', level: 'high', label: 'XML external entity', re: [/<!DOCTYPE[^>]*\[\s*<!ENTITY/i, /<!ENTITY\s+\w+\s+SYSTEM/i] },
  { cls: 'ssrf', level: 'high', label: 'Server-side request forgery', re: [/(^|[=\s"'])https?:\/\/(127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|\[::1\])/i, /\b(gopher|dict|file):\/\//i] },
  { cls: 'redirect', level: 'low', label: 'Open redirect probe', re: [/[?&](next|url|redirect|return|goto|dest|continue)=(https?:)?\/\/(?!127\.0\.0\.1)[a-z0-9.-]+/i] },
  { cls: 'deser', level: 'high', label: 'Deserialization payload', re: [/rO0AB/, /O:\d+:"[a-z_\\]+":\d+:\{/i, /\baced0005\b/i] },
  { cls: 'scanner', level: 'medium', label: 'Scanner / fuzzing tool', ua: /\b(sqlmap|nikto|nuclei|gobuster|dirbuster|dirb|ffuf|wfuzz|nmap|masscan|zgrab|acunetix|nessus|openvas|w3af|arachni|burpsuite|zap|hydra|python-requests\/|go-http-client|curl\/|wget\/)\b/i },
];

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

/**
 * classify({ url, bodyText, ua, referer }) -> [{ cls, level, label, where, sample }]
 */
function classify({ url, bodyText, ua, referer }) {
  const hits = [];
  const seen = new Set();
  const places = [
    ['url', decode(url)],
    ['body', decode(String(bodyText || '').slice(0, 8192))],
    ['referer', decode(referer)],
  ];
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

const LEVEL_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function worstLevel(hits) {
  return hits.reduce((w, h) => (LEVEL_RANK[h.level] > LEVEL_RANK[w] ? h.level : w), 'info');
}

module.exports = { classify, worstLevel, CLASSES, LEVEL_RANK };
