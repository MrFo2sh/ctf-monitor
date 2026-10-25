'use strict';
// Hides secrets. Anything whose NAME contains one of the configured words becomes "***".

const MASK = '***';

function isSensitive(name, fields) {
  const n = String(name).toLowerCase();
  return fields.some((f) => n.includes(f));
}

function maskObject(obj, fields, depth = 0) {
  if (obj == null || typeof obj !== 'object' || depth > 6) return obj;
  if (Array.isArray(obj)) return obj.map((v) => maskObject(v, fields, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (isSensitive(k, fields)) out[k] = MASK;
    else if (v && typeof v === 'object') out[k] = maskObject(v, fields, depth + 1);
    else out[k] = typeof v === 'string' && v.length > 200 ? v.slice(0, 200) + '...' : v;
  }
  return out;
}

function maskUrl(url, fields) {
  const q = url.indexOf('?');
  if (q < 0) return url;
  const path = url.slice(0, q);
  const params = new URLSearchParams(url.slice(q + 1));
  let changed = false;
  for (const k of [...params.keys()]) {
    if (isSensitive(k, fields)) {
      params.set(k, MASK);
      changed = true;
    }
  }
  return changed ? `${path}?${params.toString()}` : url;
}

// Mask raw JWT-looking strings and long hex blobs inside free text.
function maskText(text) {
  if (!text) return text;
  return String(text)
    .replace(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, '<jwt:***>')
    .replace(/\b[A-Fa-f0-9]{32,}\b/g, '<hex:***>');
}

module.exports = { maskObject, maskUrl, maskText, isSensitive, MASK };
