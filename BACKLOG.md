# Backlog — CTF Watch

Everything not yet done, one line each, most valuable first. The numbered issues in `ISSUES.md`
are all fixed; these are what remain.

- `admin.js` has no unit test; `store.js` and `replay.js` are only covered by running the stack.
- `macFor()` caches a `null` result forever, so a device that joins the LAN later is never resolved (`util.js`).
- `thresholds` in `rules.json` use `||` defaults, so `0` cannot be configured (`config.js`).
- `OPS_BY_TYPE.time` omits `in` although the compiler supports it; autocomplete never offers it (`query.js`).
- `maskObject` stops masking below six levels of nesting (`mask.js`).
- `gate.unrevoke()` / `gate.isRevoked()` are unused; the form handler deletes from `revoked` directly (`namegate.js`).
- Type-check gate is syntax-only (`checkJs` off): 37 JSDoc/inference findings to clean before turning it on.
- Biome formatter is off to avoid reformatting the tree in the adoption commit; turn it on in a format-only commit.
- Biome `noAssignInExpressions` is disabled (idiomatic `while ((m = re.exec(s)))` loops); decide per site.
