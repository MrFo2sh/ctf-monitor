# ctf-watch — notes for any coding agent

This project is a product of the **software factory** (repo `software-factory`, same author). The
factory is not cloned here on purpose: its ledger and ideas inbox live in one place. On the
author's machine the factory is at `D:\software-factory` and this folder is linked into it as
`products/ctf-watch` (a directory junction), so the factory CLI sees it as any other product.

Work on this project the factory way:

1. Read `SPEC.md` (what it is), `BACKLOG.md` (what is next), `ISSUES.md` (what was fixed and why).
2. Make one change at a time. After each, from the factory root:
   `node bin/factory.mjs check ctf-watch`
   It runs lint, typecheck, test, build (Docker image) and audit, logs to `.factory/logs/`, and
   prints PASS/FAIL. The commands it runs are in `factory.json`; they are the source of truth.
   Without the factory, the same gates are `npm --prefix proxy run lint|typecheck|test`.
3. The golden replay test (`proxy/test/golden.test.js`, 230 recorded exchanges) must not change
   unless the change intends it; then re-baseline with `node proxy/test/golden-rebaseline.js` and
   quote the reviewed diff in the commit.
4. Every bug fix gets a test. Config comes from `.env` (see `.env.example`), never hard-coded.
5. To release: bump `version` in `factory.json` and the tag in its `release` command, add the
   entry under `## Unreleased` in `CHANGELOG.md`, then `node bin/factory.mjs ship ctf-watch`.
   It commits and tags this repository; pushing is done by a human.

Hard rules: defensive tooling only. Never log or commit secrets (`logs/`, `data/`, `.env`,
`certs/` are ignored for that reason).

Verifying the dashboard: `proxy/tools/shot_dash.js` screenshots any view through headless Chrome
(log in with curl against `/api/login` first, pass the `ctfw_sid` cookie). It never touches the real
cursor; never drive the owner's mouse or keyboard. Gate pages and fonts are served by the proxy
under `/__ctfwatch/`; the dashboard serves `/fonts/`.
