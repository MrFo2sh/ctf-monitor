# CTF Watch

**One-liner:** Live SOC dashboard for web CTFs: a logging reverse proxy between zrok and the CTF app
that shows who is doing what, per student, as it happens.
**Blueprint:** api-service (adopted into the factory on 2026-10-28; vanilla Node 24, no framework)
**Date:** 2026-10-28

## Problem
An instructor running a web CTF for a class cannot see what students are doing: who is enumerating
ids, who found an IDOR, who is throwing injection payloads, who is stuck. Logs on the CTF container
are raw and the CTF itself must not be touched.

## MVP (shipped as 1.0.0)
1. Reverse proxy in front of the CTF container; every request recorded (SQLite), nothing changed for students.
2. Identity per student (gate name, id/email, app username, MAC; ip shown but never trusted to merge people).
3. Detectors: IDOR attempts and successes, enumeration, brute force, error bursts, web attacks
   (SQLi, XSS, SSTI, traversal, shells, scanners) with info-level tagging for plain scripting tools.
4. Dashboard with login (admin + N user accounts generated per start): Live, triage, investigate,
   query language with autocomplete, actions (block, rename, acknowledge, import, replay), CTFs tab.
5. Playground: fake CTF app plus nine fake student personas to rehearse before the event.
6. Hardening: trusted-proxy list for forwarded headers, masked secrets in samples, optional HTTPS,
   flush retry on database errors, one session per account with alert and block on reuse.

## Not in MVP
See `BACKLOG.md`.

## Interfaces
- Proxy on `PROXY_PORT` (default 8888); dashboard on `DASHBOARD_PORT` (default 8080), `/healthz`.
- `start.sh`, `stop.sh`, `inspect.sh`; `docker compose up`.
- Operator docs in `docs/`, developer docs per module in `dev_docs/`.

## Data
SQLite under `data/` (ctfs, players, requests, alerts, accounts); logs under `logs/`; rules in
`config/rules.json`. Both folders are volumes and ignored by git.

## Risks
Node's SQLite module is still experimental (warning on every run); pinned to Node 24 in the image.

## Done when
- `node bin/factory.mjs check ctf-watch` passes: Biome lint, tsc syntax check, 58 tests including
  the golden replay, Docker image build, npm audit.
- A fresh clone runs with `./start.sh` and the Playground produces alerts on the Live tab.
