# Changelog

## Unreleased

## 1.3.5 - 2026-10-29
- Queue decisions last for one event. Starting a new CTF record or switching the queue on clears every approval and block, so students go through the queue again; before, an approval from an earlier event let the same name straight in. The Queue tab has a "⟲ Reset queue" button for doing it by hand (`POST /api/queue/clear`).

## 1.3.4 - 2026-10-28
- Query editor: autocomplete and the partial-word detection now work after a quoted value (`student = "Fo2sh" and status > 200` offers AND/OR, fields, operators and values at every step). The context logic moved into the shared query module (`contextAt`) with a test. Ctrl+Space always opens suggestions; the hint line says so.

## 1.3.3 - 2026-10-28
- Strict gate: a tool without the cookie coming from an address where exactly one student already filled the form passes as that student (curl, wget and scripts from the same machine after the browser signed in). Unknown and shared addresses are still refused and recorded. Browsers without the cookie still get the form.

## 1.3.2 - 2026-10-28
- Clicking a student selects exactly that student; the case-insensitive match is now only a fallback for typed searches (clicking "Fo2sh" used to select "fo2sh").
- A gate name that differs only in case from a student already seen keeps the known spelling, so one person does not get two lanes.

## 1.3.1 - 2026-10-28
- Requests the gate turns away (strict mode, pending approval, rejected name) are recorded as `gate-refused` requests with status 428 and the client's user agent, so a student's card lists the tools they tried (curl, wget, scripts) even though nothing reached the CTF. Before, such attempts were invisible.

## 1.3.0 - 2026-10-28
- CTFs tab: select one or many event records and delete them (admin only, with a confirmation that lists them). Requests and alerts of those CTFs are removed in one transaction; the active CTF and a CTF being replayed are refused. `POST /api/ctfs/delete { ids }`.

## 1.2.1 - 2026-10-28
- The student-facing gate pages (form, waiting page, blocked page) wear the same phosphor theme as the dashboard. The proxy serves the two fonts itself under `/__ctfwatch/fonts/`, so students need no internet access; the Gate tab's live preview loads them through the dashboard.

## 1.2.0 - 2026-10-28
- Every view shares one header anatomy: `> TITLE`, a one-line subtitle, filters, a count, small action buttons and the open-in-tab button.
- All 105 inline styles in the dashboard markup replaced by a small utility vocabulary (`row`, `hint`, `count`, `w-s/m/l`, `badge on/off/warn/notice`, swatches), so cards, forms, help text and sub-headings look the same on every page.
- State badges (gate, decoy, mock app, fake students) set a class instead of a colour; search boxes share one width and placeholder shape; checkbox chips are labels everywhere.

## 1.1.0 - 2026-10-28
- Phosphor theme: the dashboard and login page now wear an 8-bit green-screen look (VT323 and Press Start 2P, self-hosted under `/fonts`, CRT scanlines and vignette, pixel-shadow buttons, glowing accents). Severity colours keep their meaning: amber 4xx, violet enumeration, orange attacks, red IDOR success.
- Login page shows a short boot banner; reduced-motion users get no blinking or pulsing.
- Fonts are served by the dashboard itself, so the look does not depend on internet access.

## 1.0.0 - 2026-10-28
- First tagged release, adopted into the software factory.
- Gates: Biome lint, tsc syntax check, 58 node tests with the golden replay fixture, Docker image build, npm audit; CI workflow runs the same steps.
- The ten issues in `ISSUES.md` are fixed: trusted proxies for forwarded headers, no ip-only merging of players, flush retry, transactional import, whole-word rename everywhere, scanner vs tool classes, query scope, masked attack samples, credentials file opt-out, optional HTTPS.
