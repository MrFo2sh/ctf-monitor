# Changelog

## Unreleased

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
