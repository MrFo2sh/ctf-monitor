# Security policy — CTF Watch

- Report issues privately to the maintainer before public disclosure.
- Supported: latest release only.
- This product is defensive tooling. It must never be modified to attack, evade detection, or
  harvest credentials.
- Secrets come only from environment variables listed in `.env.example`. Generated dashboard
  passwords are printed at start and optionally written to `logs/credentials.txt` (mode 600,
  `CREDENTIALS_FILE=0` disables it); `logs/`, `data/`, `.env` and `certs/` are never committed.
- Forwarded headers are trusted only from `TRUSTED_PROXIES`; the dashboard binds to loopback by
  default and should only be exposed with `TLS_CERT`/`TLS_KEY` set.
