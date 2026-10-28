# The login page — `proxy/public/login.html`

## Purpose

`login.html` is the only page of the dashboard that works without a session. `proxy/src/dashboard.js` serves it for `GET /login` (line 84) and redirects every other page request to it when the session cookie is missing or invalid (line 102). The page has one job: POST the username and password to `/api/login`, and on success send the browser to the view it originally wanted.

It is 48 lines: a small stylesheet (7–21), a form (24–31) and a 13-line script (32–46). It shares no code with `app.html`; the colours are copied literally rather than through CSS variables, so a theme change must be applied in both files.

## Markup

```html
<!-- lines 24-31 -->
<form id="f" autocomplete="off">
  <h1><i></i> CTF Watch</h1>
  <p>Organizer dashboard. The accounts are printed by <code>start.sh</code>.</p>
  <label for="u">Username</label><input id="u" name="username" autocomplete="username" autofocus required>
  <label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
  <button id="b" type="submit">Sign in</button>
  <div class="err" id="e"></div>
</form>
```

| Element | Role |
|---|---|
| `form#f` | The only form. `autocomplete="off"` at the form level, but the two inputs opt back in with `autocomplete="username"` / `"current-password"` so password managers still recognise the fields. There is no `action`: the script intercepts the submit. |
| `h1 i` | The green dot (lines 11–12), purely decorative; it mirrors the `#live` beacon of the dashboard but is static. |
| `input#u` (`name="username"`) | `autofocus`, `required`. Read in the script as `f.username` (form controls are reachable by `name` on the form element). |
| `input#p` (`name="password"`) | `type="password"`, `required`. |
| `button#b` | Submit button; disabled while a request is in flight. |
| `div#e` | The error line. Class `err` (yellow, line 19) for ordinary failures, `err crit` (red, line 20) for 409/403. `min-height:1.2em` keeps the layout from jumping when text appears. |

The `required` attributes give the browser's own validation: the submit event does not fire while a field is empty, so the script never sends empty credentials.

### Stylesheet (lines 7–21)

Centred card on the dark background (`body { display:flex; align-items:center; justify-content:center }`), card width `min(92vw, 360px)` so it fits phones, monospace inputs, a full-width blue button, `button:disabled { opacity:.6 }` as the busy indicator. `color-scheme: dark` (line 8) makes native controls and the autofill popup dark.

## Script

```js
// lines 33-45
const f = document.getElementById('f'), e = document.getElementById('e'), b = document.getElementById('b');
f.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  b.disabled = true; e.textContent = ''; e.className = 'err';
  try {
    const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'ctf-watch' }, body: JSON.stringify({ username: f.username.value.trim(), password: f.password.value }) });
    const j = await r.json().catch(() => ({}));
    if (r.ok) { location.href = new URLSearchParams(location.search).get('next') || '/'; return; }
    e.textContent = j.error || ('error ' + r.status);
    if (r.status === 409 || r.status === 403) e.className = 'err crit';
  } catch (err) { e.textContent = 'network error'; }
  b.disabled = false;
});
```

Line by line:

- **33** – the three elements the script touches. Unlike `app.html` there is no `$` helper and no IIFE; the three `const`s are globals of the page, which is harmless because nothing else runs here.
- **35** – `preventDefault()` stops the browser from submitting the form as `application/x-www-form-urlencoded` to the page's own URL. Everything goes through `fetch` instead, because the server only speaks JSON (`readJson`, dashboard.js 88).
- **36** – disable the button (prevents double submits and shows the busy state), clear any previous error and reset its class to the non-critical colour.
- **38** – the request. The body is JSON with the username trimmed and the password untouched (a password may legitimately start or end with a space). `X-Requested-With: ctf-watch` is the same CSRF header the dashboard uses; the login route itself does not require it (the server's header check at dashboard.js 110 runs after the session check, and `/api/login` is handled before that), but sending it keeps every `fetch` in the project uniform and costs nothing.
- **39** – parse the JSON body, tolerating an empty or non-JSON body (`{}`) so a 502 from a reverse proxy does not throw.
- **40** – success: the server has set the session cookie (`Set-Cookie: ctfw_sid=…`, dashboard.js 94); the page navigates to the `next` query parameter if present, otherwise to `/` (the live view). See the next section for where `next` comes from.
- **41** – failure: show the server's `error` text, or a generic `error <status>` when the body had none. The texts come from `auth.login` in `proxy/src/auth.js` (97–110): `401` "wrong username or password", `429` "too many attempts, try later", `403` "blocked", `409` "this account is already logged in from another place; the organizer has been alerted".
- **42** – 409 and 403 are escalated to the red `crit` style. 409 means the account already has a live session elsewhere (the "one session per account" rule mentioned on the CTFs tab, app.html 378); 403 is a blocked dashboard IP. Both mean "this is not a typo, something else is going on", which is why they are highlighted differently. A 401 (wrong password) or 429 (rate limited) stays yellow.
- **43** – a thrown `fetch` (server down, connection refused) becomes "network error".
- **44** – the button is re-enabled on every path except success (the `return` on line 40 skips it, which is fine because the page is navigating away).

Note that a 401 here is an ordinary wrong-password answer and is just displayed; it is `app.html`'s `api` helper, not this page, that treats 401 as "redirect to login".

## Interaction with `/api/login` and the `next` parameter

### The request

```
POST /api/login
Content-Type: application/json
X-Requested-With: ctf-watch

{"username":"admin","password":"…"}
```

The server (dashboard.js 85–96) reads at most 4 KB of body, calls `auth.login(username, password, ip)` and either answers with the status and `{error}` that `auth` reports, or with `200`, a `Set-Cookie` header carrying the session token (`Secure` is added when the request came in over HTTPS through a proxy, judged by `X-Forwarded-Proto`), and `{ok:true, account:{…}}`. The page ignores `account`; it only needs the cookie.

### Where `next` comes from

The page never builds the `next` parameter itself; it only consumes it. Two places produce it:

1. `app.html`'s `api` helper (app.html 523): when any API call answers 401, the dashboard sets `location.href = '/login?next=' + encodeURIComponent(location.pathname)`. So an organizer who was on `/queue` when the session expired comes back to `/queue` after signing in.
2. Nothing else. The server's own redirect for unauthenticated page loads (dashboard.js 102) is a plain `302 /login` without `next`, so opening `/alerts` in a fresh browser leads to `/` after login, not to `/alerts`. The WebSocket reconnect path in `app.html` (line 1211) also redirects to a bare `/login`.

`next` is used as-is: `location.href = next`. Because `app.html` only ever puts a path name there (never a full URL), and the value is read from the page's own query string, the practical risk of an open redirect is limited to whoever can craft a link to `/login?next=https://…` for an organizer; if that matters in your deployment, restrict it to values starting with `/` on line 40.

### After login

The browser follows `location.href`, requests the page, now with the `ctfw_sid` cookie, and `dashboard.js` serves `app.html`, whose boot sequence (`/api/me`, then the WebSocket) takes over. If `next` points at a path the server does not list in `PAGES` (dashboard.js 14), the result is a JSON 404, not the dashboard; this cannot happen from the dashboard's own redirects because they use `location.pathname` of a page that was already served.

## Changing it safely

- The two field names (`username`, `password`) are the JSON keys the server reads (dashboard.js 92); the ids (`u`, `p`) are only for the labels and the script.
- If you add a field (for example a one-time code), add it to the JSON body on line 38 and extend `auth.login`; keep the body under the 4 KB limit.
- Keep the `required` attributes: they are the only client-side validation.
- The page has its own copy of the colours; when you change the dashboard palette in `app.html` lines 10–12, update lines 9–20 here too.
- The same `node --check` idea from chapter 21 applies: extract lines 33–45 into a file and run `node --check` on it after editing.

## Exercises

1. **Show which account is signed in elsewhere.** On a 409 the server's `error` text already names the conflict; add a second line under the error that says "Ask the other organizer to log out, or wait" only when `r.status === 409`. Verify: sign in from two browsers with the same account; the second shows the red error and the hint, the first keeps working until it is kicked out.

2. **Restrict `next` to local paths.** Change line 40 so that `next` is only honoured when it starts with `/` and not with `//`; otherwise go to `/`. Verify: open `/login?next=/queue`, sign in: you land on the Queue tab; open `/login?next=https://example.com`, sign in: you land on `/`.

3. **Enter on the password field while the button is disabled.** Disable the button, then press Enter in the password field: the form still submits (implicit submission does not require an enabled button in all browsers). Guard the handler by returning early when `b.disabled` is true, and verify by throttling the network in the browser's devtools and pressing Enter twice: only one `/api/login` request appears in the Network tab.
