# The dashboard app — `proxy/public/app.html`

## Purpose

`app.html` is the whole organizer dashboard: one HTML file, 1230 lines, served unchanged by `proxy/src/dashboard.js` for every page path (`/`, `/live`, `/requests`, `/alerts`, `/students`, `/students/<name>`, `/query`, `/ctfs`, `/queue`, `/gate`, `/playground`). It contains:

- a stylesheet (lines 7–140),
- the markup of nine views plus the header, all present in the DOM at once (lines 143–499),
- one script (lines 502–1228) that talks to the JSON API, keeps a WebSocket open to `/ws`, and renders everything with `innerHTML` and small DOM updates.

There is no framework, no build step and no module system. The only external script is `/query.js` (line 501), which is the server's query parser (`proxy/src/query.js`) served to the browser so that the Query view can lint and autocomplete without a round trip. Everything else is plain DOM code wrapped in one IIFE, so nothing leaks into `window` except what `/query.js` puts there (`window.CtfQuery`).

The reader this chapter is written for knows JavaScript and the DOM but not this file. After reading it you should be able to find any behaviour by line number, know which state object drives it, and change it without breaking the other views.

## How the page is organised

### The three parts

| Lines | Part | What it holds |
|---|---|---|
| 1–6 | head | `<html data-theme="dark">`, charset, viewport, title `CTF Watch`. |
| 7–140 | `<style>` | One stylesheet. Groups are separated by `/* ---- ... ---- */` comments (header/tabs, query editor, requests view, live view). |
| 143–162 | `<header>` | Brand with the connection beacon, the nav tabs, four KPI counters, the user/target badges and Logout. |
| 163–498 | `<main>` | Nine `<section class="view" id="view-…">` blocks, one per tab. |
| 499 | `#tip` | The floating tooltip used by the live-view dots. |
| 501 | `<script src="/query.js">` | The shared query parser; exposes `window.CtfQuery`. |
| 502–1228 | `<script>` | The dashboard logic, in `// ----------` sections. |

### The views and their ids

Each tab is a `<section class="view" id="view-NAME">`. The `NAME` is the same string that appears in the nav button's `data-view`, in the URL path and in the `VIEWS` array of the script (line 531). Keeping those four in sync is the whole routing contract.

| View | Section id | Nav button (lines 146–154) | URL |
|---|---|---|---|
| live | `view-live` (166) | `data-view="live"` | `/` (also `/live`) |
| requests | `view-requests` (232) | `data-view="requests"` | `/requests` (`?student=` supported) |
| alerts | `view-alerts` (255) | `data-view="alerts"` + badge `#nav-alerts` | `/alerts` |
| students | `view-students` (270) | `data-view="students"` | `/students`, `/students/<name>` |
| query | `view-query` (285) | `data-view="query"` | `/query` |
| ctfs | `view-ctfs` (322) | `data-view="ctfs"` | `/ctfs` |
| queue | `view-queue` (383) | `data-view="queue"` + badge `#nav-queue` | `/queue` |
| gate | `view-gate` (399) | `data-view="gate"` + badge `#nav-gate` | `/gate` |
| playground | `view-playground` (452) | `data-view="playground"` + badge `#nav-mock` | `/playground` |

### The header and nav

```html
<!-- lines 143-162 (abridged) -->
<header>
  <div class="brand"><span class="live" id="live"></span> CTF Watch
    <span class="badge demo hidden" id="demo-badge">MOCK TRAFFIC</span><span class="badge replay hidden" id="replay-badge">REPLAY</span></div>
  <nav id="nav"> ...nine <button data-view="…"> ... </nav>
  <div class="spacer"></div>
  <div class="kpi"><b id="k-rps">0.0</b><span>req/s</span></div>
  <div class="kpi"><b id="k-total">0</b><span>requests</span></div>
  <div class="kpi"><b id="k-students">0</b><span>students</span></div>
  <div class="kpi"><b id="k-alerts" style="color:var(--critical)">0</b><span>open alerts</span></div>
  <div class="who"><span id="ctf-name" class="badge"></span><span id="target-badge" class="badge"></span><span id="me"></span><button class="small" id="logout">Logout</button></div>
</header>
```

- `#live` gets class `on` / `off` from the WebSocket `onopen`/`onclose` handlers (lines 1210–1211). It is the only visible sign that the feed is alive.
- `#demo-badge` is shown while the fake students are running (`m.mock.sim`, line 1192). `#replay-badge` is driven by `renderReplay` (1083).
- The four `kpi` numbers are overwritten once a second by `renderStats` (line 628–629) from the `stats` WebSocket message.
- `#ctf-name` is set at boot from `/api/me` (1219) and refreshed by `loadCtfs` (1070). `#target-badge` is set by `renderTarget` (988).
- `#me` shows `username (role)` (1219). `#logout` POSTs `/api/logout` and goes to `/login` (554).

### How a view is shown

Every section is `position:absolute; inset:0; display:none` (line 42). `showView(v)` (537) toggles class `on` on exactly one section and on exactly one nav button. Because all sections stay in the DOM, state like a half-typed query or a selected request survives switching tabs. The cost is that every view's elements must exist before the script runs, which is why the script is at the very end of `<body>`.

### Routing by URL path

The server returns the same file for all page paths; the browser picks the initial view from `location.pathname` (`viewFromPath`, line 532). Clicking a tab calls `history.pushState` so the address bar follows; the Back button triggers `popstate` (552), which calls `showView` again without pushing. `/students/<name>` is special: it is still the `students` view but boot also opens the detail panel for that name (1224). `/requests?student=x` pre-fills the student filter of the Requests view (732–733).

### The "open in new tab" buttons

Every view header has `<button class="small" data-open="/path">↗</button>`. One document-level listener (line 553) handles all of them: `window.open(b.dataset.open, '_blank')`. The same mechanism is reused inside generated markup, for example the per-student `↗` in the Students table (`data-open="/students/<name>"`, line 822), so the handler must stay delegated to `document`, not attached per button.

## CSS

The stylesheet is dense: most rules are on one line, several selectors per line. Below it is walked group by group. For each class the script code that adds or removes it is named, because that is what you need when a style "does not apply".

### Tokens and theme (lines 8–28)

```css
/* lines 8-14 (abridged) */
:root {
  color-scheme: dark;
  --bg:#0b0f14; --panel:#111820; --panel-2:#0e141b; --border:#1f2a36; --text:#e6edf3; --muted:#8b98a5; --faint:#5b6774;
  --accent:#3987e5; --ok:#3987e5; --redirect:#6da7ec; --notice:#fab219; --server:#8b98a5; --warn:#9085e9; --high:#ec835a; --critical:#d03b3b; --good:#0ca30c;
  --l-info:#5b6774; --l-low:#fab219; --l-medium:#9085e9; --l-high:#ec835a; --l-critical:#d03b3b;
  --mono: ui-monospace,"JetBrains Mono",...; --sans: Inter,system-ui,...;
}
```

- The page is dark only (`data-theme="dark"` on `<html>`, `color-scheme: dark`). There is no light theme; the variables exist so colours are named, not so they can be swapped.
- Two colour families: request severity (`--ok`, `--redirect`, `--notice` for 4xx, `--server` for 5xx, `--warn`, `--high`, `--critical`) and alert level (`--l-info` … `--l-critical`). `sevClass` (558) maps an event to one of the first family; alert markup uses the second through `.lvl.<level>`.
- Line 16: `body { overflow:hidden; display:flex; flex-direction:column }` — the page never scrolls as a whole; each view scrolls inside `main`. The responsive rule at line 139 reverts this on narrow screens.
- Lines 18–22: base look of form controls. `button.paused` (yellow) is toggled by the two Pause buttons (721, 749); `button.danger` (red) is set on destructive buttons both in markup and from the script (`updateActions` 695 toggles it on `#btn-block`); `button.small`; `button.primary` is the blue filled style (Run, Save, Approve selected).
- Line 23–24: `.badge` is the small bordered label used in the header. `.badge.demo` and `.badge.replay` colour the two header badges.
- Lines 25–27: `.lvl.<level>` is the alert-level pill. `critical` is filled, the rest are outlined. Generated wherever an alert level is printed (feed 621, chips 801, table 812) and reused for status words in the Queue (`lvl low/info/critical`, 1135) and for the `current`/`decoy`/`active`/`imported` markers (1016, 1061).
- Line 28: `.hidden { display:none !important }` — the universal show/hide switch. Almost every `classList.toggle('hidden', cond)` in the script relies on it. The `!important` is deliberate: it must win over `.view.on`, `.lane` grid, etc.

### Header and tabs (lines 30–39)

- `header` wraps (`flex-wrap:wrap`) so on narrow screens the KPIs drop to a second line.
- `.live`, `.live.on` (green with the `beacon` animation of line 136), `.live.off` (red). The same class is reused inline in the Students table (822) as an online indicator with `animation:none`.
- `nav button.on` is the active tab (set in `showView`, 540). `nav button .cnt` is the red counter bubble; the Queue/Gate/Playground bubbles override its colour inline in the markup (152–154). `#nav-alerts` is filled by `renderStats` (629), `#nav-queue` by `renderQueue`/`queueUpdate`/`handleMessage` (1141, 1144, 1194), `#nav-gate` shows "off" when the gate is disabled (1193), `#nav-mock` shows a dot when the mock app or simulator runs (1192).
- `.kpi` big mono number + small uppercase label. `.who` is the right-hand cluster.

### Views, tables, badges (lines 41–66)

- `main { flex:1; min-height:0; position:relative }` and `.view { position:absolute; inset:0; display:none; overflow:auto }` / `.view.on { display:block }` — the view-switch mechanism described above.
- `.view-head` is sticky at `top:0` inside the scrolling view, so filters stay visible while a long table scrolls. `th` is also sticky (line 47); in the Requests view the `th` offset is 41px (line 86) to sit under the sticky head.
- `td` truncates with ellipsis at 420px; `td.wrap` allows wrapping (used for alert messages, attack samples and user agents).
- Row tints: `tr.sev-critical`, `tr.sev-high`, `tr.sev-warn` are produced by `sevClass` (558) on live/requests rows and by inline checks in the Students detail, Query results and Queue (`sev-warn` = pending, `sev-critical` = blocked, 1133). `tr.ack` dims acknowledged alerts (812). `tr.clickable` is the Students table row (822).
- `.st.s2/.s3/.s4/.s5` is the status badge; `statusBadge` (613) builds `s` + first digit of the code.
- `.flag.<name>` are the per-request flags from `flagsHtml` (614): `idor-success`, `idor-attempt`, `enumeration`, `burst-errors`, `blocked`, plus `attack` for detected payload classes and `decoy`.
- `.chip` / `.chip.on` is the toggle pill used for the alert level filter (801), queue status filter (1129), the "unacknowledged only" and "online only" checkboxes, and the gate checkboxes.
- `.card`, `.card.wide` (spans two columns above 1100px), `.card h3`, `.grid2` (two-column key/value grid, class `k`/`v`), `.cols` (auto-fit column grid used by the CTFs, Gate, Playground views and the student detail), `.empty` (the "waiting for traffic" placeholder, `#empty`, hidden by `lane()` at 567).

### Query editor overlay (lines 67–82)

```css
/* lines 68-73 */
.qed { position:relative; font:13px/1.5 var(--mono) }
.qed textarea.q, .qed .qhl { margin:0; width:100%; min-height:64px; padding:8px 10px; font:inherit; box-sizing:border-box; white-space:pre-wrap; overflow-wrap:anywhere; tab-size:4 }
.qed textarea.q { position:relative; background:transparent; color:transparent; caret-color:var(--text); resize:vertical; z-index:1 }
.qed textarea.q::placeholder { color:var(--faint) }
.qed .qhl { position:absolute; inset:0; pointer-events:none; color:var(--text); background:var(--panel-2); border:1px solid var(--border); border-radius:4px; overflow:hidden }
.qed.bad .qhl { border-color:var(--critical) }
```

This is the standard "transparent textarea over a highlighted mirror" technique. The `<textarea id="q">` is what the user types into; its text is `transparent` but the caret is visible. Underneath (absolute, `pointer-events:none`) sits `<pre id="q-hl">` that `qRender` (866) fills with the same text wrapped in coloured spans. Both elements share identical font, padding, wrapping and `tab-size`, so the glyphs line up exactly. `qta` scrolling is mirrored to `qhl` on line 947. `.qed.bad` (red border) is toggled by `qRender` at 884 when the query does not validate.

- Token colours `.qhl .tf/.to/.ts/.tn/.tk/.tp` (field, operator, string, number, keyword, punctuation) and `.terr` (wavy underline + red tint) are assigned by `classFor` (874).
- `.qlint`, `.qlint.err`, `.qlint.ok` is the one-line verdict under the editor (885–887).
- `.qac` is the autocomplete dropdown, absolutely positioned under the editor; `.qac div.on` is the highlighted item (`ac.idx`, 953). It is shown/hidden by `qSuggest`/`qAcHide`.
- `.qhist span` are the clickable history pills (960); `pre.sql` the generated SQL (971); `.ex` the example queries in the markup (307–311).

### Requests view grid (lines 84–92)

- `#rq-grid` is an absolute two-column grid: the table (`#rq-main`) and a 400px sidebar (`#rq-side`). Both scroll independently.
- `#rq-rows tr.sel` highlights the selected request with a left accent bar; the class is set in the row click handler (751).
- `.kv` is the key/value grid used by `requestDetailHtml` (758); `.kv .v.path` colours the path yellow. `pre.body` is the masked request body box (760).
- Below 1000px the grid becomes a single column.

### Live view: lanes, dots, animations (lines 94–139)

- `#live-grid` is a two-column, two-row grid: lanes top-left, `#table-wrap` (recent requests) bottom-left, `aside` spanning both rows on the right.
- `#table-wrap` has three heights: default 190px, `.collapsed` 28px (just the heading), `.expanded` 60vh. The classes are toggled by `#table-toggle` (722) and `#table-expand` (723).
- `.lane` is one student row: a 210px head and a flexible body. `.lane.flash` is the red flash on a critical event, added for 1.8 s in `addDot` (596). `.lane.blocked` dims the lane and reveals the `.blk` "BLOCKED" tag (line 106); it is toggled in `renderStats` (650) from the server's per-student `blocked` flag.
- `.lane-head .name` holds the colour swatch `.av` (from `colorFor`), the clickable name `.nm` (selects the student, 573), the `.blk` tag, the `.dcb` decoy marker (hidden unless the student is on the decoy list, 651 and 1039) and `.src` (how the student was identified, 650).
- `.lane-head .counts` with `.c-req`, `.c-high`, `.c-crit` are the three counters updated on every event (584).
- `.track { flex-direction:row-reverse }` is the dot strip. Newest dot is prepended (590) and, because the row is reversed, appears at the right edge and pushes older dots left. The `overflow:hidden` plus `MAX_DOTS` (70) keep it bounded.
- `.dot` with `.sev-*` colours; `.dot.m-post` is square for non-GET methods (588); `.pulse-high` / `.pulse-crit` add the expanding ring animations (589) and `pop` is the appear animation; when drawing a snapshot `animate` is false and the script sets `style.animation='none'` (589) to avoid 500 dots popping at once.
- `.seqrow`, `.seq` with `.ep` (endpoint), `.id`, `.id.last` (the newest id, yellow), `.arrow`, `.tag` (`enumerating (n ids)` / `not theirs`) are filled in `addDot` (593–594). `.atk`/`.atkb` hold the attack-class badges (`attackBadges`, 513).
- `.panel` is a sidebar block; `.search-box`, `.slist` (student list), `.slist li.sel` (selected), `.slist li.online .nm::after` (green dot), `.slist li.blk .nm` (strike-through) are set in `renderStudentList` (673).
- `#student-card`, `.sc-name`, `#student-actions` are the selected-student card (`updateActions`, 692).
- `#alerts` and `.alert.<level>` form the feed (`addFeedAlert`, 617). `slide` is its appear animation.
- `.stat-row`, `canvas#spark`, `.bar`, `.bar-legend`, `.list li .w::after` (the proportional underline driven by the CSS variable `--w`, set inline in `renderStats` 641/643 and in the card helpers 689–691), `.lb` leaderboard styles (`renderStats`, 645–647).
- `#tip` is the fixed tooltip (788–796). `.legend` is the colour legend in the live header; hidden below 1300px.
- Keyframes `pop`, `slide`, `beacon`, `pulse-high`, `pulse-crit` (135–137).

### Responsive rules

- Line 59: `.card.wide` spans two columns only above 1100px.
- Line 92: Requests view collapses to one column below 1000px.
- Line 138: the legend disappears below 1300px.
- Line 139: below 1000px the body scrolls normally, the live grid and views become static (stacked), the sidebar moves under the lanes, and each lane becomes a single column.

## Markup, view by view

### Live (lines 166–229)

| Element | Filled by |
|---|---|
| `#lanes` (section) | `lane()` appends one `.lane` per student (572); `sortLanes` reorders them (603). Its first two children are the sticky head and `#empty`. |
| `#sort` select | `state.sort` (720). |
| `#pause` | toggles `state.paused` (721). |
| `#empty` | hidden by the first `lane()` call (567). |
| `#students-count` | `renderStudentList` (665). |
| `#filter` input + `#students-list` datalist + `#filter-clear` | student search; options added by `addFilterOption` (662). The datalist is shared with `#rq-student` and `#dc-add`. |
| `#slist` | `renderStudentList` (663). |
| `#student-card` with `#sc-close`, `#sc-av`, `#sc-nm`, `#sc-blocked`, `#student-actions` (`#btn-detail`, `#btn-block`, `#btn-ask-rename`, `#btn-rename`, `#btn-decoy`), `#sc-grid`, `#sc-ips`, `#sc-uas`, `#sc-att-box`, `#sc-attacks` | `updateActions` (692). The four admin buttons carry `admin-only`. |
| `#alerts`, `#alerts-count` | `addFeedAlert` (617), `renderStats` (630). |
| `#uptime`, `#s-rps`, `#spark`, `#status-bar`, `#status-legend`, `#top-endpoints`, `#attack-classes` | `renderStats` (631–643). |
| `#lb-first`, `#lb-idor`, `#lb-ids`, `#lb-failed`, `#lb-attacks` | `renderStats` (645–647). |
| `#table-wrap` with `#table-toggle`, `#table-hint`, `#table-search`, `#table-expand`, `#table-newtab`, `#rows` | `addRow` (605) fills `#rows`; the controls are wired at 719–725. |

### Requests (lines 232–252)

| Element | Filled by |
|---|---|
| `#rq-search`, `#rq-student` (uses the shared datalist), `#rq-count` | filters (746–747), count (744). |
| `#rq-pause`, `#rq-clear` | 749, 748. |
| `#rq-rows` | `rqAddRow` (735). Row click selects (751). |
| `#rq-req` | `requestDetailHtml` via `rqRenderSide` (764). |
| `#rq-card` | student card for the selected request's student (768); its buttons use `data-act` (775). |

### Alerts (lines 255–267)

`#lvl-chips` (level filter, `renderLevelChips` 799), `#al-search`, `#al-unacked` / `#al-unacked-cb`, `#al-ack-all`, `#al-refresh`, `#al-rows` (`renderAlertsTable` 809; the `✓ ack` buttons are handled at 814).

### Students (lines 270–282)

`#su-search`, `#su-online` / `#su-online-cb`, `#su-list` (wrapper, hidden while a detail is open), `#su-rows` (`renderStudentsTable` 818), `#su-detail` (`openStudentDetail` 825; it creates `#su-back` and, for admins, `#sd-block` dynamically).

### Query (lines 285–319)

`#qed` (the overlay container; gets `.bad`), `#q-hl` (mirror), `#q` (textarea), `#q-ac` (autocomplete), `#q-lint`, `#q-run`, `#q-limit`, `#q-ctf` (`loadCtfOptions` 984), `#q-json`, `#q-csv`, `#q-info`, the `.ex` example spans, `#q-hist`, `#q-sql`, `#q-err`, `#q-rows` (`runQuery` 972).

### CTFs (lines 322–381)

Target card `#target-card`: `#tg-scan`, `#tg-link`, `#tg-copy`, `#tg-link-note` (`renderLink` 994), `#tg-current`, `#tg-disconnect` (`renderTarget` 987), `#tg-rows` (`scanTargets` 1004; buttons `.tg-use` and `.tg-decoy`), `#tg-manual`, `#tg-use-manual`.

Decoy card `#decoy-card`: `#dc-state`, `#dc-url`, `#dc-set`, `#dc-clear`, `#dc-note`, `#dc-list` (chips with `.dc-rm`), `#dc-add` (shared datalist), `#dc-add-btn` (`renderDecoy` 1032).

Events card: `#ctf-stop`, `#ctf-new`, `#ctf-rows` (`loadCtfs` 1061; per row an export link, a `.replay` button and a `.spd` select), `#ctf-import` (file input inside a chip label), `#replay-status`, `#replay-stop` (`renderReplay` 1083).

Blocked card: `#adm-blocked` (`.unb` buttons), `#adm-ips` (`.unbip` buttons), `#adm-pending` (`loadCtfs` 1064–1066).

Session card: `#adm-me` (`loadCtfs` 1068).

### Queue (lines 383–396)

`#qu-chips` (status filter), `#qu-search`, `#qu-selinfo`, `#qu-approve-sel`, `#qu-block-sel`, `#qu-off` (shown when the queue is disabled), `#qu-head` (built dynamically because the gate's extra fields become columns; contains `#qu-all`), `#qu-rows` (`renderQueue` 1126; checkboxes `.qu-cb`, buttons `.qu-act[data-act]`).

### Gate (lines 399–449)

`#gt-state`, checkboxes `#gt-enabled`, `#gt-strict`, `#gt-queue`, text inputs `#gt-title`, `#gt-intro`, `#gt-button`, `#gt-wait-title`, `#gt-wait-text`, `#gt-fields` (table body built by `renderGate` 1100; its inputs carry `data-i` and `data-k`), the add-field row `#gt-new-key`, `#gt-new-label`, `#gt-new-type`, `#gt-new-req`, `#gt-add`, then `#gt-save`, `#gt-preview`, `#gt-reset`, `#gt-msg`, `#gt-readonly` (shown to non-admins), and the preview `<iframe id="gt-frame">`.

### Playground (lines 452–497)

`#pg-quick`, `#pg-stop-all`; mock app card: `#pg-mock-state`, `#pg-mock-port`, `#pg-mock-start`, `#pg-mock-stop`, `#pg-mock-use`, `#pg-mock-info`, `#pg-mock-log`; fake students card: `#pg-sim-state`, `#pg-honest`, `#pg-enumerator`, `#pg-sniper`, `#pg-noisy`, `#pg-anonymous`, `#pg-attacker`, `#pg-pace`, `#pg-rounds`, `#pg-loop`, `#pg-target`, `#pg-sim-start`, `#pg-sim-stop`, `#pg-sim-info`, `#pg-sim-log` (`renderPlayground` 1159, `simConfig` 1155).

## Script walkthrough

The script is one IIFE: `(() => { ... })();` (lines 503 and 1227). Every `const`/`function` inside is private. Functions are hoisted, so sections can call functions defined later (for example `showView` calls `loadCtfs`, defined at 1058). `const` bindings are not hoisted, which is why every section that defines a `const` object (`rq`, `dc`, `qu`, `ac`) places it before the code that uses it, and why `handleMessage` and boot come last.

### Helpers (lines 504–518)

```js
// lines 504-515
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmtTime = (ts) => (ts ? new Date(ts).toLocaleTimeString([], { hour12: false }) : '–');
const fmtDate = (ts) => (ts ? new Date(ts).toLocaleString([], { hour12: false }) : '–');
const palette = ['#3987e5','#d95926','#199e70','#c98500','#d55181','#008300','#9085e9','#e66767'];
const colorFor = (name) => { let h = 0; for (const c of name) h = (h * 31 + c.charCodeAt(0)) >>> 0; return palette[h % palette.length]; };
const ICON = { 'idor-success': '🚨', 'idor-attempt': '⚠️', enumeration: '🔁', 'burst-errors': '💥', 'web-attack': '🧨', 'admin-login-conflict': '🔐', 'new-student': '👤' };
// 950 -> "950", 1000 -> "1k", 1150 -> "1.1k", 12340 -> "12.3k", 1500000 -> "1.5m"
const fmtCount = (n) => { n = Number(n) || 0; if (n < 1000) return String(n); const u = n >= 1e6 ? [1e6, 'm'] : [1e3, 'k']; const v = n / u[0]; return (v >= 100 ? Math.round(v) : Math.round(v * 10) / 10) + u[1]; };
const attackBadges = (attacks) => Object.entries(attacks || {}).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]).map(([c, n]) => `<span class="atkb"><span class="flag attack">${esc(c)}</span><b>${fmtCount(n)}</b></span>`).join('');
const LEVELS = ['critical', 'high', 'medium', 'low', 'info'];
const MAX_DOTS = 70, MAX_ROWS = 80, MAX_ALERT_DOM = 120;
```

- `$` is the only element lookup used. `esc` is the HTML escaper and is applied to every server-supplied string inserted via `innerHTML` (student names, paths, user agents, attack samples). It escapes `&<>"` — enough for text nodes and double-quoted attributes. If you ever write a value into a single-quoted attribute, `esc` is not enough; the file never does that.
- `fmtTime` is `HH:MM:SS` in the browser locale, `fmtDate` adds the date. Both return an en dash for a missing timestamp.
- `colorFor` hashes a name (`h*31 + charCode`, forced unsigned with `>>> 0`) into one of eight colours. The same name always gets the same colour in lanes, lists and cards, and the server is not involved.
- `ICON` maps alert `type` strings (as the server produces them) to an emoji; unknown types fall back to `•` (621, 812).
- `fmtCount` abbreviates large numbers for the tight lane counters; the comment shows the rounding rule (one decimal below 100, none above).
- `attackBadges` turns `{ sqli: 3, xss: 1 }` into badge markup, dropping zero counts, highest first.
- `LEVELS` is the alert-level order used by the chips; `MAX_DOTS`, `MAX_ROWS`, `MAX_ALERT_DOM` bound the three live-view DOM lists so memory does not grow during a long event.

```js
// lines 517-518
const state = { me: null, view: 'live', paused: false, buffer: [], filter: '', query: '', tableQuery: '', sort: 'activity', lanes: new Map(), stats: null,
  alerts: [], alertFilter: { levels: new Set(LEVELS), text: '', unacked: false }, serverStart: null, ctfs: [] };
```

The central state object. All fields are listed in the [State](#state) section. Note that `filter` (an exact student name) and `query` (a partial, lower-cased text) are mutually exclusive: `setStudentQuery` (710) sets one and clears the other.

### api / tryApi (lines 521–528)

```js
// lines 521-528
async function api(path, body, method) {
  const r = await fetch(path, { method: method || (body ? 'POST' : 'GET'), headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'ctf-watch' }, body: body ? JSON.stringify(body) : undefined });
  if (r.status === 401) { location.href = '/login?next=' + encodeURIComponent(location.pathname); throw new Error('login required'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ('error ' + r.status));
  return j;
}
const tryApi = (p, b, m) => api(p, b, m).catch((e) => { alert(e.message); return null; });
```

- One function for every API call. Passing a `body` makes it a POST; `method` can override. The body is always JSON.
- `X-Requested-With: ctf-watch` is the CSRF token. `dashboard.js` line 110 rejects every `POST /api/*` without it (403 "missing X-Requested-With header"). A cross-site form cannot set custom headers, which is the whole protection. If you add a `fetch` call anywhere else (the WebSocket reconnect check at 1211 and `login.html` do), you must add the header too.
- 401 means the session cookie is gone (server restart regenerates accounts, or logout elsewhere). The page navigates to `/login?next=<current path>` so that after login the user lands back on the same view. The `throw` stops the caller from continuing with an empty object.
- Non-OK responses become an `Error` carrying the server's `error` field.
- `tryApi` is the "show an alert box and give up" wrapper. Most UI handlers use it and check for `null`. `api` is used directly where the caller wants to handle the error itself (`runQuery` 967 shows it in `#q-err`; boot 1218 silently returns; `dbValues` 861 falls back to an empty list).

### Routing (lines 531–554)

```js
// lines 531-550
const VIEWS = ['live', 'requests', 'alerts', 'students', 'query', 'ctfs', 'queue', 'gate', 'playground'];
function viewFromPath(p) {
  if (p.startsWith('/students')) return 'students';
  const v = p.replace(/^\//, '');
  return VIEWS.includes(v) ? v : 'live';
}
function showView(v, push) {
  state.view = v;
  for (const x of VIEWS) $('view-' + x).classList.toggle('on', x === v);
  for (const b of $('nav').children) b.classList.toggle('on', b.dataset.view === v);
  if (push) history.pushState(null, '', '/' + (v === 'live' ? '' : v));
  if (v === 'requests') { rqApplyFilter(); }
  if (v === 'alerts') loadAlerts();
  if (v === 'students') renderStudentsTable();
  if (v === 'ctfs') { loadCtfs(); loadDecoy().then(scanTargets); }
  if (v === 'query') loadCtfOptions();
  if (v === 'playground') loadPlayground();
  if (v === 'gate') loadGate();
  if (v === 'queue') loadQueue();
}
```

- `viewFromPath('/students/alice')` returns `students` (prefix match); any unknown path (including `/admin`, which the server still serves) falls back to `live`. `/live` and `/` both give `live`.
- `showView` does three things: mark the section and button, update the URL if `push` is set (the live view is `/`, not `/live`), then run the view's "on enter" loader. The loaders are what make each tab fresh when opened: alerts and CTFs are re-fetched, the requests filter is re-applied (rows may have been added while hidden, and `rqCount` is skipped while the view is not visible, 742), the students table is re-rendered from `state.stats`, the query CTF dropdown is reloaded, the playground polling timer is started, the gate config and queue are fetched. The live view needs nothing because it is always fed by the socket.
- `push` is `true` for user navigation (tab click, "Show in Live", replay, quick demo) and `false` for `popstate` and boot, so the history is never duplicated.

```js
// lines 551-554
$('nav').addEventListener('click', (e) => { const b = e.target.closest('button'); if (b) showView(b.dataset.view, true); });
window.addEventListener('popstate', () => showView(viewFromPath(location.pathname)));
document.addEventListener('click', (e) => { const b = e.target.closest('[data-open]'); if (b) window.open(b.dataset.open, '_blank'); });
$('logout').addEventListener('click', async () => { await api('/api/logout', {}); location.href = '/login'; });
```

- The nav uses one delegated listener; the counter `<span class="cnt">` inside a button is handled by `closest('button')`.
- `popstate` re-derives the view from the path. It does not re-open a student detail for `/students/<name>`; only boot does that (1224). Pressing Back from a detail to `/students` therefore shows the students view with whatever panel was last visible.
- Logout sends an empty object so `api` makes it a POST (the server only accepts POST at 128).

### Live: lanes (lines 557–614)

```js
// lines 557-563
const laneCounts = new Map();
function sevClass(ev) {
  if (['critical', 'high', 'warn'].includes(ev.severity)) return 'sev-' + ev.severity;
  if (ev.status >= 500) return 'sev-server'; if (ev.status >= 400) return 'sev-notice'; if (ev.status >= 300) return 'sev-redirect'; return 'sev-ok';
}
function studentMatches(name) { if (state.filter) return name === state.filter; if (state.query) return name.toLowerCase().includes(state.query); return true; }
function rowMatches(tr) { return studentMatches(tr.dataset.student) && (!state.tableQuery || tr.dataset.text.includes(state.tableQuery)); }
```

- `laneCounts` keeps the per-student counters (`req`, `high`, `crit`, `enum`, `attacks`) separately from the DOM lane so sorting can use numbers, not parsed text.
- `sevClass` is the single source of a request's colour class: the server's `severity` wins when it is a detection result (`warn`, `high`, `critical`); otherwise the HTTP status class decides. The same function colours dots and table rows, so they always agree.
- `studentMatches` implements the sidebar search: an exact selection (`state.filter`) hides everyone else; a partial query matches substrings; nothing set matches all. `rowMatches` adds the recent-requests text search on top. Both read `data-*` attributes that were written when the element was created, which is why filtering is cheap enough to re-run on every keystroke.

```js
// lines 564-579
function lane(name, source) {
  let L = state.lanes.get(name);
  if (L) return L;
  $('empty').classList.add('hidden');
  const el = document.createElement('div');
  el.className = 'lane'; el.dataset.student = name;
  el.innerHTML = `<div class="lane-head"><div class="name"><span class="av" style="background:${colorFor(name)}"></span><span class="nm" title="Select">${esc(name)}</span><span class="blk">BLOCKED</span><span class="dcb hidden" title="routed to the decoy app">🪤</span><span class="src">${esc(source || '')}</span></div>
    <div class="counts"><b class="c-req">0</b> req · <span class="c-high">0</span> attempts · <span class="c-crit">0</span> 🚨</div></div><div class="lane-body"><div class="track"></div><div class="seqrow"><div class="seq"></div><div class="atk"></div></div></div>`;
  $('lanes').appendChild(el);
  el.querySelector('.nm').addEventListener('click', () => selectStudent(name));
  L = { el, track: el.querySelector('.track'), seq: el.querySelector('.seq'), atk: el.querySelector('.atk'), lastSeen: 0, threat: 0, name };
  state.lanes.set(name, L); laneCounts.set(name, { req: 0, high: 0, crit: 0, enum: 0, attacks: {} });
  if (!studentMatches(name)) el.classList.add('hidden');
  addFilterOption(name);
  return L;
}
```

- `lane` is a get-or-create. It is called for every event (581) and for every student in a snapshot (1204), so the fast path (`if (L) return L`) matters.
- A lane object caches the three child elements it will update often (`track`, `seq`, `atk`) plus `lastSeen` and `threat`, the two sort keys.
- A lane created while a filter is active starts hidden; `applyFilter` would otherwise only run on the next search change.
- `addFilterOption` adds the name to the shared `<datalist>` so the search boxes offer it.

```js
// lines 580-597
function addDot(ev, animate) {
  const L = lane(ev.student, ev.source), c = laneCounts.get(ev.student);
  c.req++; if (ev.flags.includes('idor-attempt') || ev.attacks?.length) c.high++; if (ev.flags.includes('idor-success')) c.crit++; if (ev.flags.includes('enumeration')) c.enum++;
  for (const a of ev.attacks || []) c.attacks[a.cls] = (c.attacks[a.cls] || 0) + 1;
  L.el.querySelector('.c-req').textContent = fmtCount(c.req); L.el.querySelector('.c-high').textContent = fmtCount(c.high); L.el.querySelector('.c-crit').textContent = fmtCount(c.crit);
  if (ev.attacks?.length) L.atk.innerHTML = attackBadges(c.attacks);
  L.lastSeen = ev.ts; L.threat = c.crit * 100 + c.high * 10 + c.enum;
  const d = document.createElement('span');
  d.className = `dot ${sevClass(ev)}${ev.method !== 'GET' ? ' m-post' : ''}`;
  if (animate) { if (ev.severity === 'critical') d.classList.add('pulse-crit'); else if (ev.severity === 'high') d.classList.add('pulse-high'); } else d.style.animation = 'none';
  d._ev = ev; L.track.prepend(d); while (L.track.children.length > MAX_DOTS) L.track.lastChild.remove();
  if (ev.endpoint && ev.seq && ev.seq.length) {
    const ids = ev.seq.slice(-8);
    L.seq.innerHTML = `<span class="ep">${esc(ev.endpoint)}:</span> ` + ids.map((id, i) => `<span class="id${i === ids.length - 1 ? ' last' : ''}">${esc(id)}</span>`).join('<span class="arrow">→</span>') +
      (ev.flags.includes('enumeration') ? `<span class="tag">enumerating (${ev.distinctIds} ids)</span>` : '') + (ev.mine === false ? `<span class="tag" style="color:var(--high)">not theirs${ev.owner ? ' (' + esc(ev.owner) + ')' : ''}</span>` : '');
  }
  if (animate && ev.severity === 'critical') { L.el.classList.add('flash'); setTimeout(() => L.el.classList.remove('flash'), 1800); }
}
```

- An "attempt" (`c.high`) is either an IDOR attempt flag or any detected attack payload, so the middle counter is really "suspicious requests".
- `threat` is a weighted score (`crit*100 + high*10 + enum`) used by the "Sort: threat" option.
- The dot's `className` is built from `sevClass`; non-GET methods get `m-post` (square). `animate` is true for live events and false when replaying a snapshot (1202); in the latter case the CSS animation is disabled per element so a reload does not pulse hundreds of dots.
- `d._ev = ev` keeps the whole event object on the DOM node. The tooltip (790) reads it back; nothing else needs an id-to-event map.
- `prepend` + `row-reverse` puts the newest dot on the right. The `while` loop trims to `MAX_DOTS`.
- The sequence line shows the last eight object ids the student requested on the matched endpoint, highlighting the latest; `ev.mine === false` (explicit false, not undefined) means the server established that the object belongs to someone else, and `ev.owner` names who.
- A critical event flashes the lane red for 1.8 s via `.lane.flash` (line 102).

```js
// lines 598-604
function sortLanes() {
  const arr = [...state.lanes.values()];
  if (state.sort === 'name') arr.sort((a, b) => a.name.localeCompare(b.name)); else if (state.sort === 'threat') arr.sort((a, b) => b.threat - a.threat || b.lastSeen - a.lastSeen); else arr.sort((a, b) => b.lastSeen - a.lastSeen);
  const parent = $('lanes'); let changed = false;
  arr.forEach((L, i) => { if (parent.children[i + 2] !== L.el) changed = true; });
  if (changed) for (const L of arr) parent.appendChild(L.el);
}
```

- Called once a second from `renderStats` (656) and on sort change (720), not on every event, so the lanes do not jump under the mouse.
- `children[i + 2]`: `#lanes` has two fixed children before the lanes, the sticky `.view-head` and `#empty`. If you add another fixed element to `#lanes`, change the offset or the function will re-append every second.
- Reordering uses `appendChild` of existing nodes, which moves them without recreating, so running CSS animations are preserved.

```js
// lines 605-614
function addRow(ev) {
  const tr = document.createElement('tr');
  tr.className = sevClass(ev); tr.dataset.student = ev.student;
  tr.dataset.text = `${ev.method} ${ev.path} ${ev.objectId ?? ''} ${ev.status} ${ev.flags.join(' ')} ${ev.owner ?? ''} ${ev.student}`.toLowerCase();
  if (!rowMatches(tr)) tr.classList.add('hidden');
  tr.innerHTML = `<td>${fmtTime(ev.ts)}</td><td>${esc(ev.student)}</td><td>${esc(ev.method)}</td><td title="${esc(ev.path)}">${esc(ev.path)}</td><td>${esc(ev.objectId ?? '')}</td><td>${statusBadge(ev.status)}</td><td>${ev.size}</td><td>${ev.latencyMs}</td><td>${flagsHtml(ev)}</td>`;
  const tb = $('rows'); tb.prepend(tr); while (tb.children.length > MAX_ROWS) tb.lastChild.remove();
}
const statusBadge = (s) => `<span class="st s${String(s)[0]}">${s}</span>`;
const flagsHtml = (ev) => (ev.flags || []).filter((f) => !f.startsWith('attack:')).map((f) => `<span class="flag ${f}">${f}</span>`).join('') + (ev.attacks || []).map((a) => `<span class="flag attack" title="${esc(a.where + ': ' + a.sample)}">${esc(a.cls)}</span>`).join('');
```

- The "Recent requests" table under the lanes. `dataset.text` is a pre-lowercased search blob so `rowMatches` is a single `includes`. The blob is built once; if you add a column that should be searchable, add it here too.
- `statusBadge` relies on the first digit of the status to pick `.st.s2` … `.st.s5`.
- `flagsHtml` drops `attack:<class>` flags (the server stores them for querying) and instead renders the richer `ev.attacks` list, with `where: sample` in the title so hovering shows the payload. The helper is also fed hand-made objects (`{ flags, attacks }`) from the student detail (839) and query results (972).

### Live: alert feed (lines 617–623)

```js
// lines 617-623
function addFeedAlert(a, animate) {
  const el = document.createElement('div');
  el.className = `alert ${a.level}` + (studentMatches(a.student || '') ? '' : ' hidden'); el.dataset.student = a.student || '';
  if (!animate) el.style.animation = 'none';
  el.innerHTML = `<div class="ic">${ICON[a.type] || '•'}</div><div><div class="t">${fmtTime(a.ts)} · <span class="lvl ${a.level}">${a.level}</span> ${esc(a.type)}</div><div class="m">${esc(a.msg)}</div></div>`;
  const box = $('alerts'); box.prepend(el); while (box.children.length > MAX_ALERT_DOM) box.lastChild.remove();
}
```

The sidebar feed only ever grows by prepending; it is cleared on snapshot (1201). Alerts without a student (for example the admin login conflict) have `dataset.student = ''`, and `studentMatches('')` is true only when no filter is active, so they disappear while a student is selected. `a.level` is inserted unescaped into a class name; it comes from the server's fixed set, so this is acceptable, but it is a reason not to let arbitrary strings into `level`.

### Live: stats (lines 626–658)

```js
// lines 626-636
function renderStats(st) {
  state.stats = st;
  $('k-rps').textContent = st.rpsNow.toFixed(1); $('s-rps').textContent = st.rpsNow.toFixed(1); $('k-total').textContent = st.total; $('k-students').textContent = st.students.length;
  $('k-alerts').textContent = st.alertsUnacked; $('nav-alerts').textContent = st.alertsUnacked; $('nav-alerts').classList.toggle('hidden', !st.alertsUnacked);
  $('alerts-count').textContent = `${st.alertsTotal} total`;
  const up = st.uptimeSec; $('uptime').textContent = `up ${Math.floor(up / 3600)}h ${Math.floor((up % 3600) / 60)}m`;
  const cv = $('spark'), ctx = cv.getContext('2d'), dpr = window.devicePixelRatio || 1;
  const W = cv.width = (cv.clientWidth || 340) * dpr, H = cv.height = 44 * dpr; ctx.clearRect(0, 0, W, H);
  const data = st.rps, max = Math.max(1, ...data); ctx.beginPath();
  data.forEach((v, i) => { const x = (i / (data.length - 1)) * W, y = H - (v / max) * (H - 4) - 2; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
  ctx.strokeStyle = '#3987e5'; ctx.lineWidth = 2 * dpr; ctx.stroke(); ctx.lineTo(W, H); ctx.lineTo(0, H); ctx.closePath(); ctx.fillStyle = 'rgba(57,135,229,.15)'; ctx.fill();
```

- `renderStats` runs once per second (the `stats` message) and once per snapshot. It stores the stats object because many other functions read `state.stats.students` later (card, students table, autocomplete).
- The sparkline is drawn with the 2D canvas API. Setting `cv.width`/`cv.height` to the CSS size times `devicePixelRatio` makes it sharp on high-DPI screens; CSS (line 128) keeps the displayed size at 100% × 44px. Assigning `width` also clears the canvas, but `clearRect` is called anyway. `st.rps` is the server's last-60-seconds array; `max` is at least 1 to avoid division by zero; the 2px margins keep the line inside the box. After stroking the line, the path is extended to the bottom corners and filled for the area tint.

```js
// lines 637-647
  const cls = st.statusClasses, tot = Math.max(1, Object.values(cls).reduce((a, b) => a + b, 0)), col = { '2xx': 'var(--ok)', '3xx': 'var(--redirect)', '4xx': 'var(--notice)', '5xx': 'var(--server)' };
  $('status-bar').innerHTML = Object.entries(cls).map(([k, v]) => `<i style="width:${(v / tot) * 100}%;background:${col[k]}"></i>`).join('');
  $('status-legend').innerHTML = Object.entries(cls).map(([k, v]) => `<span><i style="background:${col[k]}"></i>${k} ${v}</span>`).join('');
  const mx = Math.max(1, ...st.topEndpoints.map((e) => e.count));
  $('top-endpoints').innerHTML = st.topEndpoints.map((e) => `<li><span class="w" style="--w:${(e.count / mx) * 100}%" title="${esc(e.name)}">${esc(e.name)}</span><span class="n">${e.count}</span></li>`).join('') || '<li><span style="color:var(--faint)">no requests yet</span></li>';
  const at = Object.entries(st.attackTotals || {}).sort((a, b) => b[1] - a[1]), amx = Math.max(1, ...at.map((x) => x[1]));
  $('attack-classes').innerHTML = at.map(([c, n]) => `<li><span class="w" style="--w:${(n / amx) * 100}%">${esc(c)}</span><span class="n">${n}</span></li>`).join('') || '<li><span style="color:var(--faint)">none detected</span></li>';
  const lb = st.leaderboard;
  $('lb-first').innerHTML = lb.firstIdorSuccess ? `<span class="first">${esc(lb.firstIdorSuccess.student)}</span><span class="v">${fmtTime(lb.firstIdorSuccess.ts)} · ${esc(lb.firstIdorSuccess.endpoint)} #${esc(lb.firstIdorSuccess.objectId)}</span>` : '<span class="k">nobody yet</span>';
  const rows = (arr, suffix) => arr.length ? arr.map((r, i) => `<div class="row"><span class="k">${i + 1}. ${esc(r.student)}</span><span class="v">${r.value} ${suffix}</span></div>`).join('') : '<div class="row"><span class="k" style="color:var(--faint)">–</span></div>';
  $('lb-idor').innerHTML = rows(lb.mostIdor, '🚨'); $('lb-ids').innerHTML = rows(lb.mostIds, 'ids'); $('lb-failed').innerHTML = rows(lb.mostFailed, 'fails'); $('lb-attacks').innerHTML = rows(lb.mostAttacks || [], '🧨');
```

- The status bar is a flex row of `<i>` elements with percentage widths; the legend repeats the counts.
- The "proportional underline" lists (`top-endpoints`, `attack-classes`, and the card lists) set the CSS custom property `--w` inline; the `.list li .w::after` rule (line 131) draws a bar of that width. This avoids a second element per row.
- The leaderboard helper `rows(arr, suffix)` renders any `[{student, value}]` array; `mostAttacks` is guarded with `|| []` because older servers did not send it.

```js
// lines 648-658
  for (const s of st.students) {
    const L = state.lanes.get(s.name); if (!L) continue;
    L.el.querySelector('.src').textContent = s.source + (s.appName ? ' · app user ' + s.appName : '') + (s.id ? ' · id ' + s.id : ''); L.el.classList.toggle('blocked', !!s.blocked);
    L.el.querySelector('.dcb').classList.toggle('hidden', !s.decoy);
    // server counts are authoritative (they survive a page reload); redraw the badges when they differ
    const c = laneCounts.get(s.name), srv = s.attacks || {};
    if (c && JSON.stringify(c.attacks) !== JSON.stringify(srv)) { c.attacks = { ...srv }; L.atk.innerHTML = attackBadges(c.attacks); }
  }
  renderStudentList(st.students); updateActions(); sortLanes();
  if (state.view === 'students' && $('su-detail').classList.contains('hidden')) renderStudentsTable();
}
```

- The per-second pass also refreshes lane metadata the events do not carry: identification source, blocked state, decoy marker. The attack-class badges are reconciled with the server's counts because the client's counters only know events seen since the page loaded (a snapshot holds at most 500 events).
- Lanes are not created here for students that have no lane yet; `loadSnapshot` does that (1204). A student who exists on the server but sent no event since the snapshot has a lane only if they were in the snapshot's student list.
- The last line keeps the Students table live while it is visible and no detail panel is open.

### Live: sidebar student list and card (lines 661–729)

```js
// lines 661-677
const listItems = new Map(), filterOpts = new Set();
function addFilterOption(name) { if (filterOpts.has(name)) return; filterOpts.add(name); const o = document.createElement('option'); o.value = name; $('students-list').appendChild(o); }
function renderStudentList(students) {
  const ul = $('slist'), sorted = students.slice().sort((a, b) => a.name.localeCompare(b.name)), online = students.filter((s) => Date.now() - s.lastSeen < 120000).length;
  $('students-count').textContent = `${online} online · ${students.length} total`;
  const seen = new Set();
  sorted.forEach((s, i) => {
    seen.add(s.name);
    let li = listItems.get(s.name);
    if (!li) { li = document.createElement('li'); li.dataset.name = s.name; li.innerHTML = `<span class="av" style="background:${colorFor(s.name)}"></span><span class="nm">${esc(s.name)}</span><span class="meta"></span>`; li.addEventListener('click', () => selectStudent(s.name)); listItems.set(s.name, li); addFilterOption(s.name); }
    const att = Object.values(s.attacks || {}).reduce((a, b) => a + b, 0);
    li.querySelector('.meta').innerHTML = `${s.queue === 'pending' ? '⏳ ' : ''}${fmtCount(s.requests)} req${s.idorAttempts ? ` · ${fmtCount(s.idorAttempts)} ⚠` : ''}${s.idorSuccess ? ` · <span class="c">${fmtCount(s.idorSuccess)} 🚨</span>` : ''}${att ? ` · ${fmtCount(att)} 🧨` : ''}${s.renamePending ? ' · 🔁' : ''}`;
    li.classList.toggle('blk', !!s.blocked); li.classList.toggle('online', Date.now() - s.lastSeen < 120000); li.classList.toggle('sel', state.filter === s.name); li.classList.toggle('hidden', !studentMatches(s.name));
    if (ul.children[i] !== li) ul.insertBefore(li, ul.children[i] || null);
  });
  for (const [name, li] of listItems) if (!seen.has(name)) { li.remove(); listItems.delete(name); }
}
```

- The list is reconciled, not rebuilt: existing `<li>` nodes are kept (so hover and click targets are stable), new ones are created, each is moved to its sorted index only if it is not already there, and names the server no longer reports (after a rename or a CTF reset) are removed.
- "Online" means seen in the last 120 s; the same threshold is used in the Students view (821–822).
- The `.meta` text summarises requests, IDOR attempts/successes, attack count, queue-pending (⏳) and rename-pending (🔁).

```js
// lines 678-688
function selectedStudent() { return state.stats && state.stats.students.find((s) => s.name === state.filter); }
// the student card body, shared by the Live sidebar and the Requests sidebar
function cardGridHtml(s) {
  const rows = [['identified by', s.source], ['app username', (s.appNames && s.appNames.length ? s.appNames.join(', ') : s.appName) || '–'], ['user id', s.id || '–'], ['player #', s.playerId || '–'], ['first seen', fmtTime(s.firstSeen)], ['last seen', fmtTime(s.lastSeen)],
    ['requests', `${s.requests} (${s.failed} failed)`], ['IDOR', `${s.idorAttempts} attempts · ${s.idorSuccess} successful`], ['distinct IDs', s.distinctIds]];
  for (const [k, v] of Object.entries(s.profile || {})) if (!k.startsWith('_')) rows.push(['🪪 ' + k, v]); // answers to the extra gate fields
  if (s.queue) rows.push(['queue', s.queue === 'pending' ? '⏳ waiting for approval' : s.queue === 'approved' ? '✅ approved' : '⛔ blocked']);
  if (s.decoy) rows.push(['routing', '🪤 decoy app']);
  if (s.renamePending) rows.push(['rename', 'requested - waiting for the student']);
  return rows.map(([k, v]) => `<span class="k">${esc(k)}</span><span class="v">${esc(v)}</span>`).join('');
}
```

- The selected student is always derived from `state.filter` + `state.stats`; there is no separate "selected" variable, which is why selecting a student and filtering to a student are the same action.
- `cardGridHtml`, `cardIpsHtml` (689), `cardUasHtml` (690) and `cardAttacksHtml` (691) return markup fragments that both the Live sidebar card (`updateActions`) and the Requests sidebar card (`rqRenderSide`) use, so the two cards cannot drift apart. Profile keys beginning with `_` are internal (the gate stores metadata there) and are skipped.

```js
// lines 692-702
function updateActions() {
  const s = selectedStudent(); $('student-card').classList.toggle('hidden', !s);
  if (!s) return;
  $('btn-block').textContent = s.blocked ? '✅ Unblock' : '⛔ Block'; $('btn-block').classList.toggle('danger', !s.blocked); $('btn-ask-rename').classList.toggle('hidden', !!s.renamePending);
  $('btn-decoy').textContent = s.decoy ? '↩ Back to real CTF' : '🪤 Send to decoy';
  $('sc-av').style.background = colorFor(s.name); $('sc-nm').textContent = s.name; $('sc-blocked').classList.toggle('hidden', !s.blocked);
  $('sc-grid').innerHTML = cardGridHtml(s);
  $('sc-ips').innerHTML = cardIpsHtml(s);
  $('sc-uas').innerHTML = cardUasHtml(s);
  const att = cardAttacksHtml(s); $('sc-att-box').classList.toggle('hidden', !att); $('sc-attacks').innerHTML = att;
}
```

Runs on every stats tick (656), on every filter change (708) and on decoy changes (1041), so the card is never more than a second stale. The admin buttons are hidden for the observer role at boot (1220) by the `admin-only` class, not here; `updateActions` only changes their labels. Note that `btn-ask-rename` uses `hidden` while `renamePending`, which combines correctly with `admin-only` because both are the same class.

```js
// lines 703-714
function applyFilter() {
  for (const L of state.lanes.values()) L.el.classList.toggle('hidden', !studentMatches(L.name));
  for (const [name, li] of listItems) { li.classList.toggle('hidden', !studentMatches(name)); li.classList.toggle('sel', state.filter === name); }
  for (const el of $('alerts').children) el.classList.toggle('hidden', !studentMatches(el.dataset.student));
  for (const tr of $('rows').children) tr.classList.toggle('hidden', !rowMatches(tr));
  updateActions();
}
function setStudentQuery(text) {
  const q = text.trim(), exact = [...listItems.keys(), ...state.lanes.keys()].find((n) => n.toLowerCase() === q.toLowerCase());
  state.filter = exact || ''; state.query = exact ? '' : q.toLowerCase(); applyFilter();
}
function selectStudent(name) { $('filter').value = name; setStudentQuery(name); }
```

- `applyFilter` touches four DOM collections (lanes, list, feed, recent rows). Everything is hide/show by class; nothing is re-created, so the filter is instant even with hundreds of rows.
- `setStudentQuery` decides between exact and partial: if the typed text equals an existing name (case-insensitive) it becomes a selection (`state.filter`, card shown); otherwise a substring query (`state.query`, no card). Both the list and the lanes are consulted because a student can be in one but not yet the other.
- `selectStudent` is what lane names (573), list items (670) and "Show in Live" (779) call.

```js
// lines 715-725
$('filter').addEventListener('input', (e) => setStudentQuery(e.target.value));
$('filter').addEventListener('keydown', (e) => { if (e.key === 'Escape') { $('filter').value = ''; setStudentQuery(''); } if (e.key === 'Enter') { const f = [...listItems.entries()].find(([, li]) => !li.classList.contains('hidden')); if (f) selectStudent(f[0]); } });
$('filter-clear').addEventListener('click', () => { $('filter').value = ''; setStudentQuery(''); });
$('sc-close').addEventListener('click', () => { $('filter').value = ''; setStudentQuery(''); });
$('table-search').addEventListener('input', (e) => { state.tableQuery = e.target.value.trim().toLowerCase(); applyFilter(); });
$('sort').addEventListener('change', (e) => { state.sort = e.target.value; sortLanes(); });
$('pause').addEventListener('click', () => { state.paused = !state.paused; const b = $('pause'); b.classList.toggle('paused', state.paused); b.textContent = state.paused ? '▶ Resume' : '⏸ Pause'; if (!state.paused) for (const m of state.buffer.splice(0)) handleMessage(m, false); });
$('table-toggle').addEventListener('click', () => { const w = $('table-wrap'); w.classList.toggle('collapsed'); $('table-hint').textContent = w.classList.contains('collapsed') ? '▸ expand' : '▾ collapse'; });
$('table-expand').addEventListener('click', () => { const w = $('table-wrap'); w.classList.remove('collapsed'); w.classList.toggle('expanded'); $('table-expand').textContent = w.classList.contains('expanded') ? '⤡ Shrink' : '⤢ Expand'; });
$('btn-detail').addEventListener('click', () => state.filter && window.open('/students/' + encodeURIComponent(state.filter), '_blank'));
$('table-newtab').addEventListener('click', () => window.open('/requests' + (state.filter ? '?student=' + encodeURIComponent(state.filter) : ''), '_blank'));
```

- Enter in the search box selects the first visible list item, so typing a prefix and pressing Enter is a quick select.
- Pause: while `state.paused`, the socket handler (1213) buffers every non-stats message; Resume replays the buffer through `handleMessage(m, false)` (no animations). Stats messages keep flowing so the numbers stay current while the lanes are frozen.
- "New tab" for the recent-requests table opens the Requests view with the current student pre-filled through the `?student=` parameter.

```js
// lines 726-729
$('btn-block').addEventListener('click', async () => { const s = selectedStudent(); if (!s) return; if (s.blocked) return tryApi('/api/admin/unblock', { student: s.name }); if (confirm(`Block "${s.name}"?\n\nEvery request from this student (and their IP, unless shared) gets "Access blocked" from the proxy.`)) await tryApi('/api/admin/block', { student: s.name }); });
$('btn-ask-rename').addEventListener('click', async () => { if (state.filter && confirm(`Ask "${state.filter}" to enter a different name?\n\nTheir browser shows the name page again and other requests are refused until they do.`)) await tryApi('/api/admin/require-rename', { student: state.filter }); });
$('btn-rename').addEventListener('click', async () => { if (!state.filter) return; const n = prompt(`New name for "${state.filter}":`, state.filter); if (!n || n.trim() === state.filter) return; const j = await tryApi('/api/admin/rename', { student: state.filter, newName: n.trim() }); if (j && j.ok) { addFilterOption(j.name); $('filter').value = j.name; } });
$('btn-decoy').addEventListener('click', () => state.filter && toggleDecoy(state.filter));
```

The card actions call the admin API and then do nothing locally: the next `stats` message (within a second) carries the new `blocked`/`renamePending` state and `updateActions` re-labels the buttons. After a rename, the server returns the cleaned `name` (it may differ from what was typed); the search box is set to it, but `state.filter` is only updated on the next `input` event or stats tick, which is why the list may briefly show no selection.

### Requests view (lines 732–785)

```js
// lines 732-745
const rq = { paused: false, buffer: [], search: '', student: new URLSearchParams(location.search).get('student') || '', sel: null, max: 2000 };
if (rq.student) $('rq-student').value = rq.student;
function rqMatches(tr) { return (!rq.student || tr.dataset.student.toLowerCase().includes(rq.student.toLowerCase())) && (!rq.search || tr.dataset.text.includes(rq.search)); }
function rqAddRow(ev) {
  const tr = document.createElement('tr');
  tr.className = sevClass(ev); tr.dataset.student = ev.student; tr._ev = ev;
  tr.dataset.text = `${ev.method} ${ev.path} ${ev.objectId ?? ''} ${ev.status} ${ev.flags.join(' ')} ${(ev.attacks || []).map((a) => a.cls).join(' ')} ${ev.owner ?? ''} ${ev.student} ${ev.ip}`.toLowerCase();
  tr.innerHTML = `<td>${fmtTime(ev.ts)}</td><td>${esc(ev.student)}</td><td>${esc(ev.ip)}</td><td>${esc(ev.method)}</td><td title="${esc(ev.path)}">${esc(ev.path)}</td><td>${esc(ev.objectId ?? '')}</td><td>${statusBadge(ev.status)}</td><td>${ev.size}</td><td>${ev.latencyMs}</td><td>${flagsHtml(ev)}</td>`;
  if (!rqMatches(tr)) tr.classList.add('hidden');
  const tb = $('rq-rows'); tb.prepend(tr); while (tb.children.length > rq.max) tb.lastChild.remove();
  if (state.view === 'requests') rqCount();
}
function rqCount() { const all = $('rq-rows').children.length, vis = [...$('rq-rows').children].filter((t) => !t.classList.contains('hidden')).length; $('rq-count').textContent = rq.search || rq.student ? `${vis} of ${all}` : `${all} rows`; }
function rqApplyFilter() { for (const tr of $('rq-rows').children) tr.classList.toggle('hidden', !rqMatches(tr)); rqCount(); }
```

- The Requests view has its own independent state `rq`: its own pause/buffer, its own filters, a 2000-row cap, and the selected event. It is fed by every event (`rqFeed`, from `handleMessage` 1185 and from the snapshot 1202) whether or not the view is visible, so switching to it shows history.
- The student filter in this view is a substring match (unlike the live sidebar's exact selection) and is read from `?student=` on load.
- `tr._ev = ev` keeps the event for the detail panel, the same trick as the dots.
- `rqCount` is skipped while the view is hidden because counting visible rows is O(n) and the number is not shown anyway; `showView('requests')` calls `rqApplyFilter` to catch up (542).

```js
// lines 746-751
$('rq-search').addEventListener('input', (e) => { rq.search = e.target.value.trim().toLowerCase(); rqApplyFilter(); });
$('rq-student').addEventListener('input', (e) => { rq.student = e.target.value.trim(); rqApplyFilter(); history.replaceState(null, '', rq.student ? `/requests?student=${encodeURIComponent(rq.student)}` : '/requests'); });
$('rq-clear').addEventListener('click', () => { $('rq-rows').innerHTML = ''; rqCount(); });
$('rq-pause').addEventListener('click', () => { rq.paused = !rq.paused; const b = $('rq-pause'); b.classList.toggle('paused', rq.paused); b.textContent = rq.paused ? '▶ Resume' : '⏸ Pause'; if (!rq.paused) for (const ev of rq.buffer.splice(0)) rqAddRow(ev); });
function rqFeed(ev) { if (rq.paused) { rq.buffer.push(ev); if (rq.buffer.length > 5000) rq.buffer.shift(); } else rqAddRow(ev); }
$('rq-rows').addEventListener('click', (e) => { const tr = e.target.closest('tr'); if (!tr || !tr._ev) return; for (const t of $('rq-rows').children) t.classList.remove('sel'); tr.classList.add('sel'); rq.sel = tr._ev; rqRenderSide(); });
```

- Typing a student name rewrites the URL with `replaceState` (no history entry), so the tab's address can be copied or bookmarked.
- The pause here buffers raw events (up to 5000), separate from the live view's message buffer.

```js
// lines 752-761
function requestDetailHtml(ev) {
  const kv = [['time', fmtDate(ev.ts)], ['student', ev.student], ['identified by', ev.source + (ev.rawName && ev.rawName !== ev.student ? ` (raw: ${ev.rawName})` : '')], ['ip', ev.ip], ['method', ev.method], ['path', ev.path, 'path'],
    ['endpoint', ev.endpoint ? `${ev.endpoint} · id ${ev.objectId ?? '–'}` : '–'], ['owner', ev.owner ? `${ev.owner}${ev.ownerBasis ? ` (${ev.ownerBasis})` : ''}${ev.mine === false ? ' · NOT theirs' : ev.mine === true ? ' · theirs' : ''}` : '–'],
    ['status', `${ev.status}`], ['response', `${ev.size} bytes · ${ev.latencyMs} ms`], ['severity', ev.severity], ['flags', (ev.flags || []).filter((f) => !f.startsWith('attack:')).join(', ') || '–'], ['user agent', ev.ua || '–']];
  if (ev.seq && ev.seq.length) kv.push(['id sequence', ev.seq.join(' → ')]);
  if (ev.error) kv.push(['error', ev.error]);
  return `<h3>Request <span>#${ev.n || ''}</span></h3><div class="kv">${kv.map(([k, v, cls]) => `<span class="k">${esc(k)}</span><span class="v ${cls || ''}">${esc(v)}</span>`).join('')}</div>` +
    ((ev.attacks || []).length ? `<h4 style="margin:10px 0 4px;font-size:11px;color:var(--high)">🧨 Attack payloads</h4><div class="kv">${ev.attacks.map((a) => `<span class="k"><span class="flag attack">${esc(a.cls)}</span></span><span class="v">${esc(a.label)} in ${esc(a.where)}:<br><span style="color:var(--notice)">${esc(a.sample)}</span></span>`).join('')}</div>` : '')
    + (ev.body ? `<h4 style="margin:10px 0 4px;font-size:11px;color:var(--faint)">Request body (secrets masked)</h4><pre class="body">${esc(JSON.stringify(ev.body, null, 1))}</pre>` : '');
}
```

- A key/value list built as an array of `[key, value, optionalClass]` triples and then mapped to markup. Adding a row is adding a triple. `ev.mine` is tri-state (`true`, `false`, `undefined`), so the text distinguishes "theirs", "NOT theirs" and "unknown".
- `ev.body` is the request body as the proxy stored it (already masked by the server); it is pretty-printed with indent 1 inside `pre.body`.

```js
// lines 762-774 (the h4 headings are abridged)
function rqRenderSide() {
  const ev = rq.sel; if (!ev) return;
  $('rq-req').innerHTML = requestDetailHtml(ev);
  const s = state.stats && state.stats.students.find((x) => x.name === ev.student);
  const card = $('rq-card'); card.classList.toggle('hidden', !s); if (!s) return;
  const isAdmin = state.me && state.me.role === 'admin';
  card.innerHTML = `<h3>Student</h3><div class="sc-name"><span class="av" style="background:${colorFor(s.name)}"></span><b>${esc(s.name)}</b> ${s.blocked ? '<span class="badge" style="color:var(--critical);border-color:var(--critical)">BLOCKED</span>' : ''}</div>
    <div class="rq-actions" style="display:flex;gap:6px;flex-wrap:wrap;margin:4px 0 8px"><button class="small" data-act="details">📄 Details ↗</button>${isAdmin ? `<button class="small ${s.blocked ? '' : 'danger'}" data-act="block">${s.blocked ? '✅ Unblock' : '⛔ Block'}</button>${s.renamePending ? '' : '<button class="small" data-act="ask">🔁 Ask to rename</button>'}<button class="small" data-act="rename">✎ Rename</button><button class="small" data-act="decoy">${s.decoy ? '↩ Back to real CTF' : '🪤 Send to decoy'}</button>` : ''}<button class="small" data-act="live">📡 Show in Live</button></div>
    <div class="grid2">${cardGridHtml(s)}</div>
    <h4 ...>IP addresses</h4><ul class="list">${cardIpsHtml(s)}</ul>
    <h4 ...>User agents</h4><ul class="list">${cardUasHtml(s)}</ul>
    ${cardAttacksHtml(s) ? `<h4 ...>🧨 Attack classes</h4><ul class="list">${cardAttacksHtml(s)}</ul>` : ''}`;
}
```

This card is generated as a whole string, unlike the live card which updates fixed elements. Because it is generated, the admin buttons are simply not emitted for observers (`isAdmin` check) instead of relying on `admin-only`. The buttons carry `data-act` and are handled by one delegated listener:

```js
// lines 775-785
$('rq-card').addEventListener('click', async (e) => {
  const b = e.target.closest('button[data-act]'); if (!b || !rq.sel) return;
  const name = rq.sel.student, s = state.stats.students.find((x) => x.name === name);
  if (b.dataset.act === 'details') return window.open('/students/' + encodeURIComponent(name), '_blank');
  if (b.dataset.act === 'live') { selectStudent(name); return showView('live', true); }
  if (b.dataset.act === 'block') { if (s && s.blocked) await tryApi('/api/admin/unblock', { student: name }); else if (confirm(`Block "${name}"?`)) await tryApi('/api/admin/block', { student: name }); }
  if (b.dataset.act === 'ask' && confirm(`Ask "${name}" to enter a different name?`)) await tryApi('/api/admin/require-rename', { student: name });
  if (b.dataset.act === 'rename') { const n = prompt(`New name for "${name}":`, name); if (n && n.trim() !== name) await tryApi('/api/admin/rename', { student: name, newName: n.trim() }); }
  if (b.dataset.act === 'decoy') await toggleDecoy(name);
  setTimeout(rqRenderSide, 1200);
});
```

The `setTimeout(rqRenderSide, 1200)` re-renders the card slightly after the next stats tick so it reflects the server's new state. This card does not re-render on its own each second (only `decoyUpdate` 1041 refreshes it), so without this delay the Block button would keep its old label until the next click.

### Tooltip (lines 788–796)

```js
// lines 788-796
const tip = $('tip');
document.addEventListener('mouseover', (e) => {
  const d = e.target.closest('.dot'); if (!d || !d._ev) { tip.style.display = 'none'; return; }
  const ev = d._ev;
  tip.innerHTML = `<b>${esc(ev.method)} ${esc(ev.path)}</b><br>${fmtTime(ev.ts)} · HTTP ${ev.status} · ${ev.size} B · ${ev.latencyMs} ms` + (ev.endpoint ? `<br>endpoint: ${esc(ev.endpoint)} · id ${esc(ev.objectId)}${ev.owner ? ' · owner ' + esc(ev.owner) + (ev.ownerBasis ? ' (' + ev.ownerBasis + ')' : '') : ''}` : '') +
    (ev.flags.length ? `<br>flags: ${esc(ev.flags.join(', '))}` : '') + (ev.attacks?.length ? `<br>attacks: ${esc(ev.attacks.map((a) => `${a.label} [${a.where}: ${a.sample}]`).join(' | '))}` : '') + (ev.body ? `<br>body: ${esc(JSON.stringify(ev.body)).slice(0, 200)}` : '');
  tip.style.display = 'block';
});
document.addEventListener('mousemove', (e) => { if (tip.style.display !== 'block') return; tip.style.left = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 10) + 'px'; tip.style.top = Math.min(e.clientY + 14, window.innerHeight - tip.offsetHeight - 10) + 'px'; });
```

One `mouseover` listener on `document` (dots are created constantly, so per-dot listeners would be wasteful). Hovering anything that is not a dot hides the tip. The `mousemove` handler keeps the box 14px from the pointer and clamps it inside the viewport. `#tip` has `pointer-events:none` (line 133) so it never steals the hover.

### Alerts view (lines 799–814)

```js
// lines 799-808
function renderLevelChips() {
  const by = (state.stats && state.stats.alertsByLevel) || {};
  $('lvl-chips').innerHTML = LEVELS.map((l) => `<span class="chip ${state.alertFilter.levels.has(l) ? 'on' : ''}" data-lvl="${l}"><span class="lvl ${l}">${l}</span><b>${by[l] || 0}</b></span>`).join(' ');
}
$('lvl-chips').addEventListener('click', (e) => { const c = e.target.closest('.chip'); if (!c) return; const l = c.dataset.lvl; state.alertFilter.levels.has(l) ? state.alertFilter.levels.delete(l) : state.alertFilter.levels.add(l); renderLevelChips(); renderAlertsTable(); });
$('al-search').addEventListener('input', (e) => { state.alertFilter.text = e.target.value.toLowerCase(); renderAlertsTable(); });
$('al-unacked-cb').addEventListener('change', (e) => { state.alertFilter.unacked = e.target.checked; renderAlertsTable(); });
$('al-refresh').addEventListener('click', loadAlerts);
$('al-ack-all').addEventListener('click', async () => { await tryApi('/api/alerts/ack', { all: true, ids: [] }); state.alerts.forEach((a) => (a.ack = 1)); renderAlertsTable(); });
async function loadAlerts() { const rows = await tryApi('/api/alerts?limit=1000'); if (rows) { state.alerts = rows; renderLevelChips(); renderAlertsTable(); } }
```

- The chips show counts from the stats (`alertsByLevel`) and toggle membership in the `levels` Set. They are re-rendered each stats tick while the view is open (1195) so the counts stay live.
- `loadAlerts` replaces `state.alerts` with the server's list (up to 1000 of the current or replayed CTF). Between loads, live alerts are `unshift`ed by `handleMessage` (1186).
- "Acknowledge all" marks the local copies too so the table updates without a reload.

```js
// lines 809-814
function renderAlertsTable() {
  const f = state.alertFilter, tb = $('al-rows');
  const rows = state.alerts.filter((a) => f.levels.has(a.level) && (!f.unacked || !a.ack) && (!f.text || `${a.student || ''} ${a.type} ${a.msg} ${a.ip || ''}`.toLowerCase().includes(f.text)));
  tb.innerHTML = rows.map((a) => `<tr class="${a.ack ? 'ack' : ''}" data-id="${a.id || ''}"><td>${fmtDate(a.ts)}</td><td><span class="lvl ${a.level}">${a.level}</span></td><td>${ICON[a.type] || '•'} ${esc(a.type)}</td><td>${a.student ? `<a href="/students/${encodeURIComponent(a.student)}" target="_blank">${esc(a.student)}</a>` : ''}</td><td>${esc(a.ip || '')}</td><td class="wrap">${esc(a.msg)}</td><td>${a.ack ? '' : `<button class="small ack" data-id="${a.id || ''}">✓ ack</button>`}</td></tr>`).join('') || '<tr><td colspan="7" style="color:var(--faint)">no alerts match</td></tr>';
}
$('al-rows').addEventListener('click', async (e) => { const b = e.target.closest('button.ack'); if (!b) return; const id = Number(b.dataset.id); if (!id) return; await tryApi('/api/alerts/ack', { ids: [id] }); const a = state.alerts.find((x) => x.id === id); if (a) a.ack = 1; renderAlertsTable(); });
```

The table is rebuilt from `state.alerts` on every change; this is fine for up to ~1000 rows. Alerts that arrived live before the database assigned an id have `a.id` undefined, which makes the ack button a no-op (`if (!id) return`); a Refresh fixes that.

### Students view (lines 817–842)

```js
// lines 818-824
function renderStudentsTable() {
  if (!state.stats) return;
  const q = $('su-search').value.trim().toLowerCase(), onlineOnly = $('su-online-cb').checked;
  const rows = state.stats.students.filter((s) => (!q || `${s.name} ${Object.keys(s.ips || {}).join(' ')} ${(s.appNames || []).join(' ')}`.toLowerCase().includes(q)) && (!onlineOnly || Date.now() - s.lastSeen < 120000)).sort((a, b) => b.lastSeen - a.lastSeen);
  $('su-rows').innerHTML = rows.map((s) => { const att = Object.entries(s.attacks || {}); return `<tr class="clickable" data-name="${esc(s.name)}"><td><span class="live ${Date.now() - s.lastSeen < 120000 ? 'on' : ''}" style="display:inline-block;animation:none"></span></td><td>${esc(s.name)}${s.blocked ? ' <span class="lvl critical">blocked</span>' : ''}${s.renamePending ? ' 🔁' : ''}</td><td>${esc(s.source)}</td><td>${esc((s.appNames || []).join(', ') || s.appName || '')}</td><td>${Object.keys(s.ips || {}).length}</td><td>${s.requests}</td><td>${s.failed}</td><td>${s.idorAttempts}</td><td>${s.idorSuccess}</td><td>${att.map(([c, n]) => `${c}×${n}`).join(' ') || ''}</td><td>${fmtTime(s.lastSeen)}</td><td><button class="small" data-open="/students/${encodeURIComponent(s.name)}">↗</button></td></tr>`; }).join('') || '<tr><td colspan="12" style="color:var(--faint)">no students yet</td></tr>';
}
$('su-rows').addEventListener('click', (e) => { if (e.target.closest('[data-open]')) return; const tr = e.target.closest('tr[data-name]'); if (tr) openStudentDetail(tr.dataset.name, true); });
```

- Built entirely from `state.stats.students`, no API call. The search covers name, IPs and app usernames. Sorted by last activity.
- Row click opens the in-page detail; the `↗` button opens it in a new tab through the global `data-open` handler, which is why the row handler returns early when the click was on that button.

```js
// lines 825-830 (the detail panel; the big template at 830-839 is abridged)
async function openStudentDetail(name, push) {
  const d = await tryApi('/api/students/' + encodeURIComponent(name)); if (!d) return;
  if (push) history.pushState(null, '', '/students/' + encodeURIComponent(name));
  $('su-list').classList.add('hidden'); const box = $('su-detail'); box.classList.remove('hidden');
  const l = d.live || {}, att = Object.entries(d.attacks || {}).sort((a, b) => b[1].count - a[1].count);
  box.innerHTML = `...`;
```

- `/api/students/<name>` returns the database detail (`requests`, `ips`, `userAgents`, `attacks`, `player`, `playerId`) merged with `live` (the in-memory student if present, with `blocked` and `renamePending`). `l` may be empty for a student from a past CTF, hence the `??` fallbacks in the template (`l.requests ?? d.requests.length`).
- The template (830–839) renders: a header with a Back button and an admin Block button; a `.cols` grid of cards (Profile incl. gate answers, IP table, user-agent table, and "Known player across CTFs" when `d.player` exists); an attack-attempts card with one table per class and its samples; and the full request table (newest first, up to 5000 rows, flags via `flagsHtml`).

```js
// lines 840-841
  $('su-back').addEventListener('click', () => { box.classList.add('hidden'); $('su-list').classList.remove('hidden'); history.pushState(null, '', '/students'); renderStudentsTable(); });
  const bb = $('sd-block'); if (bb) bb.addEventListener('click', async () => { await tryApi(l.blocked ? '/api/admin/unblock' : '/api/admin/block', { student: name }); openStudentDetail(name, false); });
}
```

Because `#su-back` and `#sd-block` are created by the template, their listeners must be attached after each render, inside the function. The Block button re-fetches the detail so the label flips.

### Query view (lines 845–984)

```js
// lines 845-847
let lastRows = [];
const Q = window.CtfQuery; // parser shared with the server (/query.js)
const qta = $('q'), qhl = $('q-hl'), qac = $('q-ac'), qlint = $('q-lint');
```

`Q` exposes `tokenize`, `validate`, `FIELDS` (name → `{col, type, help}`) and `OPS_BY_TYPE` (type → allowed operators) from `proxy/src/query.js`. Because the browser runs the same parser as the server, "✓ valid" in the editor means the server will accept the query.

```js
// lines 848-864 (VALUE_HINTS abridged)
const VALUE_HINTS = {
  method: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'].map((v) => [v, 'method']),
  status: [['200', 'ok'], ['201', 'created'], ['302', 'redirect'], ...],
  severity: ['ok', 'notice', 'warn', 'high', 'critical'].map((v) => [v, 'severity']),
  flag: [['idor-success', 'read something not theirs'], ...],
  attack: [['sqli', 'SQL injection'], ['xss', 'cross-site scripting'], ...],
  source: [['name', 'gate form'], ['ip-match', 'ip matched to a gate name'], ...],
  ts: [['-5m', 'last 5 minutes'], ['-15m', 'last 15 minutes'], ...],
};
const valueCache = {};
async function dbValues(field) {
  if (!['student', 'raw', 'ip', 'endpoint', 'owner', 'ua', 'id'].includes(field)) return [];
  if (valueCache[field] && Date.now() - valueCache[field].at < 30000) return valueCache[field].values;
  const j = await api('/api/query/values?field=' + field + ($('q-ctf').value ? '&ctf=' + $('q-ctf').value : '')).catch(() => ({ values: [] }));
  valueCache[field] = { at: Date.now(), values: j.values.map((x) => [x.v, `${x.n} req`]) };
  return valueCache[field].values;
}
```

- `VALUE_HINTS` are static `[value, description]` pairs for fields with a known vocabulary. `dbValues` fetches the top 60 distinct values of free-text fields from the database, cached for 30 s per field. The server whitelists the column (dashboard.js 221), so an unknown field returns an empty list rather than an error.

```js
// lines 866-889
function qRender() {
  const src = qta.value;
  const v = Q.validate(src);
  let toks = [];
  try { toks = Q.tokenize(src); } catch (e) { toks = []; }
  const errPos = v.ok ? -1 : v.pos, errEnd = v.ok ? -1 : (v.pos ?? 0) + (v.len || 1);
  let out = '', i = 0;
  const push = (text, cls) => { out += cls ? `<span class="${cls}">${esc(text)}</span>` : esc(text); };
  const classFor = (t) => (t.t === 'ident' ? (Q.FIELDS[t.v.toLowerCase()] ? 'tf' : 'terr') : t.t === 'op' ? 'to' : t.t === 'str' ? 'ts' : t.t === 'num' ? 'tn' : ['AND', 'OR', 'NOT', 'IN'].includes(t.t) ? 'tk' : 'tp');
  for (const t of toks) {
    if (t.pos > i) push(src.slice(i, t.pos));
    const inErr = errPos >= 0 && t.pos < errEnd && t.pos + t.len > errPos;
    push(src.slice(t.pos, t.pos + t.len), classFor(t) + (inErr ? ' terr' : ''));
    i = t.pos + t.len;
  }
  if (i < src.length) { const rest = src.slice(i); if (errPos >= 0 && errPos >= i) { push(rest.slice(0, errPos - i)); push(rest.slice(errPos - i), 'terr'); } else push(rest); }
  if (errPos >= 0 && errPos >= src.length) out += '<span class="terr"> </span>';
  qhl.innerHTML = out + '\n';
  $('qed').classList.toggle('bad', !v.ok && src.trim() !== '');
  if (src.trim() === '') { qlint.textContent = 'empty query = every request of the current CTF'; qlint.className = 'qlint'; }
  else if (v.ok) { qlint.textContent = '✓ valid'; qlint.className = 'qlint ok'; }
  else { qlint.textContent = `✖ ${v.error}${v.pos != null ? ` (at ${v.pos + 1})` : ''}`; qlint.className = 'qlint err'; }
  $('q-run').disabled = !v.ok && src.trim() !== '';
}
```

- The highlighter: `validate` gives `{ok, error, pos, len}`; `tokenize` gives tokens with `pos`, `len`, `t` (kind) and `v` (value). Tokenizing can throw on an unterminated string, in which case there are no tokens and the whole text is emitted plain with the error range underlined.
- The loop copies the source verbatim, token by token, keeping the whitespace between tokens (`src.slice(i, t.pos)`), so the mirror has exactly the same characters as the textarea. This is essential for the overlay alignment. `esc` is applied to every slice.
- A token overlapping the error range gets `terr` in addition to its colour. An error at the very end (for example "missing operator") gets a one-space `terr` span so there is something to underline.
- The trailing `'\n'` in `qhl.innerHTML` matters: a `<pre>` ignores a final newline, while the textarea reserves a line for it; adding one keeps the heights equal when the user ends with Enter.
- The lint line and the Run button's disabled state follow the verdict. An empty query is valid and means "everything in the current CTF".

```js
// lines 891-911
const ac = { items: [], idx: 0, replace: null };
function contextAt(src, caret) {
  // what comes before the caret: tokens so far + the partial word being typed
  let toks = [];
  try { toks = Q.tokenize(src.slice(0, caret)); } catch { try { toks = Q.tokenize(src.slice(0, caret).replace(/["'][^"']*$/, '')); } catch { toks = []; } }
  const before = src.slice(0, caret);
  const partialM = /([A-Za-z_][A-Za-z0-9_-]*|"[^"]*|'[^']*|[-\d.]+)$/.exec(before);
  const partial = partialM ? partialM[1] : '';
  const isOpenStr = /^["']/.test(partial);
  const done = partial && toks.length && toks[toks.length - 1].pos + toks[toks.length - 1].len === caret && !isOpenStr ? toks.slice(0, -1) : toks;
  const last = done[done.length - 1], prev = done[done.length - 2];
  let kind, field, op;
  if (last && last.t === '(' && prev && prev.t === 'IN') { kind = 'value'; field = (done.slice().reverse().find((t) => t.t === 'ident') || {}).v; field = field && field.toLowerCase(); op = 'in'; }
  else if (!last || ['(', 'AND', 'OR', 'NOT'].includes(last.t)) kind = 'field';
  else if (last.t === 'ident') { kind = 'op'; field = last.v.toLowerCase(); }
  else if (last.t === 'op' && prev && prev.t === 'ident') { kind = 'value'; field = prev.v.toLowerCase(); op = last.v; }
  else if ((last.t === 'IN' || last.t === ',') ) { kind = 'value'; field = (done.slice().reverse().find((t) => t.t === 'ident') || {}).v; field = field && field.toLowerCase(); op = 'in'; }
  else if (last.t === 'str' || last.t === 'num' || last.t === ')') kind = 'logic';
  else kind = 'none';
  return { kind, field, op, partial, isOpenStr, start: caret - partial.length };
}
```

- `contextAt` answers "what kind of thing belongs at the caret": a `field`, an `op`, a `value` (and for which field and operator), a `logic` keyword, or `none`. It only looks at the text before the caret.
- Tokenizing the prefix fails if the user is in the middle of a string; the fallback strips the open string and tokenizes the rest.
- `partial` is the word being typed (identifier, open string, or number). If that partial is itself the last complete token (caret right after it, not an open string), it is removed from `done` so the decision is based on what precedes it. Example: in `status >= 4|` the partial is `4`, `done` ends with the `>=` operator, so `kind = 'value'`, `field = 'status'`, `op = '>='`.
- For `in (` lists, the field is found by scanning back to the last identifier, because `(` and `,` tokens sit between.
- `start` is where the replacement will begin when a suggestion is accepted.

```js
// lines 912-935 (the operator description map is abridged)
async function qSuggest() {
  const src = qta.value, caret = qta.selectionStart;
  const c = contextAt(src, caret);
  let items = [];
  const p = c.partial.replace(/^["']/, '').toLowerCase();
  if (c.kind === 'field') items = Object.entries(Q.FIELDS).map(([k, f]) => ({ text: k + ' ', label: k, desc: f.help, tag: f.type }));
  else if (c.kind === 'op') { const f = Q.FIELDS[c.field]; if (f) items = Q.OPS_BY_TYPE[f.type].map((o) => ({ text: o + (o === 'in' ? ' (' : ' '), label: o, desc: { '=': 'equals', ... }[o], tag: 'op' })); }
  else if (c.kind === 'value') {
    const f = Q.FIELDS[c.field]; if (!f) return qAcHide();
    const hints = VALUE_HINTS[c.field] || [];
    const live = c.field === 'student' ? (state.stats ? state.stats.students.map((s) => [s.name, `${s.requests} req`]) : []) : c.field === 'endpoint' ? (state.stats ? state.stats.topEndpoints.filter((e) => !e.name.startsWith('/')).map((e) => [e.name, `${e.count} req`]) : []) : [];
    const fromDb = await dbValues(c.field);
    const seen = new Set();
    const merged = [...hints, ...live, ...fromDb].filter(([v]) => (seen.has(v) ? false : seen.add(v)));
    const quote = (v) => (f.type === 'num' && /^-?\d+(\.\d+)?$/.test(v) ? v : `"${String(v).replace(/"/g, '\\"')}"`);
    items = merged.map(([v, d]) => ({ text: quote(v) + (c.op === 'in' ? ', ' : ' '), label: quote(v), desc: d, tag: f.type }));
    if (c.op === 'in') items.push({ text: ') ', label: ')', desc: 'close the list', tag: '' });
  } else if (c.kind === 'logic') items = [{ text: 'AND ', label: 'AND', desc: 'both conditions', tag: 'logic' }, { text: 'OR ', label: 'OR', desc: 'either condition', tag: 'logic' }];
  if (p) items = items.filter((it) => it.label.toLowerCase().replace(/^"/, '').startsWith(p) || it.label.toLowerCase().includes(p));
  if (!items.length) return qAcHide();
  ac.items = items.slice(0, 40); ac.idx = 0; ac.replace = { start: c.start, end: caret };
  qac.innerHTML = ac.items.map((it, i) => `<div class="${i === 0 ? 'on' : ''}" data-i="${i}"><b>${esc(it.label)}</b><span>${esc(it.desc || '')}</span><em>${esc(it.tag || '')}</em></div>`).join('');
  qac.classList.remove('hidden');
}
```

- Each suggestion is `{text, label, desc, tag}`: `text` is what gets inserted (with trailing space or `, `), `label` is shown bold.
- Value candidates come from three sources merged in priority order: static hints, live stats (student names, endpoint rule names — top endpoints starting with `/` are raw paths, not rule names, and are skipped), and the database. Duplicates are removed keeping the first.
- `quote` wraps text values in double quotes with escaping; numeric fields stay bare when the value looks like a number.
- Filtering by the partial accepts prefix or substring matches. At most 40 items are kept; `ac.replace` records the span to overwrite.

```js
// lines 936-956
function qAcHide() { qac.classList.add('hidden'); ac.items = []; }
function qAcAccept(i) {
  const it = ac.items[i]; if (!it || !ac.replace) return;
  const src = qta.value, before = src.slice(0, ac.replace.start), after = src.slice(ac.replace.end);
  qta.value = before + it.text + after.replace(/^\s+/, '');
  const pos = before.length + it.text.length; qta.setSelectionRange(pos, pos); qta.focus();
  qRender(); qSuggest();
}
qac.addEventListener('mousedown', (e) => { const d = e.target.closest('div[data-i]'); if (d) { e.preventDefault(); qAcAccept(Number(d.dataset.i)); } });
qta.addEventListener('input', () => { qRender(); qSuggest(); });
qta.addEventListener('click', () => qSuggest());
qta.addEventListener('scroll', () => { qhl.scrollTop = qta.scrollTop; });
qta.addEventListener('blur', () => setTimeout(qAcHide, 150));
qta.addEventListener('keydown', (e) => {
  const open = !qac.classList.contains('hidden');
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); qAcHide(); return runQuery(); }
  if (!open) { if (e.key === ' ' && e.ctrlKey) { e.preventDefault(); qSuggest(); } return; }
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); ac.idx = (ac.idx + (e.key === 'ArrowDown' ? 1 : -1) + ac.items.length) % ac.items.length; [...qac.children].forEach((d, i) => d.classList.toggle('on', i === ac.idx)); qac.children[ac.idx].scrollIntoView({ block: 'nearest' }); }
  else if (e.key === 'Tab' || e.key === 'Enter') { e.preventDefault(); qAcAccept(ac.idx); }
  else if (e.key === 'Escape') { e.preventDefault(); qAcHide(); }
});
```

- `qAcAccept` splices the suggestion over the partial, strips any whitespace that followed (the suggestion already ends with one), moves the caret after it, re-highlights and immediately asks for the next suggestion so the user can chain field → op → value with Tab.
- The dropdown uses `mousedown` with `preventDefault` so the textarea does not lose focus before the click is processed; the `blur` handler hides the list 150 ms later for the case where focus really leaves.
- Keyboard: Ctrl/Cmd+Enter runs; Ctrl+Space opens suggestions; with the list open, arrows move (wrapping), Tab/Enter accept, Escape closes. Plain Enter with the list closed inserts a newline, which the parser treats as whitespace.
- The scroll sync keeps the mirror aligned when the textarea is taller than its content box.

```js
// lines 958-963
const HIST_KEY = 'ctfwatch.queries';
const loadHist = () => { try { return JSON.parse(localStorage.getItem(HIST_KEY) || '[]'); } catch { return []; } };
function renderHist() { const h = loadHist(); $('q-hist').innerHTML = h.length ? '<span style="border:0;color:var(--faint);cursor:default;padding-left:0">recent:</span>' + h.map((q) => `<span title="${esc(q)}">${esc(q.length > 48 ? q.slice(0, 46) + '…' : q)}</span>`).join('') : ''; }
$('q-hist').addEventListener('click', (e) => { const s = e.target.closest('span[title]'); if (s) { qta.value = s.title; qRender(); runQuery(); } });
function pushHist(q) { if (!q.trim()) return; try { const h = [q, ...loadHist().filter((x) => x !== q)].slice(0, 12); localStorage.setItem(HIST_KEY, JSON.stringify(h)); } catch {} renderHist(); }
renderHist(); qRender();
```

The last 12 successful queries are kept in `localStorage` per browser. The full query is stored in the pill's `title` attribute (escaped), so clicking a truncated pill still restores the whole text. The "recent:" label has no `title`, so clicking it does nothing. Line 963 draws the history and the initial (empty) lint message at load.

```js
// lines 965-973 (the row template of line 972 is abridged)
async function runQuery() {
  $('q-err').textContent = ''; $('q-sql').classList.add('hidden'); $('q-info').textContent = 'running…';
  const j = await api('/api/query', { q: $('q').value, limit: Number($('q-limit').value), ctf: $('q-ctf').value || undefined }).catch((e) => { $('q-err').textContent = e.message; return null; });
  if (!j) { $('q-info').textContent = ''; return; }
  pushHist($('q').value);
  lastRows = j.rows; $('q-csv').disabled = $('q-json').disabled = !j.rows.length;
  $('q-info').textContent = `${j.count} row${j.count === 1 ? '' : 's'}`; $('q-sql').textContent = j.sql + '   -- params: ' + JSON.stringify(j.params); $('q-sql').classList.remove('hidden');
  $('q-rows').innerHTML = j.rows.map((r) => `<tr class="...">...</tr>`).join('');
}
```

- `api` (not `tryApi`) so the error is shown inline in `#q-err` rather than in an alert box. The server echoes the compiled SQL and parameters, shown under the editor for learning and debugging.
- Rows are database rows (`object_id`, `latency`, `ctf_id`, `flags` array, `attacks` array), not live event objects, so the column names differ from the live tables; `flagsHtml` is called with `attacks: []` and the attack classes rendered separately (972).
- `lastRows` feeds the two export buttons: JSON (976–978) wraps the rows with the query text and a timestamp; CSV (979–983) writes a fixed column list, converts `ts` to ISO, JSON-encodes nested values and double-quotes everything. Both use a temporary `<a download>` with a Blob URL.
- `loadCtfOptions` (984) fills `#q-ctf` from `/api/ctfs` so a past CTF can be queried; the empty option means "current (or replayed) CTF", which the server resolves (`scopeCtf`, dashboard.js 49).

### CTFs view: target (lines 987–1028)

```js
// lines 987-1002
function renderTarget(t) {
  $('target-badge').textContent = t ? '→ ' + t.replace(/^http:\/\//, '') : '→ no CTF';
  $('target-badge').style.color = t ? 'var(--good)' : 'var(--notice)';
  $('tg-current').textContent = t || 'nothing (proxy answers "CTF not open yet")';
  $('tg-disconnect').classList.toggle('hidden', !t || !(state.me && state.me.role === 'admin'));
  $('tg-manual').value = t || '';
}
function renderLink(l) {
  if (!l) return;
  const has = !!l.url;
  $('tg-link').textContent = has ? l.url : `http://127.0.0.1:${l.proxyPort || 8888} (this machine only)`;
  $('tg-link').style.color = has ? 'var(--good)' : 'var(--notice)';
  $('tg-copy').classList.toggle('hidden', !has);
  $('tg-copy').dataset.url = l.url || '';
  $('tg-link-note').textContent = has ? `zrok share (${l.source}${l.since ? ', since ' + fmtTime(l.since) : ''})` : (l.hint || '');
}
```

- `renderTarget(t)` takes the upstream URL (or `null`) and updates the header badge, the "currently reaches" line, the Disconnect button and the manual input. It is called from boot (1221), from every stats tick when the target changed (1191, skipped while the user is typing in `#tg-manual`), and after target changes.
- `renderLink` shows the public student link (a zrok share when one exists, otherwise the local proxy address). The copy button stores the URL in `dataset.url`; the click handler (1003) uses the Clipboard API and falls back to a `prompt` when the API is unavailable (non-secure context).

```js
// lines 1004-1018 (row template abridged)
async function scanTargets() {
  $('tg-rows').innerHTML = '<tr><td colspan="4" style="color:var(--faint)">scanning…</td></tr>';
  tryApi('/api/link').then(renderLink); // quick, independent of the port scan
  const j = await tryApi('/api/targets'); if (!j) return;
  renderTarget(j.current); renderLink(j.link);
  const isAdmin = state.me && state.me.role === 'admin';
  $('tg-rows').innerHTML = j.candidates.map((c) => {
    const p = c.probe || {};
    const looks = p.ok ? `<span class="st s${String(p.status)[0]}">${p.status}</span> ${esc(p.title || p.contentType || '')}...` : `<span style="color:var(--faint)">not http (${esc(p.error || '')})</span>`;
    const where = c.container ? `🐳 ${esc(c.container)} ...` : c.source === 'desktop-host' ? 'process on this computer' : `host process...`;
    const cur = j.current === c.url;
    const isDecoy = dc.target === c.url;
    return `<tr class="${cur ? 'sev-warn' : ''}"><td>${esc(c.url)}${cur ? ' <span class="lvl low">current</span>' : ''}${isDecoy ? ' <span class="lvl medium">decoy</span>' : ''}</td><td>${where}</td><td>${looks}</td><td>${isAdmin && !cur ? `<button class="small tg-use" data-url="${esc(c.url)}" data-label="...">▶ Use</button> ` : ''}${isAdmin && !cur && !isDecoy ? `<button class="small tg-decoy" data-url="${esc(c.url)}">🪤 decoy</button>` : ''}</td></tr>`;
  }).join('') || '<tr><td colspan="4" style="color:var(--faint)">no listening ports found</td></tr>';
}
```

- `/api/targets` runs a port/container scan on the server and can take seconds; `/api/link` is fetched in parallel so the link appears immediately.
- Each candidate has an HTTP probe result (`status`, `title`, `server`, `location`) and a provenance (`container`/`image`, `desktop-host`, or a host process with its bind address). The row for the current target is tinted and has no buttons; rows that are the decoy lose the decoy button. `dc.target` is read here, so `showView('ctfs')` loads the decoy before scanning (545).

```js
// lines 1019-1028
async function useTarget(url, label) {
  const total = state.stats ? state.stats.total : 0;
  let newCtf = false, ctfName = '';
  if (total > 0) { newCtf = confirm(`Switch the proxy to ${url}.\n\nAlso start a NEW CTF record for it? (OK = yes, the current one is closed and kept; Cancel = keep recording into the current CTF)`); }
  if (newCtf) { ctfName = prompt('Name of the new CTF:', label || url.replace(/^http:\/\//, '')); if (ctfName === null) return; }
  const j = await tryApi('/api/targets', { url, label, newCtf, ctfName });
  if (j) { renderTarget(j.target); scanTargets(); loadCtfs(); }
}
$('tg-scan').addEventListener('click', scanTargets);
$('tg-rows').addEventListener('click', (e) => { const b = e.target.closest('button.tg-use'); if (b) return useTarget(b.dataset.url, b.dataset.label); const d = e.target.closest('button.tg-decoy'); if (d) setDecoy(d.dataset.url); });
```

- The "new CTF record?" question is only asked if the current record already has traffic; otherwise the server itself opens a record when none is active (dashboard.js 146). Cancelling the name prompt aborts the whole switch (`ctfName === null`).
- `useTarget` is shared with the Playground ("Point proxy here", 1177) and the manual input (1054).

### Decoy (lines 1031–1055)

```js
// lines 1031-1043
const dc = { target: null, students: [] };
function renderDecoy() {
  const on = !!dc.target, isAdmin = state.me && state.me.role === 'admin';
  $('dc-state').textContent = on ? 'on' : 'off'; $('dc-state').style.color = on ? 'var(--warn)' : 'var(--muted)';
  if ($('dc-url') !== document.activeElement) $('dc-url').value = dc.target || '';
  $('dc-clear').classList.toggle('hidden', !on || !isAdmin);
  $('dc-note').textContent = on ? `students on the list are routed to ${dc.target}` : 'no decoy set: everyone reaches the real CTF';
  $('dc-list').innerHTML = dc.students.length ? dc.students.map((s) => `<span class="chip" style="margin:2px 4px 2px 0">🪤 ${esc(s.name)} <span style="color:var(--faint)">${fmtTime(s.since)}${s.by ? ' · ' + esc(s.by) : ''}</span>${isAdmin ? ` <b class="dc-rm" data-name="${esc(s.name)}" title="back to the real CTF" style="cursor:pointer;color:var(--critical)">✕</b>` : ''}</span>`).join('') : '<span style="color:var(--faint)">nobody</span>';
  for (const L of state.lanes.values()) { const b = L.el.querySelector('.dcb'); if (b) b.classList.toggle('hidden', !dc.students.some((s) => s.name === L.name)); }
}
function decoyUpdate(m) { dc.target = m.target; dc.students = m.students || []; renderDecoy(); updateActions(); if (state.view === 'requests' && rq.sel) rqRenderSide(); }
async function loadDecoy() { const j = await tryApi('/api/decoy'); if (j) decoyUpdate(j); }
async function setDecoy(url) { const j = await tryApi('/api/decoy', { url: url || null }); if (j) { decoyUpdate(j); scanTargets(); } }
```

- `dc` mirrors the server's decoy state: the decoy URL and the list of `{name, since, by}` routed to it. `decoyUpdate` is the single entry point, used by the initial load, by every decoy API response and by the `decoy` WebSocket message (1188); after updating it refreshes the lane markers, the live card and the requests card.
- The URL input is not overwritten while focused, so a push from another organizer does not clobber what the admin is typing.

```js
// lines 1044-1055
$('dc-set').addEventListener('click', () => { const v = $('dc-url').value.trim(); if (v) setDecoy(v); });
$('dc-clear').addEventListener('click', () => { if (confirm('Remove the decoy? Students on the list go back to the real CTF.')) setDecoy(null); });
$('dc-add-btn').addEventListener('click', async () => { const n = $('dc-add').value.trim(); if (!n) return; const j = await tryApi('/api/decoy/add', { student: n }); if (j) { $('dc-add').value = ''; decoyUpdate(j); } });
$('dc-list').addEventListener('click', async (e) => { const b = e.target.closest('.dc-rm'); if (b) { const j = await tryApi('/api/decoy/remove', { student: b.dataset.name }); if (j) decoyUpdate(j); } });
async function toggleDecoy(name) {
  const on = dc.students.some((s) => s.name === name);
  if (!on && !dc.target) return alert('Pick a decoy app first (CTFs tab, "Decoy app behind the proxy").');
  if (!on && !confirm(`Route "${name}" to the decoy app?\n\nThey keep the same link and will not notice anything.`)) return;
  const j = await tryApi(on ? '/api/decoy/remove' : '/api/decoy/add', { student: name }); if (j) decoyUpdate(j);
}
$('tg-use-manual').addEventListener('click', () => { const v = $('tg-manual').value.trim(); if (v) useTarget(v, ''); });
$('tg-disconnect').addEventListener('click', async () => { if (confirm('Disconnect the proxy from the CTF app? Students will see "CTF not open yet".')) { const j = await tryApi('/api/targets', { url: null }); if (j) { renderTarget(null); scanTargets(); } } });
```

`toggleDecoy` is the action behind the card buttons in both sidebars. It refuses when no decoy app is configured and confirms before adding (removing is silent). The server responds with the full decoy list, which is applied immediately rather than waiting for the broadcast.

### CTFs view: events, blocked, session, replay (lines 1058–1089)

```js
// lines 1058-1072 (row templates abridged)
async function loadCtfs() {
  const [j, adm] = await Promise.all([tryApi('/api/ctfs'), tryApi('/api/admin')]); if (!j) return;
  state.ctfs = j.list; const isAdmin = state.me && state.me.role === 'admin';
  $('ctf-rows').innerHTML = j.list.map((c) => `<tr><td>${c.id}</td><td>${esc(c.name)}${j.active && j.active.id === c.id ? ' <span class="lvl low">active</span>' : ''}${c.imported ? ' <span class="lvl info">imported</span>' : ''}</td><td>${fmtDate(c.started_at)}</td><td>${fmtDate(c.ended_at)}</td><td>${c.students}</td><td>${c.requests}</td><td>${c.alerts}</td>
    <td><a href="/api/export?ctf=${c.id}" ...>⬇ export .json</a>${isAdmin && !(j.active && j.active.id === c.id) ? ` · <button class="small replay" data-id="${c.id}">▶ replay</button> <select class="small spd" data-id="${c.id}">...1x/10x/60x/max...</select>` : ''}</td></tr>`).join('');
  if (adm) {
    $('adm-blocked').innerHTML = adm.blocked.map((b) => `<li>...${isAdmin ? `<button class="small unb" data-name="${esc(b.name)}">unblock</button>` : ''}</li>`).join('') || '<li>...nobody</li>';
    $('adm-ips').innerHTML = adm.dashboardBlockedIps.map((b) => `<li>...${isAdmin ? `<button class="small unbip" data-ip="${esc(b.ip)}">unblock</button>` : ''}</li>`).join('') || '<li>...none</li>';
    $('adm-pending').innerHTML = adm.renamePending.map((n) => `<li><span>${esc(n)}</span></li>`).join('') || '<li>...none</li>';
  }
  $('adm-me').innerHTML = [['user', state.me.username], ['role', state.me.role], ['active CTF', j.active ? `#${j.active.id} ${j.active.name}` : '– (stopped)']].map(...).join('');
  $('ctf-stop').classList.toggle('hidden', !(isAdmin && j.active));
  $('ctf-name').textContent = j.active ? j.active.name : 'no active CTF';
  $('ctf-name').style.color = j.active ? '' : 'var(--notice)';
}
```

- Two requests in parallel. `/api/ctfs` gives `{active, list}`; `/api/admin` gives the blocked players, dashboard-blocked IPs and rename-pending names. Replay controls are only offered for CTFs that are not active (you cannot replay the record you are writing to).
- The export link is a plain `<a href>`: the server answers with `Content-Disposition: attachment` (dashboard.js 249), so the browser downloads it. That is also why there is no `X-Requested-With` needed: it is a GET.

```js
// lines 1073-1082 (the confirm text of line 1074 is abridged)
$('ctf-stop').addEventListener('click', async () => {
  if (!confirm('Stop the current CTF?\n\n...')) return;
  const j = await tryApi('/api/ctfs/stop', {}); if (j) { renderTarget(null); loadCtfs(); scanTargets(); }
});
$('ctf-rows').addEventListener('click', async (e) => { const b = e.target.closest('button.replay'); if (!b) return; const id = b.dataset.id, spd = $('view-ctfs').querySelector(`select.spd[data-id="${id}"]`).value; if (confirm(`Replay CTF #${id} at ${spd}x into the live view?`)) { await tryApi('/api/replay', { ctf: Number(id), speed: Number(spd) }); showView('live', true); } });
$('adm-blocked').addEventListener('click', async (e) => { const b = e.target.closest('button.unb'); if (b) { await tryApi('/api/admin/unblock', { student: b.dataset.name }); loadCtfs(); } });
$('adm-ips').addEventListener('click', async (e) => { const b = e.target.closest('button.unbip'); if (b) { await tryApi('/api/admin/unblock-ip', { ip: b.dataset.ip }); loadCtfs(); } });
$('ctf-new').addEventListener('click', async () => { const n = prompt('Name of the new CTF (the current one is closed, its data stays):'); if (n === null) return; const j = await tryApi('/api/ctfs/new', { name: n }); if (j) { loadCtfs(); } });
$('ctf-import').addEventListener('change', async (e) => { const f = e.target.files[0]; if (!f) return; let data; try { data = JSON.parse(await f.text()); } catch { return alert('not a JSON file'); } const j = await tryApi('/api/import', data); if (j) { alert(`Imported as CTF #${j.ctf.id}. Use ▶ replay to watch it.`); loadCtfs(); } e.target.value = ''; });
$('replay-stop').addEventListener('click', async () => { await tryApi('/api/replay/stop', {}); });
```

- Replay: the speed is read from the `select.spd` sharing the same `data-id`; after starting, the page switches to Live, where the server's reset snapshot (dashboard.js 413) clears the lanes and the replayed events stream in.
- Import: the file is parsed in the browser (fast failure for non-JSON) and POSTed whole; the server accepts up to 200 MB. Resetting `e.target.value` lets the same file be chosen again.

```js
// lines 1083-1089
function renderReplay(r) {
  const running = !!(r && r.running), loaded = !!(r && r.loaded);
  $('replay-badge').classList.toggle('hidden', !running && !loaded);
  $('replay-badge').textContent = running ? `REPLAY #${r.ctfId} ${Math.round((r.done / r.total) * 100)}%` : loaded ? `REPLAY #${r.loaded} (finished)` : 'REPLAY';
  $('replay-stop').classList.toggle('hidden', !running);
  $('replay-status').textContent = running ? `replaying CTF #${r.ctfId} at ${r.speed}x: ${r.done}/${r.total}` : loaded ? `live view shows replayed CTF #${r.loaded}; alerts, student pages and queries read it too. Stop CTF or New CTF to go back live.` : '';
}
```

Replay has two states worth showing: `running` (progress) and `loaded` (finished but the live store still holds the replayed CTF). It is driven by `/api/me` at boot and by the `replay` field of every stats message.

### Gate view (lines 1092–1122)

```js
// lines 1092-1095
let gateCfg = null;
function gateFromForm() {
  return { enabled: $('gt-enabled').checked, strict: $('gt-strict').checked, queue: $('gt-queue').checked, title: $('gt-title').value, intro: $('gt-intro').value, button: $('gt-button').value, waitTitle: $('gt-wait-title').value, waitText: $('gt-wait-text').value, fields: gateCfg.fields };
}
```

`gateCfg` is the working copy of the gate configuration. The scalar settings live in the form inputs and are read back by `gateFromForm`; the `fields` array lives only in `gateCfg.fields` and is edited in place by the table handlers. So `gateFromForm()` is always "what the admin sees now", saved or not.

```js
// lines 1096-1111 (the field-row template is abridged)
function renderGate() {
  const c = gateCfg; if (!c) return;
  $('gt-state').textContent = c.enabled ? `on${c.strict ? ' · strict' : ''}${c.queue ? ' · queue' : ''}` : 'off'; $('gt-state').style.color = c.enabled ? 'var(--good)' : 'var(--notice)';
  $('gt-enabled').checked = c.enabled; ... $('gt-wait-text').value = c.waitText || '';
  $('gt-fields').innerHTML = c.fields.map((f, i) => `<tr><td><code>${esc(f.key)}</code>${f.locked ? ' 🔒' : ''}</td><td><input data-i="${i}" data-k="label" value="${esc(f.label)}"></td>
    <td>${f.locked ? 'text' : `<select data-i="${i}" data-k="type">...</select>`}</td>
    <td>${f.locked ? 'yes' : `<input type="checkbox" data-i="${i}" data-k="required" ${f.required ? 'checked' : ''}>`}</td>
    <td><input data-i="${i}" data-k="${f.type === 'select' ? 'options' : 'placeholder'}" value="..."></td>
    <td>${i > 1 ? `<button class="small gt-up" data-i="${i}">↑</button>` : ''}${i > 0 && i < c.fields.length - 1 ? ` <button class="small gt-down" data-i="${i}">↓</button>` : ''}${f.locked ? '' : ` <button class="small danger gt-del" data-i="${i}">✕</button>`}</td></tr>`).join('');
  $('gt-frame').src = '/api/gate/preview?config=' + encodeURIComponent(JSON.stringify(gateFromForm()));
}
async function loadGate() {
  const j = await tryApi('/api/gate'); if (!j) return;
  gateCfg = j.config; renderGate();
  const isAdmin = state.me && state.me.role === 'admin'; $('gt-readonly').classList.toggle('hidden', isAdmin);
}
```

- Every input in the fields table carries `data-i` (field index) and `data-k` (property name). The first field (`username`) is `locked`: its type and required flag are fixed text and it has no delete button. Move buttons: `↑` only from index 2 (index 1 cannot move above the locked field), `↓` for 1 ≤ i < last.
- For `select` fields the fifth column edits `options` (comma-separated); for other types it edits `placeholder`.
- The preview iframe loads `/api/gate/preview?config=<json>`: the server renders the real gate page with the unsaved configuration (dashboard.js 272–285), with the form's submit disabled and `frame-ancestors 'self'` so it can be framed by the dashboard only.

```js
// lines 1112-1122 (reset defaults abridged)
$('gt-fields').addEventListener('input', (e) => { const el = e.target; if (!el.dataset.k) return; const f = gateCfg.fields[Number(el.dataset.i)]; if (!f) return;
  if (el.dataset.k === 'required') f.required = el.checked; else if (el.dataset.k === 'options') f.options = el.value.split(/[\n,]/).map((s) => s.trim()).filter(Boolean); else f[el.dataset.k] = el.value;
  if (el.dataset.k === 'type') renderGate(); else $('gt-frame').src = '/api/gate/preview?config=' + encodeURIComponent(JSON.stringify(gateFromForm())); });
$('gt-fields').addEventListener('click', (e) => { const b = e.target.closest('button'); if (!b) return; const i = Number(b.dataset.i), f = gateCfg.fields;
  if (b.classList.contains('gt-del')) f.splice(i, 1); else if (b.classList.contains('gt-up') && i > 1) [f[i - 1], f[i]] = [f[i], f[i - 1]]; else if (b.classList.contains('gt-down') && i < f.length - 1) [f[i + 1], f[i]] = [f[i], f[i + 1]]; renderGate(); });
$('gt-add').addEventListener('click', () => { const key = $('gt-new-key').value.trim().toLowerCase().replace(/[^a-z0-9_]/g, ''); if (!key) return alert('key: letters, digits, _'); if (gateCfg.fields.some((f) => f.key === key)) return alert('that key already exists');
  gateCfg.fields.push({ key, label: $('gt-new-label').value.trim() || key, type: $('gt-new-type').value, required: $('gt-new-req').checked, placeholder: '', options: $('gt-new-type').value === 'select' ? [] : undefined }); $('gt-new-key').value = ''; $('gt-new-label').value = ''; renderGate(); });
for (const id of ['gt-enabled', 'gt-strict', 'gt-queue', 'gt-title', 'gt-intro', 'gt-button', 'gt-wait-title', 'gt-wait-text']) $(id).addEventListener('input', () => { $('gt-frame').src = '/api/gate/preview?config=' + encodeURIComponent(JSON.stringify(gateFromForm())); });
$('gt-save').addEventListener('click', async () => { const j = await tryApi('/api/gate', gateFromForm()); if (j) { gateCfg = j.config; renderGate(); $('gt-msg').textContent = 'saved ✓ (students see it on their next page load)'; setTimeout(() => ($('gt-msg').textContent = ''), 3000); } });
$('gt-preview').addEventListener('click', () => window.open('/api/gate/preview?config=' + encodeURIComponent(JSON.stringify(gateFromForm())), '_blank'));
$('gt-reset').addEventListener('click', () => { if (confirm('Reset the gate form to the default (username only, strict, queue)?')) { gateCfg = { enabled: true, strict: true, queue: true, title: 'Welcome to the CTF', ..., fields: [{ key: 'username', label: 'Your name', type: 'text', required: true, placeholder: 'Your name', locked: true }] }; renderGate(); } });
```

- Typing in a field row updates `gateCfg.fields[i]` in place and refreshes only the iframe; changing a field's *type* re-renders the whole table because the fifth column changes meaning. Structural edits (delete, move, add) always re-render.
- The key is normalised to `[a-z0-9_]` and must be unique.
- Save POSTs the form; the server normalises and returns the stored config, which replaces the working copy (so any server-side cleanup is reflected). Reset only changes the working copy; Save is still needed.

### Queue (lines 1125–1151)

```js
// lines 1125-1132
const qu = { items: [], counts: { pending: 0, approved: 0, blocked: 0 }, fields: [], filter: 'pending', search: '', sel: new Set(), enabled: true };
function renderQueue() {
  const isAdmin = state.me && state.me.role === 'admin';
  $('qu-off').classList.toggle('hidden', qu.enabled);
  $('qu-chips').innerHTML = ['pending', 'approved', 'blocked', 'all'].map((s) => `<span class="chip ${qu.filter === s ? 'on' : ''}" data-s="${s}">${...icon...} ${s}<b>${s === 'all' ? qu.items.length : qu.counts[s] || 0}</b></span>`).join(' ');
  const extra = qu.fields.filter((f) => f.key !== 'username');
  $('qu-head').innerHTML = `<tr><th><input type="checkbox" id="qu-all" title="select all shown"></th><th>status</th><th>name</th>${extra.map((f) => `<th>${esc(f.label)}</th>`).join('')}<th>ip</th><th>user agent</th><th>waiting since</th><th>decided</th><th></th></tr>`;
  const rows = qu.items.filter((it) => (qu.filter === 'all' || it.status === qu.filter) && (!qu.search || `${it.name} ${Object.values(it.profile || {}).join(' ')} ${it.ip || ''}`.toLowerCase().includes(qu.search)));
```

- `qu` holds the admission queue: `items` (`{name, status, profile, ip, ua, firstSeen, decidedAt, by}`), the status `counts`, the gate `fields` (so the extra gate answers become columns), the active status filter, the search text, the selection (a Set of names) and whether the queue is enabled at all.
- The table head is generated because its columns depend on the gate configuration. `#qu-all` therefore exists only after the first render, which is why its listener is delegated to `#qu-head` (1147).

```js
// lines 1133-1144 (row template abridged)
  $('qu-rows').innerHTML = rows.map((it) => `<tr class="${it.status === 'blocked' ? 'sev-critical' : it.status === 'pending' ? 'sev-warn' : ''}" data-name="${esc(it.name)}">
    <td><input type="checkbox" class="qu-cb" data-name="${esc(it.name)}" ${qu.sel.has(it.name) ? 'checked' : ''}></td>
    <td><span class="lvl ${it.status === 'pending' ? 'low' : it.status === 'approved' ? 'info' : 'critical'}">${it.status}</span></td>
    <td><b>${esc(it.name)}</b></td>${extra.map((f) => `<td>${esc((it.profile || {})[f.key] ?? '')}</td>`).join('')}
    <td>${esc(it.ip || '')}</td><td title="${esc(it.ua || '')}">${esc((it.ua || '').slice(0, 40))}</td><td>${fmtTime(it.firstSeen)}</td><td>${it.decidedAt ? `${fmtTime(it.decidedAt)}${it.by ? ' · ' + esc(it.by) : ''}` : ''}</td>
    <td style="white-space:nowrap">${isAdmin ? `...Approve / to decoy / Block / back to queue buttons with class qu-act and data-act...` : ''}</td></tr>`).join('') || `<tr><td colspan="${8 + extra.length}" ...>${qu.filter === 'pending' ? 'nobody is waiting' : 'nothing here'}</td></tr>`;
  $('qu-selinfo').textContent = qu.sel.size ? `${qu.sel.size} selected` : '';
  $('qu-approve-sel').disabled = $('qu-block-sel').disabled = !qu.sel.size;
  $('nav-queue').textContent = qu.counts.pending || ''; $('nav-queue').classList.toggle('hidden', !qu.enabled || !qu.counts.pending);
}
async function loadQueue() { const j = await tryApi('/api/queue'); if (!j) return; qu.enabled = j.enabled; qu.fields = j.fields; qu.items = j.items; qu.counts = j.counts; renderQueue(); }
function queueUpdate(m) { qu.items = m.items; qu.counts = m.counts; for (const n of [...qu.sel]) if (!qu.items.some((it) => it.name === n && it.status === 'pending')) qu.sel.delete(n); if (state.view === 'queue') renderQueue(); else { $('nav-queue').textContent = qu.counts.pending || ''; $('nav-queue').classList.toggle('hidden', !qu.enabled || !qu.counts.pending); } }
```

- The action buttons offered depend on the row's status: Approve (and "to decoy" when a decoy app is set) unless already approved, Block unless already blocked, "back to queue" unless pending.
- `queueUpdate` is called for the `queue` WebSocket message (1187): the server pushes the full list on every arrival or decision, so there is no polling. Selected names that are no longer pending are dropped from the selection. If the view is not open only the nav bubble is updated, which keeps the per-message cost low.
- `loadQueue` (on entering the view) additionally fetches `enabled` and `fields`, which the push message does not carry; `enabled` is also refreshed from each stats message (1194).

```js
// lines 1145-1151
$('qu-chips').addEventListener('click', (e) => { const c = e.target.closest('.chip'); if (c) { qu.filter = c.dataset.s; renderQueue(); } });
$('qu-search').addEventListener('input', (e) => { qu.search = e.target.value.trim().toLowerCase(); renderQueue(); });
$('qu-head').addEventListener('change', (e) => { if (e.target.id === 'qu-all') { for (const cb of document.querySelectorAll('.qu-cb')) { cb.checked = e.target.checked; e.target.checked ? qu.sel.add(cb.dataset.name) : qu.sel.delete(cb.dataset.name); } renderQueue(); } });
$('qu-rows').addEventListener('change', (e) => { const cb = e.target.closest('.qu-cb'); if (cb) { cb.checked ? qu.sel.add(cb.dataset.name) : qu.sel.delete(cb.dataset.name); $('qu-selinfo').textContent = qu.sel.size ? `${qu.sel.size} selected` : ''; $('qu-approve-sel').disabled = $('qu-block-sel').disabled = !qu.sel.size; } });
$('qu-rows').addEventListener('click', async (e) => { const b = e.target.closest('button.qu-act'); if (!b) return; if (b.dataset.act === 'block' && !confirm(`Block "${b.dataset.name}"? They will not be able to reach the CTF.`)) return; if (b.dataset.act === 'approve-decoy') return tryApi('/api/queue/approve', { names: [b.dataset.name], decoy: true }); await tryApi('/api/queue/' + b.dataset.act, { names: [b.dataset.name] }); });
$('qu-approve-sel').addEventListener('click', async () => { if (qu.sel.size) { await tryApi('/api/queue/approve', { names: [...qu.sel] }); qu.sel.clear(); } });
$('qu-block-sel').addEventListener('click', async () => { if (qu.sel.size && confirm(`Block ${qu.sel.size} student(s)?`)) { await tryApi('/api/queue/block', { names: [...qu.sel] }); qu.sel.clear(); } });
```

- "Select all" only affects the checkboxes currently rendered (the filtered rows). A single checkbox change updates the selection info without a full re-render so the other checkboxes keep focus.
- Per-row actions map `data-act` directly onto `/api/queue/<act>` (`approve`, `block`, `reset`); `approve-decoy` is the exception, calling `approve` with `decoy: true`. None of the handlers re-render: the server broadcasts the new list and `queueUpdate` does it.

### Playground (lines 1154–1181)

```js
// lines 1154-1158
let pgTimer = null;
function simConfig() {
  return { honest: Number($('pg-honest').value), enumerator: $('pg-enumerator').checked, sniper: $('pg-sniper').checked, noisy: $('pg-noisy').checked, anonymous: $('pg-anonymous').checked, attacker: $('pg-attacker').checked,
    pace: Number($('pg-pace').value), rounds: Number($('pg-rounds').value), loop: $('pg-loop').checked, target: $('pg-target').value.trim() || undefined };
}
```

`simConfig` reads the fake-student form into the object the server's simulator expects. `target` is `undefined` when empty so the server uses its default (the proxy).

```js
// lines 1159-1174 (info templates abridged)
function renderPlayground(p) {
  if (!p) return;
  const m = p.mock, s = p.sim;
  $('pg-mock-state').textContent = m.running ? 'running' : 'stopped'; ...
  $('pg-sim-state').textContent = s.running ? 'running' : 'stopped'; ...
  $('pg-mock-info').innerHTML = [['address', m.url], ['status', m.running ? `running since ${fmtTime(m.startedAt)} (pid ${m.pid})` : m.lastExit ? `exited ${fmtTime(m.lastExit.at)}` : 'not started'], ['proxy points here', getCurrentTarget() === m.url ? 'yes' : 'no']].map(...).join('');
  $('pg-mock-log').textContent = m.log.join('\n') || '(no output yet)';
  const c = s.config || {};
  $('pg-sim-info').innerHTML = [['status', ...], ['sending to', c.target || '–'], ['players', ...], ['pace / rounds', ...]].map(...).join('');
  $('pg-sim-log').textContent = s.log.join('\n') || '(no output yet)';
  if (!m.running && $('pg-mock-port').value === '' ) $('pg-mock-port').value = m.port;
  $('pg-mock-use').disabled = !m.running; $('pg-mock-stop').disabled = !m.running; $('pg-mock-start').disabled = m.running; $('pg-sim-stop').disabled = !s.running; $('pg-sim-start').disabled = s.running;
}
let currentTarget = null; function getCurrentTarget() { return currentTarget; }
async function loadPlayground() { const p = await tryApi('/api/playground'); renderPlayground(p); clearInterval(pgTimer); pgTimer = setInterval(async () => { if (state.view !== 'playground') return clearInterval(pgTimer); renderPlayground(await api('/api/playground').catch(() => null)); }, 2000); }
const pg = async (path, body) => { const j = await tryApi(path, body || {}); if (j) renderPlayground(j); return j; };
```

- The playground status (`mock` child process and `sim` child process, each with `running`, `log`, timestamps) is polled every 2 s while the view is open; the interval cancels itself when the view changes. This is the only polling in the page; everything else is pushed.
- `currentTarget` is a module-level copy of the proxy target, kept current by boot (1221) and the stats message (1191), used to say whether the proxy points at the mock app.
- `pg` is a small helper: POST, then render the returned status (every playground POST returns the full status).

```js
// lines 1175-1181
$('pg-mock-start').addEventListener('click', () => pg('/api/playground/mock', { action: 'start', port: Number($('pg-mock-port').value) }));
$('pg-mock-stop').addEventListener('click', () => pg('/api/playground/mock', { action: 'stop' }));
$('pg-mock-use').addEventListener('click', async () => { const p = await api('/api/playground'); await useTarget(p.mock.url, 'mock CTF app'); loadPlayground(); });
$('pg-sim-start').addEventListener('click', () => pg('/api/playground/sim', { action: 'start', config: simConfig() }));
$('pg-sim-stop').addEventListener('click', () => pg('/api/playground/sim', { action: 'stop' }));
$('pg-quick').addEventListener('click', async () => { if (!confirm('Start the mock app, point the proxy at it in a new CTF record "playground", and start the fake students?')) return; const j = await pg('/api/playground/quick', { port: Number($('pg-mock-port').value), config: simConfig() }); if (j) { renderTarget(j.target); showView('live', true); } });
$('pg-stop-all').addEventListener('click', () => pg('/api/playground/stop-all'));
```

"Point proxy here" reuses `useTarget` (with its new-CTF question). "Start everything" is the one-click demo: the server starts the mock app, opens a CTF record named `playground`, points the proxy at it and starts the simulator, after which the page jumps to Live.

### WebSocket (lines 1184–1214)

```js
// lines 1184-1197
function handleMessage(m, live) {
  if (m.type === 'event') { addDot(m.event, live); addRow(m.event); rqFeed(m.event); }
  else if (m.type === 'alert') { addFeedAlert(m.alert, live); state.alerts.unshift(m.alert); if (state.view === 'alerts') { renderLevelChips(); renderAlertsTable(); } }
  else if (m.type === 'queue') queueUpdate(m);
  else if (m.type === 'decoy') decoyUpdate(m);
  else if (m.type === 'stats') {
    renderStats(m.stats); renderReplay(m.replay);
    if (m.target !== undefined) { currentTarget = m.target; if ($('tg-manual') !== document.activeElement) renderTarget(m.target); }
    if (m.mock) { $('demo-badge').classList.toggle('hidden', !m.mock.sim); $('nav-mock').classList.toggle('hidden', !(m.mock.app || m.mock.sim)); }
    if (m.gate !== undefined) $('nav-gate').classList.toggle('hidden', !!m.gate);
    if (m.queue !== undefined) { qu.enabled = !!m.queue; if (m.queue) qu.counts = m.queue; $('nav-queue').textContent = qu.enabled ? (qu.counts.pending || '') : ''; $('nav-queue').classList.toggle('hidden', !qu.enabled || !qu.counts.pending); }
    if (state.view === 'alerts') renderLevelChips();
  }
}
```

The dispatcher for every pushed message (the `snapshot` type is handled before this, in `onmessage`). `live` is `true` for messages arriving in real time and `false` when draining the pause buffer, and it only controls animations.

- `event`: one proxied request → a dot in its lane, a row in the recent table, a row in the Requests view.
- `alert`: feed + `state.alerts`; the Alerts table is re-rendered only if visible.
- `queue` / `decoy`: delegated to the view code described above.
- `stats` (once a second; see dashboard.js 417 for the exact shape): the live stats, the replay status, the proxy target, the mock/sim flags for the two header badges, the gate state (`m.gate` is a boolean; the "off" bubble is shown when it is false) and the queue counts (`m.queue` is `null` when the queue is switched off, otherwise the counts object).

```js
// lines 1198-1206
function loadSnapshot(s) {
  if (state.serverStart && s.stats.startedAt && s.stats.startedAt !== state.serverStart) { location.reload(); return; }
  state.serverStart = s.stats.startedAt;
  $('lanes').querySelectorAll('.lane').forEach((e) => e.remove()); state.lanes.clear(); laneCounts.clear(); $('rows').innerHTML = ''; $('alerts').innerHTML = ''; $('rq-rows').innerHTML = '';
  for (const ev of s.events) { addDot(ev, false); addRow(ev); rqAddRow(ev); }
  for (const a of s.alerts) addFeedAlert(a, false);
  for (const st of s.stats.students) { lane(st.name, st.source); addFilterOption(st.name); }
  renderStats(s.stats); setStudentQuery($('filter').value);
}
```

- A snapshot (`{events (last 500), alerts (last 150), stats}`) arrives on every (re)connection and whenever the server resets its store (new CTF, stop, replay). It rebuilds the three live lists from scratch.
- The server-restart trick: `stats.startedAt` is the server process start time. If the page has seen a different value before, the server was restarted, which means accounts and sessions were regenerated; the cleanest thing to do is a full reload, which lands on `/login` through the 401 path. On the very first snapshot `serverStart` is null, so it is simply recorded.
- Lanes are created for every known student, not just those with events in the last 500, so quiet students still appear. Finally the current search is re-applied to the rebuilt DOM.

```js
// lines 1207-1214
let retry = 1000;
function connect() {
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  ws.onopen = () => { $('live').className = 'live on'; retry = 1000; };
  ws.onclose = (e) => { $('live').className = 'live off'; if (e.code === 1006 && retry > 4000) fetch('/api/me', { headers: { 'X-Requested-With': 'ctf-watch' } }).then((r) => r.status === 401 && (location.href = '/login')); setTimeout(connect, retry); retry = Math.min(retry * 2, 10000); };
  ws.onerror = () => ws.close();
  ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.type === 'snapshot') return loadSnapshot(m); if (state.paused && m.type !== 'stats') { state.buffer.push(m); if (state.buffer.length > 3000) state.buffer.shift(); return; } handleMessage(m, true); };
}
```

- The socket URL follows the page's scheme and host. The server checks the session cookie during the upgrade (dashboard.js 388–395) and simply destroys the socket when it is missing, which the browser reports as close code 1006 (abnormal closure).
- Reconnection uses exponential backoff from 1 s to 10 s, reset to 1 s on success. After a few failed attempts (`retry > 4000`, i.e. the third failure or later) with code 1006, the page asks `/api/me`; a 401 means the session is gone and the page goes to `/login`. This is how a logged-out tab eventually notices.
- `onerror` just closes, so all recovery goes through `onclose`.
- `onmessage`: snapshots always apply (they reset everything, including when paused); while paused, everything except `stats` is buffered (bounded at 3000 messages); otherwise it is dispatched live.

### Boot (lines 1217–1226)

```js
// lines 1217-1226
(async () => {
  const me = await api('/api/me').catch(() => null); if (!me) return;
  state.me = me; $('me').textContent = `${me.username} (${me.role})`; $('ctf-name').textContent = me.ctf ? me.ctf.name : 'no active CTF';
  if (me.role !== 'admin') document.querySelectorAll('.admin-only').forEach((el) => el.classList.add('hidden'));
  renderReplay(me.replay); renderTarget(me.target); currentTarget = me.target; loadDecoy();
  const p = location.pathname; showView(viewFromPath(p), false);
  if (!me.target && me.role === 'admin' && viewFromPath(p) === 'live') showView('ctfs', true); // nothing connected yet: start on the picker
  if (p.startsWith('/students/')) openStudentDetail(decodeURIComponent(p.slice('/students/'.length)), false);
  connect();
})();
```

- `/api/me` returns the session user (`username`, `role`) plus the active CTF, the replay status and the proxy target (dashboard.js 134). If it fails with 401, `api` has already redirected to login; any other failure leaves the page blank by design (`return`).
- Role gating is done once here: every element with class `admin-only` is hidden for observers. Generated markup checks `state.me.role` itself instead.
- Then the initial view is picked from the path. An admin who opens the dashboard while no CTF app is connected is sent to the CTFs tab (the target picker) instead of an empty live view; `push` is true so Back returns to `/`.
- A `/students/<name>` URL opens that student's detail without pushing a duplicate history entry.
- Only now does the socket connect, so `state.me` is set before the first snapshot renders anything role-dependent.

## State

| Object.field | Type | Meaning / who writes it |
|---|---|---|
| `state.me` | object or null | Session user from `/api/me` (`username`, `role`, `ctf`, `replay`, `target`). Set once at boot (1219). |
| `state.view` | string | Current view name. `showView` (538). |
| `state.paused` | boolean | Live view paused. Pause button (721). |
| `state.buffer` | array | WebSocket messages held while paused (max 3000). `onmessage` (1213); drained by Resume. |
| `state.filter` | string | Exact selected student name, or `''`. `setStudentQuery` (712). |
| `state.query` | string | Lower-cased partial student search, or `''`. Exclusive with `filter`. |
| `state.tableQuery` | string | Lower-cased text filter for the recent-requests table (719). |
| `state.sort` | `'activity'`/`'threat'`/`'name'` | Lane order (720). |
| `state.lanes` | Map name → lane object `{el, track, seq, atk, lastSeen, threat, name}` | `lane()` (575); cleared by `loadSnapshot`. |
| `state.stats` | object or null | Last stats payload from the server. `renderStats` (627). Read by many views. |
| `state.alerts` | array | Alerts for the Alerts view: loaded by `loadAlerts` (808), prepended by live alerts (1186). |
| `state.alertFilter.levels` | Set | Levels currently shown (803). |
| `state.alertFilter.text` | string | Alerts search text (804). |
| `state.alertFilter.unacked` | boolean | Show only unacknowledged (805). |
| `state.serverStart` | number or null | Server `startedAt` from the first snapshot; a different value later forces a reload (1199). |
| `state.ctfs` | array | CTF list from `/api/ctfs` (984, 1060). Kept but not read elsewhere. |
| `laneCounts` (Map) | name → `{req, high, crit, enum, attacks}` | Per-student counters for lane badges and threat score (575, 582–583). |
| `listItems` (Map) | name → `<li>` | Sidebar list nodes (670). |
| `filterOpts` (Set) | names | Names already added to the shared datalist (662). |
| `rq.paused` | boolean | Requests view paused (749). |
| `rq.buffer` | array | Events held while paused (max 5000) (750). |
| `rq.search` | string | Lower-cased text filter (746). |
| `rq.student` | string | Student substring filter, from `?student=` or the input (732, 747). |
| `rq.sel` | event or null | Selected request (751). |
| `rq.max` | number | Row cap, 2000. |
| `ac.items` | array | Current autocomplete suggestions (932). |
| `ac.idx` | number | Highlighted suggestion (953). |
| `ac.replace` | `{start, end}` or null | Text span a suggestion replaces (932). |
| `lastRows` | array | Rows of the last query, for export (970). |
| `valueCache` | object | Per-field cached `/api/query/values` results, 30 s (862). |
| `dc.target` | string or null | Decoy app URL (1041). |
| `dc.students` | array of `{name, since, by}` | Students routed to the decoy (1041). |
| `qu.items` | array | Queue entries (1143, 1144). |
| `qu.counts` | `{pending, approved, blocked}` | Status counts (1143, 1144, 1194). |
| `qu.fields` | array | Gate fields, for the extra columns (1143). |
| `qu.filter` | string | Status filter chip, default `'pending'` (1145). |
| `qu.search` | string | Queue search text (1146). |
| `qu.sel` | Set of names | Checked rows (1147–1148). |
| `qu.enabled` | boolean | Queue switched on in the gate config (1143, 1194). |
| `gateCfg` | object or null | Working copy of the gate configuration (1109, 1120, 1122). |
| `pgTimer` | interval id | Playground polling timer (1173). |
| `currentTarget` | string or null | Proxy target as last reported (1191, 1221). |
| `retry` | number | WebSocket reconnect delay in ms (1207–1211). |

## Interactions

### HTTP API routes consumed

| Route | Method | Called from | Notes |
|---|---|---|---|
| `/api/me` | GET | boot (1218); reconnect check (1211) | Session, active CTF, replay, target. |
| `/api/logout` | POST | 554 | |
| `/api/alerts?limit=1000` | GET | `loadAlerts` (808) | Scoped to current/replayed CTF by the server. |
| `/api/alerts/ack` | POST `{ids}` or `{all:true, ids:[]}` | 807, 814 | |
| `/api/students/<name>` | GET | `openStudentDetail` (826) | DB detail + live object. |
| `/api/admin/block`, `/unblock` | POST `{student}` | 726, 780, 841, 1078 | |
| `/api/admin/require-rename` | POST `{student}` | 727, 781 | |
| `/api/admin/rename` | POST `{student, newName}` | 728, 782 | Returns `{ok, name}`. |
| `/api/admin/unblock-ip` | POST `{ip}` | 1079 | |
| `/api/admin` | GET | `loadCtfs` (1059) | Blocked players, blocked dashboard IPs, rename-pending. |
| `/api/ctfs` | GET | `loadCtfOptions` (984), `loadCtfs` (1059) | `{active, list}`. |
| `/api/ctfs/new` | POST `{name}` | 1080 | |
| `/api/ctfs/stop` | POST | 1075 | |
| `/api/query` | POST `{q, limit, ctf}` | `runQuery` (967) | `{rows, count, sql, params}`; errors carry `pos`/`len`. |
| `/api/query/values?field=&ctf=` | GET | `dbValues` (861) | Autocomplete values. |
| `/api/export?ctf=` | GET (link) | 1062 | Download. |
| `/api/import` | POST (export JSON) | 1081 | |
| `/api/replay` | POST `{ctf, speed}` | 1077 | |
| `/api/replay/stop` | POST | 1082 | |
| `/api/targets` | GET | `scanTargets` (1007) | `{current, link, proxyPort, candidates}`. |
| `/api/targets` | POST `{url, label, newCtf, ctfName}` or `{url:null}` | `useTarget` (1024), 1055 | |
| `/api/link` | GET | `scanTargets` (1006) | Student link. |
| `/api/decoy` | GET | `loadDecoy` (1042) | |
| `/api/decoy` | POST `{url}` | `setDecoy` (1043) | `null` clears. |
| `/api/decoy/add`, `/remove` | POST `{student}` | 1046, 1047, 1052 | |
| `/api/gate` | GET | `loadGate` (1108) | `{config, types, path}`. |
| `/api/gate` | POST config | 1120 | Returns normalised `{config}`. |
| `/api/gate/preview?config=` | GET (iframe / new tab) | 1105, 1114, 1119, 1121 | Rendered gate page. |
| `/api/queue` | GET | `loadQueue` (1143) | `{enabled, fields, counts, items}`. |
| `/api/queue/approve`, `/block`, `/reset` | POST `{names}` (+`decoy:true`) | 1149–1151 | |
| `/api/playground` | GET | `loadPlayground` (1173), 1177 | Status, polled every 2 s on the tab. |
| `/api/playground/mock`, `/sim` | POST `{action, port}` / `{action, config}` | 1175–1179 | |
| `/api/playground/quick` | POST `{port, config}` | 1180 | |
| `/api/playground/stop-all` | POST | 1181 | |
| `/query.js` | script tag | 501 | The parser. |

Every POST goes through `api`, which sets `X-Requested-With: ctf-watch`; the server rejects POSTs without it.

### WebSocket messages consumed (`/ws`)

| `type` | Payload | Handler |
|---|---|---|
| `snapshot` | `events`, `alerts`, `stats` | `loadSnapshot` (1198) — on connect and on server store reset. |
| `event` | `event` | `handleMessage` → `addDot`, `addRow`, `rqFeed`. |
| `alert` | `alert` | `handleMessage` → `addFeedAlert`, `state.alerts`. |
| `stats` | `stats`, `replay`, `target`, `mock {app, sim}`, `gate`, `queue` (counts or null) | `handleMessage` → `renderStats`, `renderReplay`, `renderTarget`, badges. Once per second. |
| `queue` | `counts`, `items` | `queueUpdate` (1144). |
| `decoy` | `target`, `students` | `decoyUpdate` (1041). |

## Changing it safely

### Add a view

1. Add the section: `<section class="view" id="view-NAME">` with a `.view-head` (include `<button class="small" data-open="/NAME">↗</button>`) inside `<main>`.
2. Add `<button data-view="NAME">Label</button>` to `<nav id="nav">`.
3. Add `'NAME'` to `VIEWS` (line 531). `viewFromPath` and `showView` then work without changes.
4. If the view needs data when opened, add `if (v === 'NAME') loadNAME();` in `showView`.
5. Add `/NAME` to the `PAGES` set in `proxy/src/dashboard.js` (line 14), otherwise a direct visit to `/NAME` returns 404 instead of `app.html`.
6. If observers must not act in it, give the controls the `admin-only` class (static markup) or check `state.me.role` when generating markup.

### Add a column to a live table

The recent-requests table (`addRow`, 610) and the Requests view (`rqAddRow`, 739) each have a `<thead>` in the markup (226 and 245) and an `innerHTML` template in the script. Add the `<th>` and the `<td>` in the same position in both places; if the value should be searchable, add it to the `dataset.text` blob (608 / 738). For the Query results, the header is at 317 and the template at 972; those rows are database rows with snake_case names (`object_id`, `latency`). For the student detail, header and template are both inside the template at 839. Escape every string with `esc`.

### Add a card action

The student card exists twice: a static one in the Live sidebar (buttons at 189–193, handlers at 724–729) and a generated one in the Requests sidebar (`rqRenderSide` 769, dispatcher 775–785). To add an action:

1. Add a `<button class="small admin-only" id="btn-X">` to `#student-actions` and a handler using `selectedStudent()` / `state.filter`.
2. Add `<button class="small" data-act="X">` to the generated card (inside the `isAdmin` branch if admin-only) and an `if (b.dataset.act === 'X')` branch in the dispatcher.
3. Put the actual work in one shared function (as `toggleDecoy` is) so both buttons stay identical.
4. If the server needs a new route, add it to `dashboard.js` and make the call with `tryApi` (POST, so the CSRF header is set).

### The checks

There is no bundler or test for this file, so two quick checks catch the most common mistakes before opening a browser. Both are done by one small script; save it anywhere (it is not part of the repository) and run it from the repository root with `node check-app.js`.

```js
// check-app.js — run from the repository root
const fs = require('fs'), os = require('os'), path = require('path'), { execFileSync } = require('child_process');
const h = fs.readFileSync('proxy/public/app.html', 'utf8');
const script = h.slice(h.lastIndexOf('<script>') + 8, h.lastIndexOf('</script>'));
// 1. every id the script looks up with $('...') must exist as id="..." somewhere in the file
const ids = new Set([...h.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
const used = [...new Set([...script.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]))];
const missing = used.filter((i) => !ids.has(i));
console.log(`${used.length} ids used by the script, ${missing.length} missing`, missing);
// 2. the inline script must parse: write it to a temp file and let node --check it
const tmp = path.join(os.tmpdir(), 'app-script.js');
fs.writeFileSync(tmp, script);
execFileSync(process.execPath, ['--check', tmp], { stdio: 'inherit' });
console.log('syntax ok');
process.exit(missing.length ? 1 : 0);
```

**The ids-exist check.** A typo in `$('some-id')` throws `Cannot read properties of null` at runtime, often only when that view is opened, and only for the role that sees it. The check scans the whole file for `id="…"`, so ids created inside template strings (`su-back`, `sd-block`, `qu-all`) count as present. At the time of writing it reports 179 ids used, none missing.

**The `node --check` trick.** `node --check file.js` parses a file and exits non-zero on a syntax error without executing it, so browser globals like `document` are no problem. The script above extracts everything between the last `<script>` and `</script>` (the inline dashboard script, not the `/query.js` tag) and checks it. This catches an unbalanced brace or an unterminated template literal, which in the browser would silently leave every handler unregistered.

After both pass, open the dashboard, open the browser console, and click through every tab once: the console must stay empty. The Playground tab ("Start everything") gives you traffic for the live, requests, alerts and students views without a real CTF.

## Exercises

1. **Add a "latency" column to the Live sidebar card.** In `cardGridHtml` (680) add a row showing the student's average latency. The stats student object does not carry it, so compute it client-side: keep a running sum and count in `laneCounts` (update them in `addDot` from `ev.latencyMs`) and read them in `cardGridHtml` via `laneCounts.get(s.name)`. Verify: start the Playground demo, click a student in the sidebar; the card shows a number that changes every second, and the same row appears in the Requests sidebar card when you click a request (because both cards share `cardGridHtml`).

2. **Make the Alerts view remember its filters.** Persist `state.alertFilter.levels` (as an array) and `unacked` in `localStorage` the way the query history does (`HIST_KEY`, 958–962), and restore them at boot before `renderLevelChips` runs. Verify: untick `info` and `low`, tick "unacknowledged only", reload the page, open Alerts: the chips and the checkbox are as you left them, and `renderAlertsTable` already applies them.

3. **Add a "Copy as curl" action to the Requests detail.** In `requestDetailHtml` (752) add a button with `data-act="curl"`, and in the `#rq-card` dispatcher add a branch that builds `curl -X <method> '<target><path>'` (use `currentTarget` for the host, `JSON.stringify(ev.body)` with `-d` when present) and writes it with `navigator.clipboard.writeText`. Note the button is inside `#rq-req`, not `#rq-card`, so either attach a second delegated listener on `#rq-req` or move the button into the card. Verify: click a POST request from the Playground's mallory player, press the button, paste into a terminal: the command targets the mock app's URL and carries the (masked) body.
