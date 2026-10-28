# The event pipeline — `proxy/src/pipeline.js`

## Purpose

`buildEvent(x, deps)` turns one raw proxy exchange into the event object that `store.add` receives.
It used to be the body of `onEvent` in `server.js`; it was moved into its own module so that the
golden test can run recorded exchanges through the exact same code without the HTTP proxy. Nothing
in the logic changed in the move.

## Where it sits

`server.js` calls `buildEvent` from `onEvent` with a `deps` object built once at boot:

| dep | provided by | used for |
|---|---|---|
| `getConfig` | `config.js` | mask fields, `successMinBytes` |
| `identity` | `identity.js` | `resolve`, `learn` |
| `detector` | `detect.js` | `analyze` |
| `alias(name)` | `admin.alias` | organizer renames |
| `profiles` | gate answers map | the `profile` field |
| `playerIdFor(who, ip, ts)` | `server.js` | the `playerId` field |
| `isDecoy(name)` | `decoy.has` | the `decoy` flag and field |

`rawToJson` / `rawFromJson` serialise an exchange for the `RECORD_RAW` recorder and rebuild it for
the test. Bodies are base64; the request is reduced to `{ method, url, headers, socket.remoteAddress }`.

## Walkthrough

The steps are the ones listed under "Flow 2" in the [README](README.md): parse bodies, resolve and
learn identity with the two fix-ups (login request attributed to the learner; gate name keeps the
app username as `appName`), apply the alias, the "has data" heuristic, `detector.analyze` (or the
fixed `blocked` verdict), `classify` for attacks with the severity upgrade, the `decoy` flag, and
the final object.

## Recording and the golden test

- `RECORD_RAW=/path/file.jsonl` makes `server.js` append every exchange as one JSON line
  (`rawToJson`). Used once to produce `proxy/test/fixtures/golden-raw.jsonl`.
- `proxy/test/golden.test.js` rebuilds the pipeline from the modules (config from `config/`, a
  gate with the fixture's secret, identity, detector, a store with no database), replays the
  fixture, and compares student, source, endpoint, object id, owner, flags, severity, attack
  classes and masked path of every event, plus the multiset of alerts by type and level, with
  `golden-expected.json`.
- To **re-record** after an intended behaviour change: run the mock app and the monitor with
  `RECORD_RAW` set on a fresh `DATA_DIR`, switch the gate to `strict: false, queue: false`, point
  the proxy at the mock, run one simulator round (`SIM_CONFIG='{"pace":0.25,"rounds":1,"loop":false}'`),
  export the CTF, and save the raw lines, the export's per-request fields and the gate secret as
  the three fixture files. The exact commands are in the commit that introduced the harness.

## Changing it safely

Any change here or in the modules it calls must keep `npm test` green; the golden test is the one
that will complain. If the change is intended, re-record the fixture in the same commit and explain
the diff in the commit message.

## Re-baselining the fixture

`node test/golden-rebaseline.js --dry` replays the fixture with the current code and prints every per-event difference against `golden-expected.json` and the alert count changes. Read the list: every line must be explained by the change you intended. Then run it without `--dry` to rewrite the expected file, and commit the fixture together with the code change, quoting the differences in the commit message.
