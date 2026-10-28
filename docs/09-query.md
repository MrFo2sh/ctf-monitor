# 9. Searching with the Query tab

The Query tab searches every recorded request of the current event (or of the one being replayed).
Type a condition, press Run or Ctrl+Enter. The box helps: it colours what you type, underlines
mistakes and says what was expected, and suggests as you go (fields, then the operators that fit,
then real values from your data, then AND / OR). Arrow keys pick a suggestion, Tab or Enter accepts,
Esc closes, Ctrl+Space reopens.

## The language in one minute

```
field operator value
```

joined with `AND`, `OR`, `NOT` and parentheses. Text values go in quotes.

| Field | Means | Example |
|---|---|---|
| `student` | the name on the dashboard | `student = "Sara"` |
| `ip` | client IP | `ip = "41.33.2.9"` |
| `method`, `path` | the request | `method = "POST" AND path ~ "/login"` |
| `endpoint`, `id` | the matched rule and object id | `endpoint = "orders" AND id = "1043"` |
| `owner` | who the object belongs to | `owner = "alice" AND NOT student = "alice"` |
| `status`, `size`, `latency` | the answer | `status >= 500`, `size > 10000` |
| `flag` | what was detected | `flag = "idor-success"`, `flag = "decoy"` |
| `attack` | attack class | `attack ~ "sqli"` |
| `severity` | ok, notice, warn, high, critical | `severity = "critical"` |
| `ua`, `source` | browser, how identified | `ua ~ "curl"`, `source = "ip"` |
| `ts` | time | `ts > "-15m"`, `ts > "2026-10-28T10:00"` |
| `ctf`, `player` | other events, same person | `ctf = 3`, `player = 12` |

Operators: `=` `!=` `>` `>=` `<` `<=`, `~` (contains), `!~` (does not contain), `in ("a", "b")`.

## Questions and their queries

| Question | Query |
|---|---|
| Who got flags, in order | `flag = "idor-success"` (newest first; scroll to the bottom for the first) |
| Everything Sara did in the last 10 minutes | `student = "Sara" AND ts > "-10m"` |
| Everyone who touched alice's objects | `owner = "alice" AND NOT student = "alice"` |
| Injection attempts of any kind | `attack ~ "sqli" OR attack ~ "cmdi" OR attack ~ "ssti"` |
| Scripts rather than browsers | `ua ~ "python" OR ua ~ "curl" OR ua ~ "go-http"` |
| Who is hammering the login | `path ~ "/login" AND method = "POST" AND status = 401` |
| Slow or broken endpoints | `status >= 500 OR latency > 2000` |
| What the decoy students did | `flag = "decoy"` |

Results show as a table; ⬇ results .csv or .json saves them. Recent queries are kept as chips under
the examples. The drop-down next to Run searches a past event instead of the current one.
