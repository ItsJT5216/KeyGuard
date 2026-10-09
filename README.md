# KeyGuard

KeyGuard is a local-first Ubuntu daemon for tracking API-provider credentials without exposing stored secrets to its browser dashboard.

The current implementation includes the [X-5 foundation](https://linear.app/itstanner5216/issue/X-5/1-build-keyguard-foundation-daemon-vault-sqlite-localhost-dashboard), the [X-7 OpenRouter protection path](https://linear.app/itstanner5216/issue/X-7/2-define-provider-adapter-contract-and-ship-first-verified-protection), the [X-6 adaptive scheduler](https://linear.app/itstanner5216/issue/X-6/3-implement-adaptive-polling-and-burn-rate-escalation), the [X-8 live dashboard](https://linear.app/itstanner5216/issue/X-8/4-wire-the-html-dashboard-to-live-daemon-state-and-controls), and [X-9 ntfy reporting](https://linear.app/itstanner5216/issue/X-9/5-add-ntfy-notifications-and-protection-event-reporting):

- a loopback-only Python HTTP daemon;
- GNOME Keyring storage through `keyring`, with no plaintext fallback;
- SQLite storage for non-secret credential configuration, usage snapshots, scheduler state, and event history;
- a daemon-served HTML dashboard backed by real usage, scheduler, provider, and event state;
- dashboard controls for on-demand checks, threshold and polling edits, pause/resume,
  auto-protection, manual protection, history, and removal;
- persisted distance- and burn-rate-driven polling with bounded jitter;
- ntfy alerts for tier transitions, repeated provider failures, externally disabled credentials, and verified protection results;
- a user-service installer and desktop launcher.

## Install for the current user

```bash
python3 -m venv ~/.local/share/keyguard/venv
~/.local/share/keyguard/venv/bin/pip install .
~/.local/share/keyguard/venv/bin/keyguard install
```

`keyguard install` writes a service to `~/.config/systemd/user/keyguard.service`, writes the desktop entry, reloads systemd, and enables the daemon. The generated unit uses the exact interpreter that installed KeyGuard.

Open the dashboard with:

```bash
keyguard open
```

The dashboard may be closed without stopping the daemon. Reopening it reconnects to the same daemon and SQLite state.

The dashboard refreshes while it is open and shows the latest authoritative usage,
remaining allocation, burn rate, polling interval, check times, protection mode, and
last protection result. Active credentials are ordered by the soonest provider reset
when that information is available. Manual destructive actions require confirmation;
automatic threshold protection continues without browser interaction. The notification
test control reports that X-9 is not implemented until its real backend exists rather
than displaying a false success.

## Adaptive polling

The daemon schedules each active credential from real successful usage snapshots. Default distance tiers are four hours when usage is more than 10 units from the configured threshold, then one hour, 15 minutes, five minutes, and one minute as the remaining distance crosses 10, 5, 2, and 0.5 units. The same model works for USD, credits, tokens, characters, requests, or another adapter unit.

Each credential can override its distance boundaries, intervals, safety margin, and non-critical jitter through the API's `polling` object. Recent successful snapshots also produce a burn-rate estimate. When projected time to the threshold is shorter than the distance-selected interval plus its safety margin, KeyGuard moves to a faster tier before distance alone would require it.

Polling tier, current interval, next check, last check, and consecutive failures live in SQLite. Overdue work runs promptly after daemon restart. Provider failures create no zero-usage snapshot and use bounded retry scheduling instead. Paused, disabled, provisioning, and cleanup-required credentials are not polled.

## OpenRouter provider

KeyGuard's first verified adapter uses OpenRouter's documented management-key API. Add the management key as the provider credential and the target API key's 64-character hash as provider metadata. A configured `disable` action performs the full X-7 protection flow: fetch usage, confirm a crossed threshold with a second fresh fetch, disable the key, fetch it again, and report success only when OpenRouter returns `disabled: true`.

- Usage endpoint: `GET /api/v1/keys/{hash}`.
- Usage scope: the individual OpenRouter API key identified by the hash.
- Credential: an OpenRouter Management API key with permission to read and update API keys.
- Units: USD credits; `usage` is the selected key's recorded usage, while `limit`, `limit_remaining`, and `limit_reset` describe its configured cap and reset period.
- Implemented protection action: reversible key disable through `PATCH /api/v1/keys/{hash}` with `{"disabled": true}`.
- Verification: a fresh `GET /api/v1/keys/{hash}` must return `disabled: true`.
- Other documented capabilities: delete key and set its USD limit. They are reported as provider capabilities but are not offered as KeyGuard actions yet.
- Monitoring limits: HTTP 429 is treated as a failed provider check; KeyGuard never converts it into zero usage. Adaptive polling uses a bounded error-retry schedule without recording a false zero balance.
- Billing lag: OpenRouter does not publish a guaranteed settlement interval. KeyGuard therefore performs a second authoritative read immediately before protection and never treats missing or malformed usage as zero.

The provider adapter tests use recorded response shapes and an injectable transport. They do not require or expose a live management key.

## Security boundary

- The server binds to `127.0.0.1` only.
- The daemon selects and records an owner-only per-user port, avoiding a host-wide fixed-port collision between desktop users.
- A per-user owner token proves daemon identity with challenge-response. It is never put in a browser URL or cookie.
- The launcher mints a signed, short-lived, one-use browser bootstrap. The dashboard exchanges it for an in-memory session kept in origin-scoped `sessionStorage` and attaches that session explicitly to API requests.
- Requests reject unexpected Host and Origin values to prevent non-local browser access and DNS rebinding.
- Credential writes require JSON and reject non-local browser origins.
- Raw API keys are handed directly to Secret Service and are never written to SQLite, returned by GET endpoints, rendered into the dashboard, or placed in logs.
- If Secret Service is unavailable, credential writes fail closed.
- Database queries are parameterized and API payloads are size- and type-validated.

## Development checks

The test suite uses an in-memory fake vault; it never touches the real keyring.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```
