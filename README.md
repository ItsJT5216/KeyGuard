# KeyGuard

KeyGuard is a local-first Ubuntu daemon for tracking API-provider credentials without exposing stored secrets to its browser dashboard.

This first foundation implements [Linear X-5](https://linear.app/itstanner5216/issue/X-5/1-build-keyguard-foundation-daemon-vault-sqlite-localhost-dashboard):

- a loopback-only Python HTTP daemon;
- GNOME Keyring storage through `keyring`, with no plaintext fallback;
- SQLite storage for non-secret credential configuration, usage snapshots, scheduler state, and event history;
- a daemon-served HTML dashboard backed by the real API;
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

The dashboard may be closed without stopping the daemon. Reopening it reconnects to the same daemon and SQLite state. Adaptive polling is added by X-6; the first provider protection path is described below.

## OpenRouter provider

KeyGuard's first verified adapter uses OpenRouter's documented management-key API. Add the management key as the provider credential and the target API key's 64-character hash as provider metadata. A configured `disable` action performs the full X-7 protection flow: fetch usage, confirm a crossed threshold with a second fresh fetch, disable the key, fetch it again, and report success only when OpenRouter returns `disabled: true`.

- Usage endpoint: `GET /api/v1/keys/{hash}`.
- Usage scope: the individual OpenRouter API key identified by the hash.
- Credential: an OpenRouter Management API key with permission to read and update API keys.
- Units: USD credits; `usage` is the selected key's recorded usage, while `limit`, `limit_remaining`, and `limit_reset` describe its configured cap and reset period.
- Implemented protection action: reversible key disable through `PATCH /api/v1/keys/{hash}` with `{"disabled": true}`.
- Verification: a fresh `GET /api/v1/keys/{hash}` must return `disabled: true`.
- Other documented capabilities: delete key and set its USD limit. They are reported as provider capabilities but are not offered as KeyGuard actions yet.
- Monitoring limits: HTTP 429 is treated as a failed provider check; KeyGuard never converts it into zero usage. The provider's `Retry-After` policy will be incorporated into X-6 scheduling.
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
