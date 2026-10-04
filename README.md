# KeyGuard

KeyGuard is a local-first Ubuntu daemon for tracking API-provider credentials without exposing stored secrets to its browser dashboard.

This first foundation implements [Linear X-5](https://linear.app/itstanner5216/issue/X-5/1-build-keyguard-foundation-daemon-vault-sqlite-localhost-dashboard):

- a loopback-only Python HTTP daemon;
- GNOME Keyring storage through `keyring`, with no plaintext fallback;
- SQLite storage for non-secret credential configuration and event history;
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

The dashboard may be closed without stopping the daemon. Reopening it reconnects to the same daemon and SQLite state. Adaptive polling and provider protection are added by X-6 and X-7.

## Security boundary

- The server binds to `127.0.0.1` only.
- A per-user owner-readable token authenticates the loopback API. The launcher passes it in the URL fragment, which the page exchanges for an HttpOnly, SameSite session cookie before clearing the fragment.
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
