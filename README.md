# KeyGuard

KeyGuard is a local-first daemon and dashboard for monitoring API credentials without exposing stored secrets to the browser or SQLite.

This first foundation provides:

- a localhost-only FastAPI daemon;
- GNOME Keyring / Secret Service storage through `keyring`;
- SQLite metadata and event history with no secret columns;
- a daemon-served HTML dashboard;
- a systemd user service installer and desktop launcher;
- credential CRUD endpoints that never return raw secrets.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
keyguard serve
```

The dashboard is available at `http://127.0.0.1:8765`.

## User service

After installing KeyGuard:

```bash
keyguard install-service
systemctl --user status keyguard.service
```

The generated unit uses the exact installed `keyguard` executable. `keyguard open` starts the service if necessary and opens the existing daemon dashboard. Closing the browser does not stop monitoring.

KeyGuard deliberately refuses known plaintext/fallback keyring backends. A working Secret Service backend must be available before credentials can be saved.
