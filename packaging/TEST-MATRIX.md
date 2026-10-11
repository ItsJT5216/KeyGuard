# Debian package verification matrix

Run these checks on a supported Ubuntu desktop before publishing a release package.

| Check | Command or action | Expected result |
| --- | --- | --- |
| Clean build | `SOURCE_DATE_EPOCH=0 python3 packaging/build_deb.py` | `dist/keyguard_0.1.0_all.deb` is created from the checkout alone. |
| Fresh install | `sudo apt install ./dist/keyguard_0.1.0_all.deb && keyguard install` | The package installs and the user service is enabled and running. |
| Service lifecycle | `systemctl --user stop keyguard; systemctl --user start keyguard; systemctl --user restart keyguard` | Every command succeeds and there is one KeyGuard daemon. |
| Login persistence | Log out, log in, then run `systemctl --user is-active keyguard` | The enabled user service is active. |
| Reboot persistence | Reboot, log in, then run `systemctl --user is-active keyguard` | Monitoring resumes through the enabled user service. |
| Launcher | Open KeyGuard from the application menu twice | Both launches reuse the daemon and open its dashboard. |
| Upgrade | Install a newer `.deb` with `sudo apt install ./dist/keyguard_VERSION_all.deb` | Code/assets update and existing configuration and secrets remain. |
| Remove | `sudo apt remove keyguard` | Packaged files are removed; user configuration, SQLite state, and keyring secrets remain. |
| Reinstall | Reinstall the package, run `keyguard install`, and open the launcher | The preserved user state is available again. |

The automated packaging tests additionally verify reproducible bytes, package ownership and modes, exact installed paths, launcher/service agreement, dashboard inclusion, and the absence of checkout or temporary paths.
