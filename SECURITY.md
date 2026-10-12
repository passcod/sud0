# Security policy

Report vulnerabilities directly against the public issue tracker.

## Not security issues

- Authorization for `nz.passcod.sud0.run` permits arbitrary root commands.
- Retained polkit grants.
- Logs.
- Rendered prompts to authentication agents containing supported info.
- Administrators changing the `sud0` binary or its configuration.
- Compromised trusted components (root, kernel, systemd, system D-Bus, polkit, or authentication agent).
