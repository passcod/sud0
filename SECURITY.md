# Security policy

Report vulnerabilities against the public issue tracker.
You are encouraged to fix issues yourself if you care.

## Not security issues

Expected behavior:

- Authorization for `nz.passcod.sud0.run` permits arbitrary root commands.
- Retained polkit grants may cover another command, usually for five minutes within the same process family; others may reauthenticate.
- Authentication agents receive the rendered command, working directory, and description; logs may retain them. Root-defined prompts can also expose environment values, directory identity, or the request digest.
- Administrators can alter sud0, its configuration, and anything on its fixed root `PATH`.
- Target commands have root's access and risks, without the broker's hardening.
- Compromised trusted components (root, kernel, systemd, system D-Bus, polkit, or authentication agent) are outside sud0's security boundary.
- Invalid or unsupported requests and configurations are rejected.
- Private D-Bus and frozen-request interfaces may break during 0.x.
