# Security policy

Report vulnerabilities against the public issue tracker.
You are encouraged to fix issues yourself if you care.

## Not security issues

The following are expected behavior and are not considered security issues:

- A subject authorized for `nz.passcod.sud0.run` can execute arbitrary commands as root.
- A retained polkit grant can authorize a different command from the one that prompted, normally for about five minutes within the same invoking process family.
- Separate terminals or process families may require separate authentication.
- Authentication agents receive the rendered command, working directory, and optional description; verbose polkit logging may record them.
- A root-configured prompt template may additionally expose environment values, working-directory identity, or the request digest.
- Root or an administrator can alter sud0's binaries, policy, service files, prompt template, and commands or directories on its fixed root `PATH`.
- An authorized target command may consume system resources, access or modify anything available to root, emit terminal control sequences, or contain vulnerabilities of its own.
- Target commands do not inherit the broker service's hardening.
- Compromise of root, the kernel, systemd, system D-Bus, polkit, or the selected authentication agent is outside sud0's security boundary.
- Unsupported systems, malformed requests, blocked environment names, exceeded resource limits, and invalid or missing prompt templates are rejected rather than accommodated.
- The private D-Bus and frozen-request interfaces may change incompatibly during the 0.x series.
