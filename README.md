# sud0

`sud0` is `run0` but friendlier for desktop use.

Like run0, this is using polkit, _not_ a setuid binary like sudo.

Not audited. Do not use in production.

## Examples

```console
$ sud0 id
```

By default, the auth prompt includes a sanitized argv summary and the descriptor-derived working directory. This can be customized with `/etc/sud0/prompt.template` using `{command}`, `{cwd}`, `{description_line}`, and `{environment_line}`.

You can also provide custom text; the command and workdir will be appended:

```console
$ sud0 -d 'editing the SSH config' /usr/bin/nvim /etc/ssh/sshd_config
```

Command-line text and imported environment values must be UTF-8. Common sudo/run0 options are also available:

```console
$ sud0 -D /var/lib/my-service --pipe /usr/bin/find . -maxdepth 1
$ sud0 --setenv TERM --pty /usr/bin/bash
```

## Setup

```console
$ make release
$ make check
# make install
# systemctl daemon-reload
```

Do not run `make release` or `make check` as root.

Alternatively, on Arch Linux:

```console
$ makepkg -si -D packaging/arch
```

## Troubleshooting

- `Failed to connect to system bus`: confirm the system D-Bus service is running and the activation and policy files are installed under `/usr/share/dbus-1`.
- `Failed to register authentication agent`: install polkit and verify `/usr/bin/pkttyagent`; a desktop agent may still satisfy the request.
- Authorization fails without a prompt under `-n`: retry without `-n`.
- Broker startup or transient-unit failures: inspect `systemctl status sud0-broker.service` and `journalctl -u sud0-broker.service`.
- A bare command is not found: use an absolute pathname (`PATH` may not be the same under `root`).
- PTY selection is unsuitable for a pipeline or redirected stream: pass `--pty` or `--pipe` explicitly.
