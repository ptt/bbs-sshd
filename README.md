# bbs-sshd

BBS SSH/WebSocket daemon.

## Crates

- `bbs-common` - `logind` client, telnet protocol, socket options, shared config
  settings and the daemon startup/accept loop.
- `bbs-sshd`   - SSH server, builds `bbs-sshd`.
- `bbs-wsd`    - WebSocket server, builds `bbs-wsd`.

## Build and Run

The following commands build the release binaries.

```
$ cargo build --release
$ target/release/bbs-sshd -f bbs-sshd.toml
$ target/release/bbs-wsd -f bbs-wsd.toml
```

The following commands build the debug binaries.

```
$ cargo build
$ target/debug/bbs-sshd -f bbs-sshd.toml
$ target/debug/bbs-wsd -f bbs-wsd.toml
```

Run `cargo test --workspace` for the test suite, and `cargo clippy --workspace
--all-targets` for the lints.

See `sample` directory for config file examples, including
`sample/etc/nginx/bbs-wsd.conf` for running `bbs-wsd` behind nginx.

## License

- Apache License 2.0. See `LICENSE-2.0.txt`.
