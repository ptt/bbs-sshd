# bbs-sshd

BBS SSH daemon.

## Build and Run

The following commands build and run the release binary.

```
$ cargo build --release
$ target/release/bbs-sshd -f bbs-sshd.toml
```

The following commands build and run the debug binary.

```
$ cargo build
$ target/debug/bbs-sshd -f bbs-sshd.toml
```

See `sample` directory for config file examples.

## License

- Apache License 2.0. See `LICENSE-2.0.txt`.
