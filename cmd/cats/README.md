# cats-cli

`cats-cli` provides the `cats` command-line client for the
[Cats](https://github.com/ahuazhu/cats) microVM platform.

## Install

The CLI requires Rust 1.97 or newer:

```console
cargo install cats-cli
```

## Use

Sign in through the browser, then inspect the active workspace:

```console
cats login
cats whoami
cats ls
```

For a self-hosted Control Plane, set `CATS_API_URL`. Machine and administrator
workflows can supply `CATS_TOKEN`; ordinary users should use `cats login`.

Run `cats --help` and `cats <command> --help` for the complete command surface.

## License

MIT
