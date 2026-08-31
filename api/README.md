# cats-api

`cats-api` contains the public HTTP request and response types used by clients
of the [Cats](https://github.com/ahuazhu/cats) microVM platform.

Cross-component wire contracts and strict codecs live in `cats-protocol`.
Fail-closed readers for installed Host artifacts live in `cats-artifacts`.
Compatibility features preserve the former `cats_api` module paths for
existing library consumers; workspace components use the owning crates
directly.

Platform architecture, protocol status, and compatibility boundaries are
documented in the repository.

## License

MIT
