# cats-artifacts

`cats-artifacts` contains fail-closed readers and launch-time validators for
the one installed Cats runtime release. It validates canonical paths, file and
directory ownership, permissions, link counts, stable metadata, bounded bytes,
and protocol digests before Control or Node consumes an artifact.

Wire types and codecs live in `cats-protocol`; public HTTP types live in
`cats-api`.

## License

MIT
