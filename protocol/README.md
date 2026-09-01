# cats-protocol

`cats-protocol` contains the shared wire contracts, strict codecs, canonical
encoders, signature inputs, protocol constants, and validation rules used by
Cats components.

It deliberately contains no installed Host filesystem I/O. Public HTTP-only
types live in `cats-api`; fail-closed installed artifact readers live in
`cats-artifacts`.

Platform architecture, protocol status, and compatibility boundaries are
documented in the repository.

## License

MIT
