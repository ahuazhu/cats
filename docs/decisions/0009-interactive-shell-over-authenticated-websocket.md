# ADR-0009: Provide interactive shell as an authenticated WebSocket PTY

- Status: Accepted
- Date: 2026-07-22

## Context

`cats exec` is a bounded argv request and cannot represent an interactive PTY,
terminal resizing, streaming input/output, or remote exit status. Running sshd
inside every Guest would add a second user, key, port, and authorization
lifecycle beside Cats workspace identity.

## Decision

1. `cats shell <cat>` uses the caller's current Cats identity and Workspace. It
   creates no Guest SSH account, SSH key, or TCP 22 listener.
2. The public API upgrades an authenticated workspace/Cat route to WebSocket.
   Authorization completes before wake or Node connection. Internal hops use
   machine credentials distinct from the user's token.
3. If needed, the request wakes the Cat through the normal lifecycle API. The
   Node admits the session only while the exact runtime is Running and holds a
   local activity guard for the complete stream, so sleep cannot cross it.
4. The Guest agent creates a login PTY and bridges it over the existing
   Unix/vsock control channel. Client disconnect closes the PTY; this contract
   has no detached session.
5. Binary WebSocket frames carry uninterpreted terminal bytes. Text frames are
   limited to resize, close, exit status, and structured errors. The exact wire
   contract is [Interactive Shell Protocol v1](../specs/interactive-shell-protocol.md).
6. Terminal dimensions and frame sizes are bounded. Every hop uses bounded
   buffering and propagates cancellation and backpressure.
7. Terminal contents are not written to resource rows or normal application
   logs. An explicit exit frame is required before the CLI reports the remote
   exit code; an abnormal close is a failure.

## Security boundary

- Workspace authorization applies to the public upgrade exactly as it does to
  resource APIs.
- WorkOS, service, storage, and metadata credentials never enter the Guest.
- The Cat is one Guest trust boundary. The default shell runs with the Guest
  agent's configured system identity; this ADR does not create multi-user
  isolation inside a Cat.
- `cats exec` remains the non-PTY interface for scripts and structured output.

## Consequences

The existing authenticated HTTPS path also carries the PTY stream, keeping one
public identity and routing boundary. A separate session service is justified
only by a measured scaling or isolation boundary and would require its own ADR;
it is not part of this contract.
