## Current release boundary

Endpoint collection and mutation routes are not part of the release product router during the signed runtime cutover. The shipped CLI and browser console do not expose Endpoint controls and fail locally instead of probing legacy paths.

## Target admission model

Route Grant v2 binds a runtime incarnation and one per-Endpoint serving epoch. Node-installed admission must be closed before leaving Running, and it can reopen only after a fresh Desired state raises that Endpoint epoch. A route TTL or heartbeat timeout is not a Host fence.

This architecture remains the target contract, not permission for a user client to construct an Endpoint mutation while the production route is absent.
