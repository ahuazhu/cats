## Publish a Guest port

    cats expose dev 3000 --name web --protocol http
    cats endpoint ls dev

The command creates an Endpoint with a stable hostname, a target Guest port, and `wake_on_request` by default. The hostname is tied to the Cat resource, not a particular host.

## Wake policy

    cats expose dev 3000 --name internal-preview --no-wake

- **wake on request:** the gateway singleflights concurrent activation attempts for a sleeping Cat, waits for readiness, and then routes to the new activation epoch.
- **no wake:** a request does not start the Cat; use this for workloads that should serve only while explicitly Running.

A client should tolerate `503` with retry guidance during activation and reconnect after lifecycle or host changes. Stable hostname does not mean stable long-lived connections.

## Protocols and routing safety

The V1 product model covers HTTP, HTTPS, WebSocket, and secure WebSocket through a regional edge. The node gateway revalidates project, Cat, target port, and route epoch; an old cached route must fail closed instead of reaching a different Guest.

## Current source availability

**Cloud Hypervisor networking is not complete**

The endpoint API, route epoch logic, wake flow, and FakeVmm gateway path are implemented and tested. Tap/overlay Guest networking for the Cloud Hypervisor Phase-A runtime is not implemented in this repository. Treat a real CH public Endpoint as unavailable until that milestone lands.

## Prepare the Guest service

1.  Listen on the target Guest port, not on a platform-reserved port.
2.  Return readiness only after dependencies and disk state are usable.
3.  Do not expect Cats to preserve application TCP state across sleep.
4.  If background work must keep the Cat Running, acquire a [work lease](/docs/runtime-api/).

## Troubleshoot an Endpoint

    cats get dev
    cats endpoint ls dev
    cats operation ls
    cats exec dev -- sh -lc 'ss -lnt'

Verify the Cat is healthy, the Endpoint targets the expected port, the latest activation Operation succeeded, and the Guest service is actually listening. Operators should also check route epoch mismatch and gateway/node connectivity metrics.
