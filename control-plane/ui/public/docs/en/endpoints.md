## Default URL

    cats create dev
    cats endpoint ls dev
    curl https://dev-<cat-suffix>.cats.run/

Every Cat receives a stable HTTPS Endpoint named `web`. It forwards to Guest port `8080` and uses `wake_on_request`; no `cats expose` step is required. The URL is tied to the Cat resource, not a host, and is also printed by `cats create` and `cats get`.

The application must listen on `0.0.0.0:8080` (or `:::8080`). A service bound only to Guest loopback cannot be reached through the tap network.

## Additional ports

    # Repoint the default URL to port 3000
    cats expose dev 3000

    # Or add a second URL
    cats expose dev 3000 --name preview --protocol http
    cats endpoint ls dev

Without `--name`, `cats expose` reconfigures the default `web` Endpoint. Use a different name to add a second URL. V1 Endpoints are publicly addressable; do not expose an unauthenticated administration or secrets interface.

## Wake policy

    cats expose dev 3000 --name internal-preview --no-wake

- **wake on request:** the gateway singleflights concurrent activation attempts for a sleeping Cat, waits for readiness, and then routes to the new activation epoch.
- **no wake:** a request does not start the Cat; use this for workloads that should serve only while explicitly Running.

A client should tolerate `503` with retry guidance during activation and reconnect after lifecycle or host changes. Stable hostname does not mean stable long-lived connections.

## Protocols and routing safety

The implemented path supports HTTP/1.1 and WebSocket Upgrade with TLS termination at the regional edge. HTTP preserves method, path/query, application headers, response status, and request/response bodies. WebSocket preserves application headers and relays text, binary, ping, pong, and close frames while holding a work lease for the connection. The owning node revalidates Cat ownership and Running state; an old cached route fails closed instead of reaching a different Guest.

## Where this stands today

HTTP and WebSocket ingress work: Endpoint addresses, route binding, wake-on-request, and connection-length work leases are in place.

Not yet available: **private Guest-to-Guest networking across nodes**.

## Prepare the Guest service

1.  Listen on `0.0.0.0:8080` for the default URL, or on the selected additional Endpoint port.
2.  Return readiness only after dependencies and disk state are usable.
3.  Do not expect Cats to preserve application TCP state across sleep.
4.  If background work must keep the Cat Running, acquire a [work lease](/docs/runtime-api/).

## Troubleshoot an Endpoint

    cats get dev
    cats endpoint ls dev
    cats operation ls
    cats exec dev -- sh -lc 'ss -lnt'

Verify the Cat is healthy, the Endpoint targets the expected port, the latest activation Operation succeeded, and the Guest service is actually listening. Operators should also check route epoch mismatch and gateway/node connectivity metrics.
