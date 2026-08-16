## Lifecycle model

Running, Suspended, Warm, and Cold remain distinct runtime states:

| State | Process memory | Host-bound |
|----|----|----|
| Running | Active | No |
| Suspended | Preserved; pages may move to local NVMe | Yes |
| Warm | Preserved in a local VM snapshot; VMM exits | Yes |
| Cold | Discarded; boot from durable disks | No |

Suspended and Warm cannot be merged. Both protect Host-local state; Cold starts a new kernel and processes. Leaving Running closes route admission and drains guards before Guest, VMM, blockd, or attachment effects.

## Current release boundary

The signed runtime cutover exposes Cat create and read projections, but no user lifecycle mutation. The per-Cat reconciler is the sole physical-effect executor and `DesiredRuntimeSpec` is the sole lifecycle intent. A browser or CLI cannot invent a transition, steal an attachment, or infer Cold from missing local evidence.

Missing or corrupt checkpoint/inventory evidence blocks or quarantines reconciliation. An unplanned cross-Node recovery additionally requires trusted Host-fence and exact Volume takeover authority.
