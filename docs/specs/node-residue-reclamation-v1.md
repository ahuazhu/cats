# Node Residue Reclamation v1

- Status: Proposed; not accepted and not production authority
- Lifecycle authority: [ADR-0040](../decisions/0040-level-triggered-runtime-reconciliation.md)
- Volume authority: [ADR-0042](../decisions/0042-volume-authority-and-disk-lifecycle.md)
- Observation contract: [Runtime Reconciliation v1](runtime-reconciliation-v1.md)

This note records the clean-slate wire and recovery design implemented for
review in `feat/108-residue-reporting`. It does not amend either accepted ADR.
Until this proposal is accepted and the physical reclaimer has its durable
restart record, every reported residue remains retained and lifecycle/route
admission remains fail-closed.

## 1. Observation is not authority

A complete physical inventory reports every stable foreign artifact as one
closed `NodeResidue` instead of aborting the whole scan. A partial or unstable
source does not invent residue: it makes the inventory incomplete.

`NodeResidue.data_directory` carries the observed path, allocated bytes,
optional Cat/Disk/Volume hints, ownership-token evidence, a closed retention
reason and either unreadable lineage or this exact readable lineage:

- Workspace, Cat, Disk, Disk kind and Volume;
- attachment ID and epoch;
- the normal transition ID or takeover authorization ID which created it,
  plus that acquisition's complete immutable request/result or consumed
  authorization/receipt pair;
- the domain-separated SHA-256 digest of that complete acquisition value;
- current Desired revision, spec digest and assigned placement, plus the
  historical acquisition placement epoch;
- local and remote durable generations, complete remote head, pending-pack
  count and local fenced observation.

The acquisition digest preimage is
`"cats.runtime.residue-acquisition.v1" || NUL || canonical(acquisition)`.
It is a corruption/binding check, never a replacement for the complete
acquisition receipt carried beside it.

Hints and retention reasons are diagnostic only. They MUST NOT authorize a
filesystem mutation. Readable lineage fields must agree with any repeated
hints. Unknown, corrupt, duplicated, raced, over-budget or partially scanned
artifacts remain visible when they can be bounded and remain retained; they
never become guessed Cold state or guessed deletion proof.

Unassigned data is enumerated only through retained directory descriptors.
Each child is opened with no-follow semantics and matched back to the device,
inode, owner and expected type that was enumerated. Allocated-byte traversal
is iterative and depth bounded. One source-wide counter admits at most 4,096
residue values; discovery of item 4,097, cancellation, deadline, depth
overflow, a path/type substitution or any partial enumeration makes the data
source incomplete without deleting or hiding the retained bytes.

A corrupt or wrong-binding checkpoint at the canonical filename of an
assigned Cat is projected as that Cat's `CheckpointEvidence.corrupt`, not as a
second top-level residue at the same path. The Cat remains at
`InspectInventory`, lifecycle admission remains closed, and an independently
exact local data lineage may still be observed without treating the corrupt
checkpoint as process, route or mutation authority.

## 2. Exact Control query

The proposed signed endpoint name is
`POST /v1/internal/runtime/residue-authority`, but the production router does
not install it while this document remains Proposed. Its read-only Store seam
uses the common current AgentSession proof and binds the request lineage's
Node to that authenticated session. Control evaluates one exact lineage in one
repeatable-read PostgreSQL snapshot and returns the same session and lineage
plus exactly one outcome:

- `retained { reason }`, which is diagnostic only; or
- `reclaimable { proof }`, containing one of the three proofs in §3.

The same repeatable-read snapshot must bind the current Desired Workspace,
Cat, revision, spec digest and assigned Node/placement; its exact Volume intent
must bind Disk, kind, Volume, attachment and acquisition coordinate; and the
product Disk row (or the exact typed completion retained after atomic product
deletion) must bind the same Workspace/Disk/Volume/Cat. Existing cross-
Workspace coordinates and missing coordinates return the same closed error so
this seam cannot become a metadata-existence oracle.

The query is read-only. Response loss is resolved by repeating the same exact
query; no reply is a deletion authorization. Missing, duplicate, split or
corrupt authority rows fail closed. Enabling the HTTP route or using a proof
for physical deletion requires a separately accepted decision and release
composition change.

## 3. Closed reclaim proofs

No proof outside this list is valid:

1. `ordinary_release`: the current canonical Volume row is unowned and its
   last transition is the exact Release successor of the retained attachment
   ID and epoch. The retained lineage must have `R == L`; its remote head must
   be the release head or an earlier generation proven by that release.
2. `normal_delete_completion`: the canonical completion names the exact Disk
   and Volume, and its unowned predecessor epoch is the retained attachment's
   direct successor. The retained lineage must have `R == L`; the completion
   head must be the same or later.
3. `disposable_root_delete_completion`: a Root-only completion and its exact
   consumed disposable-delete authorization jointly bind Cat, Disk, Volume,
   delete ID, old attachment, old epoch, Node, placement and head. The
   completion's delete ID must equal both the authorization and consumed
   receipt, and its completion time must not precede consumption. This is the
   only proof allowed to consume a retained `R < L` tail.

PersistentDisk, unknown lineage and `R < L` without the exact disposable Root
pair always remain retained. Observation fields, directory names, audit logs,
timeouts, lease expiry and ownership-token hints cannot substitute for these
proofs.

## 4. Physical effect remains a separate acceptance item

Even a closed Control proof is insufficient by itself. A future physical
reclaimer must retain an already-open descriptor to the scanned directory,
revalidate its device/inode and complete child set, prove the exact local
lineage and absence of every live process, device, mount, network and socket
owner, then persist a bounded restart checkpoint before the first unlink. It
must unlink only descriptor-relative validated entries and fsync each parent.

Blind `remove_dir_all`, path re-resolution after qualification and best-effort
cleanup are forbidden. Crash, cancellation, restart and ambiguous completion
must rediscover the checkpoint and exact postcondition. This reporting/query
slice deliberately installs no physical data-directory deletion effect.
