# Design plan: V2 single-use nullifier admission

**Status:** Proposed / not implemented. **Date:** 2026-11-11. **Related research:** [nullifier-uniqueness-research.md](nullifier-uniqueness-research.md).  
**Target:** `holochain-zero-knowledge-admission`, current main at `b0799e784a7d0df0533e14df14a1c6658ac7f0af`.  
**Review gates:** scope/finality ADR, protocol + threat-model review, integration tests, security review.  
**This document specifies an MVP, not a claim that production guarantees have been achieved.**

## 0. Decisions and exclusions

**Recommended MVP: operator-trusted atomic redemption service** with (1) durable transactional uniqueness, (2) a DNA-pinned receipt-signing key whose use is gated by the registry, and (3) deterministic receipt verification by the Holochain integrity zome. The first implementation can use etcd v3 transactions / Raft. The protocol separates *who decides* from *how validators verify* so it can later use a 3-of-4 durable witness quorum or established BFT consensus.

| Decision | Proposed initial choice | Why / caveat |
| --- | --- | --- |
| Canonical single-use scope | One logical admission per `(DNA deployment_id, canonical domain, nullifier)` | Matches the existing HMAC inputs. **Not** once per credential across arbitrary domains. |
| Domain policy | Exactly one DNA-configured admission domain for MVP | A client-selected domain would permit the same secret to yield multiple nullifiers. Verify domain against DNA policy before redemption and in integrity validation. |
| What is unique? | **Logical admission/entitlement**, identified by canonical spend key | Multiple identical DHT actions or receipt replays may exist; consuming applications must not grant duplicate entitlements. |
| Ordering authority | Operator-trusted service, backed by linearizable, durable etcd transactions | Protects against concurrent requests and crash faults under Raft assumptions, **not** malicious operator equivocation. |
| Signature authority | Dedicated receipt key pinned in DNA properties; only the post-commit signer can access it | Operational controls restrict signing but do not prove cryptographically that an adversarial operator never bypassed the registry. |
| Finality | Successful, durable `put-if-absent` commits `K` permanently to one intent | Issuing a receipt is recoverable afterward. A committed key never becomes free just because receipt delivery failed. |
| ZK statements | Retain `ZkStatementV1` and both SP1/native Groth16 proof relations | Add a V2 wrapper and receipt; avoid SP1 guest/ELF rebuild for this change. |
| Versioning | New `ZkProofEntryV2` and DNA properties / entry type; V1 not accepted as equivalent entitlement | The README says no deployed V1 network exists; verify before migration. |
| DNA joining | **Decision gate:** is this a membrane admission or a post-join entitlement? | If preventing agents joining is required, V2 receipt must also be checked by `AgentValidationPkg` validation; ordinary proof entry checks are too late. |

**Non-goals of MVP:** operator Byzantine resistance; new zero-knowledge circuit or proof system; generic on-chain consensus; a DHT-wide mutable uniqueness query; revocable/recyclable spend keys; dynamic sharding; replacing issuer-authentication work.

## 1. Threat model and properties

An adversary may control arbitrary Holochain client agents, clone a credential secret, re-randomize Groth16 proofs, submit conflicting statements concurrently, replay receipts, omit publication, alter fields, partition network links, and crash/restart clients. Assume some validators can be faulty, but honest integrity validators use the same pinned DNA trust configuration. For MVP, the operator, receipt signer and majority of etcd voters are **trusted according to the service's stated security model**; malicious operator or compromised signer are out of scope for strict prevention but must be detectable/auditable where possible.

**Safety invariant S1:** for each spend key `K`, at most one *intent digest* may become durably committed and receive any legitimate final receipt. Same-intent retries return the same committed result.

**Safety invariant S2:** validation accepts a V2 proof entry only with a valid receipt whose immutable signed fields match the complete statement, admission capability, intended author and DNA-pinned registry identity. Any accepted entry still needs all existing bindings, signatures, SP1 and native proof verification.

**Safety invariant S3:** no client, signer or recovery process can produce a final receipt for an intent other than the durably committed owner of `K`. After a transaction commits, `K` is never deleted or repurposed.

**Safety invariant S4:** users of the admission entitlement key access from `K` / admission ID and apply idempotent semantics. Duplicate publication cannot multiply rights.

**Liveness L1:** with a healthy authority, valid proofs, issuer-authorized credentials, unspent nullifiers and available DHT dependencies, a request eventually obtains a receipt and an accepted logical entitlement. Partitions may block progress, not violate S1.

**Explicit limitations:** S1 assumes correct authority/signing service. The current repository does *not* cryptographically establish issuer provenance, so a correct uniqueness registry prevents reusing the **same nullifier**, not inventing arbitrarily many credential secrets. Cryptographic issuer authentication is a separate **production blocker**.

## 2. Architecture

```text
Prover/agent
  | 1. construct ZkStatementV1 with pinned DNA/domain and own AgentPubKey
  | 2. create both existing Groth16 proofs (no registry spend yet)
  | 3. obtain/bind valid operator admission capability (final sequencing choice below)
  v
Admission API / authenticated policy checks
  | validate statement, signed capability, proofs and intended recipient
  | build canonical IntentV2 (K, statement_hash, capability_id, prover, ...)
  v
etcd Raft-backed registry -- atomic compare(version(K) == 0) and put
  | winner: persist ownership K -> exact intent + registry epoch
  | same intent retry: read same committed ownership
  | different intent: permanently reject DUPLICATE
  v
Receipt signer (post-commit only; dedicated DNA-pinned Ed25519 key)
  | sign FINAL_SPEND_RECEIPT_V2(K, intent_digest, commit_revision, ...)
  v
Prover publishes ZkProofEntryV2(statement, admission, both proofs, receipt)
  v
Holochain integrity zome
  | verify receipt against DNA-pinned registry key
  | compare statement/capability/author/scope; original V1 checks
  | SP1 + native Groth16
  v
Application entitlement keyed by K (not action/proof hash)
```

**No online registry calls are made from Holochain integrity validation.** Holochain's deterministic validation API can retrieve only known-address immutable dependencies with `must_get_*`, not mutable global link sets. Embed the complete signed receipt in the V2 entry for the MVP; a future separately published immutable receipt action is optional and must not create a circular hash dependency.

## 3. Canonical bytes and data structures

All bytes must have a formally specified, test-vector-backed canonical encoding. The examples below are **illustrative types**, not compile-ready public interfaces. Do not serialize signatures using unspecified Serde layout when signing.

### 3.1 Fixed-width spend key

```text
spend_key_v2 = SHA256(
    ASCII("HC-ZK-SPEND-KEY-V2") || 0x00
    || deployment_id[32]
    || domain[32]
    || nullifier[32]
)
```

Inputs are already fixed-width; use an exact test vector and versioned domain separator. The nullifier is unchanged from `hashes::nullifier`. A different domain changes the nullifier, so DNA policy **must** constrain it if membership is to be once per deployment. An epoch is **not** included: epoch-bound reuse would require a deliberate protocol upgrade.

### 3.2 Intent and receipt

```rust
// Illustrative protocol objects, not final code.
struct AdmissionIntentV2 {
    version: u16,
    registry_id: [u8; 32],
    registry_epoch: u64,
    deployment_id: [u8; 32],
    domain: [u8; 32],
    nullifier: [u8; 32],
    statement_hash: [u8; 32],
    capability_id: [u8; 32],
    prover_key: Vec<u8>, // canonical Holochain author key representation
    request_id: [u8; 32],
}
struct FinalSpendReceiptV2 {
    version: u16,
    registry_id: [u8; 32],
    registry_epoch: u64,
    spend_key: [u8; 32],
    intent_digest: [u8; 32],
    decision_revision: u64,
    signer_key_id: [u8; 32],
    signature: [u8; 64],
}
struct ZkProofEntryV2 {
    statement: ZkStatementV1,  // unchanged relation and SP1 program
    admission: AdmissionV1,   // existing signed capability
    groth16_proof: Vec<u8>,
    nullifier_proof: NullifierGroth16ProofV1,
    spend_receipt: FinalSpendReceiptV2,
}
```

A canonical intent digest uses a separate domain tag (`HC-ZK-ADMISSION-INTENT-V2\0`), fixed-width network-order fields, and explicit length-prefix encoding for `prover_key`. Pin the precise conversion of a Holochain `AgentPubKey` to the `ProverKeyV1` representation used by `validate_admission_bindings`. For receipt signing, use a different tag (`HC-ZK-FINAL-SPEND-RECEIPT-V2\0`), with all receipt fields except `signature`. Store bytes or their hash for deterministic recovery.

**Never include:** Groth16 proof bytes, the DHT action hash of the entry being created, the receipt itself in its own intent hash, or an untrusted timestamp as a uniqueness component.

**Bind all of:** statement hash, capability ID, owner key, registry identity and epoch. The capability already binds sequence window, policy and statement; receipt binding to its ID is defense in depth. An action on another author chain cannot reuse the receipt if author/statement/capability validation is correct.

A request ID is for retries, not a new uniqueness scope. Choosing a new request ID for the same `K` **must never** grant an additional spend.

### 3.3 DNA configuration

Proposed `DnaPropertiesV2` extends existing proof keys/configuration with:

```rust
registry_id: [u8; 32],
registry_receipt_key: [u8; 32],
registry_receipt_key_id: [u8; 32],
registry_epoch: u64,
admission_domain: [u8; 32],
```

All are DNA-authenticated. Define whether registry epoch means *key/configuration version* vs *credential-admission epoch*: they are not interchangeable. Rotating an authority must inherit the historical spent set and a handover that prevents old and new authorities from signing overlapping contradictory decisions. **Do not rotate signer and reset the registry.**

## 4. Redemption transaction, crashes, and proof timing

### 4.1 Normal path

1. Build an intent from an already computed statement and valid admission capability; validate DNA/domain, exact author, issuer policy, both proofs, signatures and protocol fields *before* committing. The registrar must independently reject invalid requests rather than burning a nullifier on obviously invalid evidence.
2. Read-only preflight checks are advisory only. Submit one etcd `Txn` comparing `version(K) == 0`, with success branch writing the canonical intent digest plus full intent/recovery data. Both comparison and write occur atomically.
3. Successful transaction establishes the permanent owner of `K`. Capture the committed revision/decision metadata for the receipt. If comparison fails, read the committed owner using a linearizable read: same intent -> return its receipt/status; other intent -> conflict.
4. Only **after** the durable transaction may the receipt signer sign the canonical final receipt. The signer must confirm the committed owner and never sign for a losing request. Persist signed receipt or deterministically reproduce the *same* payload after restart.
5. Return `FINAL`, `ALREADY_FINAL_SAME_INTENT`, `CONFLICT`, or `PENDING_RECOVERY`. The client publishes the V2 proof entry only with a verified final receipt.

**Failure edge:** if state commits but receipt signing fails permanently, the nullifier remains consumed (fail-closed safety). Restore signer access and finish the same receipt; never free `K` to a different intent. The registry must not use TTLs or leases for finalized spend keys. A pending *preflight* object may expire, but it must not authorize admission.

### 4.2 Proof sequencing problem in this repo

Currently `crates/prover/src/lib.rs::prove_entry` requires `AdmissionV1` and constructs native+SP1 proofs, while the SP1 proof itself commits **only `ZkStatementV1`**. Therefore the registry receipt need not be present during SP1 proving. Factor out a pre-proof API that returns proof bytes from a frozen statement, then pair it with a capability and final receipt before publishing.

The existing capability requires a bounded source-chain action sequence; SP1 proving can take ~8–10 minutes. During proving, extra source-chain actions may invalidate the chosen sequence. Preserve the sequence constraints by checking intended candidate sequence just before publication, reserving a dedicated agent workflow, and aborting/re-proving if the immutable statement or capability changes. An irreversible spend must not be made until those preconditions are satisfied. Better sequence-window or preauthorization ergonomics are a separate design task.

**Recommended pipeline:** construct statement -> generate proofs -> acquire a valid operator capability for the unchanged statement and expected author sequence -> atomically redeem -> verify receipt -> immediately publish. If policy demands issuing capabilities before proving, they remain non-final until registry redemption.

## 5. Rust integration and affected paths

| File / component | Planned work | Acceptance criterion |
| --- | --- | --- |
| `crates/protocol/src/hashes.rs` and new `spend.rs` | Canonical spend key, intent digest and receipt message; fixed-width encodings | Golden vectors, domain separation, collision-of-encodings tests |
| `crates/protocol/src/admission.rs` | Explicit V2 receipt/key types; no implicit compatibility with V1 | Version-specific parse/verify, exhaustive field mismatch tests |
| `crates/protocol/src/proof.rs` | `ZkProofEntryV2` wrapper carrying both unchanged proofs and receipt | Missing receipt cannot be parsed as valid V2 |
| New `crates/registry-core` | Pure state-machine logic, idempotency, authorization outcomes | Race and crash recovery tests with injectable backend |
| New `crates/registry-service` | etcd transaction adapter, policy validation, post-commit signing, status API | Concurrent same-nullifier requests commit one intent |
| `crates/prover/src/lib.rs` | Separate proving from assembling final entry; client receipt verification | No SP1 guest ELF change; old proof API preserved or versioned |
| `crates/integrity-zome/src/lib.rs` | Exact V2 entry type validation, DNA-pinned receipt verification, existing V1 cryptographic checks | Tampered/wrong DNA/author/scope/registry receipts rejected |
| `crates/integrity-zome/src/crypto.rs` | Receipt Ed25519 signature verification with domain separation | Wrong key/signature/epoch rejected without network requests |
| `crates/integrity-zome/src/activity.rs` | Ensure valid V2 create path across relevant DHT ops; account for prior V1 proof entry if applicable | No unintended bypass via alternate op path or V1 type |
| New `crates/registry-client` | Request/retry/status; verify final receipt before publication | Idempotent recovery across client crash and lost reply |
| `tests` / conductor tests | Real multi-agent concurrent claim and replay | No competing final entitlements; validity failures deterministic |

Rust workspace / HDI pinned today: `hdi = 0.8.0`, `hdk = 0.7.0`. The Holochain zome has **no** etcd client or outbound network dependency. Any new Rust API, membrane callback, and entry type must be verified against these pinned versions, not assumed from a newer Holochain example.

### Integration invariant

Existing `validate` currently accepts Create actions for the exact `zk_proof_v1` entry type and returns `Valid` early for unrelated operations. A V2 deployment must define an exhaustive `zk_proof_v2` validation path and ensure **V1 proof entries do not confer V2 admission**. Test `CreateRecord`, `CreateEntry` and `AgentActivity` contexts as the Holochain op model requires, including cases with no cached entry. If a future authorization is a known-address DHT dependency, validate required invariants in `CreateRecord` and use `must_get_valid_record` with its documented limitations.

## 6. API sketch

```text
POST /v2/admissions/redeem
  Body: canonical statement + admission capability + both proof bytes + request_id
  Response: { status: FINAL | CONFLICT | PENDING_RECOVERY,
              intent_digest, receipt? }

GET /v2/admissions/requests/{intent_digest}
  Response: { status, receipt? }
```

API calls require transport authentication, TLS, authorization/rate limiting, anti-DoS controls, fixed maximum payload sizes, and a stable canonical wire format. A user must **not** be allowed to query arbitrary registry keys to learn credential existence unless the privacy impact is accepted; prefer status queries authorized by the original request or capability. Distinguish HTTP/service errors from durable outcome state. Endpoints are design placeholders, not deployed URLs.

The service must verify that a validly signed capability was issued for the exact statement, and prevent rejected/invalid requests from consuming spent keys. The complete production issuance policy depends on implementing issuer-secret provenance (separate workstream).

## 7. Security, privacy and operational requirements

- **Secret/key handling:** the registry stores only scoped nullifier and statement/capability hashes plus minimal recovery fields, never credential secrets, private prover material, or SP1 witness data. Receipt signing key separate from admission delegation key.
- **No signer bypass:** signing happens behind a policy gate that checks committed ownership; audit all signature issuance. Key custody and crash recovery are part of the trusted computing base; an adversarial operator can still equivocate in MVP.
- **Persistence:** data loss/rollback of etcd or signing state may break safety. Define quorum backups, restore fencing and monotonically increasing authority epochs, and reject unsafe restores.
- **Availability:** if quorum unavailable, no new FINAL receipts. Never fall back to local cache or best-effort DHT uniqueness checks.
- **Privacy:** stable public nullifiers are linkable within their scope, and the service can observe redemption metadata. Avoid logs containing full proofs, IP addresses or credential identity where possible; document retention and privacy policy.
- **Receipt verification:** cap input sizes; reject unknown versions, wrong program/DNA, noncanonical encodings, key mismatch, wrong registry epoch and malformed signatures; fail closed.
- **Replays and entitlement semantics:** prove idempotence at registry layer and application layer. Holochain validation alone cannot guarantee exact-one physical record globally.
- **Migration:** adding DNA properties and entry schemas changes DNA identity. Since README states no V1 network is deployed, prefer a clean V2 DNA rather than dual accepting V1 without the receipt.
- **Future federation:** for `n=4, t=3, f=1`, quorum intersection `2t - n > f` supports conflicting-certificate exclusion *only if* each honest signer durably refuses the second intent. Membership changes, signing nonce safety, rollback and liveness need additional design and security review.

## 8. Work packages, deliverables, and exit criteria

### Phase 0 — Protocol ADR and security gates (P0)

- [ ] Decide uniqueness scope, canonical DNA admission domain and entitlement semantics.
- [ ] Decide membrane admission vs proof-entry-only authorization.
- [ ] Record trusted-operator threat assumption vs future Byzantine upgrade.
- [ ] Define issuer-authentication dependency and credential reissuance/recovery policy.
- [ ] Review key rollover, frozen source-chain sequence constraints and V1 migration assumption.

**Exit:** signed-off ADR / testable security invariants; no code claims production readiness before issuer authentication.

### Phase 1 — Pure V2 protocol and verifier (P0)

- [ ] Add canonical intent, spend key, receipt, signing bytes and fixed test vectors.
- [ ] Add V2 entry type and fail-closed protocol versioning, preserving V1 ZK witness relation.
- [ ] Add deterministic receipt verification function with no I/O.
- [ ] Build negative tests for every bound field, authority key, version, scope and signature.

**Exit:** cross-language-independent vectors and property tests; exact schema and signature audit completed.

### Phase 2 — Atomic registry MVP (P0)

- [ ] Create registry state machine with `UNSEEN` -> durably `COMMITTED`, same-intent recovery, and conflicts.
- [ ] Implement etcd `Txn` compare/version-0 and linearizable read of winning intent.
- [ ] Implement post-commit signer and recoverable receipt/status storage; enforce no key deletion.
- [ ] Add client authentication, rate limiting, request size caps and minimal audit events.

**Exit:** in repeated concurrent two-client runs, exactly one distinct intent becomes FINAL; crash/restart never changes the winning intent.

### Phase 3 — Prover and Holochain integration (P0)

- [ ] Split proofs from publication; let prover attach a final receipt after proving.
- [ ] Add V2 DNA settings and mandatory V2 receipt checks to integrity zome.
- [ ] Ensure V1 entries cannot confer V2 rights, and all DHT validation op variants behave correctly.
- [ ] If the product means network joining, validate membrane proof at agent genesis as well.

**Exit:** two-agent conductor integration, valid claim accepted, malformed/conflicting claims rejected, no network query in `validate`.

### Phase 4 — Failure-mode testing and security review (P0 for production)

- [ ] Exercise timeouts, duplicate requests, exact receipt replay, re-randomized proofs and client crashes.
- [ ] Exercise leader elections, partitions, signer restart, stale restore, malicious signer/key loss and V1 bypass.
- [ ] Benchmark steady-state and burst admission latency separate from SP1 proving.
- [ ] Complete issuer-secret authentication implementation and end-to-end proof tests.
- [ ] Publish a security model listing remaining operator and rollback assumptions; independent review.

**Exit:** all required failure cases meet advertised safety invariant; release checklist approved.

### Phase 5 — Optional decentralization upgrade (P2)

- [ ] Prototype durable 3-of-4 witness signatures or an established BFT replicated state machine.
- [ ] Design key rotation, membership-change handoff and state transfer without conflicting epochs.
- [ ] Evaluate sparse Merkle / append-only log checkpoints and COSE receipt profile for auditability.
- [ ] Compare availability, operator independence, storage cost, verification cost and tail latency.

**Exit:** switch authority mechanism without changing the canonical `spend_key` or rebuilding SP1/native proof circuits, unless threat model demands a separate protocol version.

## 9. Adversarial acceptance matrix

| Test | Expected invariant |
| --- | --- |
| 100 concurrent distinct intents with same `K` | Exactly one committed winning intent / FINAL receipt |
| Same intent delivered 100 times | Identical decision and receipt; one logical entitlement |
| Vary statement nonce, author, capability or request ID for same `K` | Conflict, never another FINAL |
| Rerandomize SP1/native proof bytes | No new spend; proofs do not define uniqueness |
| Drop response immediately after etcd commit | Retrying retrieves receipt for **same** intent |
| Kill signer after commit / before signature | Same intent recoverable; `K` stays consumed |
| Lose majority / partition replicas | No unsafe FINAL result; recovery after quorum returns |
| Restore stale snapshot / reintroduce old key | Detect/fence unsafe restore; no conflicting FINAL |
| Rotate registry signing key | Historical ownership persists; old/new epochs cannot conflict |
| Wrong domain, DNA, registry ID, epoch or signer | Rejected by deterministic zome verifier |
| Reuse receipt on another agent's action | Rejected by bound author + capability + statement |
| Publish same logical admission multiple times | At most one application entitlement; document DHT duplicates |
| Source-chain sequence moves during slow SP1 proof | No invalid receipt issued/published; deterministic recovery |
| Invalid/non-issued credential secret | Rejected once issuer-authentication workstream ships |
| DNA join without membrane proof (if membership goal) | Rejected during genesis / agent validation |
| Future 3-of-4 Byzantine quorum: one equivocal signer | No two conflicting FINAL quorum certificates |

## 10. Go/no-go criteria

**Prototype success:** V2 proof entry with a DNA-pinned signature verifies in the integrity zome, two conflicting registrants cannot both obtain final receipts from the trusted atomic service, and retries/crashes preserve the winner.

**Production go:** issuer authenticity, correct admission entry-vs-membrane boundary, multi-agent conductor coverage, real SP1 proof exercised in end-to-end tests, fault recovery runbooks, key custody, observed latency/storage benchmarks and explicit acceptance of the trusted-operator assumption. None of these should be inferred solely from passing unit tests.

**Security upgrade go:** when operator equivocation is unacceptable, require documented, independently verified quorum/BFT safety and key-rotation semantics before changing the trust claim.

## References

- Research survey: [DHT-wide nullifier uniqueness](nullifier-uniqueness-research.md).
- Holochain: [`must_get_*` and deterministic validation](https://developer.holochain.org/build/must-get-host-functions/); [validate callback / membrane](https://developer.holochain.org/build/validate-callback/); [genesis_self_check](https://developer.holochain.org/build/genesis-self-check-callback/).
- etcd: [Transaction API and compare semantics](https://etcd.io/docs/v3.7/learning/api/).
- IETF: [Privacy Pass RFC 9577](https://www.rfc-editor.org/rfc/rfc9577.html); [FROST RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html).
- Cashu: [NUT-07 state check](https://cashubtc.github.io/nuts/07/).
- I-confluence: [Coordination Avoidance in Database Systems](https://www.vldb.org/pvldb/vol8/p185-bailis.pdf).
