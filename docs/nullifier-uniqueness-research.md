# Research: DHT-wide nullifier uniqueness and admission finality

Status: **research / design proposal, not implemented or audited**  
Updated: **2026-11-11**  
Scope: `zk-admission`; no changes to proof circuits or validation logic are made by this document.

## Executive summary

The repo checks admission bindings, source-chain history, signatures, an SP1 Groth16 proof, and a native arkworks Groth16 nullifier proof. It does **not** enforce DHT-wide uniqueness of a nullifier. Two separate Holochain authors can each submit otherwise-valid proofs for the same nullifier. Different proof bytes or action hashes must never count as different spends.

**Conclusion:** a deterministic ZK nullifier is a *stable identifier*, not a globally serialized single-use right. Strict first-use finality requires an exclusive decision authority (possibly replicated or Byzantine-resilient); a DHT index, non-membership witness, or timestamp alone cannot supply that ordering. Holochain integrity validation can verify **immutable, known-address evidence** for an already-authorized spend but cannot safely query global mutable state to establish absence.

**Recommendation:** Prototype a small external, crash-fault-tolerant *single-use redemption service* (etcd/Raft transactional backend) with independently verifiable, signed, statement-bound receipts, then compare it against a *durable 3-of-4 witness quorum* using adversarial tests. If stronger Byzantine fault tolerance and operator independence are hard requirements, evaluate an existing BFT state-machine framework rather than inventing consensus. Add a verifiable log/map only after the ordering and finality rules are settled. Keep both existing Groth16 proofs.

## Current repository boundary

Verified against `main` at commit `b0799e784a7d0df0533e14df14a1c6658ac7f0af`:

- `crates/protocol/src/hashes.rs`: `nullifier(secret, deployment_id, domain, protocol_version)` is HMAC-SHA256 with domain separation. Epoch and prover key are **not** part of the nullifier derivation.
- `crates/protocol/src/statement.rs`: `ZkStatementV1` contains `deployment_id`, `domain`, `prover`, issuer identifiers, epoch, nonce, and `nullifier`.
- `crates/protocol/src/admission.rs`: `AdmissionCapabilityV1` binds a `statement_hash`, prover, sequence window, policy, and operational signer.
- `crates/integrity-zome/src/lib.rs`: `validate` checks the candidate against deterministic admission bindings, prior activity on that **author's** branch, Ed25519 admission signatures, SP1, and native Groth16.
- `crates/integrity-zome/src/activity.rs`: prior activity checks a source-chain sequence window; it is not a cross-author nullifier index.
- The README explicitly lists DHT-wide uniqueness **and** issuer-secret authentication as incomplete.

Scope question to resolve *before* designing storage: do we want once per **(deployment, domain, nullifier)**, once per deployment/credential, or once per credential/epoch? Since the current HMAC includes domain but not epoch, changing this scope is a protocol change, not just a database index change.

If the objective is preventing an agent from **joining a DNA**, assess `AgentValidationPkg` / membrane-proof validation, not just an ordinary proof entry that an agent can publish after genesis.

## Required security properties and trust model

1. **Safety:** for a canonical scope key `K`, at most one **distinct logical admission** can receive a *final* valid authorization. Replays of the exact same authorization may be idempotent, but must not confer a second right.
2. **Crash safety:** restart/retry cannot turn an already finalized spend into `UNSPENT`. A receipt issued before a crash must remain authoritative afterwards.
3. **Binding:** the final authorization identifies the exact statement hash, deployment, domain, nullifier, intended agent, protocol version and registry configuration/epoch.
4. **Deterministic integrity validation:** peers verify signatures, policy, fixed references and immutable dependencies; no time-dependent DHT-wide absence queries.
5. **Fault model:** document separately what remains safe against (a) network partitions, (b) crash faults, (c) registrar/operator key compromise, (d) Byzantine signers, (e) forks/rollback, (f) censorship, and (g) malformed or cloned credentials.
6. **Privacy:** nullifier scope should limit linkability; never store the secret or unnecessary identity data in the registry.
7. **Liveness:** describe which failures merely pause admissions and how recovery proceeds without weakening safety.

**Important nuance:** the existing admission authority can sign a capability for any statement it chooses. If it can bypass the uniqueness decision engine, an ordinary capability signature is not proof of exclusivity. Either trust the authority to obey an atomic registry, restrict signing behind that registry, or require a cryptographically verifiable quorum/consensus certificate.

## Why a DHT-only uniqueness lookup is insufficient

Holochain's `validate` callback must be deterministic across validators. The developer documentation says `get_links`/`get_details` are unavailable there; `must_get_*` fetches content by a stable address, not a changing global collection. `must_get_valid_record` is useful for validating a known immutable dependency, with caveats about which DHT operations it actually validates [H1].

Even outside integrity validation, two agents can both check "N not found" and publish N concurrently before gossip converges. A common nullifier anchor entry or `EntryHash` can help *discover* collisions; it is not an atomic test-and-set. Likewise, choosing the lexicographically lowest action hash gives at best eventual conflict resolution (and late claims can overturn a previous application decision), not immediate finality.

The theoretical framing is *invariant confluence*: separately valid operations that merge into a state violating a uniqueness invariant require coordination if safety must hold while decisions are made [D1].

Source-chain fork detection, agent-key-bound credentials, and countersigning can narrow the threat model but do not replace a proof of globally exclusive authorization. Holochain explicitly distinguishes countersigning from double-spend prevention [H2, H3].

## Survey: existing protocol families

| Protocol / pattern | What we can reuse | What it **does not** guarantee |
| --- | --- | --- |
| Privacy Pass (RFC 9577) | Single-use redemption; explicitly shared double-spend state across accepting servers [P1] | The token proof cannot enforce global state without origin coordination |
| Semaphore | Scope-derived ZK nullifiers and consuming-application spent-set checks [P2] | Proof generation alone cannot prevent reuse |
| Zcash Orchard / Monero-style key images | Stable cryptographic spend identifiers with stateful prevention [P3] | Alternative identifier construction would not eliminate ordering |
| Cashu NUT-07 | `UNSPENT`, `PENDING`, `SPENT`; concurrent in-flight spends must be remembered [P4] | A state-query API does not itself provide replicated finality |
| Waku RLN / offline e-cash | Double-signaling detection, accountability, possible penalties [P5] | Detection after the fact is not strict single-use admission |
| DNS UPDATE RFC 2136; HTTP conditional requests | Conditional first-writer semantics [I1, I2] | A protocol precondition is only as reliable as its authoritative backend |
| etcd transactions over Raft | Atomic compare/version-0 creation for a spent key [I3] | Crash-fault tolerance is **not** Byzantine operator resistance |
| Fedimint / AlephBFT architecture | Federated ordered transactions, consensus-applied module state, status/recovery patterns [I4] | Considerable operational weight; not a ready-made Holochain admission module |
| FROST RFC 9591 | Threshold signing, including Ed25519-compatible ciphersuite [C1] | FROST has **no built-in** per-nullifier non-equivocation or consensus |
| BFT quorum certificate | Prevent two conflicting final receipts if quorum intersection contains an honest signer | Needs membership/reconfiguration, durable anti-double-sign state, availability rules |
| Sparse Merkle map / Trillian log-derived map | Compact membership/non-membership witnesses; auditable historical commitments [T1] | Two non-membership proofs against the same old root can both be valid |
| Certificate Transparency RFC 9162 / COSE Receipts RFC 9942 / RFC 9943 | Inclusion/consistency, receipt formats, log auditing [T2, T3, T4] | Transparency detects equivocation; no spontaneous global settlement |
| Issuer-bound agent identity / source-chain position | Restricts where a credential can be redeemed; potentially useful for permanent identity [H3] | Issuer duplication, key rotation and deliberate source-chain forks remain |
| Escrow rights / sharding | Coordinate only *conflicting* nullifiers; independent shards process unrelated keys | Exclusive right allocation, migration and state rollback still need safety proofs |

**Not recommended:** replacing HMAC-SHA256 with key images, adding another Groth16 proof, using `get_links` as a uniqueness guard, or treating a non-membership proof against an unauthenticated root as "unspent". These do not solve serialization.

## Candidate A: trusted atomic redemption authority (first implementation)

Use a trusted operator-owned service whose *sole* role is to allocate first-use rights. The service atomically inserts a canonical key; no code path can sign a final authorization unless the committed record is owned by the same request.

Suggested canonical key:

```text
K = SHA256(
  "HC-ZK-SPEND-KEY-V2" ||
  canonical_deployment_id ||
  canonical_domain ||
  nullifier
)
```

Use fixed-width canonical encoding; if varying fields are added, length-prefix them. Version all message formats and define exact byte vectors. The expression above is **illustrative**, not an approved serialization specification.

An etcd compare-and-create transaction can guard `version(K) == 0` and store `statement_hash` and an idempotency identifier on success. Store final receipt material and the durable spend outcome before release. **Never** reintroduce `K` as absent after any final receipt could have escaped. Backups, disaster recovery, and failover must preserve monotonic spent state.

For a long SP1 proving step, prefer *prove before final spend* (wastes work on losing races but avoids long reservations), or an explicit **non-authorizing preflight** followed by final atomic redemption. Avoid expiring an authoritative reservation if any valid final authorization may already exist.

Security statement: one logical admission per `K` assuming a correctly operating, non-equivocating service, the backend's safety assumptions, and signing keys that cannot bypass it. A signed receipt alone does not make a malicious registrar incapable of signing conflicting receipts.

## Candidate B: durable quorum witnesses (stronger operator independence)

Require `t` of `n` witnesses to authorize the same canonical spend message. Each honest witness records the *first* statement it approved for `K` on stable storage before releasing its signature/share; competing statements for that `K` are refused. Repeated requests for the same statement are idempotent.

With fixed membership and at most `f` Byzantine signers, the safety condition is:

```text
2 * t - n > f
```

For `n=4`, `t=3` and `f=1`, any two quorum sets overlap in at least two witnesses, including at least one honest witness; thus conflicting certificates cannot both be issued **if** honest witnesses do not lose their decisions. During partitions, safety is maintained by stopping new authorizations if a quorum is unavailable.

Option B1: independent signatures and signer bitmap/IDs, simpler to inspect and audit. Option B2: FROST-compatible aggregate signature, smaller receipt but more operational/key-management complexity. An aggregate signature is **not by itself** a certificate that each signer checked a global history; that property depends on signed-message design and correct stateful witness behavior. FROST nonce handling, DKG, membership changes, signer recovery, and Byzantine coordinators require specialist review [C1].

If membership is dynamic or state transfers are required, prefer an existing BFT consensus framework rather than treating the intersection inequality as a complete protocol.

## Candidate C: Byzantine federation / ordered state machine

A Fedimint-style small federation orders claims, executes a `put-if-absent(K)` transition in consensus state and produces an authenticated final decision. The client learns whether its transaction was accepted, rejected, or still pending, then supplies a finalized authorization to the Holochain zome.

Pros: better-defined recovery, global consistency of committee state, potential multi-operator operation. Cons: operational infrastructure, governance and BFT safety assumptions, finality-verification integration. **Do not** conflate an uncommitted transaction submission with a final receipt [I4].

## Candidate D: transparent registry (layer *on top*, not instead)

Use a sparse Merkle map `K -> final admission digest` for efficient inclusion/non-inclusion queries, derived from an append-only ordered decision log; sign checkpoints and make them available to independent auditors. Trillian documents why a map alone cannot prove append-only evolution and how a log-derived map helps [T1]. CT teaches inclusion/consistency verification and split-view caveats [T2]. COSE Receipts and RFC 9943 may guide interoperability once the wire format is chosen [T3, T4].

The critical rule: **the signed authoritative state root must itself be non-equivocating / finalized**. Two insertions can both prove non-membership in the same prior root; membership and non-membership witnesses don't choose which insertion wins.

## Proposed V2 trust boundary and binding

This is a **design sketch**, not compiled Rust:

```text
CanonicalAdmissionIntentV2 {
  protocol_version,
  deployment_id, domain, nullifier,
  statement_hash, prover_agent_pubkey,
  registry_id, registry_epoch,
  request_id
}

FinalSpendReceiptV2 {
  intent_digest,
  canonical_spend_key,
  decision_id, final_state = SPENT,
  registry_commitment_or_revision,
  authority_signature_or_quorum_certificate
}
```

- The intent digest excludes proof bytes, DHT action hash, and final receipt itself to avoid cyclic hashes and proof rerandomization issues.
- Validate a receipt against the DNA-pinned authority/committee key or a DNA-authenticated, versioned configuration. Verify the statement's existing binding rules and both ZK proofs **in addition** to the receipt.
- Signed `decision_id` and `request_id` support idempotent retries but must not permit a new conflicting statement for the same `K`.
- Choose whether "same receipt in two actions" is permitted as a harmless duplicate representation or must be rejected at the application layer. Exactly one **logical entitlement** is the achievable invariant; exact one-copy DHT publication is not necessarily achievable.
- Optionally publish a public immutable `NullifierSpendRecordV2` and reference it by known `ActionHash`. `must_get_valid_record` can validate this dependency **only within the guarantees described by Holochain**; mere record existence is not evidence of exclusive issuance [H1].
- Do not treat receipt expiration as permission to reuse a spent nullifier. Define key rotation/committee reconfiguration, revocation, account recovery and checkpoint upgrades before deployment.
- If admission is a **membrane** decision, enforce the receipt during agent-joining validation, not solely later entry publication [H4].

## Issuer authentication remains independent

The current proof relation establishes a secret/nullifier relationship but not that the secret was legitimately issued by the DNA-configured issuer. A perfect spent-set can prevent a *particular* secret from being reused while allowing limitless invented secrets. Resolve issuer provenance, revocation and issuance duplication together with the redemption design, but do not assume issuer authentication solves distributed spending on its own.

A privacy constraint: the nullifier is a stable public identifier *within its scope*. Broad scope means broader linkability; per-domain scope may permit multiple admissions for one credential by design. Agent-binding can reduce cross-agent reuse but changes transfer/recovery policy.

## State transitions and failure handling

A useful internal lifecycle (inspired by Cashu NUT-07):

```text
UNSEEN --reserve/request--> PENDING
PENDING --commit final authorization--> SPENT
PENDING --abort with proof no final authorization escaped--> UNSEEN
SPENT --duplicate exact same request--> SPENT (return same result)
SPENT --different statement/request--> REJECT
```

Only `SPENT` authorizes actual membership/resource use. Whether `PENDING -> UNSEEN` is ever safe depends on the chosen authority protocol and its durable evidence. Simpler safe prototype: once a finalizable request is accepted into a single-use slot, never free that slot; add recovery for identical requests.

## Implementation sequence (proposed, no code yet)

1. **Threat-model / scope decision:** choose uniqueness domain, what counts as a logical admission, fault bound and whether this is proof-entry authorization or actual DNA membrane admission.
2. **Pure protocol types and vectors:** canonical `K` and intent digest; typed V2 receipt; versioned signing domains; wrong-scope and encoding negative tests.
3. **Reference registry:** one atomic backend and crash-safe signer, idempotent status lookup; no network calls from integrity validation.
4. **Deterministic verifier:** check receipt signature(s)/certificate, DNA-authorized registry, statement hash, nullifier, agent, scope, epoch and final decision in addition to existing V1 checks. Version the protocol; do not silently accept missing receipts.
5. **Conductor/Sweettest integration:** real two-agent replay, DHT dependency resolution, validate callback and optional membrane integration.
6. **Adversarial comparison:** 4-node persistent witness prototype, injected crashes/partitions and malicious signer; compare with trusted-backend design.
7. **Audit/transparency:** signed append-only checkpoint and optional log-derived map only if justified by measurement and threat model.
8. **Security review:** issuer-authentication fix, key-rotation and trust assumptions; formal review of quorum intersection and rollback safety.

### Mandatory tests

| Scenario | Required observation |
| --- | --- |
| Two agents simultaneously submit identical `K` but different statement hashes | At most one **final** authorization |
| Same agent retries after network timeout | Same decision, no new entitlement |
| Registrar crashes before reply / after commit / after signing | Recovery preserves first winner; no invalid reset |
| Re-randomized Groth16 proof / altered entry hash | Same `K`, no second final admission |
| Duplicate receipt attached to two DHT actions | No second logical entitlement |
| Different domain/deployment/epoch | Behavior follows explicitly chosen scope rule |
| Replica partition, leader failover, stale backup | No conflicting authorization under advertised fault model |
| One Byzantine of four witnesses, threshold three | No conflicting quorum certificates |
| Signer disk rollback or conflicting committee epochs | Refuse unsafe signing or fail closed |
| Malicious issuer / arbitrary credential secret | Rejected once issuer binding is implemented |
| DHT temporarily missing referenced registry record | Unresolved dependency / retry, not false "unused" |
| Membership joining before proof entry | Rejected if membrane admission is the intended security boundary |

## Decision gates / open questions

- Is finality **operator-trusted**, **quorum-honest**, or fully external-consensus-backed?
- Is one use per `(DNA, domain)` correct, or must a credential be globally single-use across domains?
- Is an accepted proof entry itself the entitlement, or is admission at DNA genesis required?
- May two actions represent one logical spend, or must clients reject all duplicate representations?
- Is key rotation/credential reissuance allowed to create another admission? Who authorizes recovery?
- Do we need auditability of a dishonest registrar, or prevention of dishonest registrar double-signing?
- What is acceptable unavailability during partitions?

Until these are answered, **do not claim** DHT-wide uniqueness from a Merkle proof, signed capability, countersigning session, or DHT index alone.

## Sources (primary docs and research)

- [H1] Holochain: [`must_get_*` host functions](https://developer.holochain.org/build/must-get-host-functions/), including deterministic validation, unresolved dependencies, and `CreateRecord` caveat.
- [H2] Holochain: [Countersigning and double spending](https://developer.holochain.org/concepts/10_countersigning).
- [H3] Holochain: [Getting an agent's status / source-chain conflicts](https://developer.holochain.org/build/getting-an-agents-status/).
- [H4] Holochain: [Validate callback / agent joining](https://developer.holochain.org/build/validate-callback/).
- [D1] Bailis et al.: [Coordination Avoidance in Database Systems](https://www.vldb.org/pvldb/vol8/p185-bailis.pdf) and [I-confluence overview](https://www.bailis.org/blog/when-does-consistency-require-coordination/).
- [P1] IETF [RFC 9577, Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html).
- [P2] Semaphore [FAQ](https://docs.semaphore.pse.dev/faq) and [circuits](https://docs.semaphore.pse.dev/technical-reference/circuits).
- [P3] Zcash [Orchard nullifier design](https://zcash.github.io/orchard/design/nullifiers.html).
- [P4] Cashu [NUT-07: Token state check](https://cashubtc.github.io/nuts/07/).
- [P5] [RLN protocol research](https://github.com/logos-co/logos-lips/blob/master/docs/anoncomms/draft/32/rln-v1.md).
- [I1] IETF [RFC 2136, Dynamic Updates in DNS](https://www.rfc-editor.org/rfc/rfc2136.html).
- [I2] IETF [RFC 9110, HTTP Semantics / conditional requests](https://www.rfc-editor.org/rfc/rfc9110.html).
- [I3] etcd [v3.7 Transaction API](https://etcd.io/docs/v3.7/learning/api/).
- [I4] Fedimint [architecture](https://github.com/fedimint/fedimint/blob/master/docs/architecture.md) and [technical reference](https://docs.fedimint.org/).
- [C1] IRTF [RFC 9591, FROST](https://www.rfc-editor.org/rfc/rfc9591.html).
- [T1] Trillian [verifiable logs, maps and log-derived maps](https://github.com/google/trillian/blob/master/docs/VerifiableDataStructures-Latest.md).
- [T2] IETF [RFC 9162, Certificate Transparency v2](https://www.rfc-editor.org/rfc/rfc9162.html).
- [T3] IETF [RFC 9942, COSE Receipts](https://www.rfc-editor.org/rfc/rfc9942.html).
- [T4] IETF [RFC 9943, An Architecture for Trustworthy and Transparent Digital Supply Chains](https://www.rfc-editor.org/rfc/rfc9943.html).
