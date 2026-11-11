# zk-admission

Holochain admission protocol in which an agent publishes a proof-bearing
entry (`ZkProofEntryV1`) showing that it holds a credential secret for a
deployment-scoped nullifier, under an operator-issued admission
capability.

Every proof entry carries **two mandatory proofs** about the same
`ZkStatementV1`:

- an **SP1 Groth16 proof** of the full canonical statement, and
- a **native arkworks Groth16 proof** of the credential-secret/nullifier
  relation only.

The native proof is an additional check, not a replacement for SP1. It
proves the nullifier relation, **not** the entire statement (see
[Why SP1 is still required](#why-sp1-is-still-required)).

## Workspace

| Crate | Role | Depends on |
|---|---|---|
| `crates/protocol` | Statement, admission, entry and proof types; canonical encodings; hashes; `validate_admission_bindings` | — |
| `crates/groth16-verifier` | Native proof wire format, canonical decoding, VK fingerprints, pinned-key verification against a `ZkStatementV1`. `wasm32` compatible, no rayon | `protocol` |
| `crates/groth16-circuit` | Arkworks nullifier circuit, setup, proving, production proving API, `nullifier_groth16_setup` tool. No SP1 | `protocol`, `groth16-verifier` |
| `crates/integrity-zome` | Holochain integrity zome: validation of `ZkProofEntryV1` | `protocol`, `groth16-verifier` (`groth16-circuit` only as a dev-dependency) |
| `crates/sp1-guest` | SP1 program committing the canonical statement | `protocol` |
| `crates/prover` | SP1 proving and `prove_entry`; re-exports the native API as `groth16::api` | everything above, `sp1-sdk` |

The integrity zome never depends on `prover` or `sp1-sdk`.

## Architecture

```text
             credential holder (prover side)
  ┌───────────────────────────────────────────────────────┐
  │ statement + credential_secret + admission (operator)  │
  │        │                                   │          │
  │        ▼                                   ▼          │
  │  NullifierProvingKeyV1::prove_statement   SP1 prove   │
  │  (native, ~1.3 s)                         (~8–10 min) │
  │        │                                   │          │
  │        └──────────► ZkProofEntryV1 ◄───────┘          │
  └──────────────────────────┬────────────────────────────┘
                             │ published to the DHT
                             ▼
                integrity zome  validate()
  ┌───────────────────────────────────────────────────────┐
  │ 1. decode zk_proof_v1 entry                           │
  │ 2. deployment_id := DNA hash;  config := DNA props    │
  │ 3. validate_admission_bindings  (statement ↔ DNA,     │
  │      author, capability, delegation, statement hash,  │
  │      nonce, epoch, resource class, sequence window)   │
  │ 4. prior source-chain activity / rate limit           │
  │ 5. Ed25519: root → delegation → op key → capability   │
  │ 6. SP1 Groth16: proof ↔ pinned SP1 program ↔          │
  │      encode_statement(statement)                      │
  │ 7. native Groth16: proof ↔ DNA-pinned VK ↔            │
  │      (deployment_id, domain, nullifier)               │
  └───────────────────────────────────────────────────────┘
```

## Security boundary of each layer

| Layer | Establishes | Does not establish |
|---|---|---|
| `validate_admission_bindings` | `statement.deployment_id` = DNA hash; `statement.prover` = `capability.prover` = action author; `capability.statement_hash` = hash of the full statement; nonce, delegation/capability IDs, epoch range, resource class, sequence window; version 1; eligibility | That `domain`/`nullifier` are correctly derived; any signature |
| Admission signatures | DNA root key signed the delegation; delegated op key signed the capability, and with it the full statement hash | Anything about the credential secret |
| SP1 proof | Guest checked version = 1, eligibility, and `nullifier = HMAC(secret, …)`, and committed **all** statement fields as public values | Issuer validity of the secret (see limitations) |
| Native proof | Knowledge of a 32-byte secret with `nullifier = HMAC(secret, …)` for `deployment_id` and `domain`, protocol version 1 | `prover`, `statement_nonce`, issuer, epoch, `program_id` |

### Why SP1 is still required

The native circuit has no input for the prover key or the nonce. A native
proof is public once its entry is on the DHT. An attacker can attach it,
with the victim's nullifier, to a statement naming the attacker as
prover. If the attacker also has a capability for that statement, the
bindings and the native proof both accept. The SP1 proof rejects it:
its public values are the full canonical statement, and a new SP1 proof
needs the victim's secret. The tests
`native_proof_alone_does_not_bind_the_author_so_sp1_remains_required`
and `…_nonce_…` in `crates/integrity-zome/src/binding_tests.rs` document
this.

Replacing SP1 with the native proof would at least require binding the
full statement into the circuit. One option is a public input carrying
`statement_hash(statement)` with a non-trivial constraint on it; an
input that appears in no constraint has a zero verifying-key coefficient
and binds nothing. It would also need a decision on the trusted setup
(below) and an equivalence argument. None of that is implemented.

## Native nullifier proof

### Relation

```text
nullifier == HMAC-SHA256(
    credential_secret,
    "HOLOCHAIN-ZK-NULLIFIER-V1" || deployment_id || domain || u16_be(protocol_version)
)
```

This is the same definition as `zk_admission_protocol::hashes::nullifier`.
The circuit reads the domain separator from the protocol crate, and a
test pins the literal.

- **Private input:** `credential_secret`, exactly 32 bytes.
- **Public inputs**, in this order, each packed into two BN254 scalars
  (31 + 1 bytes, as `UInt8::new_input_vec` / `ToConstraintField` pack
  them): `deployment_id`, `domain`, `nullifier`. Six field elements in
  total. They are always taken from the entry's `ZkStatementV1`.
- **Protocol version:** a circuit constant (`1`). It is bound through the
  verifying key; the verifier also requires `statement.protocol_version
  == 1`.
- BN254, Groth16, arkworks 0.5 SHA-256 gadget, about 204k constraints.

### Protocol object and wire format

```rust
pub struct NullifierGroth16ProofV1 {
    pub verifying_key_id: [u8; 32], // claimed VK fingerprint, untrusted
    pub proof: Vec<u8>,             // wire format below
}
```

The object carries no copy of the statement, so it cannot disagree with
the statement bound by the capability and SP1.

```text
proof = "ZKGP" (4) || 0x01 (format version) || A ∈ G1 (32) || B ∈ G2 (64) || C ∈ G1 (32)
        = 133 bytes, arkworks compressed, canonical
```

Decoding rejects:
- the wrong length, magic or version;
- points that are invalid or outside the subgroup;
- any encoding that does not re-encode to the same bytes, which includes
  trailing bytes.

### Verifying key pinning

The key lives in DNA properties, so it is covered by the DNA hash. Each
deployment runs its own circuit-specific setup, and the same integrity
zome WASM serves every deployment, like the existing root keys and SP1
program hash.

```yaml
# DnaPropertiesV1 (in addition to the existing admission/issuer/SP1 fields)
nullifier_groth16_vk: [229, 202, 135, ...]           # 456 bytes, canonical compressed VK
nullifier_groth16_vk_fingerprint: [238, 54, ...]     # SHA-256(nullifier_groth16_vk), 32 bytes
```

Validation requires all of the following:
- `SHA-256(nullifier_groth16_vk) == nullifier_groth16_vk_fingerprint`;
- the VK decodes canonically and has exactly 6 public inputs;
- `proof.verifying_key_id == nullifier_groth16_vk_fingerprint`.

A key supplied by the prover is never used.

The fingerprint is plain SHA-256 over the canonical compressed VK bytes.
The circuit is identified as `HOLOCHAIN-ZK-NULLIFIER-GROTH16-BN254-V1`
(`NULLIFIER_GROTH16_CIRCUIT_ID_V1`).

**Prototype key.** The development key in `target/groth16/` (not
committed) has fingerprint
`c15ec289a32f962e86b6dd8b15dad739af4a9c56ce6687aabe324a727c121cae`. It
round-trips through the production path, but it is **not** a production
key. Each deployment must generate its own key and record its
fingerprint.

## SP1 proof

The guest (`crates/sp1-guest`) reads the statement and the secret,
asserts protocol version 1, eligibility and the nullifier relation, and
commits `encode_statement(statement)`. The zome checks that
`statement.program_id` equals the DNA-pinned `sp1_program_vkey_hash`, and
verifies the 356-byte SP1 Groth16 proof against the canonical statement
bytes.

The current SP1 program vkey hash is
`003f9649923b9dc13669ce8bac70548312746d2dd3fd10b4f8949c60b7974197`.

`crates/sp1-guest/rustfmt.toml` disables formatting for the guest: panic
locations (file:line) are compiled into the ELF, so reformatting would
change this hash. After any guest rebuild, re-check the hash with
`cargo run --release -p zk-admission-prover --example program_vkey`.

## Procedures

### Setup (once per deployment, by the deployment authority)

```bash
cargo run --release -p zk-admission-groth16-circuit \
    --bin nullifier_groth16_setup -- <output-dir>
```

The `<output-dir>` must not already exist; the tool creates it only
after both key files have been generated and synchronized successfully.
It writes `nullifier_groth16_pk.bin` (about 40.6 MB) and
`nullifier_groth16_vk.bin` (456 bytes) into a temporary directory, syncs
the files and directory, then atomically publishes the complete key pair.
A failed setup cleans up the temporary directory and never publishes a
partial key pair. It prints the fingerprint and the two DNA-property
values. Setup uses `OsRng` and never runs during proving. Record the
fingerprint, put the VK and fingerprint in the DNA properties, and
distribute the proving key to provers.

### Proving

```rust
let key = NullifierProvingKeyV1::load(pk_path, &pinned_fingerprint)?; // ~8 s (checked decode)
let entry = zk_admission_prover::prove_entry(statement, admission, secret, &key)?;
```

- `load` requires the verifying key embedded in the proving key to match
  the pinned fingerprint.
- `prove_entry` first makes the native proof. That uses statement-derived
  public inputs and `OsRng`, takes about 1.3 s, and self-verifies before
  returning. It then makes the SP1 proof.
- Run a native-only round-trip with
  `cargo run --release -p zk-admission-groth16-circuit --example nullifier_groth16_roundtrip -- <pk> <vk> <fingerprint-hex>`.

### Verification

The `validate()` order is shown above. Native verification is
`groth16_verifier::verify_statement_nullifier_proof`, reached through
`integrity-zome/src/native_groth16.rs`; the zome contains no other
verification logic. It takes about 1.3 ms natively.

## Building and testing

```bash
cargo fmt --all
cargo test -p zk-admission-protocol
cargo test -p zk-admission-groth16-verifier
cargo test -p zk-admission-groth16-circuit      # real proofs; ~1–2 min
cargo test -p zk-admission-integrity-zome       # includes binding tests with real proofs
cargo check -p zk-admission-groth16-verifier --target wasm32-unknown-unknown
cargo check -p zk-admission-integrity-zome   --target wasm32-unknown-unknown

# Release zome WASM. Do NOT set RUSTFLAGS: it replaces the wasm32 flags in
# .cargo/config.toml (--import-undefined, getrandom_backend="custom").
cargo build --release -p zk-admission-integrity-zome --lib --target wasm32-unknown-unknown

# The prover crate embeds the SP1 guest ELF and needs:
env "SP1_ELF_zk-admission-sp1-guest=$PWD/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-admission-sp1-guest" \
    cargo check -p zk-admission-prover --all-targets
```

Without that variable, `cargo check -p zk-admission-prover` fails with
`environment variable SP1_ELF_zk-admission-sp1-guest not defined`. That
is the SP1 build environment, not a code error.

The workspace optimises the arkworks crates in dev/test builds, and turns
off `ark-groth16` debug assertions so that tests behave like release.
Arkworks only `debug_assert`s witness satisfiability, so the tests can
produce cheating proofs and show they are rejected.

## Security assumptions

- The DNA hash authenticates the DNA properties, including the root keys,
  the SP1 program hash, and the native VK and fingerprint.
- BN254 Groth16 is knowledge-sound and HMAC-SHA256 is a PRF.
- SP1's Groth16 wrapper setup and verifier are sound.
- **Native trusted setup.** `circuit_specific_setup` is a single-party
  setup. Anyone who kept its trapdoor could forge native proofs for that
  key. Arkworks drops it on return, but the deployment authority running
  setup must be trusted not to keep it. That authority already decides
  admission by issuing capabilities, and SP1 is still required. A
  multi-party ceremony would remove this assumption.
- **Proving key provenance.** Provers must get the proving key from the
  deployment authority. A maliciously constructed proving key could
  undermine zero-knowledge for the prover, even when its embedded VK
  matches the pin.
- All randomness for setup and proving comes from `OsRng`.

## Nullifier uniqueness research

See the [DHT-wide nullifier uniqueness research](docs/nullifier-uniqueness-research.md) for protocol alternatives and security assumptions, and the [V2 single-use admission design plan](docs/nullifier-uniqueness-design-plan.md) for the recommended implementation architecture, file-level changes, phases, and acceptance tests. **No uniqueness mechanism is implemented yet.**

## Hardening and security review

The native Groth16 path is deliberately hardened at several independent
boundaries:

- **Canonical proof encoding:** native proofs use an exact 133-byte
  `ZKGP`/versioned wire format. Decoding requires valid compressed BN254
  points and byte-for-byte canonical re-encoding, so truncation, trailing
  data, alternate encodings and malformed points are rejected.
- **Canonical verifying-key encoding:** the pinned verifying key is
  decoded and re-encoded canonically before it is accepted.
- **Cryptographic VK pinning:** the DNA contains the canonical verifying
  key and its SHA-256 fingerprint. Validation recomputes the fingerprint,
  verifies the key structure and public-input count, and requires the
  proof's `verifying_key_id` to equal the pinned fingerprint.
- **Statement-derived public inputs:** the native verifier derives
  `(deployment_id, domain, nullifier)` directly from the entry's
  `ZkStatementV1`. The proof does not carry a second copy of these values.
- **Protocol-version pinning:** version 1 is both a circuit constant and
  an explicit verifier check. A new protocol version requires a new
  circuit setup and pinned key.
- **Proving-key provenance:** the production proving API verifies that
  the verifying key embedded in the proving key matches the deployment's
  pinned fingerprint before proving.
- **Self-verification:** newly generated native proofs are verified
  against the pinned key before the prover returns them.
- **Independent negative tests:** the circuit and integrity-zome tests
  use real Groth16 proofs to exercise changed public inputs, every bit of
  the public inputs, corrupted proof bytes, wrong keys, wrong fingerprints,
  wrong proof key IDs, alternate setups and reissued capabilities.
- **SP1 remains mandatory:** the native circuit intentionally does not
  bind the complete statement. The SP1 proof therefore remains the
  cryptographic binding for `prover`, `statement_nonce`, `program_id` and
  the other canonical statement fields. The binding tests include attacks
  that native Groth16 plus admission bindings alone would accept.
- **Setup isolation:** native setup is a deployment-authority operation,
  never part of normal proving. Generated key material is published only
  after both files have been written and synchronized successfully, so a
  failed setup cannot leave a partially published key pair that looks
  complete.
- **Randomness:** setup and proving use `OsRng`; no deterministic or
  hard-coded randomness is used for production key generation or proofs.

The hardening does **not** claim that the protocol is complete. In
particular, two security properties remain explicit follow-up work:

1. **DHT-wide nullifier uniqueness:** validation currently does not provide
   a global uniqueness guarantee for a nullifier across the DHT. A future
   design must define the uniqueness authority and race/replay semantics;
   proof bytes and entry hashes are unsuitable uniqueness keys because
   Groth16 proofs may be re-randomized.
2. **Issuer authentication:** the current validation/SP1 path does not
   cryptographically establish that the credential secret was issued by
   the configured issuer. `issuer_root_key`, `issuer_id` and
   `issuer_key_id` are currently carried as protocol data but are not
   independently authenticated by the proof relation. This must be
   addressed before treating issuer provenance as a security invariant.

The native Groth16 trusted-setup assumption also remains: a party retaining
the circuit-specific setup trapdoor could forge native proofs for that
verifying key. The current design accepts this assumption because SP1 is
still mandatory; a multi-party ceremony would remove the native setup
trapdoor assumption.

## Known limitations

- The native circuit proves the nullifier relation only. It is not bound
  to `prover`, `statement_nonce`, issuer, epoch or `program_id`, and it
  cannot replace SP1 (see above).
- The native circuit accepts only 32-byte credential secrets. SP1 accepts
  any length. For 32-byte secrets the two nullifier definitions are
  identical.
- Groth16 proofs can be re-randomised: anyone can produce different
  valid proof bytes for the same statement. The nullifier, not the proof
  bytes or entry hash, must be the uniqueness key.
- Protocol version is a circuit constant. A new protocol version needs a
  new setup and a new pinned VK.
- Adding `nullifier_proof` to `ZkProofEntryV1` and the VK to
  `DnaPropertiesV1` changes the entry schema and DNA. This assumes no V1
  network has been deployed yet.
- The binding tests run the deterministic steps (bindings and native
  proof) with real native proofs. They do not exercise source-chain
  activity, Ed25519 signatures or SP1 (no conductor/Sweettest tests, and
  no real SP1 proof in CI), so scenarios rejected only by SP1 are
  documented, not executed.
- Pre-existing, outside this change:
  - nothing enforces DHT-wide nullifier uniqueness;
  - `issuer_root_key*`, `issuer_id` and `issuer_key_id` are not checked by
    validation or the SP1 guest, so neither proof shows the credential
    secret was issued by the issuer;
  - `crates/integrity-zome/src/bin/type_probe.rs` cannot link for
    `wasm32`; build the zome with `--lib`.
- Proving keys, verifying-key files and other `*.bin` artifacts are
  git-ignored. Distributing them is outside this repository.
