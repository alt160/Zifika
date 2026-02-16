## 1. Purpose and Audience

This file is the main design reference for Zifika behavior.

Primary audience:
- cryptanalysis reviewers
- independent implementers
- maintainers checking code changes against the design model

This file defines what has to be true for an implementation to match the design, including:
- externally visible behavior
- mode-specific invariants
- wire-level meaning and rejection behavior
- compatibility boundaries

This file does not define:
- coding style or internal architecture
- optimization strategy
- formal proof claims or standard-cipher equivalence claims

Words like `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are used intentionally (RFC 2119 / RFC 8174 sense).

If this file conflicts with explanatory text in `README.md`, this file is the source of truth for conformance and critique.

## 2. Scope and Boundaries

This is a behavior and compatibility contract document with a validation-first orientation. It describes requirements implementations have to satisfy.

### 2.1 In Scope (Required)

The following are required for conformance:

- behavior of encryption, decryption, minting, and verification
- key-role capability boundaries
- determinism and fail-closed behavior
- wire interpretation (field meaning, order, and length rules)
- acceptance and rejection rules for valid and invalid ciphertext
- compatibility rules across versions
- compatibility profile choices for cryptographic primitives

### 2.2 Out of Scope

The following are intentionally not fixed here unless explicitly stated elsewhere:

- internal code structure and API surface shape
- memory layout, allocation strategy, and optimization approach
- language-specific abstraction choices
- debug tooling and diagnostics format

Implementations can differ in these areas and still be conformant.

### 2.3 Source of Truth Order

For conformance and critique:

1. `DESIGN.md` is authoritative.
2. Test vectors and conformance fixtures (when present) are authoritative for observable outputs.
3. `README.md` and other narrative docs are explanatory if conflicts exist.

### 2.4 Conformance Statement

An implementation MUST NOT claim conformance unless it satisfies all required items in this file for the claimed modes (Symmetric, Mint/Verify, or both).

### 2.5 Primitive Flexibility and Compatibility Profiles

Zifika as a construction is not tied to one specific hash or PRF primitive.

At the design level, the construction requires deterministic keyed byte streams and digest behavior that are stable and reproducible for validation.
The design does not depend on any unique property of a specific PRF selection.

For wire compatibility, each profile pins exact primitive choices.
Ciphers produced under one profile are only expected to decrypt under that same profile.
Switching primitives creates a different compatibility profile, not a fork of the design.

This is intentional. Different deployments can choose different profiles when their compute, memory, or security targets differ (for example constrained IoT vs higher-assurance environments).
Security properties are profile-dependent: weaker primitive choices weaken or can invalidate security claims for that profile, without changing the core Zifika model definition.

### 2.6 Diversification Inputs

`startLocation` and `intCat` are per-message diversification inputs.
Payload walk processing MUST use a per-message `workingKeyState` derived from base key state and diversification inputs under active profile rules.

Determinism invariants in this file are conditioned on fixed values of those inputs.

Each profile defines how diversification inputs are generated.

Production-oriented profiles SHOULD use cryptographically strong randomness or an equivalent uniqueness policy.

Test and analysis profiles MAY use fixed or caller-supplied values.

## 3. Terms and State Vocabulary

This section defines the terms used in the rest of this file.

### 3.1 Notation

- `byte`: unsigned 8-bit value (`0..255`)
- `u16`, `u32`: 16-bit and 32-bit unsigned integers (used where a profile pins those widths)
- `LE`: little-endian byte order
- `||`: byte-string concatenation
- `wrap to N`: reduce a value into `0..N-1` with circular boundary behavior
- `x[i]`: zero-based index into `x`

### 3.2 Core Key and Grid Terms

- `keyBlockSize`: number of key rows
- `keyBytes`: row-major permutation bytes, length `keyBlockSize * 256`
- `keyRow`: one row of 256 bytes, permutation of `0..255`
- `rkd`: inverse-row lookup where `rkd[row][value] = column`
- `keyHash`: 64-byte digest of base key bytes under the active compatibility profile
- `baseKeyState`: key-derived state before per-message reshaping
- `workingKeyState`: per-message key state deterministically derived from `baseKeyState` and diversification inputs under active profile rules; payload walk operations use this state
- `keyReshaping`: profile-defined derivation from `baseKeyState` to `workingKeyState`

### 3.3 Walk-State Terms

- `row`: current row index in `0..keyBlockSize-1`
- `col`: current column index in `0..255`
- `startLocation`: initial flat cursor location; integer width is profile-defined and interpreted with wrap to `(keyBlockSize * 256)` at walk start
- `jumpValue`: jump value from `NextJump`
- `rowJump`: row delta derived from `jumpValue`
- `colJump`: column delta derived from `jumpValue`
- `distance`: forward wrapped column distance from current `col` to target plaintext byte position in active row
- `encodedStep`: row-encoded byte emitted for one payload step, derived from `distance` in active row
- `rowOffsetStream`: ordered sequence of payload `encodedStep` bytes

### 3.4 Header and Integrity Terms

- `intCat`: interference catalyst bytes carried in header space and reused in payload mapping
- `intCatLen`: one-byte catalyst length field
- `integritySeal`: integrity seal material used for decryption validation prior to processing plaintext output
- `enc(...)`: encryption operation under full-key semantics for symmetric wire elements
- `enc_v(...)`: header encryption operation decodable by verifier-side material in Mint/Verify mode

### 3.5 Mint/Verify Terms

- `vKeyLock`: verifier lock value carried in plaintext to bootstrap verifier header decode
- `checkpointCount`: checkpoint count field (mapped in Mint/Verify control stream)
- `authorityContext`: exact ordered field set bound by checkpoint proof verification. The active profile MUST publish field membership, ordering, encoding, and whether binding is direct or via `observerState`
- `signature`: authority proof bytes produced by the active profile's digital-signature scheme over the checkpoint message
- `cipherLen`: mapped payload-length field in Mint/Verify control stream
- `observerState`: state snapshot bytes used for authority checkpoint signing and verification

### 3.6 Behavioral Labels

- `fail-closed`: if validation or integrity fails, no plaintext is released
- `fail-null`: ciphertext-processing failures collapse to one externally indistinguishable failure outcome, with no failure subtype detail exposed by decrypt/verify APIs

## 4. Model Invariants

This section defines behavior that MUST hold for implementations claiming conformance.

### 4.1 Semantic Invariants

- Determinism under fixed inputs: under the same compatibility profile, identical key material, identical `startLocation`, identical `intCat`, and identical plaintext MUST produce identical ciphertext.
Check: run the same encryption input set twice; outputs match byte-for-byte.

- Correct round-trip: decrypting a valid ciphertext produced by the matching encrypt/mint path MUST recover the original plaintext exactly.
Check: encrypt then decrypt, and compare full plaintext bytes.

- Walk-state dependence: payload ciphertext bytes represent encrypted walk actions from keyed state, not direct plaintext substitution.
Check: interpretation of `rowOffsetStream` without matching keyed state must not be sufficient to directly recover plaintext.

- Per-message key reshaping: payload walk processing MUST use `workingKeyState`, not raw `baseKeyState`.
Check: verify payload-walk behavior changes when diversification inputs change under otherwise fixed base key and plaintext.

- Working-key determinism: under fixed profile, fixed `baseKeyState`, fixed `startLocation`, and fixed `intCat`, derived `workingKeyState` MUST be identical across runs.
Check: run identical fixtures multiple times and verify identical payload-walk outputs.

- Fail-null ciphertext handling: if integrity, signature verification, or structural validation fails, decrypt/verify MUST return a single externally indistinguishable failure outcome and MUST NOT release plaintext.
Check: induce different failure causes and verify decrypt/verify returns the same external failure outcome with no plaintext output.

### 4.2 Capability Invariants

- Symmetric capability: full key material MUST support both encryption and decryption for symmetric mode.
Check: full-key encrypt/decrypt succeeds for valid inputs.

- Mint capability: mint-authorized material MUST produce ciphertext that matching verifier material can verify and decrypt.
Check: mint then verify/decrypt under paired authority and profile.

- Verifier non-mintability: verifier-side material MUST NOT be sufficient to mint new ciphertext that passes verifier checks as validly minted output.
Check: attempted verifier-only minting path does not exist or cannot produce verifier-acceptable minted ciphertext.

- Authority-binding: checkpoint proofs MUST bind to `authorityContext` defined by the active profile; replay or substitution across mismatched `authorityContext` values MUST fail verification.
Check: replay signatures against modified authority context fields and verify rejection.

### 4.3 Interface and Compatibility Invariants

- Structural rejection: malformed, truncated, or inconsistent ciphertext structure MUST be rejected.
Check: fuzz structural fields and verify rejection through the same external failure outcome.

- Failure-type opacity: decrypt/verify API surfaces MUST NOT expose distinguishable failure subtypes for ciphertext-processing failures.
Check: trigger structural failure, integrity failure, and signature failure, then verify the caller-observable failure outcome is indistinguishable.

- Profile-bound interoperability: ciphertext created under one profile is only required to decrypt under that same profile.
Check: cross-profile decrypt attempts are rejected or treated as non-conformant input.

- Sealed-path integrity requirement: sealed decrypt/verify paths MUST enforce integrity validation before plaintext release.
Check: remove or alter integrity material and verify sealed path fails closed.

- Unsealed-path scope: unsealed APIs MAY exist for research/debug, but are outside standard conformance claims.
Check: conformance assertions and tests are based on sealed behavior unless explicitly stated otherwise.

## 5. Behavioral Spec (State Transitions)

This section defines required processing order. Profiles can vary field encodings and primitive choices, but MUST preserve these state-transition semantics.

### 5.1 Symmetric Encrypt

Required transition order:

1. Initialize per-message state (`startLocation`, `intCat`) under profile policy.
2. Derive `workingKeyState` from `baseKeyState` and per-message inputs using profile-defined `keyReshaping`, then initialize walk state.
3. Walk and encrypt payload bytes into `rowOffsetStream`.
4. Encrypt and emit symmetric header fields.
5. If sealed, compute `integritySeal` over the profile-defined transcript and append it in encrypted form.
6. Emit final ciphertext.

### 5.2 Symmetric Decrypt

Required transition order:

1. Parse and decrypt symmetric header fields.
2. Reconstruct `workingKeyState` from `baseKeyState` and decoded diversification inputs using profile-defined `keyReshaping`, then initialize walk state.
3. Separate encrypted payload stream from encrypted integrity material (if sealed).
4. If sealed, validate integrity before releasing plaintext.
5. Decrypt payload stream by replaying the walk.
6. Return plaintext only if all required checks succeed; otherwise return fail-null.

### 5.3 Mint

Required transition order:

1. Initialize per-message mint context, including verifier bootstrap material and payload-walk inputs.
2. Derive `workingKeyState` from `baseKeyState` and diversification inputs using profile-defined `keyReshaping`, then initialize payload walk state.
3. Walk and encrypt payload into `rowOffsetStream` while computing checkpoint observer state data.
4. Produce authority proofs over checkpoint messages defined by the active profile.
5. Encrypt and emit Mint/Verify control fields and payload stream in profile-defined order.
6. If sealed, compute and append encrypted `integritySeal` over the profile-defined transcript.
7. Emit final minted ciphertext.

### 5.4 Verify and Decrypt

Required transition order:

1. Read bootstrap fields needed to decode verifier control fields.
2. Decrypt and parse Mint/Verify control fields, including checkpoint metadata and payload bounds.
3. Reconstruct `workingKeyState` from `baseKeyState` and decoded diversification inputs using profile-defined `keyReshaping`, then initialize authority-verification context.
4. Replay payload walk and verify checkpoint proofs against the profile-defined checkpoint messages.
5. If sealed, validate integrity before plaintext release.
6. Release plaintext only after all required verification steps succeed; otherwise return fail-null.

### 5.5 Ordering and Failure Rules

- Plaintext release MUST occur only after all required validation for the selected mode/path.
- Payload walk processing MUST NOT materialize a caller-visible plaintext buffer until all required integrity/proof checks for the selected mode/path have passed.
- Implementations MAY compute transient plaintext bytes during validation, but MUST NOT commit plaintext to output buffers or return plaintext before required checks pass.
- Any structural, integrity, or authority-proof failure MUST terminate in fail-null.
- API-visible behavior for ciphertext-processing failure MUST remain failure-type opaque (single indistinguishable failure outcome).
- Profiles MAY differ in internal implementation details, but MUST preserve the same externally observable transition ordering and failure semantics.

## 6. Wire Semantics and Rejection Rules

This section defines how ciphertext bytes are interpreted for conformance. Exact field encodings are profile-defined, but semantic roles and rejection behavior are required.

### 6.1 Wire Structure Model

At a model level, ciphertext is composed of:

1. Bootstrap/control material needed to initialize decryption state.
2. Payload action stream (`rowOffsetStream`).
3. Optional integrity material for sealed paths.

Profiles define exact field names, order, encoding widths, and serialization formats.

### 6.2 Parsing Contract

- Decrypt/verify paths MUST parse ciphertext in the exact field order required by the active profile.
- Each parsed field MUST satisfy profile-defined structural constraints before downstream use.
- Parsed lengths and counts MUST be internally consistent with remaining bytes and mode semantics.
- Any parse, bound, or consistency violation MUST terminate in fail-null.

### 6.3 Symmetric Mode Wire Semantics

- Symmetric ciphertext MUST contain profile-defined control fields sufficient to recover `startLocation`, `intCat`, and payload boundaries.
- Payload bytes are interpreted as encrypted walk actions (`rowOffsetStream`) under symmetric `workingKeyState` semantics.
- Sealed symmetric paths MUST include and validate profile-defined integrity material before plaintext release.
- Unsealed symmetric paths MAY omit integrity material but remain outside standard conformance claims.

### 6.4 Mint/Verify Mode Wire Semantics

- Mint/Verify ciphertext MUST contain bootstrap material sufficient to decode verifier-visible control fields.
- Control fields MUST provide profile-defined checkpoint/proof metadata and payload bounds.
- Payload bytes are interpreted as encrypted walk actions under Mint/Verify `workingKeyState` semantics.
- Proof material MUST be parsed and validated against profile-defined checkpoint messages.
- Sealed Mint/Verify paths MUST include and validate integrity material before plaintext release.

### 6.5 Rejection Rules

The following conditions MUST terminate in fail-null:

- malformed or truncated control/header material
- inconsistent length/count fields
- payload boundary inconsistencies
- missing required proof or integrity material on sealed paths
- invalid proof verification results
- integrity validation failure
- any mode/profile mismatch that prevents valid interpretation under the selected profile

### 6.6 Failure Surface Requirements

- All ciphertext-processing failures MUST map to one externally indistinguishable failure outcome.
- Decrypt/verify APIs MUST NOT expose failure subtype details for structural, integrity, or proof failures.
- Implementations MAY record internal diagnostics, but those diagnostics MUST NOT alter caller-visible failure classification.

## 7. Conformance and Validation Artifacts

This section defines what evidence is required to claim conformance to this design.

### 7.1 Conformance Claim Scope

Implementations MUST state conformance scope explicitly:

- Symmetric-only conformance
- Mint/Verify-only conformance
- Full conformance (both modes)

Conformance claims MUST also name the compatibility profile used for validation.

### 7.2 Required Positive Tests

At minimum, the following MUST pass for each claimed mode:

- Deterministic replay test under fixed key material, fixed `startLocation`, and fixed `intCat`.
- Round-trip test where valid encrypt/mint output is recovered exactly by matching decrypt/verify.
- Multi-length test coverage, including empty payload and non-trivial payload lengths.

### 7.3 Required Negative Tests

At minimum, the following MUST fail with fail-null outcome:

- malformed/truncated bootstrap or control/header material
- inconsistent length/count fields
- integrity tamper on sealed paths
- authority proof tamper in Mint/Verify paths
- mode/profile mismatch input

### 7.4 Failure-Surface Validation

Conformance evidence MUST include tests that demonstrate:

- no plaintext release on ciphertext-processing failure
- one externally indistinguishable failure outcome across structural, integrity, and proof failures
- no externally visible failure subtype channel from decrypt/verify APIs

### 7.5 Test Vectors

Test vectors used for conformance SHOULD include:

- profile identifier
- key material (or profile-defined key fixture reference)
- diversification inputs (`startLocation`, `intCat`) or profile-defined generation fixture
- plaintext input
- expected ciphertext output
- expected decrypt/verify outcome (success with exact plaintext, or fail-null)

Where sealed and unsealed paths are both implemented, vectors SHOULD label which path is under test.

### 7.6 Cross-Implementation Validation

When multiple implementations claim the same profile:

- equivalent input fixtures MUST produce equivalent ciphertext/decrypt outcomes
- failure conditions MUST match on caller-visible behavior (including fail-null collapse)

Differences in internal diagnostics, memory layout, or optimization strategy do not affect conformance if caller-visible behavior matches this design.

## 8. Compatibility and Versioning Rules

This section defines how compatibility claims are scoped over time.

### 8.1 Breaking Changes

The following are breaking changes for a profile unless published under a new profile/version identifier:

- changes to wire field meaning, ordering, or parse interpretation
- changes to validation gating relative to plaintext release
- changes to failure-surface behavior (including fail-null collapse behavior)
- changes to profile-bound primitive choices or encoding rules
- changes to checkpoint/proof semantics used for Mint/Verify validation

### 8.2 Non-Breaking Changes

The following are non-breaking when caller-visible behavior remains unchanged:

- internal refactors
- performance optimizations
- memory/layout changes
- diagnostic and telemetry changes that do not alter API-visible outcomes

### 8.3 Profile Evolution

- Primitive swaps, encoding changes, or wire-layout changes MUST be published as a new compatibility profile/version.
- Profiles MUST be explicitly named in conformance claims and validation artifacts.
- Implementations MUST NOT silently drift profile behavior under an existing profile identifier.

### 8.4 Version and Profile Declaration

Conformance statements SHOULD include:

- design document version reference
- compatibility profile identifier
- mode scope (Symmetric-only, Mint/Verify-only, or Full)

Without explicit profile declaration, compatibility claims are incomplete.

### 8.5 Unsupported Version/Profile Handling

- Inputs that cannot be interpreted under the selected version/profile MUST fail with fail-null.
- Implementations MUST NOT partially decode or partially release plaintext for unsupported version/profile inputs.

### 8.6 Profile Identifier and Selection Rules

- A compatibility profile MUST have a stable profile identifier represented as an ASCII string token.
- The profile identifier format MUST be published by profile documentation and treated as part of compatibility contract data.
- Decrypt/verify entry points MUST have an unambiguous active profile selection before ciphertext interpretation.
- Active profile selection MAY come from an explicit wire field or from API/config binding that fixes one profile per entry point.
- If profile selection is ambiguous, interpretation MUST terminate in fail-null.

## 9. Security Posture and Non-Claims

This design document defines conformance behavior, not a formal security proof.

### 9.1 Security Posture

- Zifika is an experimental construction intended for analysis and critique.
- Security properties are profile-dependent and threat-model dependent.
- Conformance to this document means behavioral fidelity to the model; it does not, by itself, establish cryptographic strength.

### 9.2 Explicit Non-Claims

This document does not claim:

- formal proof of security
- equivalence to standardized ciphers
- post-quantum security
- universal security across all profile choices

### 9.3 Profile-Specific Security Responsibility

- Profile authors are responsible for primitive choices, parameter choices, and deployment assumptions.
- Profile-defined `keyReshaping` exists to reduce stable base-key structure reuse across messages and narrow oracle-style analysis surface; this is a design objective, not a proof claim.
- Weaker profile choices can reduce or invalidate security claims for that profile.
- Such profile-level weakening does not, by itself, redefine the core Zifika model.

### 9.4 Analysis and Reporting

- Critique, attack analysis, and negative results are valid and encouraged.
- Security-relevant findings should be evaluated in the context of both model behavior and selected profile assumptions.
