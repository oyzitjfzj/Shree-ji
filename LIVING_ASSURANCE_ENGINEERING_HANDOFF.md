# Living Assurance Engineering Handoff

This file is the durable recovery point for a new architect/AI session. It records only claims that are supported by observed repository/workflow evidence. A statement marked **OPEN** is not a solved fact and must not be promoted into one.

## Operating rule

1. Recover reality from the private source and the public verification controller; do not trust this handoff over contradictory primary evidence.
2. Bind every acceptance claim to the exact private revision under test. A historical GREEN does not certify a newer source tree.
3. Keep the candidate revision frozen while exact acceptance verification is running. Any source mutation creates a new snapshot and invalidates acceptance evidence for the old snapshot.
4. Do not weaken warnings, lints, tests, proof settings, model-checking scope, or fail-closed behavior merely to obtain GREEN.
5. Before calling a failure a regression, compare it against the immediate parent/baseline under the same gate.
6. Public logs must not disclose private repository names, refs, source text, or sensitive paths. Prefer proofs, hashes, ordinals, aggregate counts, and non-sensitive tool/lint identifiers.
7. Temporary diagnostic workflows are instruments, not architecture. Remove them after closure; retain the verified lesson here.

## Exact current acceptance binding

The current materialized candidate is identified publicly by opaque evidence rather than by publishing its private ref or commit ID:

- private-ref hash: `2df69cb8a4bb6483271cad9822de8a4a7f09b30ed6c591040398170e851c9305`
- snapshot proof: `65306c5200b96bbc17d1a85b0eb042196d3c1f2a1d1630542aaddfc8134ca854`
- tree proof: `a5bff9ef779be5f28fd84780411b1bbd36dbb3bcd729d76dc89cf4032013730d`
- canonical verifier blob: `62e3e6dc0fad5dddc7fb0a453a3cd681d911e590`
- canonical TLC profile count: `202`

Always re-resolve these proofs from the private repository before using them. If any proof no longer resolves exactly once, stop rather than guessing.

## Solved problem: stale verification evidence

### Problem

Long-running canonical/formal jobs can remain bound to an older private snapshot while implementation continues. A successful historical run is valid evidence about that historical snapshot only; treating it as certification of the current candidate is an evidence-substitution error.

### Verified solution

- Resolve the intended private ref by an opaque ref hash.
- Resolve the exact candidate by a cryptographic snapshot proof and verify its tree proof.
- Verify the canonical verifier blob before execution.
- Run acceptance gates against the detached exact revision, not merely the latest branch name.
- Keep the candidate frozen during the acceptance run.
- If source changes, derive a new proof set and rerun applicable acceptance evidence.

A currently running historical resumable TLC job must therefore be preserved as historical evidence/checkpoint work, but must not be counted as certification of the current candidate.

## Solved problem: one TLC profile exceeds ordinary single-run practicality

### Problem

Canonical TLC profile 39 is materially more expensive than ordinary profiles and has previously exhausted normal workspace/runtime envelopes. Ordinary reruns lose progress and can waste hours.

### Verified solution

Use resumable TLC slices with committed TLC checkpoints. Seal the checkpoint artifact cryptographically using the private credential context plus the exact snapshot proof and profile index; validate the manifest before recovery; dispatch the next segment only after a valid committed checkpoint is sealed. A checkpoint from one snapshot must never be resumed as evidence for a different snapshot.

For current acceptance, profile 39 must obtain evidence bound to the current snapshot. Historical profile-39 progress does not transfer semantically to a changed source tree.

## Solved problem: privacy-preserving failure diagnosis

### Problem

Canonical verification runs on private source, while the controller is public. Dumping private logs, paths, refs, or source names would violate the private-source/public-runner boundary; reporting only `FAIL` is too opaque to diagnose safely.

### Verified solution

Keep raw logs private to the runner and emit only the minimum non-sensitive classifier surface required for diagnosis: stage result, return code, aggregate failure count, cryptographic log/signature hashes, lint/error identifiers where non-sensitive, resource/network markers, and hashed/ordinal owner information. Narrow the diagnosis iteratively until the source owner is known, then make the smallest source-level correction and re-run the full canonical gate.

## Current Root FFI evidence

The minimal production Root FFI boundary has been materialized and separately demonstrated through strict production-focused checks, Clippy at the library surface, focused Root tests, full all-features library tests, and a real Ada-backed install/commit/revoke production execution. This is strong component evidence, but it does not replace the repository-wide canonical verifier.

The production design deliberately keeps the test/oracle Root ABI separate from the minimal non-test production boundary, constrains trusted ingress to a sealed authenticated seam, and keeps Root mutation/final-liveness operations serialized through the shared production authority boundary.

## OPEN blocker: repository-wide canonical pre-TLC Clippy

The exact current candidate was recovered successfully by the new 202-profile acceptance workflow, but the canonical pre-TLC phase failed before TLC.

A dedicated Rust matrix established the current pattern precisely:

- `cargo fmt --all -- --check`: PASS
- strict `cargo check --all-targets`: PASS in default, Linux, Root, and all-feature modes
- strict `cargo test --all-targets`: PASS in default, Linux, Root, and all-feature modes
- `cargo clippy --all-targets -- -D warnings`: FAIL in exactly four modes: default, Linux, Root, and all-features

Therefore the present blocker is a repository-wide all-targets Clippy issue, not an observed compile/test/runtime failure. Do **not** suppress it or downgrade the gate.

A current-vs-immediate-parent Clippy differential is the next decision gate. It must determine whether the lint is inherited debt or introduced by the materialization delta, and identify its source owner without leaking private paths. Only after that evidence should source be changed.

## Acceptance sequence after the Clippy blocker is corrected

1. Rebind proofs to the new exact candidate revision produced by the correction.
2. Re-run the full canonical pre-TLC verifier with no criteria weakened.
3. Run the 202-profile canonical set, with 201 ordinary profiles sharded and profile 39 handled through its exact-snapshot resumable lane.
4. Require all formal/proof/model-checking evidence to bind to the same accepted source revision or to a justified immutable ancestor whose applicability has been explicitly re-established.
5. Only after complete current-snapshot evidence is GREEN may promotion be considered under the repository-defined promotion procedure.
6. Update this handoff with the exact problem, root cause, correction, and verification evidence; then remove temporary diagnostics that are no longer needed.

## Failure-handling template for future sessions

For every new blocker, record:

- **Observed failure:** exact gate and evidence, without interpretation.
- **Classification:** source defect, inherited debt, verifier defect, environment/resource issue, or still unknown.
- **Counter-hypothesis:** strongest plausible alternative explanation and how it was tested.
- **Root cause:** only after evidence distinguishes it from alternatives.
- **Correction:** smallest architecture-preserving source/tooling change; no suppression to obtain GREEN.
- **Regression evidence:** parent/differential result where applicable.
- **Closure evidence:** exact candidate proof plus all gates that re-ran successfully.
- **Residual risk:** anything not yet demonstrated.

This document is a navigation aid, not an authority source. Primary source, exact repository state, and reproducible verification outrank it.