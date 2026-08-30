# RESX Secure Development Lifecycle

## Requirements

- Treat binaries, symbols, rules, JSON, paths, and FFI input as hostile.
- Run analysis without elevation.
- Do not execute analyzed code.
- Keep unsafe mapping opt-in and isolated.
- Bound memory, recursion, work queues, graph growth, and file traversal.

## Design Review

For new input surfaces, document:

- Trust boundary and attacker control.
- Length, offset, count, and integer checks.
- File and network access.
- Resource limits and cancellation behavior.
- FFI ownership and concurrency rules.

## Implementation

- Prefer safe Rust.
- Keep `unsafe` blocks small and justified.
- Validate before slicing, allocating, decoding, following pointers, or writing output.
- Return structured errors; do not panic across FFI.
- Avoid shell command construction from untrusted input.

## Verification

Required checks are listed in [CONTRIBUTING.md](../../CONTRIBUTING.md).

Security-sensitive changes also require:

- Positive, negative, malformed, truncated, and oversized input tests.
- Regression tests for every confirmed defect.
- Fuzzing for changed parsers or recursive analysis paths.
- Dependency and advisory review before release.
- Verification that release artifacts do not contain secrets or local paths.

## Release and Response

- Triage reports privately under [SECURITY.md](../../SECURITY.md).
- Patch supported versions and publish an advisory when impact is confirmed.
- Record affected versions, fixes, mitigations, and regression coverage.
