## What this changes

<!-- Why, not what. The diff already says what. -->

## Evidence, not conclusions

<!-- If this adds or changes a tool: what facts does it return? Argus reports
     addresses, bytes, instructions and callers; it does not tell the model what
     they mean. Delete this section for docs and build changes. -->

## Architecture

- [ ] Behaves identically on x86 and x64
- [ ] Behaves differently — the tool description says so
- [ ] Not architecture-dependent

## Checks

- [ ] `cargo fmt --all`
- [ ] `cargo clippy --workspace --all-targets`
- [ ] `cargo test --workspace`
- [ ] Builds for `i686-pc-windows-msvc` as well as `x86_64-pc-windows-msvc`

## Verified against

<!-- What did you actually run this on? "A packed 32-bit client under WOW64" is
     useful. You do not need to name the target. -->

## Notes

- [ ] No hardcoded process names, offsets, or signatures for a specific application
- [ ] Changelog updated under `## [Unreleased]` if this is user-visible
