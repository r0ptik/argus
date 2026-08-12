# Releasing

Maintainer checklist. Not needed to use or contribute to Argus.

## 1. Sync from the dev workspace

This repo is a downstream snapshot. Development happens elsewhere.

```powershell
.\sync-from-dev.ps1
git diff
```

Read the diff. Nothing dev-only, target-specific, or private should appear.

## 2. Verify

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```

Then scan for anything that should not ship:

```bash
git grep -nEi "TW[0-9]{6,}|Lin\.bin|D:\\\\|C:\\\\"
```

The only expected hit is the example path in the READMEs.

## 3. Smoke-test the release layout

The router finds engines as siblings, so test that arrangement rather than the
cargo tree:

```powershell
$s = "dist/smoke"
New-Item -ItemType Directory -Force $s | Out-Null
Copy-Item target/x86_64-pc-windows-msvc/release/argus-router.exe "$s/"
Copy-Item target/x86_64-pc-windows-msvc/release/argus-rs.exe "$s/argus-rs-x64.exe"
Copy-Item target/i686-pc-windows-msvc/release/argus-rs.exe "$s/argus-rs-x86.exe"

'{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | & "$s/argus-router.exe"
```

A tool list should come back. If the router reports a missing engine, the
sibling naming is wrong.

## 4. Update the changelog

Move everything under `## [Unreleased]` into a new version heading with today's
date, and update the link definitions at the bottom.

## 5. Tag

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin main --tags
```

The `release` workflow builds both architectures, assembles
`argus-windows.zip` with a SHA256 sidecar, and publishes the GitHub release.

## 6. Verify the published artifact

Download the archive from the release page — not the local build — unzip it
somewhere clean, and run the smoke test from step 3 against it. This is the only
step that proves what users actually receive works.

## 7. MCP registry

The official registry stores metadata only; the package has to be resolvable
first. Generate the descriptor rather than writing it by hand:

```bash
mcp-publisher init      # produces server.json
mcp-publisher login github
mcp-publisher publish
```

Under GitHub authentication the server name must be `io.github.r0ptik/argus`.

Then submit to the community directories: mcp.so, Smithery, PulseMCP, Glama, and
open a PR against the awesome-mcp-servers lists.

## 8. crates.io (not yet)

Publishing to crates.io additionally requires every path dependency to carry a
`version` field, and each crate manifest to declare `description`, `repository`,
and `keywords`. Those manifests live in the dev workspace, so that change has to
be made upstream and synced down — it cannot be patched here or the next sync
will discard it.
