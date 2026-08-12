# Contributing

Thanks for taking a look. Argus is a small, focused tool and I would like to keep
it that way, so this document is mostly about what fits and what does not.

The project exists to recover protocols from software that no longer has a server
to talk to — dead games, abandoned clients, formats nobody documented. That goal
is what the boundaries below are drawn around.

## What fits

- New evidence-gathering tools that return facts about a live process.
- Better resolution of indirect control flow — vtables, dispatch tables, thunks,
  jump tables.
- Structure recovery improvements.
- Support for more of the runtime surface: TLS callbacks, exception tables,
  loader data, heap metadata.
- Correctness fixes, especially anything involving WOW64 pointer width or PE
  parsing edge cases.
- Documentation, particularly worked examples of real analysis sessions.

## What does not fit

- **Conclusions.** Argus returns addresses, bytes, instructions, and callers. It
  does not tell the model what they mean. Tools that emit an interpretation
  instead of evidence will be turned down.
- **Static analysis.** Ghidra and IDA already have good MCP bridges. Argus is the
  runtime half; correlating the two is what `correlate_addr` is for.
- **Game-specific or target-specific behavior.** No hardcoded process names,
  offsets, or signatures for a particular application. Everything must be
  parameterized.
- **Cheat features.** Aimbots, ESP, packet spoofing helpers, anti-anti-cheat.
  Argus is an analysis tool and is going to stay one.

## Development setup

You need a Rust toolchain and both Windows targets, because the router dispatches
between a 32-bit and a 64-bit engine:

```bash
rustup target add x86_64-pc-windows-msvc i686-pc-windows-msvc

cargo test --workspace
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```

During development the router finds the engines through the cargo target tree
automatically. To point it somewhere else, set `ARGUS_ROUTER_X86` and
`ARGUS_ROUTER_X64`.

## Layout

| Crate | Role |
|---|---|
| `argus-router` | front-end binary; architecture detection and dispatch |
| `argus-rs` | MCP server; tool definitions and request handling |
| `argus-engine` | analysis engine; disassembly, structure recovery, tracing |
| `argus-winmem` | Win32 process and memory access |
| `argus-scan` | pattern and value scanning primitives |
| `evidence-core` | address, module, RVA and evidence data models |

Shared data models belong in `evidence-core`. Anything touching Win32 belongs in
`argus-winmem` — the other crates should not link `windows-sys` directly.

## Before you open a pull request

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```

Adding a tool means adding its schema in `argus-rs`, a handler, and a test. If
the tool behaves differently on x86 and x64, say so in the tool description —
that text is what the model reads.

## Commit messages

Explain why, not what. The diff already says what.

## Reporting a security issue

Do not open a public issue. See [SECURITY.md](SECURITY.md).
