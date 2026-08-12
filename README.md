# Argus

**An MCP server that gives AI agents evidence from a *running* process.**

Every reverse-engineering MCP server so far bridges a *static* analyzer — Ghidra, IDA,
apktool. They hand your agent the file on disk. None of them can tell the agent what the
program is actually doing right now: what got decrypted into that buffer, which address
the vtable slot resolved to at runtime, which call site sent that packet.

Argus is the other half. It attaches to a live Windows process and returns runtime
evidence: real bytes at real addresses, disassembly of the code that actually executed,
resolved IAT thunks, caller chains walked from live memory, and a hypothesis ledger that
tracks what has been proven versus what is still a guess.

It does not draw conclusions for the model. It returns addresses, module/RVA context,
instructions, callers, callees, and local evidence, then gets out of the way.

---

## Why runtime evidence matters

Static analysis stops where the program starts lying to you:

| Situation | Static analyzer | Argus |
|---|---|---|
| Packed / self-decrypting code | sees the packer | disassembles the unpacked bytes in memory |
| Indirect call through a vtable | sees `call [rax+0x18]` | resolves the slot to a concrete target |
| Import resolved at runtime | sees a thunk stub | resolves the thunk to the real API |
| Buffer contents after decryption | nothing | reads the plaintext |
| Which of 40 call sites actually fires | guesses | records the one that ran |

---

## Tools

**Process and memory**
`processes_list` · `processes_find` · `mem_attach` · `mem_modules` · `memory_regions`
`mem_read` · `mem_read_chain` · `mem_write`

**Scanning**
`scan_bytes` · `scan_string` · `scan_regex` · `scan_pointers_to` · `scan_callers`
`scan_x86_call_sites` · `value_scan_start` · `value_scan_refine` · `value_explain` · `real_rate`

**Disassembly and structure recovery**
`disasm_at` · `analyze_function` · `find_vtable` · `extract_dispatch_tables`
`analyze_send_call_sites` · `read_struct` · `diff_struct`

**Import and API resolution**
`runtime_imports` · `runtime_exports` · `resolve_iat_thunks` · `resolve_api_targets`

**Tracing and correlation**
`trace_call_chain` · `correlate_addr` · `locate`

**Evidence ledger**
`record_hypothesis` · `verify_hypothesis` · `query_hypotheses` · `add_evidence`

---

## Two design decisions worth knowing about

### Automatic architecture routing

Attaching a 64-bit analyzer to a 32-bit (WOW64) target is a classic source of silently
wrong pointer arithmetic and garbage PE parsing. Argus ships a thin front-end,
`argus-router`, which inspects the target process, determines whether it is x86 or x64,
and dispatches to the matching `argus-rs` build. You configure one binary; the correct
engine is selected per target.

### The evidence ledger

Agents are good at producing plausible explanations and bad at noticing when a plausible
explanation is unsupported. `record_hypothesis` / `verify_hypothesis` / `add_evidence`
force the distinction: a claim is stored as a hypothesis, and only becomes an established
fact when evidence is attached and verification passes. `query_hypotheses` lets a later
session pick up where the previous one stopped without re-deriving everything.

---

## Install

### Prebuilt binaries

Download the latest release and unpack it anywhere:

**[Releases](https://github.com/r0ptik/argus/releases)**

The archive contains `argus-router.exe` plus both engine builds
(`argus-rs-x64.exe`, `argus-rs-x86.exe`). Keep them in the same directory.

### From source

Requires a Rust toolchain with both Windows targets installed:

```bash
rustup target add x86_64-pc-windows-msvc i686-pc-windows-msvc

git clone https://github.com/r0ptik/argus
cd argus
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```

---

## Configure

### Claude Code

```bash
claude mcp add argus -- C:\path\to\argus-router.exe
```

### Any MCP client

```json
{
  "mcpServers": {
    "argus": {
      "command": "C:\\path\\to\\argus-router.exe"
    }
  }
}
```

---

## Scope and intended use

Argus is a reverse-engineering and program-analysis tool. It is built for work such as
network protocol analysis, interoperability and clean-room reimplementation, malware
analysis, crash and corruption debugging, and security research.

It requires the ability to open and read another process, so use it only against
processes you own or are authorized to analyze. Attaching to software you do not have
permission to analyze may violate that software's terms or your local law. That is your
responsibility, not the tool's.

---

## Platform support

Windows only. The memory access layer (`argus-winmem`) is built on the Win32 process
and memory APIs; there is no Linux or macOS backend today.

Both x86 and x64 targets are supported, including 32-bit processes running under WOW64.

---

## Crates

| Crate | Role |
|---|---|
| `argus-router` | front-end binary; architecture detection and dispatch |
| `argus-rs` | MCP server; tool definitions and request handling |
| `argus-engine` | analysis engine; disassembly, structure recovery, tracing |
| `argus-winmem` | Win32 process and memory access |
| `argus-scan` | pattern and value scanning primitives |
| `evidence-core` | address, module, RVA and evidence data models |

---

## License

MIT. See [LICENSE](LICENSE).
