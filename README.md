# Argus

English · [繁體中文](docs/i18n/README.zh-TW.md) · [简体中文](docs/i18n/README.zh-CN.md) · [日本語](docs/i18n/README.ja.md) · [한국어](docs/i18n/README.ko.md)

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

## Why this exists

Games die. The publisher shuts the servers down, the studio folds, the genre moves
on. What survives is a client sitting on somebody's hard drive that can no longer
connect to anything — no source, no protocol documentation, no server left to talk
to. Just an executable that still remembers how to speak a language nobody is
listening to anymore.

Argus was built to bring those back.

Reconstructing a server for a dead game means recovering its protocol: packet
layouts, encryption, opcode dispatch, the state machine on the other side of the
wire. The only surviving specification is the client binary itself. Nobody wrote
the document you need, and the people who knew have long since moved on.

Static analysis gets you partway. But a twenty-year-old client is packed, its
strings are encrypted, its handlers dispatch through tables that only exist once
the process is up. So you run it, and you watch it work — which is where the next
section comes in.

That is what this tool is for: not breaking into something alive, but getting
something dead to speak again.

---

## Why go to the running process at all

**A CPU cannot execute ciphertext.**

Whatever a program does to protect itself on disk — packing, string encryption,
virtualized instructions, imports resolved at load time — all of it has to be undone
before the processor can run the code. At the instant of execution, the real
instructions and the real data are sitting in memory in the clear. They have to be.
That is not a flaw in any particular protector; it is a consequence of how processors
work, and no amount of obfuscation gets around it.

So the two approaches are reading different things:

- **Static analysis reads the file.** What the author shipped.
- **Runtime analysis reads what the file turned into.** What the machine is actually running.

When those two differ, the second one is the truth.

| Situation | Static analyzer | Argus |
|---|---|---|
| Packed / self-decrypting code | sees the packer | disassembles the unpacked bytes in memory |
| Indirect call through a vtable | sees `call [rax+0x18]` | resolves the slot to a concrete target |
| Import resolved at runtime | sees a thunk stub | resolves the thunk to the real API |
| Buffer contents after decryption | nothing | reads the plaintext |
| Which of 40 call sites actually fires | guesses | records the one that ran |

### Where static analysis wins

The trade runs the other way too, and it is worth being blunt about it: a static
analyzer sees *every* path, including the ones that never execute. Argus only sees
what actually ran. A branch that was never taken leaves no runtime evidence at all,
and a function nobody called may as well not exist.

Neither view is complete on its own. That is what `correlate_addr` is for — map a
runtime address back to a module and RVA, look it up in Ghidra or IDA, and work with
both halves. Argus is built to sit alongside a static analyzer, not to replace one.

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
game and server preservation, network protocol analysis, interoperability and
clean-room reimplementation, malware analysis, crash and corruption debugging, and
security research.

It is explicitly **not** built for attacking live services. No cheat features are
accepted into this repository — see [CONTRIBUTING.md](CONTRIBUTING.md).

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
