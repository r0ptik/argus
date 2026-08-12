# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-12

First public release.

### Added

- MCP server exposing runtime evidence from a live Windows process.
- Process and memory tools: `processes_list`, `processes_find`, `mem_attach`,
  `mem_modules`, `memory_regions`, `mem_read`, `mem_read_chain`, `mem_write`.
- Scanning: `scan_bytes`, `scan_string`, `scan_regex`, `scan_pointers_to`,
  `scan_callers`, `scan_x86_call_sites`, plus the iterative value scanner
  (`value_scan_start`, `value_scan_refine`, `value_explain`, `real_rate`).
- Disassembly and structure recovery: `disasm_at`, `analyze_function`,
  `find_vtable`, `extract_dispatch_tables`, `analyze_send_call_sites`,
  `read_struct`, `diff_struct`.
- Import and API resolution: `runtime_imports`, `runtime_exports`,
  `resolve_iat_thunks`, `resolve_api_targets`.
- Tracing and correlation: `trace_call_chain`, `correlate_addr`, `locate`.
- Evidence ledger: `record_hypothesis`, `verify_hypothesis`, `query_hypotheses`,
  `add_evidence` — findings are stored as hypotheses and only promoted once
  evidence is attached and verification passes.
- `argus-router`, which inspects the target process, determines whether it is
  x86 or x64, and dispatches to the matching engine build. A single configured
  binary handles both native x64 and WOW64 targets.
- Engine lookup order: `ARGUS_ROUTER_X86` / `ARGUS_ROUTER_X64` environment
  overrides, then sibling `argus-rs-x86.exe` / `argus-rs-x64.exe` next to the
  router, then the cargo target tree used during development.

[Unreleased]: https://github.com/r0ptik/argus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/r0ptik/argus/releases/tag/v0.1.0
