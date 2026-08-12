# Security Policy

## What Argus is

Argus opens handles to other processes and reads (and, when asked, writes) their
memory. That is the entire point of the tool, and it is why the sections below
draw a hard line between *designed behavior* and *a vulnerability*.

## Not vulnerabilities

The following are intended behavior. Reports about them will be closed with a
pointer to this document:

- `mem_write` modifies a target process's memory.
- `mem_read`, `scan_*`, and `read_struct` expose the contents of another
  process's address space, including secrets that happen to be resident.
- Argus requires sufficient privileges to open a target process, and will use
  them once granted.
- Argus does not verify that the operator is authorized to analyze a given
  target. Authorization is the operator's responsibility.

## Actual vulnerabilities

These are in scope, and I want to hear about them:

- Memory-safety faults in Argus itself — out-of-bounds reads while parsing a
  target's PE headers, structures, or disassembly; unsound `unsafe` blocks.
- A crafted target process being able to influence Argus beyond returning wrong
  analysis results — for example, causing Argus to execute attacker-controlled
  code, write outside the region the operator asked for, or escape the requested
  target.
- The MCP layer accepting a request that reaches a process the operator never
  named, or that performs a write when only reads were requested.
- Path traversal or arbitrary write via the evidence ledger.
- Credential or token disclosure through logs or tool output.

## Reporting

Use GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/r0ptik/argus/security/advisories/new)**

Please do not open a public issue for anything in the "actual vulnerabilities"
list above.

Include the target platform and architecture, the Argus version
(`argus-router.exe --version` or the release tag), the tool call that triggered
it, and a minimal reproduction if you have one. A crashing target binary is
useful; a description of one is usually enough to start.

I will acknowledge a report within 7 days. This is a single-maintainer project,
so please calibrate expectations accordingly — I would rather tell you honestly
that a fix will take weeks than go silent.

## Supported versions

The latest release is supported. Older tags do not receive backported fixes.
