use regex::{bytes::RegexBuilder as BytesRegexBuilder, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::BufWriter;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argus_engine::{
    ArgusEngine, InMemoryBackend, MemoryRegion, ModuleInfo, ValueCandidate, ValuePredicate,
    ValueRefinement, ValueScanSession, ValueType,
};
use argus_winmem::{processes, MemoryRegionInfo, WinProcess};
use evidence_core::{Address, TargetArch};

const PROTOCOL_VERSION: &str = "2025-11-25";
const ARGUS_ADDRESS_WIDTH: u32 = usize::BITS;
const INSTRUCTIONS: &str = "Argus-rs is an AI-first runtime memory evidence and reverse-tracing tool. It models how experienced reversers work: anchor on runtime send/recv/decrypt/dispatch evidence, resolve imports/IAT/thunks, disassemble exact runtime bytes, walk caller/callee chains, inspect strings/globals/buffers, and only then form hypotheses. It does not make conclusions for the model; it returns addresses, module/RVA context, instructions, callers, callees, local evidence, and next-tool hints so GPT/Opus-class reasoning can verify or reject hypotheses.";
const TEXT_HIT_DISPLAY_LIMIT: usize = 12;
const MODULE_DISPLAY_LIMIT: usize = 16;
const PREVIEW_DISPLAY_LIMIT: usize = 96;

#[derive(Debug, Clone)]
struct StaticStructField {
    offset: u64,
    name: String,
    type_name: String,
    length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotScope {
    All,
    Module,
    Heap,
    Executable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextEncoding {
    Utf8,
    Utf16Le,
    Both,
}

impl TextEncoding {
    fn label(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::Utf16Le => "utf16le",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanOutputFormat {
    Csv,
    Json,
}

impl ScanOutputFormat {
    fn label(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone)]
struct TextScanOptions<'a> {
    pid: u32,
    pattern: &'a str,
    regex: bool,
    encoding: TextEncoding,
    case_sensitive: bool,
    region: SnapshotScope,
    address: Option<Address>,
    size: usize,
    max_results: usize,
    full: bool,
    out_path: Option<PathBuf>,
    out_format: ScanOutputFormat,
}

#[derive(Debug)]
struct TextScanResult {
    hits: Vec<Value>,
    total_hit_count: usize,
    out_path: Option<PathBuf>,
    out_format: Option<ScanOutputFormat>,
    scanned_region_count: usize,
    scanned_bytes: usize,
}

impl SnapshotScope {
    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Module => "module",
            Self::Heap => "heap",
            Self::Executable => "executable",
        }
    }

    fn limits(self) -> (usize, usize) {
        match self {
            Self::Executable | Self::Module => (16 * 1024 * 1024, 64 * 1024 * 1024),
            Self::All | Self::Heap => (1024 * 1024, 64 * 1024 * 1024),
        }
    }
}

fn region_read_limit(scope: SnapshotScope, in_main_module: bool) -> usize {
    if matches!(scope, SnapshotScope::All) && in_main_module {
        SnapshotScope::Module.limits().0
    } else {
        scope.limits().0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HypothesisEvidence {
    id: u64,
    kind: String,
    detail: String,
    source: String,
    addr: Option<String>,
    created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HypothesisRecord {
    id: u64,
    entity: String,
    claim_type: String,
    claim_value: String,
    source: String,
    confidence: Option<f64>,
    status: String,
    created_at: u64,
    updated_at: u64,
    #[serde(default)]
    evidence: Vec<HypothesisEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NegativeKnowledge {
    id: u64,
    entity: String,
    refuted_claim: String,
    reason: Option<String>,
    created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HypothesisLedger {
    #[serde(default = "default_next_id")]
    next_id: u64,
    #[serde(default = "default_next_id")]
    next_evidence_id: u64,
    #[serde(default = "default_next_id")]
    next_negative_id: u64,
    #[serde(default)]
    hypotheses: Vec<HypothesisRecord>,
    #[serde(default)]
    negative_knowledge: Vec<NegativeKnowledge>,
}

fn default_next_id() -> u64 {
    1
}

impl HypothesisLedger {
    fn normalize(&mut self) {
        let next_hypothesis = self
            .hypotheses
            .iter()
            .map(|hypothesis| hypothesis.id)
            .max()
            .unwrap_or(0)
            + 1;
        let next_evidence = self
            .hypotheses
            .iter()
            .flat_map(|hypothesis| hypothesis.evidence.iter().map(|evidence| evidence.id))
            .max()
            .unwrap_or(0)
            + 1;
        let next_negative = self
            .negative_knowledge
            .iter()
            .map(|negative| negative.id)
            .max()
            .unwrap_or(0)
            + 1;
        self.next_id = self.next_id.max(next_hypothesis).max(1);
        self.next_evidence_id = self.next_evidence_id.max(next_evidence).max(1);
        self.next_negative_id = self.next_negative_id.max(next_negative).max(1);
    }

    fn next_hypothesis_id(&mut self) -> u64 {
        self.normalize();
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn next_evidence_id(&mut self) -> u64 {
        self.normalize();
        let id = self.next_evidence_id;
        self.next_evidence_id += 1;
        id
    }

    fn next_negative_id(&mut self) -> u64 {
        self.normalize();
        let id = self.next_negative_id;
        self.next_negative_id += 1;
        id
    }
}

impl Default for HypothesisLedger {
    fn default() -> Self {
        Self {
            next_id: 1,
            next_evidence_id: 1,
            next_negative_id: 1,
            hypotheses: Vec::new(),
            negative_knowledge: Vec::new(),
        }
    }
}

fn main() {
    if let Err(err) = run_stdio() {
        eprintln!("argus-rs error: {err}");
    }
}

fn run_stdio() -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => handle_jsonrpc_message(request),
            Err(err) => Some(error(Value::Null, -32700, &format!("Parse error: {err}"))),
        };
        if let Some(response) = response {
            writeln!(stdout, "{}", serde_json::to_string(&response).unwrap())?;
            stdout.flush()?;
        }
    }

    Ok(())
}

#[cfg(test)]
fn handle_jsonrpc(request: Value) -> Value {
    handle_jsonrpc_message(request).unwrap_or_else(|| {
        error(
            Value::Null,
            -32600,
            "Notification did not produce a response",
        )
    })
}

fn handle_jsonrpc_message(request: Value) -> Option<Value> {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let response = match method {
        "notifications/initialized" => return None,
        "initialize" => response(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {
                        "listChanged": false
                    }
                },
                "serverInfo": {
                    "name": "argus-rs",
                    "title": "Argus Rust Memory Evidence MCP",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "instructions": INSTRUCTIONS
            }),
        ),
        "tools/list" => response(id, json!({ "tools": tools() })),
        "tools/call" => handle_tool_call(id, request.get("params").cloned().unwrap_or(Value::Null)),
        _ => error(id, -32601, "Method not found"),
    };
    Some(response)
}

fn handle_tool_call(id: Value, params: Value) -> Value {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

    let result = match name {
        "mem_read" => tool_mem_read(arguments),
        "mem_write" => tool_mem_write(arguments),
        "mem_read_chain" => tool_mem_read_chain(arguments),
        "read_struct" => tool_read_struct(arguments),
        "correlate_addr" => tool_correlate_addr(arguments),
        "locate" => tool_locate(arguments),
        "find_vtable" => tool_find_vtable(arguments),
        "diff_struct" => tool_diff_struct(arguments),
        "record_hypothesis" => tool_record_hypothesis(arguments),
        "add_evidence" => tool_add_evidence(arguments),
        "verify_hypothesis" => tool_verify_hypothesis(arguments),
        "query_hypotheses" => tool_query_hypotheses(arguments),
        "real_rate" => tool_real_rate(arguments),
        "mem_attach" => tool_mem_attach(arguments),
        "mem_modules" => tool_mem_modules(arguments),
        "memory_regions" => tool_memory_regions(arguments),
        "processes_list" => tool_processes_list(arguments),
        "processes_find" => tool_processes_find(arguments),
        "runtime_imports" => tool_runtime_imports(arguments),
        "runtime_exports" => tool_runtime_exports(arguments),
        "resolve_api_targets" => tool_resolve_api_targets(arguments),
        "resolve_iat_thunks" => tool_resolve_iat_thunks(arguments),
        "disasm_at" => tool_disasm_at(arguments),
        "analyze_function" => tool_analyze_function(arguments),
        "scan_x86_call_sites" => tool_scan_x86_call_sites(arguments),
        "analyze_send_call_sites" => tool_analyze_send_call_sites(arguments),
        "extract_dispatch_tables" => tool_extract_dispatch_tables(arguments),
        "trace_call_chain" => tool_trace_call_chain(arguments),
        "scan_string" => tool_scan_string(arguments),
        "scan_regex" => tool_scan_regex(arguments),
        "scan_bytes" => tool_scan_bytes(arguments),
        "scan_pointers_to" => tool_scan_pointers_to(arguments),
        "scan_callers" => tool_scan_callers(arguments),
        "value_scan_start" => tool_value_scan_start(arguments),
        "value_scan_refine" => tool_value_scan_refine(arguments),
        "value_explain" => tool_value_explain(arguments),
        _ => Err(format!("unknown tool: {name}")),
    };

    match result {
        Ok(value) => {
            let value = with_argus_context(value);
            let text = render_tool_text(name, &value).unwrap_or_else(|| render_plain_text(&value));
            response(
                id,
                json!({
                    "content": [{
                        "type": "text",
                        "text": text
                    }],
                    "isError": false
                }),
            )
        }
        Err(message) => response(
            id,
            json!({
                "content": [{
                    "type": "text",
                    "text": message
                }],
                "isError": true
            }),
        ),
    }
}

fn target_arch() -> &'static str {
    if cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    }
}

fn with_argus_context(mut value: Value) -> Value {
    if let Value::Object(ref mut object) = value {
        object.entry("argus").or_insert_with(|| {
            json!({
                "address_width": ARGUS_ADDRESS_WIDTH,
                "target_arch": target_arch(),
            })
        });
    }
    value
}

fn target_argus_context(target_arch: TargetArch) -> Value {
    json!({
        "address_width": target_arch.decoder_bitness(),
        "target_arch": target_arch.label(),
    })
}

fn render_tool_text(name: &str, value: &Value) -> Option<String> {
    match name {
        "mem_read" => Some(render_mem_read(value)),
        "mem_read_chain" => Some(render_mem_read_chain(value)),
        "mem_modules" => Some(render_mem_modules(value)),
        "read_struct" => Some(render_read_struct(value)),
        "scan_string" => Some(render_scan_string(value)),
        "scan_regex" => Some(render_scan_regex(value)),
        "scan_bytes" => Some(render_scan_bytes(value)),
        "scan_pointers_to" => Some(render_scan_pointers_to(value)),
        "scan_callers" => Some(render_scan_callers(value)),
        "disasm_at" => Some(render_disasm_at(value)),
        "analyze_function" => Some(render_analyze_function(value)),
        "scan_x86_call_sites" => Some(render_scan_x86_call_sites(value)),
        "analyze_send_call_sites" => Some(render_analyze_send_call_sites(value)),
        "extract_dispatch_tables" => Some(render_extract_dispatch_tables(value)),
        "trace_call_chain" => Some(render_trace_call_chain(value)),
        "locate" => Some(render_locate(value)),
        "find_vtable" => Some(render_find_vtable(value)),
        "diff_struct" => Some(render_diff_struct(value)),
        _ => None,
    }
}

fn render_plain_text(value: &Value) -> String {
    let mut lines = Vec::new();
    render_plain_into(None, value, 0, &mut lines);
    lines.join("\n")
}

fn render_plain_into(key: Option<&str>, value: &Value, indent: usize, lines: &mut Vec<String>) {
    let pad = " ".repeat(indent);
    if let Some(text) = plain_inline_value(key, value) {
        if let Some(key) = key {
            lines.push(format!("{pad}{key}: {text}"));
        } else {
            lines.push(format!("{pad}{text}"));
        }
        return;
    }

    match value {
        Value::Object(object) => {
            if let Some(key) = key {
                lines.push(format!("{pad}{key}:"));
            } else if let Some(tool) = object.get("tool").and_then(Value::as_str) {
                lines.push(tool.to_string());
            }

            for (field, nested) in object {
                if field == "tool" {
                    continue;
                }
                render_plain_into(Some(field), nested, indent + 2, lines);
            }
        }
        Value::Array(items) => {
            if let Some(key) = key {
                lines.push(format!("{pad}{key}:"));
            }
            if items.is_empty() {
                lines.push(format!("{}(none)", " ".repeat(indent + 2)));
                return;
            }
            for item in items {
                if let Some(text) = plain_inline_value(None, item) {
                    lines.push(format!("{}- {text}", " ".repeat(indent + 2)));
                } else {
                    lines.push(format!("{}-", " ".repeat(indent + 2)));
                    render_plain_into(None, item, indent + 4, lines);
                }
            }
        }
        _ => {
            let text = plain_inline_value(key, value).unwrap_or_else(|| "?".to_string());
            if let Some(key) = key {
                lines.push(format!("{pad}{key}: {text}"));
            } else {
                lines.push(format!("{pad}{text}"));
            }
        }
    }
}

fn plain_inline_value(key: Option<&str>, value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("-".to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::String(value) => Some(value.replace('\n', "\\n")),
        Value::Array(items) => {
            if key.map(is_bytes_key).unwrap_or(false) && is_byte_array(items) {
                return Some(bytes_hex(value));
            }
            if items.is_empty() {
                return Some("(none)".to_string());
            }
            if items.len() <= 8
                && items
                    .iter()
                    .all(|item| plain_inline_value(None, item).is_some())
            {
                return Some(
                    items
                        .iter()
                        .filter_map(|item| plain_inline_value(None, item))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            None
        }
        Value::Object(object) => {
            if key.map(is_address_key).unwrap_or(false) {
                return Some(format_address_value(value));
            }
            if object.len() == 1 {
                let (variant, nested) = object.iter().next().unwrap();
                if let Some(text) = plain_inline_value(None, nested) {
                    return Some(format!("{variant}({text})"));
                }
            }
            None
        }
    }
}

fn is_bytes_key(key: &str) -> bool {
    key.contains("bytes") || key == "prologue"
}

fn is_byte_array(items: &[Value]) -> bool {
    items
        .iter()
        .all(|item| item.as_u64().map(|value| value <= 0xff).unwrap_or(false))
}

fn is_address_key(key: &str) -> bool {
    matches!(
        key,
        "address"
            | "base"
            | "target"
            | "live_addr"
            | "static_addr"
            | "final_address"
            | "base_address"
            | "read_address"
            | "next_address"
            | "pointer"
            | "deref"
            | "rva"
            | "ghidra_image_base"
            | "iat_address"
            | "thunk_address"
            | "function_start"
            | "call_target"
            | "string_address"
            | "ref_site"
            | "vtable"
            | "type_descriptor"
            | "col"
            | "rtti_string"
    )
}

fn render_mem_read(value: &Value) -> String {
    let Some(hit) = value.get("hit") else {
        return "(no memory evidence)".to_string();
    };
    let address = hit_address(hit).unwrap_or_else(|| "?".to_string());
    let bytes = hit.pointer("/evidence/Bytes/bytes").unwrap_or(&Value::Null);
    let ascii = hit
        .pointer("/context/ascii_preview")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("{address}  {}\n{}", bytes_hex(bytes), ascii)
}

fn render_mem_read_chain(value: &Value) -> String {
    let chain = value
        .get("chain")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(format_address_value)
                .collect::<Vec<_>>()
                .join(" -> ")
        })
        .unwrap_or_else(|| "(empty chain)".to_string());
    let final_address = format_address_value(value.get("final_address").unwrap_or(&Value::Null));
    let final_bytes = bytes_hex(value.get("final_bytes").unwrap_or(&Value::Null));
    let ascii = value
        .get("ascii_preview")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("chain: {chain}\nfinal: {final_address}\n{final_bytes}\n{ascii}")
}

fn render_read_struct(value: &Value) -> String {
    let Some(words) = value.get("words").and_then(Value::as_array) else {
        return "(no struct words)".to_string();
    };
    if words.is_empty() {
        return "(no struct words)".to_string();
    }
    words
        .iter()
        .map(|word| {
            let address = format_address_value(word.get("address").unwrap_or(&Value::Null));
            let value_hex = word.get("value_hex").and_then(Value::as_str).unwrap_or("?");
            let mut line = format!("{address}  {value_hex}");
            if let Some(target) = word.pointer("/pointer_target/address") {
                line.push_str(&format!(" -> {}", format_address_value(target)));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_mem_modules(value: &Value) -> String {
    let modules = value
        .get("modules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let module_count = value
        .get("module_count")
        .and_then(Value::as_u64)
        .unwrap_or(modules.len() as u64);
    let full = value.get("full").and_then(Value::as_bool).unwrap_or(false);
    let max_results = value
        .get("max_results")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(MODULE_DISPLAY_LIMIT);
    let shown = if full {
        modules.len()
    } else {
        modules.len().min(max_results)
    };
    let arch = value
        .pointer("/argus/target_arch")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let width = value
        .pointer("/argus/address_width")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut lines = vec![format!(
        "mem_modules: module_count: {module_count}, target_arch: {arch}, address_width: {width}"
    )];
    if modules.is_empty() {
        lines.push("(no modules)".to_string());
        return lines.join("\n");
    }
    lines.extend(modules.iter().take(shown).map(format_module_line));
    if shown < modules.len() {
        lines.push(format!(
            "... {} more omitted; pass full=true or raise max_results for the full module list",
            modules.len() - shown
        ));
    }
    lines.join("\n")
}

fn format_module_line(module: &Value) -> String {
    let name = module.get("name").and_then(Value::as_str).unwrap_or("?");
    let base = format_address_value(module.get("base").unwrap_or(&Value::Null));
    let size = format_address_value(module.get("size").unwrap_or(&Value::Null));
    format!("{base} size={size} {name}")
}

fn render_scan_string(value: &Value) -> String {
    render_text_scan("scan_string", value)
}

fn render_scan_regex(value: &Value) -> String {
    render_text_scan("scan_regex", value)
}

fn render_text_scan(tool: &str, value: &Value) -> String {
    let pattern = value.get("pattern").and_then(Value::as_str).unwrap_or("");
    let Some(hits) = value.get("hits").and_then(Value::as_array) else {
        return format!("{tool} \"{pattern}\": (no hits)");
    };
    let scope = value
        .get("scan_scope")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let encoding = value.get("encoding").and_then(Value::as_str).unwrap_or("?");
    let total = value
        .get("total_hit_count")
        .and_then(Value::as_u64)
        .unwrap_or(hits.len() as u64);
    let mut lines = vec![format!(
        "{tool} \"{pattern}\" [{scope}/{encoding}]: returned={} total={total}",
        hits.len()
    )];
    if let Some(path) = value.get("out_path").and_then(Value::as_str) {
        lines.push(format!(
            "out: {} ({})",
            path,
            value
                .get("out_format")
                .and_then(Value::as_str)
                .unwrap_or("?")
        ));
    }
    if hits.is_empty() {
        lines.push("(no hits)".to_string());
        return lines.join("\n");
    }
    lines.extend(hits.iter().take(TEXT_HIT_DISPLAY_LIMIT).map(|hit| {
        let address = hit_address(hit).unwrap_or_else(|| "?".to_string());
        let tag = hit_region_module_tag(hit);
        let rva = hit_rva_suffix(hit);
        let encoding = hit.get("encoding").and_then(Value::as_str).unwrap_or("?");
        let text = hit
            .get("text")
            .and_then(Value::as_str)
            .or_else(|| hit.pointer("/evidence/Utf8/text").and_then(Value::as_str))
            .or_else(|| {
                hit.pointer("/context/ascii_preview")
                    .and_then(Value::as_str)
            })
            .unwrap_or("");
        let ascii = hit
            .pointer("/context/ascii_preview")
            .and_then(Value::as_str)
            .unwrap_or("");
        if ascii.is_empty() || ascii == text {
            format!(
                "{address}  [{encoding}/{tag}]{rva}  {}",
                truncate_preview(text)
            )
        } else {
            format!(
                "{address}  [{encoding}/{tag}]{rva}  {}  | {}",
                truncate_preview(text),
                truncate_preview(ascii)
            )
        }
    }));
    push_omitted_hint(&mut lines, hits.len(), total as usize);
    lines.join("\n")
}

fn render_scan_bytes(value: &Value) -> String {
    let pattern = value.get("pattern").and_then(Value::as_str).unwrap_or("");
    let Some(hits) = value.get("hits").and_then(Value::as_array) else {
        return format!("scan_bytes {pattern}: (no hits)");
    };
    if hits.is_empty() {
        return format!(
            "scan_bytes {pattern} [{}]: (no hits)",
            value
                .get("scan_scope")
                .and_then(Value::as_str)
                .unwrap_or("?")
        );
    }
    let mut lines = vec![format!(
        "scan_bytes {pattern} [{}]: {} hit(s)",
        value
            .get("scan_scope")
            .and_then(Value::as_str)
            .unwrap_or("?"),
        hits.len()
    )];
    lines.extend(hits.iter().take(TEXT_HIT_DISPLAY_LIMIT).map(|hit| {
        let address = hit_address(hit).unwrap_or_else(|| "?".to_string());
        let tag = hit_region_module_tag(hit);
        let rva = hit_rva_suffix(hit);
        let ascii = hit
            .pointer("/context/ascii_preview")
            .and_then(Value::as_str)
            .unwrap_or("");
        if ascii.is_empty() {
            format!("{address}  [{tag}]{rva}")
        } else {
            format!("{address}  [{tag}]{rva}  {}", truncate_preview(ascii))
        }
    }));
    push_omitted_hint(&mut lines, hits.len(), hits.len());
    lines.join("\n")
}

fn render_scan_pointers_to(value: &Value) -> String {
    let target = format_address_value(value.get("address").unwrap_or(&Value::Null));
    let hits = value
        .get("hits")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if hits.is_empty() {
        return format!("scan_pointers_to {target}: (no hits)");
    }
    let mut lines = vec![format!("scan_pointers_to {target}: {} hit(s)", hits.len())];
    lines.extend(hits.iter().map(|hit| {
        let address = hit_address(hit).unwrap_or_else(|| "?".to_string());
        let tag = region_tag(hit);
        let rva = hit_rva_suffix(hit);
        format!("{address}  [{tag}]{rva}")
    }));
    lines.join("\n")
}

fn render_scan_callers(value: &Value) -> String {
    let target = format_address_value(value.get("target").unwrap_or(&Value::Null));
    let hits = value
        .get("hits")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if hits.is_empty() {
        return format!("scan_callers {target}: (no callers)");
    }
    let mut lines = vec![format!("scan_callers {target}: {} caller(s)", hits.len())];
    lines.extend(hits.iter().map(|hit| {
        let address = hit_address(hit).unwrap_or_else(|| "?".to_string());
        let text = hit
            .pointer("/evidence/Caller/opcode")
            .or_else(|| hit.pointer("/evidence/IndirectCaller/opcode"))
            .map(|_| "call/jmp evidence")
            .unwrap_or("");
        format!("{address}  {text}")
    }));
    lines.join("\n")
}

fn render_disasm_at(value: &Value) -> String {
    let instructions = value
        .get("instructions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if instructions.is_empty() {
        return "(no disassembly)".to_string();
    }
    instructions
        .iter()
        .map(render_instruction)
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_analyze_function(value: &Value) -> String {
    let Some(function) = value.get("function").filter(|value| !value.is_null()) else {
        return "(no function analysis)".to_string();
    };
    let address = format_address_value(function.get("address").unwrap_or(&Value::Null));
    let end = format_address_value(function.get("end").unwrap_or(&Value::Null));
    let mut lines = vec![format!("fn {address} -> {end}")];
    if let Some(instructions) = function.get("instructions").and_then(Value::as_array) {
        lines.extend(instructions.iter().map(render_instruction));
    }
    if let Some(callees) = function.get("callees").and_then(Value::as_array) {
        if !callees.is_empty() {
            lines.push(format!(
                "callees: {}",
                callees
                    .iter()
                    .map(format_address_value)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    lines.join("\n")
}

fn render_scan_x86_call_sites(value: &Value) -> String {
    let target = format_address_value(value.get("target").unwrap_or(&Value::Null));
    let sites = value
        .get("call_sites")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if sites.is_empty() {
        return format!("scan_x86_call_sites {target}: (no callers)");
    }
    let mut lines = vec![format!(
        "scan_x86_call_sites {target}: {} caller(s)",
        sites.len()
    )];
    lines.extend(sites.iter().map(|site| {
        let address = format_address_value(site.get("address").unwrap_or(&Value::Null));
        let function_start = site
            .get("function_start")
            .filter(|value| !value.is_null())
            .map(format_address_value)
            .unwrap_or_else(|| "?".to_string());
        let instruction = site
            .get("instruction")
            .map(render_instruction)
            .unwrap_or_default();
        format!("{address}  fn {function_start}  {instruction}")
    }));
    lines.join("\n")
}

fn render_analyze_send_call_sites(value: &Value) -> String {
    let target = format_address_value(value.get("target").unwrap_or(&Value::Null));
    let sites = value
        .get("call_sites")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if sites.is_empty() {
        return format!("analyze_send_call_sites {target}: (no callers)");
    }
    let mut lines = vec![format!(
        "analyze_send_call_sites {target}: {} caller(s)",
        sites.len()
    )];
    for site in sites {
        let call_site = site.get("call_site").unwrap_or(&Value::Null);
        let address = format_address_value(call_site.get("address").unwrap_or(&Value::Null));
        let function_start = call_site
            .get("function_start")
            .filter(|value| !value.is_null())
            .map(format_address_value)
            .unwrap_or_else(|| "?".to_string());
        lines.push(format!("{address}  fn {function_start}"));
        if let Some(pushes) = site.get("pushes").and_then(Value::as_array) {
            for push in pushes {
                let instruction = push.get("instruction").unwrap_or(&Value::Null);
                let push_address =
                    format_address_value(instruction.get("address").unwrap_or(&Value::Null));
                let width = push.get("width_bits").and_then(Value::as_u64).unwrap_or(0);
                let value = push.get("value").and_then(Value::as_u64).unwrap_or(0);
                let mut line = format!("  push{width} 0x{value:x} @ {push_address}");
                if let Some(string) = push.get("string").and_then(Value::as_str) {
                    line.push_str(&format!("  \"{string}\""));
                }
                if let Some(packet) = push.get("packet_name").and_then(Value::as_str) {
                    line.push_str(&format!("  packet_name={packet}"));
                }
                lines.push(line);
            }
        }
        if let Some(previous) = site
            .get("preceding_instructions")
            .and_then(Value::as_array)
            .and_then(|items| items.last())
        {
            lines.push(format!("  prev: {}", render_instruction(previous)));
        }
    }
    lines.join("\n")
}

fn render_extract_dispatch_tables(value: &Value) -> String {
    let dispatcher = format_address_value(value.get("dispatcher").unwrap_or(&Value::Null));
    let index_table = value
        .get("index_table")
        .filter(|value| !value.is_null())
        .map(format_address_value)
        .unwrap_or_else(|| "?".to_string());
    let jump_table = value
        .get("jump_table")
        .filter(|value| !value.is_null())
        .map(format_address_value)
        .unwrap_or_else(|| "?".to_string());
    let mut lines = vec![
        format!("extract_dispatch_tables {dispatcher}"),
        format!("index_table: {index_table}"),
        format!("jump_table: {jump_table}"),
    ];
    if let Some(candidates) = value.get("candidates").and_then(Value::as_array) {
        if !candidates.is_empty() {
            lines.push("candidates:".to_string());
            for candidate in candidates.iter().take(8) {
                let address =
                    format_address_value(candidate.get("address").unwrap_or(&Value::Null));
                let kind = candidate.get("kind").and_then(Value::as_str).unwrap_or("?");
                let score = candidate.get("score").and_then(Value::as_u64).unwrap_or(0);
                lines.push(format!("  {kind} {address} score={score}"));
            }
        }
    }
    let entries = value
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if entries.is_empty() {
        lines.push("(no opcode entries)".to_string());
        return lines.join("\n");
    }
    lines.push(format!("entries: {}", entries.len()));
    for entry in entries {
        let opcode = entry.get("opcode").and_then(Value::as_u64).unwrap_or(0);
        let value_location =
            format_address_value(entry.get("opcode_value_location").unwrap_or(&Value::Null));
        let dispatch_index = entry
            .get("dispatch_index")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let stub = entry
            .get("stub")
            .filter(|value| !value.is_null())
            .map(format_address_value)
            .unwrap_or_else(|| "?".to_string());
        let handler = entry
            .get("handler")
            .filter(|value| !value.is_null())
            .map(format_address_value)
            .unwrap_or_else(|| "?".to_string());
        lines.push(format!(
            "  opcode 0x{opcode:02x} @ {value_location} -> index {dispatch_index} -> stub {stub} -> handler {handler}"
        ));
    }
    lines.join("\n")
}

fn render_trace_call_chain(value: &Value) -> String {
    let target = format_address_value(value.get("target").unwrap_or(&Value::Null));
    let nodes = value
        .get("chain")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if nodes.is_empty() {
        return format!("trace_call_chain {target}: (no callers)");
    }
    let mut lines = vec![format!("trace_call_chain {target}")];
    for node in nodes {
        let depth = node.get("depth").and_then(Value::as_u64).unwrap_or(0);
        let node_target = format_address_value(node.get("target").unwrap_or(&Value::Null));
        lines.push(format!("depth {depth}: target {node_target}"));
        if let Some(callers) = node.get("callers").and_then(Value::as_array) {
            for caller in callers {
                let address = format_address_value(caller.get("address").unwrap_or(&Value::Null));
                let function_start = caller
                    .get("function_start")
                    .filter(|value| !value.is_null())
                    .map(format_address_value)
                    .unwrap_or_else(|| "?".to_string());
                lines.push(format!("  {address}  fn {function_start}"));
            }
        }
    }
    lines.join("\n")
}

fn render_locate(value: &Value) -> String {
    let query = value.get("query").and_then(Value::as_str).unwrap_or("");
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if results.is_empty() {
        return format!("locate \"{query}\": (no hits)");
    }
    let mut lines = vec![format!("locate \"{query}\": {} hit(s)", results.len())];
    lines.extend(results.iter().map(|result| {
        let string_address =
            format_address_value(result.get("string_address").unwrap_or(&Value::Null));
        let ref_site = format_address_value(result.get("ref_site").unwrap_or(&Value::Null));
        let function_start = result
            .get("function_start")
            .filter(|value| !value.is_null())
            .map(format_address_value)
            .unwrap_or_else(|| "?".to_string());
        format!("{string_address} -> ref {ref_site} -> fn {function_start}")
    }));
    lines.join("\n")
}

fn render_find_vtable(value: &Value) -> String {
    let Some(evidence) = value.get("evidence") else {
        return "(no vtable evidence)".to_string();
    };
    if let Some(error) = evidence.get("error").and_then(Value::as_str) {
        return error.to_string();
    }
    let class_name = evidence
        .get("class_name")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let mut lines = vec![format!("class {class_name}")];
    for (label, key) in [
        ("vtable", "vtable"),
        ("type_descriptor", "type_descriptor"),
        ("col", "col"),
    ] {
        lines.push(format!(
            "  {label:15} {}",
            format_address_value(evidence.get(key).unwrap_or(&Value::Null))
        ));
    }
    lines.push("  methods:".to_string());
    if let Some(methods) = evidence.get("methods").and_then(Value::as_array) {
        for method in methods {
            let index = method.get("index").and_then(Value::as_u64).unwrap_or(0);
            let address = format_address_value(method.get("address").unwrap_or(&Value::Null));
            let instruction = method
                .get("instruction")
                .map(render_instruction)
                .unwrap_or_default();
            lines.push(format!("    [{index}] {address}  {instruction}"));
        }
    }
    lines.join("\n")
}

fn render_diff_struct(value: &Value) -> String {
    let struct_name = value
        .get("struct_name")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let live_address = format_address_value(value.get("live_address").unwrap_or(&Value::Null));
    let fields = value
        .get("fields")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut lines = vec![format!(
        "struct {struct_name} @ {live_address}  fields={} ptr_fields={}",
        value
            .get("field_count")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        value
            .get("ptr_field_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    )];
    for field in fields {
        let offset = field.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let name = field.get("name").and_then(Value::as_str).unwrap_or("?");
        let type_name = field.get("type").and_then(Value::as_str).unwrap_or("?");
        let raw = field.get("raw_hex").and_then(Value::as_str).unwrap_or("");
        let mut line = format!("+0x{offset:x}  {name}  {type_name}  = {raw}");
        if let Some(target) = field
            .get("pointer_target")
            .and_then(|target| target.get("address"))
        {
            line.push_str(&format!(" -> {}", format_address_value(target)));
        }
        lines.push(line);
    }
    lines.join("\n")
}

fn render_instruction(instruction: &Value) -> String {
    let address = format_address_value(instruction.get("address").unwrap_or(&Value::Null));
    let bytes = bytes_hex(instruction.get("bytes").unwrap_or(&Value::Null));
    let text = instruction
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut line = format!("{address}: {bytes:20} {text}");
    if let Some(target) = instruction
        .get("call_target")
        .filter(|value| !value.is_null())
        .map(format_address_value)
    {
        line.push_str(&format!(" -> {target}"));
    }
    if let Some(string) = instruction.get("string").and_then(Value::as_str) {
        line.push_str(&format!(" ; \"{string}\""));
    }
    line
}

fn hit_address(hit: &Value) -> Option<String> {
    hit.get("address").map(format_address_value)
}

fn hit_rva_suffix(hit: &Value) -> String {
    hit.pointer("/address_context/module/rva")
        .map(|rva| format!(" (RVA {})", format_address_value(rva)))
        .unwrap_or_default()
}

fn hit_region_module_tag(hit: &Value) -> String {
    let tag = region_tag(hit);
    hit.pointer("/address_context/module/name")
        .and_then(Value::as_str)
        .map(|name| format!("{tag}:{name}"))
        .unwrap_or_else(|| tag.to_string())
}

fn region_tag(hit: &Value) -> &'static str {
    let executable = hit
        .pointer("/address_context/region/flags/executable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if executable {
        return "exec";
    }
    if hit.pointer("/address_context/module").is_some()
        && !hit
            .pointer("/address_context/module")
            .unwrap_or(&Value::Null)
            .is_null()
    {
        "mod"
    } else {
        "heap"
    }
}

fn truncate_preview(value: &str) -> String {
    if value.chars().count() <= PREVIEW_DISPLAY_LIMIT {
        return value.to_string();
    }
    let mut output = value
        .chars()
        .take(PREVIEW_DISPLAY_LIMIT.saturating_sub(3))
        .collect::<String>();
    output.push_str("...");
    output
}

fn push_omitted_hint(lines: &mut Vec<String>, returned: usize, total: usize) {
    if returned > TEXT_HIT_DISPLAY_LIMIT {
        lines.push(format!(
            "... {} returned hit(s) omitted from text; raise max_results or use full/out_path for bulk output",
            returned - TEXT_HIT_DISPLAY_LIMIT
        ));
    }
    if total > returned {
        lines.push(format!(
            "... {} additional hit(s) not returned; use full=true with out_path for the complete set",
            total - returned
        ));
    }
}

fn format_address_value(value: &Value) -> String {
    if let Some(number) = value.as_u64() {
        return format!("0x{number:x}");
    }
    if let Some(object) = value.as_object() {
        if let Some(number) = object.values().find_map(Value::as_u64) {
            return format!("0x{number:x}");
        }
    }
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| "?".to_string())
}

fn bytes_hex(value: &Value) -> String {
    let Some(bytes) = value.as_array() else {
        return String::new();
    };
    bytes
        .iter()
        .filter_map(Value::as_u64)
        .map(|byte| format!("{:02x}", byte & 0xff))
        .collect::<Vec<_>>()
        .join(" ")
}

fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

fn tool_mem_read(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let address = required_address(&arguments, "address")?;
    let size = required_usize(&arguments, "size")?;

    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let target_arch = process.target_arch();
    let backend = process
        .snapshot_window(address, 16, size.saturating_add(16))
        .map_err(|err| format!("{err:?}"))?;
    let engine = ArgusEngine::new_for_target(backend, target_arch);
    let hit = engine
        .mem_read(address, size)
        .ok_or_else(|| format!("address not readable: 0x{:x}", address.0))?;

    Ok(json!({
        "tool": "mem_read",
        "hit": hit,
    }))
}

fn tool_mem_write(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let address = required_address(&arguments, "address")?;
    let hex_data = required_str(&arguments, "hex_data")?;
    let bytes = parse_hex_bytes(hex_data)?;
    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let bytes_written = process
        .write(address, &bytes)
        .map_err(|err| format!("{err:?}"))?;

    Ok(json!({
        "tool": "mem_write",
        "address": address,
        "bytes": bytes,
        "bytes_written": bytes_written,
    }))
}

fn tool_mem_read_chain(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let base_address = required_address_alias(&arguments, "base_address", "address")?;
    let offsets = parse_offsets(optional_str(&arguments, "offsets").unwrap_or(""))?;
    let final_size = optional_usize(&arguments, "final_size", 64);
    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let mut chain = vec![base_address];
    let mut steps = Vec::new();
    let mut current = read_pointer(&process, base_address)?;
    chain.push(current);
    steps.push(json!({
        "index": 0,
        "read_address": base_address,
        "pointer": current,
        "offset": 0,
        "next_address": current,
    }));

    for (index, offset) in offsets.iter().copied().enumerate() {
        let next = Address(current.0.saturating_add(offset));
        chain.push(next);
        let mut step = json!({
            "index": index + 1,
            "read_address": current,
            "pointer": current,
            "offset": offset,
            "next_address": next,
        });
        current = next;
        if index + 1 < offsets.len() {
            let deref = read_pointer(&process, current)?;
            chain.push(deref);
            step["deref"] = json!(deref);
            current = deref;
        }
        steps.push(step);
    }

    let data = process
        .read(current, final_size)
        .map_err(|err| format!("{err:?}"))?;

    Ok(json!({
        "tool": "mem_read_chain",
        "base_address": base_address,
        "offsets": offsets,
        "pointer_width": pointer_width_bytes(),
        "chain": chain,
        "steps": steps,
        "final_address": current,
        "final_bytes": data,
        "ascii_preview": ascii_preview(&data),
    }))
}

fn tool_read_struct(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let address = required_address(&arguments, "address")?;
    let count = optional_usize(&arguments, "count", 16);
    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let data = process
        .read(address, count.saturating_mul(4))
        .map_err(|err| format!("{err:?}"))?;
    let mut words = Vec::new();

    for index in 0..count {
        let offset = index * 4;
        if offset + 4 > data.len() {
            break;
        }
        let value = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let value_address = Address(value as u64);
        let pointer_region = process.query_region(value_address).ok();
        words.push(json!({
            "index": index,
            "address": Address(address.0 + offset as u64),
            "value_u32": value,
            "value_hex": format!("0x{value:08x}"),
            "pointer_target": pointer_region.map(|region| json!({
                "address": value_address,
                "region": region,
            })),
        }));
    }

    Ok(json!({
        "tool": "read_struct",
        "address": address,
        "word_count": words.len(),
        "words": words,
    }))
}

fn tool_correlate_addr(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let live_addr = optional_address(&arguments, "live_addr")?;
    let static_addr = optional_address(&arguments, "static_addr")?;
    let ghidra_image_base =
        optional_address(&arguments, "ghidra_image_base")?.unwrap_or(Address(0x0040_0000));
    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let modules = process.modules().map_err(|err| format!("{err:?}"))?;
    let main_module = modules
        .first()
        .ok_or_else(|| "target has no visible modules".to_string())?;

    let (live, static_address, rva) = if let Some(live) = live_addr {
        let rva = live.0.saturating_sub(main_module.base.0);
        (live, Address(ghidra_image_base.0 + rva), rva)
    } else if let Some(static_address) = static_addr {
        let rva = static_address.0.saturating_sub(ghidra_image_base.0);
        (Address(main_module.base.0 + rva), static_address, rva)
    } else {
        return Err("correlate_addr requires live_addr or static_addr".to_string());
    };

    Ok(json!({
        "tool": "correlate_addr",
        "module": main_module,
        "ghidra_image_base": ghidra_image_base,
        "rva": rva,
        "live_addr": live,
        "static_addr": static_address,
    }))
}

fn tool_locate(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let query = required_str(&arguments, "query")?;
    let max_hits = optional_usize(&arguments, "max_hits", 8);
    let engine = engine_for_pid(pid)?;
    let results = engine.locate(query, max_hits);

    Ok(json!({
        "tool": "locate",
        "query": query,
        "count": results.len(),
        "results": results,
    }))
}

fn tool_find_vtable(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let class_name = required_str(&arguments, "class_name")?;
    let max_methods = optional_usize(&arguments, "max_methods", 20);
    let engine = engine_for_pid(pid)?;
    let evidence = engine.find_vtable(class_name, max_methods);

    Ok(json!({
        "tool": "find_vtable",
        "evidence": evidence,
    }))
}

fn tool_diff_struct(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let struct_name = required_str(&arguments, "struct_name")?;
    let live_address = required_address_alias(&arguments, "live_address", "address")?;
    let max_fields = optional_usize(&arguments, "max_fields", 64);
    let fields = load_static_struct_fields(&arguments, struct_name, max_fields)?;
    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let mut rows = Vec::new();
    let mut ptr_field_count = 0usize;

    for field in fields {
        let field_address = Address(live_address.0.saturating_add(field.offset));
        let read_len = field.length.max(1).min(16);
        let row = match process.read(field_address, read_len) {
            Ok(raw) => {
                let mut pointer_value = None;
                let mut pointer_target = None;
                if field.length == 4 && raw.len() == 4 {
                    let value = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
                    let value_address = Address(value as u64);
                    pointer_value = Some(value_address);
                    if let Ok(region) = process.query_region(value_address) {
                        ptr_field_count += 1;
                        pointer_target = Some(json!({
                            "address": value_address,
                            "region": region,
                        }));
                    }
                }
                json!({
                    "offset": field.offset,
                    "address": field_address,
                    "name": field.name,
                    "type": field.type_name,
                    "length": field.length,
                    "raw_hex": hex_bytes(&raw),
                    "bytes": raw,
                    "pointer_value": pointer_value,
                    "pointer_target": pointer_target,
                })
            }
            Err(err) => json!({
                "offset": field.offset,
                "address": field_address,
                "name": field.name,
                "type": field.type_name,
                "length": field.length,
                "error": format!("{err:?}"),
            }),
        };
        rows.push(row);
    }

    Ok(json!({
        "tool": "diff_struct",
        "struct_name": struct_name,
        "live_address": live_address,
        "field_count": rows.len(),
        "ptr_field_count": ptr_field_count,
        "fields": rows,
    }))
}

fn tool_record_hypothesis(arguments: Value) -> Result<Value, String> {
    let entity = required_str(&arguments, "entity")?.to_string();
    let claim_type = required_str(&arguments, "claim_type")?.to_string();
    let claim_value = required_str(&arguments, "claim_value")?.to_string();
    let source = optional_str(&arguments, "source")
        .unwrap_or("llm")
        .to_string();
    let confidence = arguments.get("confidence").and_then(Value::as_f64);
    let path = ledger_path(&arguments);
    let mut ledger = load_ledger(&path)?;
    let id = ledger.next_hypothesis_id();
    let now = now_unix();

    ledger.hypotheses.push(HypothesisRecord {
        id,
        entity: entity.clone(),
        claim_type,
        claim_value,
        source,
        confidence,
        status: "unverified".to_string(),
        created_at: now,
        updated_at: now,
        evidence: Vec::new(),
    });
    save_ledger(&path, &ledger)?;

    Ok(json!({
        "tool": "record_hypothesis",
        "id": id,
        "entity": entity,
        "status": "unverified",
        "ledger_path": path,
    }))
}

fn tool_add_evidence(arguments: Value) -> Result<Value, String> {
    let hypothesis_id = required_u64(&arguments, "hypothesis_id")?;
    let kind = required_str(&arguments, "kind")?.to_string();
    let detail = required_str(&arguments, "detail")?.to_string();
    let source = required_str(&arguments, "source")?.to_string();
    let addr = optional_str(&arguments, "addr").map(str::to_string);
    let path = ledger_path(&arguments);
    let mut ledger = load_ledger(&path)?;
    let evidence_id = ledger.next_evidence_id();
    let now = now_unix();
    let hypothesis = ledger
        .hypotheses
        .iter_mut()
        .find(|hypothesis| hypothesis.id == hypothesis_id)
        .ok_or_else(|| format!("no hypothesis {hypothesis_id}"))?;
    hypothesis.updated_at = now;
    hypothesis.evidence.push(HypothesisEvidence {
        id: evidence_id,
        kind,
        detail,
        source,
        addr,
        created_at: now,
    });
    let status = hypothesis.status.clone();
    save_ledger(&path, &ledger)?;

    Ok(json!({
        "tool": "add_evidence",
        "ok": true,
        "hypothesis_id": hypothesis_id,
        "status": status,
        "ledger_path": path,
    }))
}

fn tool_verify_hypothesis(arguments: Value) -> Result<Value, String> {
    let hypothesis_id = required_u64(&arguments, "hypothesis_id")?;
    let verdict = required_str(&arguments, "verdict")?;
    if verdict != "verified" && verdict != "contradicted" {
        return Err("verdict must be 'verified' or 'contradicted'".to_string());
    }
    let note = optional_str(&arguments, "note").map(str::to_string);
    let path = ledger_path(&arguments);
    let mut ledger = load_ledger(&path)?;
    let now = now_unix();
    let mut negative = None;
    {
        let hypothesis = ledger
            .hypotheses
            .iter_mut()
            .find(|hypothesis| hypothesis.id == hypothesis_id)
            .ok_or_else(|| format!("no hypothesis {hypothesis_id}"))?;
        hypothesis.status = verdict.to_string();
        hypothesis.updated_at = now;
        if verdict == "contradicted" {
            negative = Some((
                hypothesis.entity.clone(),
                format!("{}={}", hypothesis.claim_type, hypothesis.claim_value),
            ));
        }
    }
    if let Some((entity, refuted_claim)) = negative {
        let id = ledger.next_negative_id();
        ledger.negative_knowledge.push(NegativeKnowledge {
            id,
            entity,
            refuted_claim,
            reason: note,
            created_at: now,
        });
    }
    save_ledger(&path, &ledger)?;

    Ok(json!({
        "tool": "verify_hypothesis",
        "id": hypothesis_id,
        "status": verdict,
        "ledger_path": path,
    }))
}

fn tool_query_hypotheses(arguments: Value) -> Result<Value, String> {
    let entity = optional_str(&arguments, "entity").map(str::to_string);
    let status = optional_str(&arguments, "status").map(str::to_string);
    let claim_type = optional_str(&arguments, "claim_type").map(str::to_string);
    let limit = optional_usize(&arguments, "limit", 50);
    let path = ledger_path(&arguments);
    let ledger = load_ledger(&path)?;
    let hypotheses: Vec<_> = ledger
        .hypotheses
        .iter()
        .rev()
        .filter(|hypothesis| {
            entity
                .as_ref()
                .map(|value| hypothesis.entity == *value)
                .unwrap_or(true)
                && status
                    .as_ref()
                    .map(|value| hypothesis.status == *value)
                    .unwrap_or(true)
                && claim_type
                    .as_ref()
                    .map(|value| hypothesis.claim_type == *value)
                    .unwrap_or(true)
        })
        .take(limit)
        .cloned()
        .collect();
    let negative_knowledge: Vec<_> = entity
        .as_ref()
        .map(|entity| {
            ledger
                .negative_knowledge
                .iter()
                .filter(|row| row.entity == *entity)
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    Ok(json!({
        "tool": "query_hypotheses",
        "count": hypotheses.len(),
        "hypotheses": hypotheses,
        "negative_knowledge": negative_knowledge,
        "ledger_path": path,
    }))
}

fn tool_real_rate(arguments: Value) -> Result<Value, String> {
    let path = ledger_path(&arguments);
    let ledger = load_ledger(&path)?;
    let mut by_status = BTreeMap::new();
    let mut by_source = BTreeMap::new();
    let mut by_claim_type = BTreeMap::new();
    for hypothesis in &ledger.hypotheses {
        *by_status.entry(hypothesis.status.clone()).or_insert(0usize) += 1;
        *by_source.entry(hypothesis.source.clone()).or_insert(0usize) += 1;
        *by_claim_type
            .entry(hypothesis.claim_type.clone())
            .or_insert(0usize) += 1;
    }
    let verified = *by_status.get("verified").unwrap_or(&0);
    let total = ledger.hypotheses.len();
    let rate = if total == 0 {
        0.0
    } else {
        ((verified as f64 / total as f64) * 10_000.0).round() / 10_000.0
    };

    Ok(json!({
        "tool": "real_rate",
        "verified": verified,
        "total": total,
        "rate": rate,
        "by_status": by_status,
        "by_source": by_source,
        "by_claim_type": by_claim_type,
        "ledger_path": path,
    }))
}

fn tool_mem_attach(arguments: Value) -> Result<Value, String> {
    let process_arg =
        optional_str(&arguments, "process").or_else(|| optional_str(&arguments, "name"));
    let pid = if let Some(value) = arguments.get("pid").and_then(Value::as_u64) {
        u32::try_from(value).map_err(|_| "argument out of u32 range: pid".to_string())?
    } else {
        let process_arg = process_arg.ok_or_else(|| {
            "missing target: pass `pid`, or `process` with the target image name or a substring"
                .to_string()
        })?;
        let needle = process_arg.to_ascii_lowercase();
        processes()
            .map_err(|err| format!("{err:?}"))?
            .into_iter()
            .find(|process| process.name.eq_ignore_ascii_case(process_arg))
            .or_else(|| {
                processes().ok().and_then(|rows| {
                    rows.into_iter()
                        .find(|process| process.name.to_ascii_lowercase().contains(&needle))
                })
            })
            .map(|process| process.pid)
            .ok_or_else(|| format!("process not found: {process_arg}"))?
    };
    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let target_arch = process.target_arch();
    let modules = process.modules().map_err(|err| format!("{err:?}"))?;
    let main_module = modules.first();

    Ok(json!({
        "tool": "mem_attach",
        "argus": target_argus_context(target_arch),
        "stateless": true,
        "pid": pid,
        "process": process_arg,
        "base": main_module.map(|module| module.base),
        "module_size": main_module.map(|module| module.size),
        "modules": modules,
        "note": "Rust Argus MCP is stateless; pass this pid to memory tools.",
    }))
}

fn tool_mem_modules(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let max_results = optional_usize(&arguments, "max_results", MODULE_DISPLAY_LIMIT);
    let full = optional_bool(&arguments, "full", false);
    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let target_arch = process.target_arch();
    let modules = process.modules().map_err(|err| format!("{err:?}"))?;

    Ok(json!({
        "tool": "mem_modules",
        "argus": target_argus_context(target_arch),
        "modules": modules,
        "module_count": modules.len(),
        "max_results": max_results,
        "full": full,
    }))
}

fn tool_memory_regions(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let limit = optional_usize(&arguments, "limit", 512);
    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let target_arch = process.target_arch();
    let all_regions = process
        .committed_regions()
        .map_err(|err| format!("{err:?}"))?;
    let returned: Vec<_> = all_regions.iter().take(limit).cloned().collect();

    Ok(json!({
        "tool": "memory_regions",
        "argus": target_argus_context(target_arch),
        "regions": returned,
        "region_count": returned.len(),
        "total_committed_region_count": all_regions.len(),
        "limit": limit,
    }))
}

fn tool_processes_list(arguments: Value) -> Result<Value, String> {
    let limit = optional_usize(&arguments, "limit", 200);
    let all_processes = processes().map_err(|err| format!("{err:?}"))?;
    let returned: Vec<_> = all_processes.into_iter().take(limit).collect();

    Ok(json!({
        "tool": "processes_list",
        "processes": returned,
        "process_count": returned.len(),
        "limit": limit,
    }))
}

fn tool_processes_find(arguments: Value) -> Result<Value, String> {
    let name_contains = arguments
        .get("name_contains")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let exact_name = arguments
        .get("exact_name")
        .and_then(Value::as_str)
        .map(|name| name.to_ascii_lowercase());
    let pid = arguments
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok());
    let limit = optional_usize(&arguments, "limit", 50);

    if name_contains.is_empty() && exact_name.is_none() && pid.is_none() {
        return Err("processes_find requires name_contains, exact_name, or pid".to_string());
    }

    let mut matches = Vec::new();
    for process in processes().map_err(|err| format!("{err:?}"))? {
        let process_name = process.name.to_ascii_lowercase();
        let pid_matches = pid.map(|pid| process.pid == pid).unwrap_or(false);
        let exact_matches = exact_name
            .as_ref()
            .map(|name| process_name == *name)
            .unwrap_or(false);
        let contains_matches = !name_contains.is_empty() && process_name.contains(&name_contains);

        if pid_matches || exact_matches || contains_matches {
            matches.push(process);
            if matches.len() >= limit {
                break;
            }
        }
    }

    Ok(json!({
        "tool": "processes_find",
        "matches": matches,
        "match_count": matches.len(),
        "limit": limit,
    }))
}

fn tool_runtime_imports(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let module_name = optional_str(&arguments, "module_name");
    let name_contains = optional_str(&arguments, "name_contains").map(str::to_ascii_lowercase);
    let dll_contains = optional_str(&arguments, "dll_contains").map(str::to_ascii_lowercase);
    let max_results = optional_usize(&arguments, "max_results", 200);
    let engine = engine_for_pid(pid)?;
    let mut imports = Vec::new();

    for import in
        engine.runtime_imports(module_name, max_results.saturating_mul(4).max(max_results))
    {
        if let Some(needle) = &name_contains {
            if !import.name.to_ascii_lowercase().contains(needle) {
                continue;
            }
        }
        if let Some(needle) = &dll_contains {
            if !import.dll.to_ascii_lowercase().contains(needle) {
                continue;
            }
        }
        imports.push(import);
        if imports.len() >= max_results {
            break;
        }
    }

    Ok(json!({
        "tool": "runtime_imports",
        "imports": imports,
        "import_count": imports.len(),
    }))
}

fn tool_runtime_exports(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let module_name = optional_str(&arguments, "module_name");
    let name_contains = optional_str(&arguments, "name_contains");
    let max_results = optional_usize(&arguments, "max_results", 200);
    let engine = engine_for_pid(pid)?;
    let exports = engine.runtime_exports(module_name, name_contains, max_results);
    let export_count = exports.len();

    Ok(json!({
        "tool": "runtime_exports",
        "exports": exports,
        "export_count": export_count,
    }))
}

fn tool_resolve_api_targets(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let max_results = optional_usize(&arguments, "max_results", 50);
    let api = optional_str(&arguments, "api");
    let explicit_module = optional_str(&arguments, "module_name");
    let explicit_name =
        optional_str(&arguments, "name").or_else(|| optional_str(&arguments, "name_contains"));
    let (api_module, api_name) = match api.and_then(|value| value.split_once('!')) {
        Some((module, name)) => (Some(module.to_string()), Some(name.to_string())),
        None => (None, api.map(str::to_string)),
    };
    let module_name = explicit_module.map(str::to_string).or(api_module);
    let name_contains = explicit_name
        .map(str::to_string)
        .or(api_name)
        .ok_or_else(|| "resolve_api_targets requires api, name, or name_contains".to_string())?;
    let engine = engine_for_pid(pid)?;
    let targets = engine.runtime_exports(
        module_name.as_deref(),
        Some(name_contains.as_str()),
        max_results,
    );
    let target_count = targets.len();

    Ok(json!({
        "tool": "resolve_api_targets",
        "query": {
            "module_name": module_name,
            "name_contains": name_contains,
        },
        "targets": targets,
        "target_count": target_count,
    }))
}

fn tool_resolve_iat_thunks(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let module_name = optional_str(&arguments, "module_name");
    let name_contains = optional_str(&arguments, "name_contains");
    let max_results = optional_usize(&arguments, "max_results", 100);
    let engine = engine_for_pid(pid)?;
    let thunks = engine.resolve_iat_thunks(module_name, name_contains, max_results);

    Ok(json!({
        "tool": "resolve_iat_thunks",
        "thunks": thunks,
        "thunk_count": thunks.len(),
    }))
}

fn tool_disasm_at(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let address = required_address(&arguments, "address")?;
    let count = optional_usize(&arguments, "count", 40);
    let window_size = optional_usize(&arguments, "window_size", count.saturating_mul(15).max(64));
    let engine = engine_for_window(pid, address, 0, window_size)?;
    let instructions = engine.disasm_at(address, count);
    let instruction_count = instructions.len();

    Ok(json!({
        "tool": "disasm_at",
        "snapshot_source": "window",
        "address": address,
        "window_size": window_size,
        "instructions": instructions,
        "instruction_count": instruction_count,
    }))
}

fn tool_analyze_function(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let address = required_address(&arguments, "address")?;
    let max_insn = optional_usize(&arguments, "max_insn", 200);
    let window_size = optional_usize(
        &arguments,
        "window_size",
        max_insn.saturating_mul(15).max(256),
    );
    let engine = engine_for_window(pid, address, 0, window_size)?;
    let function = engine.analyze_function(address, max_insn);

    Ok(json!({
        "tool": "analyze_function",
        "snapshot_source": "window",
        "address": address,
        "window_size": window_size,
        "function": function,
    }))
}

fn tool_scan_x86_call_sites(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let target = required_address_alias(&arguments, "target", "address")?;
    let max_results = optional_usize(&arguments, "max_results", 50);
    let engine = engine_for_scope(pid, SnapshotScope::Executable)?;
    let call_sites = engine.scan_x86_call_sites(target, max_results);

    Ok(json!({
        "tool": "scan_x86_call_sites",
        "snapshot_scope": SnapshotScope::Executable.label(),
        "target": target,
        "call_sites": call_sites,
        "call_site_count": call_sites.len(),
    }))
}

fn tool_analyze_send_call_sites(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let target = required_address_alias(&arguments, "target", "address")?;
    let max_results = optional_usize(&arguments, "max_results", 50);
    let max_preceding_instructions = optional_usize(&arguments, "max_preceding_instructions", 12);
    let backward_bytes = optional_usize(&arguments, "backward_bytes", 0x80);
    let engine = engine_for_scope(pid, SnapshotScope::Executable)?;
    let call_sites = engine.analyze_send_call_sites(
        target,
        max_results,
        max_preceding_instructions,
        backward_bytes,
    );

    Ok(json!({
        "tool": "analyze_send_call_sites",
        "snapshot_scope": SnapshotScope::Executable.label(),
        "target": target,
        "call_sites": call_sites,
        "call_site_count": call_sites.len(),
        "max_preceding_instructions": max_preceding_instructions,
        "backward_bytes": backward_bytes,
    }))
}

fn tool_extract_dispatch_tables(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let dispatcher = required_address_alias(&arguments, "dispatcher", "address")?;
    let max_insn = optional_usize(&arguments, "max_insn", 80);
    let max_entries = optional_usize(&arguments, "max_entries", 256);
    let index_table = optional_address(&arguments, "index_table")?;
    let jump_table = optional_address(&arguments, "jump_table")?;
    let engine = engine_for_scope(pid, SnapshotScope::All)?;
    let evidence =
        engine.extract_dispatch_tables(dispatcher, max_insn, max_entries, index_table, jump_table);

    Ok(json!({
        "tool": "extract_dispatch_tables",
        "dispatcher": evidence.dispatcher,
        "index_table": evidence.index_table,
        "jump_table": evidence.jump_table,
        "candidates": evidence.candidates,
        "entries": evidence.entries,
        "entry_count": evidence.entries.len(),
        "max_insn": max_insn,
        "max_entries": max_entries,
    }))
}

fn tool_trace_call_chain(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let target = required_address_alias(&arguments, "target", "address")?;
    let max_depth = optional_usize(&arguments, "max_depth", 3);
    let max_callers_per_depth = optional_usize(&arguments, "max_callers_per_depth", 20);
    let engine = engine_for_scope(pid, SnapshotScope::Executable)?;
    let chain = engine.trace_call_chain(target, max_depth, max_callers_per_depth);

    Ok(json!({
        "tool": "trace_call_chain",
        "snapshot_scope": SnapshotScope::Executable.label(),
        "target": target,
        "chain": chain,
        "depth_count": chain.len(),
    }))
}

fn tool_scan_string(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let pattern = required_str(&arguments, "pattern")?;
    let max_results = optional_usize(&arguments, "max_results", 20);
    let address = optional_address(&arguments, "address")?;
    let region = optional_snapshot_scope(&arguments, "region", SnapshotScope::All)?;
    let size = optional_usize(&arguments, "size", pattern.len().max(4096));
    let encoding = optional_text_encoding(&arguments, TextEncoding::Utf8)?;
    let case_sensitive = optional_bool(&arguments, "case_sensitive", true);
    let full = optional_bool(&arguments, "full", false);
    let out_path = optional_str(&arguments, "out_path").map(PathBuf::from);
    let out_format = optional_scan_output_format(&arguments, out_path.as_deref())?;
    let scan_scope = if address.is_some() {
        "window"
    } else {
        region.label()
    };
    let result = scan_text(TextScanOptions {
        pid,
        pattern,
        regex: false,
        encoding,
        case_sensitive,
        region,
        address,
        size,
        max_results,
        full,
        out_path,
        out_format,
    })?;

    Ok(json!({
        "tool": "scan_string",
        "scan_scope": scan_scope,
        "encoding": encoding.label(),
        "case_sensitive": case_sensitive,
        "full": full,
        "address": address,
        "size": size,
        "pattern": pattern,
        "hits": result.hits,
        "hit_count": result.hits.len(),
        "total_hit_count": result.total_hit_count,
        "out_path": result.out_path.map(|path| path.to_string_lossy().to_string()),
        "out_format": result.out_format.map(|format| format.label()),
        "scanned_region_count": result.scanned_region_count,
        "scanned_bytes": result.scanned_bytes,
    }))
}

fn tool_scan_regex(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let pattern = required_str(&arguments, "pattern")?;
    let max_results = optional_usize(&arguments, "max_results", 50);
    let address = optional_address(&arguments, "address")?;
    let region = optional_snapshot_scope(&arguments, "region", SnapshotScope::All)?;
    let size = optional_usize(&arguments, "size", 4096);
    let encoding = optional_text_encoding(&arguments, TextEncoding::Both)?;
    let case_sensitive = optional_bool(&arguments, "case_sensitive", true);
    let full = optional_bool(&arguments, "full", false);
    let out_path = optional_str(&arguments, "out_path").map(PathBuf::from);
    let out_format = optional_scan_output_format(&arguments, out_path.as_deref())?;
    let scan_scope = if address.is_some() {
        "window"
    } else {
        region.label()
    };
    let result = scan_text(TextScanOptions {
        pid,
        pattern,
        regex: true,
        encoding,
        case_sensitive,
        region,
        address,
        size,
        max_results,
        full,
        out_path,
        out_format,
    })?;

    Ok(json!({
        "tool": "scan_regex",
        "scan_scope": scan_scope,
        "encoding": encoding.label(),
        "case_sensitive": case_sensitive,
        "full": full,
        "address": address,
        "size": size,
        "pattern": pattern,
        "hits": result.hits,
        "hit_count": result.hits.len(),
        "total_hit_count": result.total_hit_count,
        "out_path": result.out_path.map(|path| path.to_string_lossy().to_string()),
        "out_format": result.out_format.map(|format| format.label()),
        "scanned_region_count": result.scanned_region_count,
        "scanned_bytes": result.scanned_bytes,
    }))
}

fn tool_scan_bytes(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let pattern = required_str(&arguments, "pattern")?;
    let max_results = optional_usize(&arguments, "max_results", 20);
    let address = optional_address(&arguments, "address")?;
    let region = optional_snapshot_scope(&arguments, "region", SnapshotScope::Executable)?;
    let size = optional_usize(&arguments, "size", 4096);

    let (engine, scan_scope) = if let Some(address) = address {
        (engine_for_window(pid, address, 0, size)?, "window")
    } else {
        (engine_for_scope(pid, region)?, region.label())
    };
    let hits = engine
        .scan_bytes(pattern, max_results)
        .map_err(|err| format!("{err:?}"))?;
    let hit_count = hits.len();

    Ok(json!({
        "tool": "scan_bytes",
        "scan_scope": scan_scope,
        "address": address,
        "size": size,
        "pattern": pattern,
        "hits": hits,
        "hit_count": hit_count,
    }))
}

fn tool_scan_pointers_to(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let address = required_address(&arguments, "address")?;
    let max_results = optional_usize(&arguments, "max_results", 50);
    let region = optional_snapshot_scope(&arguments, "region", SnapshotScope::All)?;

    let engine = engine_for_scope(pid, region)?;
    let hits = engine.scan_pointers_to(address, max_results);

    Ok(json!({
        "tool": "scan_pointers_to",
        "scan_scope": region.label(),
        "address": address,
        "hits": hits,
        "hit_count": hits.len(),
    }))
}

fn tool_scan_callers(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let target = required_address_alias(&arguments, "target", "address")?;
    let max_results = optional_usize(&arguments, "max_results", 50);

    let engine = engine_for_scope(pid, SnapshotScope::Executable)?;
    let hits = engine.scan_callers(target, max_results);

    Ok(json!({
        "tool": "scan_callers",
        "snapshot_scope": SnapshotScope::Executable.label(),
        "target": target,
        "hits": hits,
        "hit_count": hits.len(),
    }))
}

fn tool_value_scan_start(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let value_type = parse_value_type(required_str(&arguments, "type")?)?;
    let exact = arguments
        .get("exact")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing integer argument: exact".to_string())?;
    let max_results = optional_usize(&arguments, "max_results", 100);

    let engine = engine_for_pid(pid)?;
    let session = engine.value_scan_start(value_type, ValuePredicate::ExactU64(exact), max_results);

    Ok(json!({
        "tool": "value_scan_start",
        "type": value_type.name(),
        "exact": exact,
        "candidates": session.candidates,
        "candidate_count": session.candidates.len(),
    }))
}

fn tool_value_scan_refine(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let value_type = parse_value_type(required_str(&arguments, "type")?)?;
    let refinement = parse_value_refinement(required_str(&arguments, "refinement")?, &arguments)?;
    let candidates: Vec<ValueCandidate> = serde_json::from_value(
        arguments
            .get("candidates")
            .cloned()
            .ok_or_else(|| "missing array argument: candidates".to_string())?,
    )
    .map_err(|err| format!("invalid candidates: {err}"))?;

    let engine = engine_for_candidates(pid, &candidates)?;
    let session = ValueScanSession {
        value_type,
        candidates,
    };
    let refined = engine.value_scan_refine(&session, refinement);

    Ok(json!({
        "tool": "value_scan_refine",
        "type": value_type.name(),
        "refinement": required_str(&arguments, "refinement")?,
        "candidates": refined.candidates,
        "candidate_count": refined.candidates.len(),
    }))
}

fn tool_value_explain(arguments: Value) -> Result<Value, String> {
    let pid = required_u32(&arguments, "pid")?;
    let candidate: ValueCandidate = serde_json::from_value(
        arguments
            .get("candidate")
            .cloned()
            .ok_or_else(|| "missing object argument: candidate".to_string())?,
    )
    .map_err(|err| format!("invalid candidate: {err}"))?;

    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let target_arch = process.target_arch();
    let backend = process
        .snapshot_window(
            candidate.address,
            16,
            candidate.value_type.byte_len().saturating_add(16),
        )
        .map_err(|err| format!("{err:?}"))?;
    let engine = ArgusEngine::new_for_target(backend, target_arch);
    let hit = engine
        .value_explain(&candidate)
        .ok_or_else(|| format!("candidate not readable: 0x{:x}", candidate.address.0))?;

    Ok(json!({
        "tool": "value_explain",
        "hit": hit,
    }))
}

struct TextRegexes {
    utf8: Option<regex::bytes::Regex>,
    utf16: Option<regex::Regex>,
}

struct TextScanState {
    hits: Vec<Value>,
    total_hit_count: usize,
    max_results: usize,
    writer: Option<ScanFileWriter>,
}

impl TextScanState {
    fn record(&mut self, hit: Value) -> Result<(), String> {
        self.total_hit_count += 1;
        if let Some(writer) = &mut self.writer {
            writer.write_hit(&hit)?;
        }
        if self.hits.len() < self.max_results {
            self.hits.push(hit);
        }
        Ok(())
    }

    fn should_stop(&self, scan_all: bool) -> bool {
        !scan_all && self.total_hit_count >= self.max_results
    }
}

enum ScanFileWriter {
    Csv(BufWriter<File>),
    Json {
        writer: BufWriter<File>,
        first: bool,
    },
}

impl ScanFileWriter {
    fn new(path: &Path, format: ScanOutputFormat) -> Result<Self, String> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|err| format!("{err:?}"))?;
        }
        let file = File::create(path).map_err(|err| format!("{err:?}"))?;
        let mut writer = BufWriter::new(file);
        match format {
            ScanOutputFormat::Csv => {
                writeln!(
                    writer,
                    "address,encoding,text,module,rva,region_base,region_size,readable,writable,executable,guarded,ascii_preview"
                )
                .map_err(|err| format!("{err:?}"))?;
                Ok(Self::Csv(writer))
            }
            ScanOutputFormat::Json => {
                writer.write_all(b"[\n").map_err(|err| format!("{err:?}"))?;
                Ok(Self::Json {
                    writer,
                    first: true,
                })
            }
        }
    }

    fn write_hit(&mut self, hit: &Value) -> Result<(), String> {
        match self {
            Self::Csv(writer) => {
                let address = format_address_value(hit.get("address").unwrap_or(&Value::Null));
                let encoding = hit.get("encoding").and_then(Value::as_str).unwrap_or("");
                let text = hit.get("text").and_then(Value::as_str).unwrap_or("");
                let module = hit
                    .pointer("/address_context/module/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let rva = hit
                    .pointer("/address_context/module/rva")
                    .map(format_address_value)
                    .unwrap_or_default();
                let region_base = hit
                    .pointer("/address_context/region/base")
                    .map(format_address_value)
                    .unwrap_or_default();
                let region_size = hit
                    .pointer("/address_context/region/size")
                    .and_then(Value::as_u64)
                    .map(|value| value.to_string())
                    .unwrap_or_default();
                let readable = hit
                    .pointer("/address_context/region/flags/readable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let writable = hit
                    .pointer("/address_context/region/flags/writable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let executable = hit
                    .pointer("/address_context/region/flags/executable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let guarded = hit
                    .pointer("/address_context/region/flags/guarded")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let ascii = hit
                    .pointer("/context/ascii_preview")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                writeln!(
                    writer,
                    "{},{},{},{},{},{},{},{},{},{},{},{}",
                    csv_escape(&address),
                    csv_escape(encoding),
                    csv_escape(text),
                    csv_escape(module),
                    csv_escape(&rva),
                    csv_escape(&region_base),
                    csv_escape(&region_size),
                    readable,
                    writable,
                    executable,
                    guarded,
                    csv_escape(ascii)
                )
                .map_err(|err| format!("{err:?}"))
            }
            Self::Json { writer, first } => {
                if !*first {
                    writer.write_all(b",\n").map_err(|err| format!("{err:?}"))?;
                }
                *first = false;
                serde_json::to_writer(&mut *writer, hit).map_err(|err| format!("{err:?}"))
            }
        }
    }

    fn finish(mut self) -> Result<(), String> {
        match &mut self {
            Self::Csv(writer) => writer.flush().map_err(|err| format!("{err:?}")),
            Self::Json { writer, .. } => {
                writer
                    .write_all(b"\n]\n")
                    .map_err(|err| format!("{err:?}"))?;
                writer.flush().map_err(|err| format!("{err:?}"))
            }
        }
    }
}

fn scan_text(options: TextScanOptions<'_>) -> Result<TextScanResult, String> {
    if options.pattern.is_empty() {
        return Err("pattern must not be empty".to_string());
    }

    let scan_all = options.full || options.out_path.is_some();
    let out_path = options.out_path.clone().or_else(|| {
        options
            .full
            .then(|| default_scan_out_path(options.pid, options.regex, options.out_format))
    });
    let out_format = out_path.as_ref().map(|_| options.out_format);
    let writer = out_path
        .as_ref()
        .map(|path| ScanFileWriter::new(path, options.out_format))
        .transpose()?;
    let mut state = TextScanState {
        hits: Vec::new(),
        total_hit_count: 0,
        max_results: options.max_results,
        writer,
    };

    let regexes = compile_text_regexes(&options)?;
    let process = WinProcess::open(options.pid).map_err(|err| format!("{err:?}"))?;
    let modules = process.modules().unwrap_or_default();
    let mut scanned_region_count = 0usize;
    let mut scanned_bytes = 0usize;

    if let Some(address) = options.address {
        let region = process
            .query_region(address)
            .map_err(|err| format!("{err:?}"))?;
        let region_start = region.base.0;
        let region_end = region_start.saturating_add(region.size as u64);
        let wanted_end = address
            .0
            .saturating_add(options.size as u64)
            .min(region_end);
        let wanted_len = wanted_end.saturating_sub(address.0) as usize;
        let bytes = process
            .read(address, wanted_len)
            .map_err(|err| format!("{err:?}"))?;
        scanned_region_count = 1;
        scanned_bytes = bytes.len();
        scan_text_region(
            &options, &regexes, &region, address, &bytes, &modules, scan_all, &mut state,
        )?;
    } else {
        let regions = process
            .committed_regions()
            .map_err(|err| format!("{err:?}"))?;
        let main_module = modules
            .first()
            .map(|module| (module.base.0, module.base.0.saturating_add(module.size)));
        let (_, max_total_bytes) = if scan_all {
            (usize::MAX, usize::MAX)
        } else {
            options.region.limits()
        };

        for region in regions {
            if state.should_stop(scan_all)
                || scanned_bytes >= max_total_bytes
                || !region.flags.readable
                || region.flags.guarded
            {
                continue;
            }
            let in_main_module = main_module
                .map(|(base, end)| base <= region.base.0 && region.base.0 < end)
                .unwrap_or(false);
            let include = match options.region {
                SnapshotScope::All => true,
                SnapshotScope::Module => in_main_module,
                SnapshotScope::Heap => !in_main_module,
                SnapshotScope::Executable => region.flags.executable,
            };
            if !include {
                continue;
            }
            let remaining = max_total_bytes.saturating_sub(scanned_bytes);
            let max_region_bytes = if scan_all {
                usize::MAX
            } else {
                region_read_limit(options.region, in_main_module)
            };
            let read_len = region.size.min(max_region_bytes).min(remaining);
            let Ok(bytes) = process.read(region.base, read_len) else {
                continue;
            };
            if bytes.is_empty() {
                continue;
            }
            scanned_region_count += 1;
            scanned_bytes += bytes.len();
            scan_text_region(
                &options,
                &regexes,
                &region,
                region.base,
                &bytes,
                &modules,
                scan_all,
                &mut state,
            )?;
        }
    }

    if let Some(writer) = state.writer.take() {
        writer.finish()?;
    }

    Ok(TextScanResult {
        hits: state.hits,
        total_hit_count: state.total_hit_count,
        out_path,
        out_format,
        scanned_region_count,
        scanned_bytes,
    })
}

fn scan_text_region(
    options: &TextScanOptions<'_>,
    regexes: &TextRegexes,
    region: &MemoryRegionInfo,
    base: Address,
    bytes: &[u8],
    modules: &[ModuleInfo],
    scan_all: bool,
    state: &mut TextScanState,
) -> Result<(), String> {
    if matches!(options.encoding, TextEncoding::Utf8 | TextEncoding::Both) {
        if options.regex {
            if let Some(regex) = &regexes.utf8 {
                for found in regex.find_iter(bytes) {
                    if state.should_stop(scan_all) {
                        return Ok(());
                    }
                    record_text_match(
                        state,
                        Address(base.0 + found.start() as u64),
                        "utf8",
                        String::from_utf8_lossy(found.as_bytes()).to_string(),
                        region,
                        base,
                        bytes,
                        found.start(),
                        found.end().saturating_sub(found.start()),
                        modules,
                    )?;
                }
            }
        } else {
            scan_exact_utf8(options, region, base, bytes, modules, scan_all, state)?;
        }
    }

    if matches!(options.encoding, TextEncoding::Utf16Le | TextEncoding::Both) {
        if options.regex {
            if let Some(regex) = &regexes.utf16 {
                scan_regex_utf16(regex, region, base, bytes, modules, scan_all, state)?;
            }
        } else {
            scan_exact_utf16(options, region, base, bytes, modules, scan_all, state)?;
        }
    }

    Ok(())
}

fn scan_exact_utf8(
    options: &TextScanOptions<'_>,
    region: &MemoryRegionInfo,
    base: Address,
    bytes: &[u8],
    modules: &[ModuleInfo],
    scan_all: bool,
    state: &mut TextScanState,
) -> Result<(), String> {
    let needle = options.pattern.as_bytes();
    let mut search_from = 0usize;
    while search_from <= bytes.len().saturating_sub(needle.len()) {
        if state.should_stop(scan_all) {
            break;
        }
        let Some(relative) =
            find_bytes_with_case(&bytes[search_from..], needle, options.case_sensitive)
        else {
            break;
        };
        let offset = search_from + relative;
        record_text_match(
            state,
            Address(base.0 + offset as u64),
            "utf8",
            String::from_utf8_lossy(&bytes[offset..offset + needle.len()]).to_string(),
            region,
            base,
            bytes,
            offset,
            needle.len(),
            modules,
        )?;
        search_from = offset + needle.len().max(1);
    }
    Ok(())
}

fn scan_exact_utf16(
    options: &TextScanOptions<'_>,
    region: &MemoryRegionInfo,
    base: Address,
    bytes: &[u8],
    modules: &[ModuleInfo],
    scan_all: bool,
    state: &mut TextScanState,
) -> Result<(), String> {
    let needle: Vec<u16> = options.pattern.encode_utf16().collect();
    if needle.is_empty() {
        return Ok(());
    }
    let byte_len = needle.len() * 2;
    for parity in 0..=1usize {
        let mut offset = parity;
        while offset + byte_len <= bytes.len() {
            if state.should_stop(scan_all) {
                return Ok(());
            }
            if utf16_units_match(
                &bytes[offset..offset + byte_len],
                &needle,
                options.case_sensitive,
            ) {
                record_text_match(
                    state,
                    Address(base.0 + offset as u64),
                    "utf16le",
                    options.pattern.to_string(),
                    region,
                    base,
                    bytes,
                    offset,
                    byte_len,
                    modules,
                )?;
                offset += byte_len.max(2);
            } else {
                offset += 2;
            }
        }
    }
    Ok(())
}

fn scan_regex_utf16(
    regex: &regex::Regex,
    region: &MemoryRegionInfo,
    base: Address,
    bytes: &[u8],
    modules: &[ModuleInfo],
    scan_all: bool,
    state: &mut TextScanState,
) -> Result<(), String> {
    for parity in 0..=1usize {
        let mut decoded = String::new();
        let mut offsets = Vec::new();
        let mut offset = parity;
        while offset + 1 < bytes.len() {
            let unit = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            let ch = char::from_u32(unit as u32).unwrap_or('\u{fffd}');
            decoded.push(ch);
            offsets.push(offset);
            offset += 2;
        }
        for found in regex.find_iter(&decoded) {
            if state.should_stop(scan_all) {
                return Ok(());
            }
            let start_char = decoded[..found.start()].chars().count();
            let end_char = decoded[..found.end()].chars().count();
            let Some(&start_offset) = offsets.get(start_char) else {
                continue;
            };
            let byte_len = end_char.saturating_sub(start_char).saturating_mul(2);
            record_text_match(
                state,
                Address(base.0 + start_offset as u64),
                "utf16le",
                found.as_str().to_string(),
                region,
                base,
                bytes,
                start_offset,
                byte_len,
                modules,
            )?;
        }
    }
    Ok(())
}

fn record_text_match(
    state: &mut TextScanState,
    address: Address,
    encoding: &str,
    text: String,
    region: &MemoryRegionInfo,
    base: Address,
    bytes: &[u8],
    offset: usize,
    evidence_len: usize,
    modules: &[ModuleInfo],
) -> Result<(), String> {
    let context_start = offset.saturating_sub(16);
    let context_end = offset
        .saturating_add(evidence_len)
        .saturating_add(16)
        .min(bytes.len());
    let ascii = ascii_preview(&bytes[context_start..context_end]);
    state.record(json!({
        "address": address,
        "encoding": encoding,
        "text": text,
        "address_context": {
            "module": module_context(address, modules),
            "region": {
                "base": region.base,
                "size": region.size,
                "kind": format!("{:?}", region.kind),
                "flags": region.flags,
            }
        },
        "context": {
            "ascii_preview": ascii,
            "region_scan_base": base,
            "offset": offset,
        }
    }))
}

fn compile_text_regexes(options: &TextScanOptions<'_>) -> Result<TextRegexes, String> {
    if !options.regex {
        return Ok(TextRegexes {
            utf8: None,
            utf16: None,
        });
    }
    let utf8 = if matches!(options.encoding, TextEncoding::Utf8 | TextEncoding::Both) {
        Some(
            BytesRegexBuilder::new(options.pattern)
                .case_insensitive(!options.case_sensitive)
                .unicode(false)
                .build()
                .map_err(|err| format!("invalid UTF-8 byte regex: {err}"))?,
        )
    } else {
        None
    };
    let utf16 = if matches!(options.encoding, TextEncoding::Utf16Le | TextEncoding::Both) {
        Some(
            RegexBuilder::new(options.pattern)
                .case_insensitive(!options.case_sensitive)
                .build()
                .map_err(|err| format!("invalid UTF-16 regex: {err}"))?,
        )
    } else {
        None
    };
    Ok(TextRegexes { utf8, utf16 })
}

fn module_context(address: Address, modules: &[ModuleInfo]) -> Option<Value> {
    modules
        .iter()
        .find(|module| {
            module.base.0 <= address.0 && address.0 < module.base.0.saturating_add(module.size)
        })
        .map(|module| {
            json!({
                "name": module.name.clone(),
                "base": module.base,
                "rva": address.0.saturating_sub(module.base.0),
            })
        })
}

fn find_bytes_with_case(haystack: &[u8], needle: &[u8], case_sensitive: bool) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| bytes_equal_with_case(window, needle, case_sensitive))
}

fn bytes_equal_with_case(left: &[u8], right: &[u8], case_sensitive: bool) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| byte_equal_with_case(*left, *right, case_sensitive))
}

fn byte_equal_with_case(left: u8, right: u8, case_sensitive: bool) -> bool {
    if case_sensitive {
        left == right
    } else {
        left.eq_ignore_ascii_case(&right)
    }
}

fn utf16_units_match(bytes: &[u8], needle: &[u16], case_sensitive: bool) -> bool {
    if bytes.len() != needle.len() * 2 {
        return false;
    }
    bytes.chunks_exact(2).zip(needle).all(|(chunk, expected)| {
        let actual = u16::from_le_bytes([chunk[0], chunk[1]]);
        utf16_unit_equal_with_case(actual, *expected, case_sensitive)
    })
}

fn utf16_unit_equal_with_case(left: u16, right: u16, case_sensitive: bool) -> bool {
    if case_sensitive {
        left == right
    } else if left <= 0x7f && right <= 0x7f {
        (left as u8).eq_ignore_ascii_case(&(right as u8))
    } else {
        left == right
    }
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn default_scan_out_path(pid: u32, regex: bool, format: ScanOutputFormat) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let stem = if regex { "scan-regex" } else { "scan-string" };
    std::env::temp_dir().join(format!("argus-{stem}-{pid}-{nanos}.{}", format.label()))
}

fn engine_for_pid(pid: u32) -> Result<ArgusEngine, String> {
    engine_for_scope(pid, SnapshotScope::All)
}

fn engine_for_scope(pid: u32, scope: SnapshotScope) -> Result<ArgusEngine, String> {
    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let target_arch = process.target_arch();
    let modules = process.modules().unwrap_or_default();
    let main_module = modules
        .first()
        .map(|module| (module.base.0, module.base.0.saturating_add(module.size)));
    let (_, max_total_bytes) = scope.limits();
    let mut total_bytes = 0usize;
    let mut regions = Vec::new();

    for region in process
        .committed_regions()
        .map_err(|err| format!("{err:?}"))?
    {
        if total_bytes >= max_total_bytes || !region.flags.readable || region.flags.guarded {
            continue;
        }
        let in_main_module = main_module
            .map(|(base, end)| base <= region.base.0 && region.base.0 < end)
            .unwrap_or(false);
        let include = match scope {
            SnapshotScope::All => true,
            SnapshotScope::Module => in_main_module,
            SnapshotScope::Heap => !in_main_module,
            SnapshotScope::Executable => region.flags.executable,
        };
        if !include {
            continue;
        }

        let remaining = max_total_bytes - total_bytes;
        let max_region_bytes = region_read_limit(scope, in_main_module);
        let read_len = region.size.min(max_region_bytes).min(remaining);
        let Ok(bytes) = process.read(region.base, read_len) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        total_bytes += bytes.len();
        regions.push(MemoryRegion {
            base: region.base,
            bytes,
            kind: region.kind,
            flags: region.flags,
        });
    }

    Ok(ArgusEngine::new_for_target(
        InMemoryBackend { modules, regions },
        target_arch,
    ))
}

fn engine_for_window(
    pid: u32,
    address: Address,
    before: usize,
    after: usize,
) -> Result<ArgusEngine, String> {
    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let target_arch = process.target_arch();
    let backend = process
        .snapshot_window(address, before, after)
        .map_err(|err| format!("{err:?}"))?;
    Ok(ArgusEngine::new_for_target(backend, target_arch))
}

fn engine_for_candidates(pid: u32, candidates: &[ValueCandidate]) -> Result<ArgusEngine, String> {
    let process = WinProcess::open(pid).map_err(|err| format!("{err:?}"))?;
    let target_arch = process.target_arch();
    let modules = process.modules().unwrap_or_default();
    let mut regions = Vec::new();

    for candidate in candidates {
        let size = candidate.value_type.byte_len();
        let Ok(info) = process.query_region(candidate.address) else {
            continue;
        };
        let Ok(bytes) = process.read(candidate.address, size) else {
            continue;
        };
        regions.push(MemoryRegion {
            base: candidate.address,
            bytes,
            kind: info.kind,
            flags: info.flags,
        });
    }

    Ok(ArgusEngine::new_for_target(
        InMemoryBackend { modules, regions },
        target_arch,
    ))
}

fn load_static_struct_fields(
    arguments: &Value,
    struct_name: &str,
    max_fields: usize,
) -> Result<Vec<StaticStructField>, String> {
    let source = if let Some(fields) = arguments.get("fields") {
        fields.clone()
    } else {
        let hydra_port = optional_usize(arguments, "hydra_port", 0);
        fetch_static_struct(struct_name, hydra_port)?
    };

    let fields_value = source
        .as_array()
        .cloned()
        .or_else(|| {
            source
                .pointer("/result/fields")
                .and_then(Value::as_array)
                .cloned()
        })
        .or_else(|| source.get("fields").and_then(Value::as_array).cloned())
        .ok_or_else(|| format!("struct '{struct_name}' has no fields"))?;

    let mut fields = fields_value
        .iter()
        .map(parse_static_struct_field)
        .collect::<Result<Vec<_>, _>>()?;
    fields.sort_by_key(|field| field.offset);
    fields.truncate(max_fields);
    Ok(fields)
}

fn parse_static_struct_field(value: &Value) -> Result<StaticStructField, String> {
    let offset = value_u64(value.get("offset")).unwrap_or(0);
    let length = value_u64(value.get("length"))
        .or_else(|| value_u64(value.get("size")))
        .unwrap_or(4) as usize;
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string();
    let type_name = value
        .get("type")
        .or_else(|| value.get("type_name"))
        .or_else(|| value.get("dataType"))
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string();

    Ok(StaticStructField {
        offset,
        name,
        type_name,
        length: length.max(1),
    })
}

fn value_u64(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    let text = value.as_str()?.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse::<u64>().ok()
    }
}

fn fetch_static_struct(struct_name: &str, hydra_port: usize) -> Result<Value, String> {
    let host = std::env::var("HYDRA_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = if hydra_port != 0 {
        hydra_port
    } else {
        std::env::var("HYDRA_PORT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(8192)
    };
    let path = format!("/structs/{}", url_encode_component(struct_name));
    http_get_json(&host, port, &path)
}

fn http_get_json(host: &str, port: usize, path: &str) -> Result<Value, String> {
    let mut stream =
        std::net::TcpStream::connect((host, port as u16)).map_err(|err| format!("{err:?}"))?;
    let timeout = Some(Duration::from_secs(5));
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("{err:?}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|err| format!("{err:?}"))?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "invalid HTTP response from Hydra".to_string())?;
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        let status = headers.lines().next().unwrap_or("HTTP error");
        return Err(format!("hydra request failed: {status}"));
    }
    let value: Value = serde_json::from_str(body).map_err(|err| format!("{err:?}"))?;
    if let Some(error) = value.get("error") {
        return Err(error.to_string());
    }
    Ok(value)
}

fn url_encode_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

fn ledger_path(arguments: &Value) -> PathBuf {
    if let Some(path) = optional_str(arguments, "ledger_path") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("ARGUS_LEDGER_PATH") {
        return PathBuf::from(path);
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        return PathBuf::from(profile)
            .join(".codex")
            .join("argus_hypotheses.json");
    }
    std::env::temp_dir().join("argus_hypotheses.json")
}

fn load_ledger(path: &Path) -> Result<HypothesisLedger, String> {
    if !path.exists() {
        return Ok(HypothesisLedger::default());
    }
    let data = fs::read_to_string(path).map_err(|err| format!("{err:?}"))?;
    if data.trim().is_empty() {
        return Ok(HypothesisLedger::default());
    }
    let mut ledger: HypothesisLedger =
        serde_json::from_str(&data).map_err(|err| format!("{err:?}"))?;
    ledger.normalize();
    Ok(ledger)
}

fn save_ledger(path: &Path, ledger: &HypothesisLedger) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|err| format!("{err:?}"))?;
    }
    let data = serde_json::to_vec_pretty(ledger).map_err(|err| format!("{err:?}"))?;
    fs::write(path, data).map_err(|err| format!("{err:?}"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_value_type(value: &str) -> Result<ValueType, String> {
    match value {
        "u32" => Ok(ValueType::U32),
        other => Err(format!("unsupported value type: {other}")),
    }
}

fn parse_snapshot_scope(value: &str) -> Result<SnapshotScope, String> {
    match value {
        "all" => Ok(SnapshotScope::All),
        "module" => Ok(SnapshotScope::Module),
        "heap" => Ok(SnapshotScope::Heap),
        "executable" => Ok(SnapshotScope::Executable),
        other => Err(format!("unsupported region scope: {other}")),
    }
}

fn parse_text_encoding(value: &str) -> Result<TextEncoding, String> {
    match value {
        "utf8" | "utf-8" => Ok(TextEncoding::Utf8),
        "utf16le" | "utf-16le" | "utf16" | "utf-16" => Ok(TextEncoding::Utf16Le),
        "both" => Ok(TextEncoding::Both),
        other => Err(format!("unsupported text encoding: {other}")),
    }
}

fn parse_scan_output_format(value: &str) -> Result<ScanOutputFormat, String> {
    match value {
        "csv" => Ok(ScanOutputFormat::Csv),
        "json" => Ok(ScanOutputFormat::Json),
        other => Err(format!("unsupported output format: {other}")),
    }
}

fn optional_snapshot_scope(
    arguments: &Value,
    key: &str,
    default: SnapshotScope,
) -> Result<SnapshotScope, String> {
    optional_str(arguments, key)
        .map(parse_snapshot_scope)
        .unwrap_or(Ok(default))
}

fn optional_text_encoding(
    arguments: &Value,
    default: TextEncoding,
) -> Result<TextEncoding, String> {
    optional_str(arguments, "encoding")
        .map(parse_text_encoding)
        .unwrap_or(Ok(default))
}

fn optional_scan_output_format(
    arguments: &Value,
    out_path: Option<&Path>,
) -> Result<ScanOutputFormat, String> {
    if let Some(format) =
        optional_str(arguments, "out_format").or_else(|| optional_str(arguments, "format"))
    {
        return parse_scan_output_format(format);
    }
    if out_path
        .and_then(Path::extension)
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
    {
        Ok(ScanOutputFormat::Json)
    } else {
        Ok(ScanOutputFormat::Csv)
    }
}

fn optional_bool(arguments: &Value, key: &str, default: bool) -> bool {
    arguments
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or(default)
}

fn pointer_width_bytes() -> usize {
    std::mem::size_of::<usize>()
}

fn read_pointer(process: &WinProcess, address: Address) -> Result<Address, String> {
    let width = pointer_width_bytes();
    let data = process
        .read(address, width)
        .map_err(|err| format!("{err:?}"))?;
    if data.len() < width {
        return Err(format!("short pointer read at 0x{:x}", address.0));
    }
    let value = if width == 4 {
        u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64
    } else {
        u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])
    };
    Ok(Address(value))
}

fn parse_offsets(value: &str) -> Result<Vec<u64>, String> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|part| {
            parse_address_value(&Value::String(part.trim().to_string()))
                .map(|address| address.0)
                .map_err(|err| format!("invalid offset {part:?}: {err}"))
        })
        .collect()
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    let compact: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
    if compact.len() % 2 != 0 {
        return Err("hex_data must contain an even number of hex digits".to_string());
    }
    (0..compact.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&compact[index..index + 2], 16)
                .map_err(|_| format!("invalid hex byte: {}", &compact[index..index + 2]))
        })
        .collect()
}

fn parse_value_refinement(value: &str, arguments: &Value) -> Result<ValueRefinement, String> {
    match value {
        "changed" => Ok(ValueRefinement::Changed),
        "unchanged" => Ok(ValueRefinement::Unchanged),
        "increased" => Ok(ValueRefinement::Increased),
        "decreased" => Ok(ValueRefinement::Decreased),
        "exact" => Ok(ValueRefinement::ExactU64(
            arguments
                .get("exact")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    "missing integer argument for exact refinement: exact".to_string()
                })?,
        )),
        other => Err(format!("unsupported value refinement: {other}")),
    }
}

fn required_u32(arguments: &Value, key: &str) -> Result<u32, String> {
    let value = arguments
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing integer argument: {key}"))?;
    u32::try_from(value).map_err(|_| format!("argument out of u32 range: {key}"))
}

fn required_u64(arguments: &Value, key: &str) -> Result<u64, String> {
    arguments
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing integer argument: {key}"))
}

fn required_str<'a>(arguments: &'a Value, key: &str) -> Result<&'a str, String> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string argument: {key}"))
}

fn required_address(arguments: &Value, key: &str) -> Result<Address, String> {
    let value = arguments
        .get(key)
        .ok_or_else(|| format!("missing address argument: {key}"))?;
    parse_address_value(value).map_err(|err| format!("{key}: {err}"))
}

fn optional_address(arguments: &Value, key: &str) -> Result<Option<Address>, String> {
    arguments
        .get(key)
        .map(|value| parse_address_value(value).map_err(|err| format!("{key}: {err}")))
        .transpose()
}

fn required_address_alias(
    arguments: &Value,
    primary: &str,
    fallback: &str,
) -> Result<Address, String> {
    if arguments.get(primary).is_some() {
        return required_address(arguments, primary);
    }
    required_address(arguments, fallback)
}

fn parse_address_value(value: &Value) -> Result<Address, String> {
    if let Some(number) = value.as_u64() {
        return Ok(Address(number));
    }

    let text = value
        .as_str()
        .ok_or_else(|| "expected integer or hex string".to_string())?;
    let trimmed = text.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16)
            .map(Address)
            .map_err(|err| format!("invalid hex address: {err}"));
    }

    trimmed
        .parse::<u64>()
        .map(Address)
        .map_err(|err| format!("invalid decimal address: {err}"))
}

fn required_usize(arguments: &Value, key: &str) -> Result<usize, String> {
    let value = arguments
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing integer argument: {key}"))?;
    usize::try_from(value).map_err(|_| format!("argument out of usize range: {key}"))
}

fn optional_usize(arguments: &Value, key: &str, default: usize) -> usize {
    arguments
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(default)
}

fn optional_str<'a>(arguments: &'a Value, key: &str) -> Option<&'a str> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn tools() -> Vec<Value> {
    vec![
        json!({
            "name": "processes_list",
            "title": "List Processes",
            "description": "List running Windows processes so the AI can find a target PID before reading runtime memory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 200}
                }
            }
        }),
        json!({
            "name": "processes_find",
            "title": "Find Process",
            "description": "Find running process candidates by name substring, exact image name, or PID. Use this before memory tools when the PID is unknown.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name_contains": {"type": "string", "description": "Case-insensitive process image substring."},
                    "exact_name": {"type": "string", "description": "Case-insensitive exact process image name, such as game.exe."},
                    "pid": {"type": "integer", "description": "Optional exact PID lookup."},
                    "limit": {"type": "integer", "default": 50}
                }
            }
        }),
        json!({
            "name": "runtime_imports",
            "title": "Runtime Imports",
            "description": "Parse PE32 import/IAT data from the live mapped process image. Useful when disk EXE imports are packed or misleading.",
            "inputSchema": {"type": "object", "properties": {"pid": {"type": "integer"}, "module_name": {"type": "string"}, "dll_contains": {"type": "string"}, "name_contains": {"type": "string"}, "max_results": {"type": "integer", "default": 200}}, "required": ["pid"]}
        }),
        json!({
            "name": "runtime_exports",
            "title": "Runtime Exports",
            "description": "Parse PE export tables from live mapped modules and return exported API names with runtime VA/RVA evidence.",
            "inputSchema": {"type": "object", "properties": {"pid": {"type": "integer"}, "module_name": {"type": "string"}, "name_contains": {"type": "string"}, "max_results": {"type": "integer", "default": 200}}, "required": ["pid"]}
        }),
        json!({
            "name": "resolve_api_targets",
            "title": "Resolve API Targets",
            "description": "Resolve runtime API targets from loaded module exports. Accepts api like ws2_32!send or module_name plus name_contains.",
            "inputSchema": {"type": "object", "properties": {"pid": {"type": "integer"}, "api": {"type": "string"}, "module_name": {"type": "string"}, "name": {"type": "string"}, "name_contains": {"type": "string"}, "max_results": {"type": "integer", "default": 50}}, "required": ["pid"]}
        }),
        json!({
            "name": "resolve_iat_thunks",
            "title": "Resolve IAT Thunks",
            "description": "Find x86 import thunks such as jmp/call dword ptr [IAT] and return the runtime target plus thunk address.",
            "inputSchema": {"type": "object", "properties": {"pid": {"type": "integer"}, "module_name": {"type": "string"}, "name_contains": {"type": "string"}, "max_results": {"type": "integer", "default": 100}}, "required": ["pid"]}
        }),
        json!({
            "name": "disasm_at",
            "title": "Disassemble At",
            "description": "Decode 32-bit runtime instructions at an address using a targeted memory window. Keeps full instruction text and adds call/jmp targets and push-string evidence.",
            "inputSchema": {"type": "object", "properties": {"pid": {"type": "integer"}, "address": {"description": "Runtime address."}, "count": {"type": "integer", "default": 40}, "window_size": {"type": "integer", "description": "Bytes to snapshot from address before decoding."}}, "required": ["pid", "address"]}
        }),
        json!({
            "name": "analyze_function",
            "title": "Analyze Function",
            "description": "Disassemble one runtime function body from a targeted memory window until ret/count and collect direct callees. Evidence only, no summarization.",
            "inputSchema": {"type": "object", "properties": {"pid": {"type": "integer"}, "address": {"description": "Function entry/runtime address."}, "max_insn": {"type": "integer", "default": 200}, "window_size": {"type": "integer", "description": "Bytes to snapshot from address before decoding."}}, "required": ["pid", "address"]}
        }),
        json!({
            "name": "scan_x86_call_sites",
            "title": "Scan X86 Call Sites",
            "description": "Find direct x86 E8/E9 call/jump sites to a target, annotate each with instruction text and best-effort function start.",
            "inputSchema": {"type": "object", "properties": {"pid": {"type": "integer"}, "target": {"description": "Target function/thunk address."}, "address": {"description": "Alias for target."}, "max_results": {"type": "integer", "default": 50}}, "required": ["pid"]}
        }),
        json!({
            "name": "analyze_send_call_sites",
            "title": "Analyze Send Call Sites",
            "description": "For a send/thunk target, scan executable call sites and return compact evidence from preceding instructions: push immediate opcode candidates, push string addresses, and packet-shaped C_/S_ names. Evidence only.",
            "inputSchema": {"type": "object", "properties": {"pid": {"type": "integer"}, "target": {"description": "Send target/thunk address."}, "address": {"description": "Alias for target."}, "max_results": {"type": "integer", "default": 50}, "max_preceding_instructions": {"type": "integer", "default": 12}, "backward_bytes": {"type": "integer", "default": 128}}, "required": ["pid"]}
        }),
        json!({
            "name": "extract_dispatch_tables",
            "title": "Extract Dispatch Tables",
            "description": "For a recv dispatcher, identify index/jump table candidates from runtime instructions and, when tables are found or provided, output opcode -> dispatch index -> stub -> handler evidence with opcode_value_location.",
            "inputSchema": {"type": "object", "properties": {"pid": {"type": "integer"}, "dispatcher": {"description": "Dispatcher function address."}, "address": {"description": "Alias for dispatcher."}, "index_table": {"description": "Optional known opcode index table address."}, "jump_table": {"description": "Optional known jump table address."}, "max_insn": {"type": "integer", "default": 80}, "max_entries": {"type": "integer", "default": 256}}, "required": ["pid"]}
        }),
        json!({
            "name": "trace_call_chain",
            "title": "Trace Call Chain",
            "description": "Walk callers upward from a runtime target for a bounded number of depths. Designed for send/recv/decrypt chain evidence.",
            "inputSchema": {"type": "object", "properties": {"pid": {"type": "integer"}, "target": {"description": "Target function/thunk address."}, "address": {"description": "Alias for target."}, "max_depth": {"type": "integer", "default": 3}, "max_callers_per_depth": {"type": "integer", "default": 20}}, "required": ["pid"]}
        }),
        json!({
            "name": "mem_read",
            "title": "Read Memory",
            "description": "Read runtime memory at an address and return AI-first evidence with module/RVA, region flags, byte context, ASCII preview, and next-tool hints.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "address": {"description": "Virtual address as integer or 0x-prefixed string."},
                    "size": {"type": "integer", "description": "Number of bytes to read."}
                },
                "required": ["pid", "address", "size"]
            }
        }),
        json!({
            "name": "mem_write",
            "title": "Write Memory",
            "description": "Write exact bytes to runtime memory and return the write evidence. This does not infer patch correctness.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "address": {"description": "Virtual address as integer or 0x-prefixed string."},
                    "hex_data": {"type": "string", "description": "Hex bytes to write, such as 90 90 C3."}
                },
                "required": ["pid", "address", "hex_data"]
            }
        }),
        json!({
            "name": "mem_read_chain",
            "title": "Read Pointer Chain",
            "description": "Read a pointer chain using original Argus semantics: dereference base, add offsets, dereference intermediate nodes, then return final bytes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "base_address": {"description": "Address containing the first pointer."},
                    "address": {"description": "Alias for base_address."},
                    "offsets": {"type": "string", "description": "Comma-separated offsets such as 0x10,0x20."},
                    "final_size": {"type": "integer", "default": 64}
                },
                "required": ["pid"]
            }
        }),
        json!({
            "name": "read_struct",
            "title": "Read Struct Words",
            "description": "Read consecutive 4-byte words and report raw u32 values plus possible pointer target region evidence. It does not infer field names.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "address": {"description": "Struct/object start address."},
                    "count": {"type": "integer", "default": 16}
                },
                "required": ["pid", "address"]
            }
        }),
        json!({
            "name": "correlate_addr",
            "title": "Correlate Address",
            "description": "Convert between live process address, RVA, and Ghidra/static address using the main module base. Evidence only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "live_addr": {"description": "Live process address."},
                    "static_addr": {"description": "Static/Ghidra address."},
                    "ghidra_image_base": {"description": "Static image base, default 0x400000."}
                },
                "required": ["pid"]
            }
        }),
        json!({
            "name": "locate",
            "title": "Locate String References",
            "description": "Evidence chain matching original Argus: scan string, find pointers to it, keep executable refs, and return best-effort containing function starts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "query": {"type": "string", "description": "String to locate in runtime memory."},
                    "max_hits": {"type": "integer", "default": 8}
                },
                "required": ["pid", "query"]
            }
        }),
        json!({
            "name": "find_vtable",
            "title": "Find VTable",
            "description": "Find x86 MSVC RTTI/vtable evidence: TypeDescriptor string, COL, vtable address, and method slots. Evidence only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "class_name": {"type": "string", "description": "Class name such as CPlayer, or a decorated RTTI name."},
                    "max_methods": {"type": "integer", "default": 20}
                },
                "required": ["pid", "class_name"]
            }
        }),
        json!({
            "name": "diff_struct",
            "title": "Diff Struct",
            "description": "Overlay static struct fields from Hydra /structs/{name} or provided fields onto live memory and return raw field bytes plus pointer-region evidence.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "struct_name": {"type": "string", "description": "Static struct/class name."},
                    "live_address": {"description": "Live instance address."},
                    "address": {"description": "Alias for live_address."},
                    "max_fields": {"type": "integer", "default": 64},
                    "hydra_port": {"type": "integer", "description": "Optional Hydra HTTP port; defaults to HYDRA_PORT or 8192."},
                    "fields": {"type": "array", "description": "Optional direct static fields with offset/name/type/length."}
                },
                "required": ["pid", "struct_name"]
            }
        }),
        json!({
            "name": "record_hypothesis",
            "title": "Record Hypothesis",
            "description": "Append an unverified AI hypothesis to the evidence ledger. This only records the claim; it does not verify it.",
            "inputSchema": {"type": "object", "properties": {"entity": {"type": "string"}, "claim_type": {"type": "string"}, "claim_value": {"type": "string"}, "source": {"type": "string", "default": "llm"}, "confidence": {"type": "number"}, "ledger_path": {"type": "string"}}, "required": ["entity", "claim_type", "claim_value"]}
        }),
        json!({
            "name": "add_evidence",
            "title": "Add Evidence",
            "description": "Attach external/static/dynamic evidence to an existing hypothesis record.",
            "inputSchema": {"type": "object", "properties": {"hypothesis_id": {"type": "integer"}, "kind": {"type": "string"}, "detail": {"type": "string"}, "source": {"type": "string"}, "addr": {"type": "string"}, "ledger_path": {"type": "string"}}, "required": ["hypothesis_id", "kind", "detail", "source"]}
        }),
        json!({
            "name": "verify_hypothesis",
            "title": "Verify Hypothesis",
            "description": "Mark a hypothesis as verified or contradicted. Contradictions add negative knowledge for later queries.",
            "inputSchema": {"type": "object", "properties": {"hypothesis_id": {"type": "integer"}, "verdict": {"type": "string", "enum": ["verified", "contradicted"]}, "note": {"type": "string"}, "ledger_path": {"type": "string"}}, "required": ["hypothesis_id", "verdict"]}
        }),
        json!({
            "name": "query_hypotheses",
            "title": "Query Hypotheses",
            "description": "Read the evidence ledger by entity/status/claim_type and include negative knowledge for an entity.",
            "inputSchema": {"type": "object", "properties": {"entity": {"type": "string"}, "status": {"type": "string"}, "claim_type": {"type": "string"}, "limit": {"type": "integer", "default": 50}, "ledger_path": {"type": "string"}}}
        }),
        json!({
            "name": "real_rate",
            "title": "Real Rate",
            "description": "Return verified/total and counts by status/source/claim type from the evidence ledger.",
            "inputSchema": {"type": "object", "properties": {"ledger_path": {"type": "string"}}}
        }),
        json!({
            "name": "mem_attach",
            "title": "Attach Process",
            "description": "Compatibility alias for original Argus mem_attach. Resolves a PID and returns base/module evidence, but keeps Rust Argus stateless.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Optional exact target PID."},
                    "process": {"type": "string", "description": "Process image name or substring. Required unless pid is given."},
                    "name": {"type": "string", "description": "Alias for process."}
                }
            }
        }),
        json!({
            "name": "mem_modules",
            "title": "List Modules",
            "description": "List target process modules with base addresses and image sizes for RVA correlation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "max_results": {"type": "integer", "default": 16, "description": "Text display cap when full=false."},
                    "full": {"type": "boolean", "default": false, "description": "When true, prints the full module list."}
                },
                "required": ["pid"]
            }
        }),
        json!({
            "name": "memory_regions",
            "title": "List Memory Regions",
            "description": "List committed runtime memory regions with base, size, kind, and protection flags so AI can distinguish image/private/executable/readable areas before scanning.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "limit": {"type": "integer", "default": 512}
                },
                "required": ["pid"]
            }
        }),
        json!({
            "name": "scan_string",
            "title": "Scan String",
            "description": "Scan readable runtime memory for an exact string. Supports UTF-8/UTF-16LE, case-insensitive matching, full uncapped scan, and CSV/JSON output files for large evidence sets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "pattern": {"type": "string", "description": "Exact text to search for."},
                    "encoding": {"type": "string", "enum": ["utf8", "utf16le", "both"], "default": "utf8"},
                    "case_sensitive": {"type": "boolean", "default": true},
                    "region": {"type": "string", "enum": ["all", "module", "heap", "executable"], "default": "all"},
                    "address": {"description": "Optional runtime address for targeted window scan."},
                    "size": {"type": "integer", "description": "Optional window byte size when address is provided."},
                    "max_results": {"type": "integer", "default": 20},
                    "full": {"type": "boolean", "default": false, "description": "When true, scans all matching regions and writes all hits to out_path/default temp file."},
                    "out_path": {"type": "string", "description": "Optional CSV/JSON output path. When provided, all hits are written even if max_results is small."},
                    "out_format": {"type": "string", "enum": ["csv", "json"], "default": "csv"}
                },
                "required": ["pid", "pattern"]
            }
        }),
        json!({
            "name": "scan_regex",
            "title": "Scan Regex",
            "description": "Scan readable runtime memory with a regex, for packet names such as C_[A-Za-z0-9_]+ or S_[A-Za-z0-9_]+. Supports UTF-8/UTF-16LE, mixed-case, full scan, and CSV/JSON output files.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "pattern": {"type": "string", "description": "Regex pattern, for example C_[A-Za-z0-9_]+|S_[A-Za-z0-9_]+."},
                    "encoding": {"type": "string", "enum": ["utf8", "utf16le", "both"], "default": "both"},
                    "case_sensitive": {"type": "boolean", "default": true},
                    "region": {"type": "string", "enum": ["all", "module", "heap", "executable"], "default": "all"},
                    "address": {"description": "Optional runtime address for targeted window scan."},
                    "size": {"type": "integer", "description": "Optional window byte size when address is provided."},
                    "max_results": {"type": "integer", "default": 50},
                    "full": {"type": "boolean", "default": false, "description": "When true, scans all matching regions and writes all hits to out_path/default temp file."},
                    "out_path": {"type": "string", "description": "Optional CSV/JSON output path. When provided, all hits are written even if max_results is small."},
                    "out_format": {"type": "string", "enum": ["csv", "json"], "default": "csv"}
                },
                "required": ["pid", "pattern"]
            }
        }),
        json!({
            "name": "scan_bytes",
            "title": "Scan Bytes",
            "description": "Scan runtime memory for an AOB pattern. Supports ?? wildcards. With address/size, scans a targeted window around an anchor to avoid capped global snapshot misses.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "pattern": {"type": "string", "description": "AOB pattern such as E8 ?? 34."},
                    "region": {"type": "string", "enum": ["executable", "module", "all"], "default": "executable"},
                    "address": {"description": "Optional runtime address for targeted window scan."},
                    "size": {"type": "integer", "description": "Optional window byte size when address is provided."},
                    "max_results": {"type": "integer", "default": 20}
                },
                "required": ["pid", "pattern"]
            }
        }),
        json!({
            "name": "scan_pointers_to",
            "title": "Scan Pointers To",
            "description": "Scan readable runtime memory for pointers to an address and return AI-first pointer evidence.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "address": {"description": "Target address as integer or 0x-prefixed string."},
                    "region": {"type": "string", "enum": ["all", "module", "heap"], "default": "all"},
                    "max_results": {"type": "integer", "default": 50}
                },
                "required": ["pid", "address"]
            }
        }),
        json!({
            "name": "scan_callers",
            "title": "Scan Callers",
            "description": "Scan executable readable regions for x86 E8/E9 rel32 callers or jumpers to a target address.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "target": {"description": "Target address as integer or 0x-prefixed string."},
                    "address": {"description": "Alias for target."},
                    "max_results": {"type": "integer", "default": 50}
                },
                "required": ["pid"]
            }
        }),
        json!({
            "name": "value_scan_start",
            "title": "Start Value Scan",
            "description": "Start a typed value investigation scan. Returns candidates with evidence context for later refine/explain steps.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "type": {"type": "string", "enum": ["u32"]},
                    "exact": {"type": "integer", "description": "Exact numeric value to search for."},
                    "max_results": {"type": "integer", "default": 100}
                },
                "required": ["pid", "type", "exact"]
            }
        }),
        json!({
            "name": "value_scan_refine",
            "title": "Refine Value Scan",
            "description": "Refine value candidates using a fresh memory read. Refinements: changed, unchanged, increased, decreased, exact.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "type": {"type": "string", "enum": ["u32"]},
                    "refinement": {"type": "string", "enum": ["changed", "unchanged", "increased", "decreased", "exact"]},
                    "exact": {"type": "integer", "description": "Required when refinement is exact."},
                    "candidates": {"type": "array", "description": "Candidates returned by value_scan_start or value_scan_refine."}
                },
                "required": ["pid", "type", "refinement", "candidates"]
            }
        }),
        json!({
            "name": "value_explain",
            "title": "Explain Value Candidate",
            "description": "Explain one value candidate as AI-first evidence with local bytes, region/module context, typed numeric value, and next-tool hints.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Target process id."},
                    "candidate": {"type": "object", "description": "One candidate from value_scan_start or value_scan_refine."}
                },
                "required": ["pid", "candidate"]
            }
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn all_scope_uses_module_limit_for_main_module_region() {
        assert_eq!(
            region_read_limit(SnapshotScope::All, true),
            SnapshotScope::Module.limits().0
        );
        assert_eq!(
            region_read_limit(SnapshotScope::All, false),
            SnapshotScope::All.limits().0
        );
    }

    #[test]
    fn render_mem_modules_defaults_to_compact_list() {
        let modules = (0..20)
            .map(|idx| {
                json!({
                    "name": format!("mod{idx}.dll"),
                    "base": 0x400000u64 + (idx * 0x10000),
                    "size": 0x1000,
                })
            })
            .collect::<Vec<_>>();
        let text = render_mem_modules(&json!({
            "tool": "mem_modules",
            "modules": modules,
            "module_count": 20,
            "max_results": 3,
            "full": false,
            "argus": {"target_arch": "x86", "address_width": 32}
        }));

        assert!(text.contains("mem_modules: module_count: 20, target_arch: x86, address_width: 32"));
        assert!(text.contains("mod0.dll"));
        assert!(text.contains("mod2.dll"));
        assert!(!text.contains("mod3.dll"));
        assert!(text.contains("17 more omitted"));
    }

    #[test]
    fn render_scan_bytes_caps_text_hits_and_keeps_module_context() {
        let hits = (0..14)
            .map(|idx| {
                json!({
                    "address": 0x401000u64 + idx,
                    "address_context": {
                        "module": {"name": "game.exe", "base": 0x400000, "rva": idx},
                        "region": {"flags": {"executable": true}}
                    },
                    "context": {"ascii_preview": format!("hit-{idx}")}
                })
            })
            .collect::<Vec<_>>();
        let text = render_scan_bytes(&json!({
            "tool": "scan_bytes",
            "pattern": "FF 24 8D",
            "scan_scope": "executable",
            "hits": hits,
            "hit_count": 14
        }));

        assert!(text.contains("scan_bytes FF 24 8D [executable]: 14 hit(s)"));
        assert!(text.contains("[exec:game.exe]"));
        assert!(text.contains("hit-11"));
        assert!(!text.contains("hit-12"));
        assert!(text.contains("2 returned hit(s) omitted"));
    }

    #[test]
    fn initialize_returns_tools_capability_and_ai_instructions() {
        let response = handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"}
            }
        }));

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(
            response["result"]["capabilities"]["tools"]["listChanged"],
            false
        );
        assert!(response["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("does not make conclusions"));
    }

    #[test]
    fn tools_list_exposes_ai_first_memory_tools() {
        let response = handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }));

        let tools = response["result"]["tools"].as_array().unwrap();
        let names: Vec<_> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();

        assert!(names.contains(&"scan_string"));
        assert!(names.contains(&"scan_regex"));
        assert!(names.contains(&"scan_bytes"));
        assert!(names.contains(&"value_scan_start"));
        assert!(names.contains(&"mem_read"));
        assert!(names.contains(&"mem_write"));
        assert!(names.contains(&"mem_modules"));
        assert!(names.contains(&"memory_regions"));
        assert!(names.contains(&"mem_read_chain"));
        assert!(names.contains(&"read_struct"));
        assert!(names.contains(&"correlate_addr"));
        assert!(names.contains(&"locate"));
        assert!(names.contains(&"find_vtable"));
        assert!(names.contains(&"diff_struct"));
        assert!(names.contains(&"record_hypothesis"));
        assert!(names.contains(&"add_evidence"));
        assert!(names.contains(&"verify_hypothesis"));
        assert!(names.contains(&"query_hypotheses"));
        assert!(names.contains(&"real_rate"));
        assert!(names.contains(&"mem_attach"));
        assert!(names.contains(&"scan_pointers_to"));
        assert!(names.contains(&"scan_callers"));
        assert!(names.contains(&"value_scan_refine"));
        assert!(names.contains(&"value_explain"));
        assert!(names.contains(&"processes_list"));
        assert!(names.contains(&"processes_find"));
        assert!(names.contains(&"runtime_exports"));
        assert!(names.contains(&"resolve_api_targets"));
        assert!(names.contains(&"runtime_imports"));
        assert!(names.contains(&"resolve_iat_thunks"));
        assert!(names.contains(&"disasm_at"));
        assert!(names.contains(&"analyze_function"));
        assert!(names.contains(&"scan_x86_call_sites"));
        assert!(names.contains(&"analyze_send_call_sites"));
        assert!(names.contains(&"extract_dispatch_tables"));
        assert!(names.contains(&"trace_call_chain"));
        assert!(!names.contains(&"analysis_playbook"));
        assert!(!names.contains(&"find_dispatch_targets"));
        assert!(!names.contains(&"trace_packet_flow"));
        assert!(!names.contains(&"explain_send_recv_path"));
    }

    #[test]
    fn unknown_method_returns_jsonrpc_error() {
        let response = handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "nope",
            "params": {}
        }));

        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn initialized_notification_produces_no_response() {
        let response = handle_jsonrpc_message(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }));

        assert!(response.is_none());
    }

    static MCP_SCAN_PROBE: &[u8] = b"ARGUS_RS_MCP_SCAN_STRING";
    static MCP_VALUE_PROBE: u32 = 0xAABB_CCDD;

    fn call_tool(id: u64, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }))
    }

    fn tool_text(response: &Value) -> &str {
        response["result"]["content"][0]["text"].as_str().unwrap()
    }

    fn text_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
        let prefix = format!("{key}: ");
        text.lines()
            .find_map(|line| line.trim().strip_prefix(&prefix))
    }

    fn text_u64(text: &str, key: &str) -> u64 {
        let value = text_value(text, key).unwrap();
        let value = value.split_whitespace().next().unwrap();
        if let Some(hex) = value.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).unwrap()
        } else {
            value.parse().unwrap()
        }
    }

    fn unique_ledger_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "argus-rs-{name}-{}-{nanos}.json",
                std::process::id()
            ))
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn tools_call_scan_string_returns_text_json_evidence() {
        let response = handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "scan_string",
                "arguments": {
                    "pid": std::process::id(),
                    "pattern": "ARGUS_RS_MCP_SCAN_STRING",
                    "max_results": 1
                }
            }
        }));

        assert_eq!(MCP_SCAN_PROBE, b"ARGUS_RS_MCP_SCAN_STRING");
        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("scan_string \"ARGUS_RS_MCP_SCAN_STRING\""));
        assert!(text.contains("ARGUS_RS_MCP_SCAN_STRING"));
        assert!(!text.contains("\"tool\""));
    }

    #[test]
    fn tools_call_scan_string_writes_full_output_beyond_return_cap() {
        let blob = b"C_DESTROY_ITEM\0xxC_DESTROY_ITEM\0yyC_DESTROY_ITEM\0".to_vec();
        let out_path = PathBuf::from(unique_ledger_path("scan-full")).with_extension("csv");
        let response = call_tool(
            40,
            "scan_string",
            json!({
                "pid": std::process::id(),
                "pattern": "C_DESTROY_ITEM",
                "address": blob.as_ptr() as usize,
                "size": blob.len(),
                "max_results": 1,
                "full": true,
                "out_path": out_path,
                "out_format": "csv"
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("returned=1 total=3"));
        assert!(text.contains("out:"));
        let csv = fs::read_to_string(out_path).unwrap();
        assert_eq!(csv.lines().skip(1).count(), 3);
    }

    #[test]
    fn tools_call_scan_regex_finds_utf8_and_utf16_packet_names() {
        let mut blob = b"xxC_DESTROY_ITEM\0".to_vec();
        for unit in "S_SHOP_OPEN".encode_utf16() {
            blob.extend_from_slice(&unit.to_le_bytes());
        }
        blob.extend_from_slice(&0u16.to_le_bytes());

        let response = call_tool(
            41,
            "scan_regex",
            json!({
                "pid": std::process::id(),
                "pattern": "[CS]_[A-Za-z0-9_]+",
                "encoding": "both",
                "case_sensitive": false,
                "address": blob.as_ptr() as usize,
                "size": blob.len(),
                "max_results": 8
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("scan_regex \"[CS]_[A-Za-z0-9_]+\""));
        assert!(text.contains("C_DESTROY_ITEM"));
        assert!(text.contains("S_SHOP_OPEN"));
        assert!(text.contains("[utf16le/"));
    }

    #[test]
    fn tools_call_scan_bytes_returns_text_json_evidence() {
        let response = handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "scan_bytes",
                "arguments": {
                    "pid": std::process::id(),
                    "pattern": "41 52 47 55 53 5F 52 53",
                    "region": "all",
                    "max_results": 1
                }
            }
        }));

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("scan_bytes 41 52 47 55 53 5F 52 53 [all]"));
        assert!(text.contains("hit(s)"));
        assert!(!text.contains("\"tool\""));
    }

    #[test]
    fn tools_call_scan_bytes_defaults_to_executable_scope() {
        let response = call_tool(
            39,
            "scan_bytes",
            json!({
                "pid": std::process::id(),
                "pattern": "DE AD BE EF",
                "max_results": 1
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("scan_bytes DE AD BE EF [executable]"));
        assert!(!text.contains("\"scan_scope\""));
    }

    #[test]
    fn tools_call_scan_bytes_can_scan_targeted_window() {
        let response = call_tool(
            24,
            "scan_bytes",
            json!({
                "pid": std::process::id(),
                "pattern": "41 52 47 55 53 5F 52 53",
                "address": MCP_SCAN_PROBE.as_ptr() as u64,
                "size": MCP_SCAN_PROBE.len(),
                "max_results": 1
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("[window]"));
        assert!(text.contains("ARGUS_RS_MCP_SCAN_STRING"));
    }

    #[test]
    fn tools_call_disasm_at_uses_targeted_window_snapshot() {
        let response = call_tool(
            25,
            "disasm_at",
            json!({
                "pid": std::process::id(),
                "address": tools_call_disasm_at_uses_targeted_window_snapshot as *const () as usize,
                "count": 4
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(!text.trim().is_empty());
        assert!(!text.contains("\"snapshot_source\""));
    }

    #[test]
    fn tools_call_value_scan_start_returns_candidates() {
        let response = handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "value_scan_start",
                "arguments": {
                    "pid": std::process::id(),
                    "type": "u32",
                    "exact": MCP_VALUE_PROBE,
                    "max_results": 4
                }
            }
        }));

        assert_eq!(MCP_VALUE_PROBE, 0xAABB_CCDD);
        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("value_scan_start"));
        assert!(text.contains("candidate_count:"));
        assert!(!text.contains("\"tool\""));
    }

    #[test]
    fn tools_call_mem_modules_returns_modules() {
        let response = call_tool(
            7,
            "mem_modules",
            json!({
                "pid": std::process::id()
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("mem_modules"));
        assert!(text.contains("module_count:"));
        assert!(text.contains("target_arch:"));
    }

    #[test]
    fn tools_call_memory_regions_returns_committed_regions() {
        let response = call_tool(
            21,
            "memory_regions",
            json!({
                "pid": std::process::id(),
                "limit": 16
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("memory_regions"));
        assert!(text.contains("region_count:"));
        assert!(text.contains("regions:"));
    }

    #[test]
    fn tools_call_runtime_exports_returns_export_payload() {
        let response = call_tool(
            22,
            "runtime_exports",
            json!({
                "pid": std::process::id(),
                "module_name": "kernel",
                "name_contains": "Get",
                "max_results": 4
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("runtime_exports"));
        assert!(text.contains("export_count:"));
        assert!(text.contains("exports:"));
    }

    #[test]
    fn tools_call_resolve_api_targets_accepts_dll_bang_name() {
        let response = call_tool(
            23,
            "resolve_api_targets",
            json!({
                "pid": std::process::id(),
                "api": "kernel32!GetTickCount",
                "max_results": 4
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("resolve_api_targets"));
        assert!(text.contains("target_count:"));
        assert!(text.contains("targets:"));
    }

    #[test]
    fn tools_call_processes_list_returns_process_table() {
        let response = call_tool(12, "processes_list", json!({}));

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("processes_list"));
        assert!(text.contains("process_count:"));
        assert!(text.contains("processes:"));
    }

    #[test]
    fn tool_results_include_argus_address_width_context() {
        let response = call_tool(20, "processes_list", json!({"limit": 1}));

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains(&format!("address_width: {}", usize::BITS)));
        assert!(text.contains("target_arch:"));
    }

    #[test]
    fn tools_call_processes_find_can_find_current_process_by_pid() {
        let response = call_tool(
            13,
            "processes_find",
            json!({
                "pid": std::process::id(),
                "limit": 1
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("processes_find"));
        assert!(text.contains(&format!("pid: {}", std::process::id())));
    }

    #[test]
    fn tools_call_processes_find_can_find_current_process_by_name() {
        let exe_name = std::env::current_exe()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let response = call_tool(
            13,
            "processes_find",
            json!({
                "name_contains": exe_name,
                "limit": 5
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("processes_find"));
        assert!(text.contains(&format!("pid: {}", std::process::id())));
    }

    #[test]
    fn tools_call_mem_read_returns_ai_first_evidence() {
        let response = call_tool(
            8,
            "mem_read",
            json!({
                "pid": std::process::id(),
                "address": MCP_SCAN_PROBE.as_ptr() as u64,
                "size": MCP_SCAN_PROBE.len()
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("ARGUS_RS_MCP_SCAN_STRING"));
        assert!(!text.contains("\"tool\""));
    }

    #[test]
    fn tools_call_mem_attach_returns_stateless_process_context() {
        let response = call_tool(
            38,
            "mem_attach",
            json!({
                "pid": std::process::id()
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("mem_attach"));
        assert!(text.contains(&format!("pid: {}", std::process::id())));
        assert!(text.contains("stateless: true"));
        assert!(text.contains("modules:"));
    }

    #[test]
    fn tools_call_mem_write_writes_current_process_memory() {
        let mut buffer = *b"ARGUS_TOOL_OLD";
        let response = call_tool(
            29,
            "mem_write",
            json!({
                "pid": std::process::id(),
                "address": buffer.as_mut_ptr() as usize,
                "hex_data": "41 52 47 55 53 5F 54 4F 4F 4C 5F 4E 45 57"
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        assert_eq!(&buffer, b"ARGUS_TOOL_NEW");
        let text = tool_text(&response);
        assert!(text.contains("mem_write"));
        assert!(text.contains("bytes_written:"));
    }

    #[test]
    fn tools_call_mem_read_chain_returns_steps_and_final_bytes() {
        let final_addr = MCP_SCAN_PROBE.as_ptr() as usize;
        let pointer_value = final_addr;
        let response = call_tool(
            26,
            "mem_read_chain",
            json!({
                "pid": std::process::id(),
                "base_address": (&pointer_value as *const usize) as usize,
                "offsets": "",
                "final_size": MCP_SCAN_PROBE.len()
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("chain:"));
        assert!(text.contains("ARGUS_RS_MCP_SCAN_STRING"));
    }

    #[test]
    fn tools_call_read_struct_returns_word_evidence() {
        let response = call_tool(
            27,
            "read_struct",
            json!({
                "pid": std::process::id(),
                "address": MCP_SCAN_PROBE.as_ptr() as usize,
                "count": 2
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("0x"));
        assert!(!text.contains("\"tool\""));
    }

    #[test]
    fn tools_call_correlate_addr_returns_live_static_rva() {
        let response = call_tool(
            28,
            "correlate_addr",
            json!({
                "pid": std::process::id(),
                "live_addr": MCP_SCAN_PROBE.as_ptr() as usize,
                "ghidra_image_base": "0x400000"
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("correlate_addr"));
        assert!(text.contains("rva:"));
        assert!(text.contains("static_addr:"));
        assert!(text.contains("live_addr:"));
    }

    #[test]
    fn tools_call_diff_struct_overlays_static_fields_on_live_memory() {
        #[repr(C)]
        struct Probe {
            first: u32,
            second: u32,
        }
        let probe = Probe {
            first: 0x1234_5678,
            second: 0x90ab_cdef,
        };

        let response = call_tool(
            30,
            "diff_struct",
            json!({
                "pid": std::process::id(),
                "struct_name": "Probe",
                "live_address": (&probe as *const Probe) as usize,
                "fields": [
                    {"offset": 0, "name": "first", "type": "uint32_t", "length": 4},
                    {"offset": 4, "name": "second", "type": "uint32_t", "length": 4}
                ]
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = tool_text(&response);
        assert!(text.contains("struct Probe @"));
        assert!(text.contains("fields=2"));
        assert!(text.contains("first"));
        assert!(text.contains("78563412"));
        assert!(text.contains("second"));
        assert!(text.contains("efcdab90"));
    }

    #[test]
    fn tools_call_hypothesis_ledger_records_evidence_and_real_rate() {
        let ledger_path = unique_ledger_path("hypothesis");
        let first = call_tool(
            31,
            "record_hypothesis",
            json!({
                "entity": "func@0x401000",
                "claim_type": "name",
                "claim_value": "C_Login",
                "source": "llm",
                "ledger_path": ledger_path
            }),
        );
        assert_eq!(first["result"]["isError"], false);
        let first_text = tool_text(&first);
        assert!(first_text.contains("record_hypothesis"));
        let first_id = text_u64(first_text, "id");

        let add = call_tool(
            32,
            "add_evidence",
            json!({
                "hypothesis_id": first_id,
                "kind": "xref",
                "detail": "string ref at 0x401020",
                "source": "dynamic",
                "addr": "0x401020",
                "ledger_path": ledger_path
            }),
        );
        assert_eq!(add["result"]["isError"], false);

        let verify = call_tool(
            33,
            "verify_hypothesis",
            json!({
                "hypothesis_id": first_id,
                "verdict": "verified",
                "ledger_path": ledger_path
            }),
        );
        assert_eq!(verify["result"]["isError"], false);

        let second = call_tool(
            34,
            "record_hypothesis",
            json!({
                "entity": "func@0x402000",
                "claim_type": "name",
                "claim_value": "WrongName",
                "source": "static",
                "ledger_path": ledger_path
            }),
        );
        let second_id = text_u64(tool_text(&second), "id");
        let contradicted = call_tool(
            35,
            "verify_hypothesis",
            json!({
                "hypothesis_id": second_id,
                "verdict": "contradicted",
                "note": "dynamic caller evidence disagreed",
                "ledger_path": ledger_path
            }),
        );
        assert_eq!(contradicted["result"]["isError"], false);

        let query = call_tool(
            36,
            "query_hypotheses",
            json!({
                "entity": "func@0x402000",
                "ledger_path": ledger_path
            }),
        );
        let query_text = tool_text(&query);
        assert!(query_text.contains("query_hypotheses"));
        assert!(query_text.contains("count: 1"));
        assert!(query_text.contains("negative_knowledge:"));
        assert!(query_text.contains("WrongName"));

        let rate = call_tool(37, "real_rate", json!({"ledger_path": ledger_path}));
        let rate_text = tool_text(&rate);
        assert!(rate_text.contains("real_rate"));
        assert!(rate_text.contains("verified: 1"));
        assert!(rate_text.contains("total: 2"));
        assert!(rate_text.contains("rate: 0.5"));
    }

    #[test]
    fn tools_call_scan_pointers_to_returns_json_result() {
        let response = call_tool(
            9,
            "scan_pointers_to",
            json!({
                "pid": std::process::id(),
                "address": 0,
                "max_results": 1
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("scan_pointers_to"));
        assert!(text.contains("(no hits)") || text.contains("hit(s)"));
    }

    #[test]
    fn tools_call_scan_callers_returns_json_result() {
        let response = call_tool(
            10,
            "scan_callers",
            json!({
                "pid": std::process::id(),
                "target": 0,
                "max_results": 1
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("scan_callers"));
        assert!(text.contains("(no callers)") || text.contains("caller(s)"));
    }

    #[test]
    fn tools_call_value_scan_refine_returns_candidates() {
        let response = call_tool(
            11,
            "value_scan_refine",
            json!({
                "pid": std::process::id(),
                "type": "u32",
                "refinement": "unchanged",
                "candidates": [{
                    "address": &MCP_VALUE_PROBE as *const u32 as u64,
                    "value_type": "U32",
                    "value": {"U32": MCP_VALUE_PROBE},
                    "previous_value": null
                }]
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("value_scan_refine"));
        assert!(text.contains("candidate_count:"));
    }

    #[test]
    fn tools_call_value_explain_returns_numeric_evidence() {
        let response = call_tool(
            12,
            "value_explain",
            json!({
                "pid": std::process::id(),
                "candidate": {
                    "address": &MCP_VALUE_PROBE as *const u32 as u64,
                    "value_type": "U32",
                    "value": {"U32": MCP_VALUE_PROBE},
                    "previous_value": null
                }
            }),
        );

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("0x"));
        assert!(text.contains("Numeric"));
        assert!(!text.contains("\"tool\""));
    }
}
