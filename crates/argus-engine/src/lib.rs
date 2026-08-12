#![forbid(unsafe_code)]

use argus_scan::{match_aob_limited, parse_aob, ParseAobError};
use evidence_core::{
    Address, AddressContext, EvidenceContext, EvidenceHit, EvidenceValue, ModuleBase,
    ModuleContext, NextToolHint, RegionContext, RegionFlags, RegionKind, Rva, TargetArch,
    ToolArgument,
};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, Mnemonic, NasmFormatter};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base: ModuleBase,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: Address,
    pub bytes: Vec<u8>,
    pub kind: RegionKind,
    pub flags: RegionFlags,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InMemoryBackend {
    pub modules: Vec<ModuleInfo>,
    pub regions: Vec<MemoryRegion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgusEngine {
    backend: InMemoryBackend,
    target_arch: TargetArch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueType {
    U32,
}

impl ValueType {
    fn size(self) -> usize {
        match self {
            Self::U32 => 4,
        }
    }

    pub fn byte_len(self) -> usize {
        self.size()
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::U32 => "u32",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NumericValue {
    U32(u32),
}

impl NumericValue {
    fn as_u64(self) -> u64 {
        match self {
            Self::U32(value) => value as u64,
        }
    }
}

impl std::fmt::Display for NumericValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::U32(value) => write!(formatter, "{value}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValuePredicate {
    ExactU64(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueRefinement {
    ExactU64(u64),
    Changed,
    Unchanged,
    Increased,
    Decreased,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueCandidate {
    pub address: Address,
    pub value_type: ValueType,
    pub value: NumericValue,
    pub previous_value: Option<NumericValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueScanSession {
    pub value_type: ValueType,
    pub candidates: Vec<ValueCandidate>,
}

struct HitSpec<'a> {
    label: &'a str,
    address: Address,
    region: &'a MemoryRegion,
    offset: usize,
    evidence_len: usize,
    evidence: EvidenceValue,
    next_tools: Vec<NextToolHint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInstruction {
    pub address: Address,
    pub rva: Option<Rva>,
    pub bytes: Vec<u8>,
    pub text: String,
    pub call_target: Option<Address>,
    pub call_target_rva: Option<Rva>,
    pub string: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzedFunction {
    pub address: Address,
    pub end: Address,
    pub instructions: Vec<RuntimeInstruction>,
    pub callees: Vec<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X86CallSite {
    pub address: Address,
    pub function_start: Option<Address>,
    pub instruction: RuntimeInstruction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushEvidence {
    pub instruction: RuntimeInstruction,
    pub value: u64,
    pub width_bits: u8,
    pub string: Option<String>,
    pub packet_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendCallSiteEvidence {
    pub call_site: X86CallSite,
    pub preceding_instructions: Vec<RuntimeInstruction>,
    pub pushes: Vec<PushEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocateResult {
    pub string_address: Address,
    pub ref_site: Address,
    pub function_start: Option<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtableMethod {
    pub index: usize,
    pub address: Address,
    pub prologue: Vec<u8>,
    pub instruction: Option<RuntimeInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtableEvidence {
    pub class_name: String,
    pub decorated_name: String,
    pub rtti_string: Option<Address>,
    pub type_descriptor: Option<Address>,
    pub col: Option<Address>,
    pub vtable: Option<Address>,
    pub methods: Vec<VtableMethod>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BranchKind {
    Call,
    Jump,
    ConditionalJump,
    UnresolvedIndirect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchBranch {
    pub kind: BranchKind,
    pub instruction: RuntimeInstruction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchTableCandidate {
    pub address: Address,
    pub kind: String,
    pub score: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchTableEntry {
    pub opcode: u16,
    pub opcode_value_location: Address,
    pub dispatch_index: u8,
    pub jump_slot: Option<Address>,
    pub stub: Option<Address>,
    pub handler: Option<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchTableEvidence {
    pub dispatcher: Address,
    pub index_table: Option<Address>,
    pub jump_table: Option<Address>,
    pub candidates: Vec<DispatchTableCandidate>,
    pub entries: Vec<DispatchTableEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallChainNode {
    pub depth: usize,
    pub target: Address,
    pub callers: Vec<X86CallSite>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeImport {
    pub module: String,
    pub dll: String,
    pub name: String,
    pub ordinal: Option<u16>,
    pub iat_address: Address,
    pub target: Option<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeExport {
    pub module: String,
    pub name: String,
    pub ordinal: u32,
    pub address: Address,
    pub rva: Rva,
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IatThunk {
    pub import: RuntimeImport,
    pub thunk_address: Address,
    pub instruction: RuntimeInstruction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketFlowAnchor {
    pub name: String,
    pub address: Address,
    pub function: Option<AnalyzedFunction>,
    pub callers: Vec<X86CallSite>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketFlowReport {
    pub anchors: Vec<PacketFlowAnchor>,
}

impl ArgusEngine {
    pub fn new(backend: InMemoryBackend) -> Self {
        Self::new_for_target(backend, TargetArch::X86)
    }

    pub fn new_for_target(backend: InMemoryBackend, target_arch: TargetArch) -> Self {
        Self {
            backend,
            target_arch,
        }
    }

    pub fn target_arch(&self) -> TargetArch {
        self.target_arch
    }

    pub fn pointer_width_bytes(&self) -> usize {
        self.target_arch.pointer_width_bytes()
    }

    pub fn mem_read(&self, address: Address, size: usize) -> Option<EvidenceHit> {
        let (region, offset) = self.region_at(address)?;
        let end = offset.saturating_add(size).min(region.bytes.len());
        let bytes = region.bytes[offset..end].to_vec();

        Some(self.hit(HitSpec {
            label: "mem_read",
            address,
            region,
            offset,
            evidence_len: bytes.len(),
            evidence: EvidenceValue::Bytes { bytes },
            next_tools: vec![self.next_tool(
                "scan_pointers_to",
                "find pointers that reference this memory address",
                address,
            )],
        }))
    }

    pub fn scan_bytes(
        &self,
        pattern: &str,
        max_results: usize,
    ) -> Result<Vec<EvidenceHit>, ParseAobError> {
        let pattern = parse_aob(pattern)?;
        let mut hits = Vec::new();

        for region in self.readable_regions() {
            if hits.len() >= max_results {
                break;
            }

            for offset in match_aob_limited(
                &region.bytes,
                &pattern,
                max_results.saturating_sub(hits.len()),
            ) {
                let address = Address(region.base.0 + offset as u64);
                hits.push(self.hit(HitSpec {
                    label: "scan_bytes",
                    address,
                    region,
                    offset,
                    evidence_len: pattern.bytes.len(),
                    evidence: EvidenceValue::Bytes {
                        bytes: region.bytes[offset..offset + pattern.bytes.len()].to_vec(),
                    },
                    next_tools: vec![
                        self.next_tool(
                            "mem_read",
                            "read a wider byte window around this hit",
                            address,
                        ),
                        self.next_tool(
                            "ghydra.memory_disassemble",
                            "compare this runtime byte hit with static disassembly",
                            address,
                        ),
                    ],
                }));
            }
        }

        Ok(hits)
    }

    pub fn scan_string(&self, needle: &str, max_results: usize) -> Vec<EvidenceHit> {
        if needle.is_empty() || max_results == 0 {
            return Vec::new();
        }

        let needle_bytes = needle.as_bytes();
        let mut hits = Vec::new();
        for region in self.readable_regions() {
            if hits.len() >= max_results {
                break;
            }

            let mut search_from = 0;
            while hits.len() < max_results && search_from <= region.bytes.len() {
                let Some(relative) = find_bytes(&region.bytes[search_from..], needle_bytes) else {
                    break;
                };
                let offset = search_from + relative;
                let address = Address(region.base.0 + offset as u64);
                hits.push(self.hit(HitSpec {
                    label: "scan_string",
                    address,
                    region,
                    offset,
                    evidence_len: needle_bytes.len(),
                    evidence: EvidenceValue::Utf8 {
                        text: needle.to_string(),
                    },
                    next_tools: vec![
                        self.next_tool(
                            "scan_pointers_to",
                            "find code or data references to this string",
                            address,
                        ),
                        self.next_tool(
                            "mem_read",
                            "read a wider context window around this string",
                            address,
                        ),
                        self.next_tool(
                            "ghydra.functions_decompile",
                            "decompile nearby static code after a runtime reference is found",
                            address,
                        ),
                    ],
                }));
                search_from = offset + needle_bytes.len();
            }
        }

        hits
    }

    pub fn scan_pointers_to(&self, target: Address, max_results: usize) -> Vec<EvidenceHit> {
        if max_results == 0 || !self.pointer_can_represent(target) {
            return Vec::new();
        }

        let needle = self.pointer_bytes(target);
        let mut hits = Vec::new();

        for region in self.readable_regions() {
            if hits.len() >= max_results {
                break;
            }

            let mut search_from = 0;
            while hits.len() < max_results && search_from <= region.bytes.len() {
                let Some(relative) = find_bytes(&region.bytes[search_from..], &needle) else {
                    break;
                };
                let offset = search_from + relative;
                let address = Address(region.base.0 + offset as u64);
                hits.push(self.hit(HitSpec {
                    label: "scan_pointers_to",
                    address,
                    region,
                    offset,
                    evidence_len: needle.len(),
                    evidence: EvidenceValue::Pointer { target },
                    next_tools: vec![
                        self.next_tool("mem_read", "read the pointed-to memory target", target),
                        self.next_tool(
                            "ghydra.data_list",
                            "compare this pointer location with static data references",
                            address,
                        ),
                    ],
                }));
                search_from = offset + needle.len();
            }
        }

        hits
    }

    pub fn scan_callers(&self, target: Address, max_results: usize) -> Vec<EvidenceHit> {
        if max_results == 0 {
            return Vec::new();
        }

        let mut hits = Vec::new();
        for region in self.executable_regions() {
            if hits.len() >= max_results || region.bytes.len() < 5 {
                break;
            }

            for offset in 0..region.bytes.len() {
                let opcode = region.bytes[offset];
                let source = Address(region.base.0 + offset as u64);
                let evidence =
                    if (opcode == 0xE8 || opcode == 0xE9) && offset + 5 <= region.bytes.len() {
                        let rel = i32::from_le_bytes([
                            region.bytes[offset + 1],
                            region.bytes[offset + 2],
                            region.bytes[offset + 3],
                            region.bytes[offset + 4],
                        ]) as i64;
                        let destination = (source.0 + 5) as i64 + rel;
                        if destination < 0 || destination as u64 != target.0 {
                            continue;
                        }
                        (5, EvidenceValue::Caller { target, opcode })
                    } else if opcode == 0xFF
                        && offset + 6 <= region.bytes.len()
                        && (region.bytes[offset + 1] == 0x15 || region.bytes[offset + 1] == 0x25)
                    {
                        let bytes = &region.bytes[offset..offset + 6];
                        let Some(pointer) = self.indirect_pointer_operand(source.0, bytes) else {
                            continue;
                        };
                        if self.read_pointer_at(pointer) != Some(target) {
                            continue;
                        }
                        (
                            6,
                            EvidenceValue::IndirectCaller {
                                target,
                                opcode,
                                pointer,
                            },
                        )
                    } else {
                        continue;
                    };

                hits.push(self.hit(HitSpec {
                    label: "scan_callers",
                    address: source,
                    region,
                    offset,
                    evidence_len: evidence.0,
                    evidence: evidence.1,
                    next_tools: vec![
                        self.next_tool(
                            "ghydra.functions_decompile",
                            "decompile the static function containing this caller",
                            source,
                        ),
                        self.next_tool(
                            "mem_read",
                            "read runtime bytes around this call or jump",
                            source,
                        ),
                    ],
                }));

                if hits.len() >= max_results {
                    break;
                }
            }
        }

        hits
    }

    pub fn disasm_at(&self, address: Address, count: usize) -> Vec<RuntimeInstruction> {
        if count == 0 {
            return Vec::new();
        }

        let Some((region, offset)) = self.region_at(address) else {
            return Vec::new();
        };
        let max_len = (count * 15).min(4096);
        let end = offset.saturating_add(max_len).min(region.bytes.len());
        let data = &region.bytes[offset..end];
        let mut decoder = Decoder::with_ip(
            self.target_arch.decoder_bitness(),
            data,
            address.0,
            DecoderOptions::NONE,
        );
        let mut formatter = NasmFormatter::new();
        let mut instruction = Instruction::default();
        let mut output = String::new();
        let mut instructions = Vec::new();

        while decoder.can_decode() && instructions.len() < count {
            decoder.decode_out(&mut instruction);
            output.clear();
            formatter.format(&instruction, &mut output);

            let ip = instruction.ip();
            let start = ip.saturating_sub(address.0) as usize;
            let len = instruction.len().min(data.len().saturating_sub(start));
            let bytes = data[start..start + len].to_vec();
            let target = self.direct_or_indirect_target(ip, &bytes);
            let string = self.push_string(&bytes);
            let call_target_rva =
                target.and_then(|target| self.module_at(target).map(|module| module.rva));
            let rva = self.module_at(Address(ip)).map(|module| module.rva);

            instructions.push(RuntimeInstruction {
                address: Address(ip),
                rva,
                bytes,
                text: output.clone(),
                call_target: target,
                call_target_rva,
                string,
            });

            if instructions.len() >= count || (is_ret(&instruction) && instructions.len() > 3) {
                break;
            }
        }

        instructions
    }

    pub fn analyze_function(&self, address: Address, max_insn: usize) -> Option<AnalyzedFunction> {
        let instructions = self.disasm_at(address, max_insn);
        if instructions.is_empty() {
            return None;
        }

        let mut callees = Vec::new();
        for instruction in &instructions {
            if !instruction.text.starts_with("call") {
                continue;
            }
            if let Some(target) = instruction.call_target {
                if !callees.contains(&target) {
                    callees.push(target);
                }
            }
        }

        Some(AnalyzedFunction {
            address,
            end: instructions
                .last()
                .map(|insn| insn.address)
                .unwrap_or(address),
            instructions,
            callees,
        })
    }

    pub fn dispatch_branches(
        &self,
        address: Address,
        max_insn: usize,
    ) -> Option<Vec<DispatchBranch>> {
        let function = self.analyze_function(address, max_insn)?;
        Some(
            function
                .instructions
                .into_iter()
                .filter_map(|instruction| {
                    branch_kind(&instruction).map(|kind| DispatchBranch { kind, instruction })
                })
                .collect(),
        )
    }

    pub fn extract_dispatch_tables(
        &self,
        dispatcher: Address,
        max_insn: usize,
        max_entries: usize,
        index_table: Option<Address>,
        jump_table: Option<Address>,
    ) -> DispatchTableEvidence {
        let instructions = self.disasm_at(dispatcher, max_insn);
        let mut candidate_addresses = Vec::new();
        for instruction in &instructions {
            for address in self.immediate_address_candidates(&instruction.bytes) {
                if self.region_at(address).is_some() && !candidate_addresses.contains(&address) {
                    candidate_addresses.push(address);
                }
            }
        }

        let mut candidates = Vec::new();
        for address in &candidate_addresses {
            let index_score = self.score_index_table(*address, max_entries);
            if index_score > 0 {
                candidates.push(DispatchTableCandidate {
                    address: *address,
                    kind: "index_table".to_string(),
                    score: index_score,
                });
            }
            let jump_score = self.score_jump_table(*address, max_entries);
            if jump_score > 0 {
                candidates.push(DispatchTableCandidate {
                    address: *address,
                    kind: "jump_table".to_string(),
                    score: jump_score,
                });
            }
        }

        let index_table = index_table.or_else(|| {
            candidates
                .iter()
                .filter(|candidate| candidate.kind == "index_table")
                .max_by_key(|candidate| candidate.score)
                .map(|candidate| candidate.address)
        });
        let jump_table = jump_table.or_else(|| {
            candidates
                .iter()
                .filter(|candidate| candidate.kind == "jump_table")
                .max_by_key(|candidate| candidate.score)
                .map(|candidate| candidate.address)
        });

        let mut entries = Vec::new();
        if let (Some(index_table), Some(jump_table)) = (index_table, jump_table) {
            let capped_entries = max_entries.min(u16::MAX as usize + 1);
            let pointer_width = self.pointer_width_bytes() as u64;
            for opcode in 0..capped_entries {
                let opcode_value_location = Address(index_table.0 + opcode as u64);
                let Some(dispatch_index) = self.read_bytes_at(opcode_value_location, 1) else {
                    continue;
                };
                let dispatch_index = dispatch_index[0];
                let jump_slot = Address(jump_table.0 + dispatch_index as u64 * pointer_width);
                let stub = self.read_pointer_at(jump_slot);
                let handler = stub.and_then(|stub| self.dispatch_stub_handler(stub));
                entries.push(DispatchTableEntry {
                    opcode: opcode as u16,
                    opcode_value_location,
                    dispatch_index,
                    jump_slot: Some(jump_slot),
                    stub,
                    handler,
                });
            }
        }

        DispatchTableEvidence {
            dispatcher,
            index_table,
            jump_table,
            candidates,
            entries,
        }
    }

    pub fn find_function_start(&self, address: Address, window: usize) -> Option<Address> {
        let (region, offset) = self.region_at(address)?;
        let start = offset.saturating_sub(window);
        let bytes = &region.bytes[start..offset];
        let base = region.base.0 + start as u64;
        let prologues: [&[u8]; 3] = [b"\x55\x8B\xEC", b"\x55\x89\xE5", b"\x53\x56\x57"];

        let mut best = None;
        for prologue in prologues {
            if bytes.len() < prologue.len() {
                continue;
            }
            for idx in 0..=(bytes.len() - prologue.len()) {
                if &bytes[idx..idx + prologue.len()] == prologue {
                    best = Some(Address(base + idx as u64));
                }
            }
        }
        best
    }

    pub fn scan_x86_call_sites(&self, target: Address, max_results: usize) -> Vec<X86CallSite> {
        let mut sites = Vec::new();
        for hit in self.scan_callers(target, max_results) {
            let instruction =
                self.disasm_at(hit.address, 1)
                    .into_iter()
                    .next()
                    .unwrap_or(RuntimeInstruction {
                        address: hit.address,
                        rva: None,
                        bytes: Vec::new(),
                        text: String::new(),
                        call_target: Some(target),
                        call_target_rva: None,
                        string: None,
                    });
            sites.push(X86CallSite {
                address: hit.address,
                function_start: self.find_function_start(hit.address, 0x600),
                instruction,
            });
        }
        sites
    }

    pub fn analyze_send_call_sites(
        &self,
        target: Address,
        max_results: usize,
        max_preceding_instructions: usize,
        backward_bytes: usize,
    ) -> Vec<SendCallSiteEvidence> {
        self.scan_x86_call_sites(target, max_results)
            .into_iter()
            .map(|call_site| {
                let start = call_site.function_start.unwrap_or_else(|| {
                    self.region_at(call_site.address)
                        .map(|(region, offset)| {
                            Address(region.base.0 + offset.saturating_sub(backward_bytes) as u64)
                        })
                        .unwrap_or(call_site.address)
                });
                let instructions =
                    self.disasm_at(start, max_preceding_instructions.saturating_add(64));
                let mut preceding_instructions: Vec<_> = instructions
                    .into_iter()
                    .filter(|instruction| instruction.address.0 < call_site.address.0)
                    .collect();
                if preceding_instructions.len() > max_preceding_instructions {
                    let keep_from = preceding_instructions.len() - max_preceding_instructions;
                    preceding_instructions = preceding_instructions.split_off(keep_from);
                }
                let pushes = preceding_instructions
                    .iter()
                    .filter_map(|instruction| self.push_evidence(instruction))
                    .collect();
                SendCallSiteEvidence {
                    call_site,
                    preceding_instructions,
                    pushes,
                }
            })
            .collect()
    }

    pub fn trace_call_chain(
        &self,
        target: Address,
        max_depth: usize,
        max_callers_per_depth: usize,
    ) -> Vec<CallChainNode> {
        let mut nodes = Vec::new();
        let mut frontier = vec![target];
        let mut seen = vec![target];

        for depth in 0..max_depth {
            let mut next_frontier = Vec::new();
            for target in frontier {
                let callers = self.scan_x86_call_sites(target, max_callers_per_depth);
                for caller in &callers {
                    if let Some(function_start) = caller.function_start {
                        if !seen.contains(&function_start) {
                            seen.push(function_start);
                            next_frontier.push(function_start);
                        }
                    }
                }
                nodes.push(CallChainNode {
                    depth,
                    target,
                    callers,
                });
            }
            if next_frontier.is_empty() {
                break;
            }
            frontier = next_frontier;
        }

        nodes
    }

    pub fn locate(&self, query: &str, max_hits: usize) -> Vec<LocateResult> {
        if query.is_empty() || max_hits == 0 {
            return Vec::new();
        }

        let mut results = Vec::new();
        for string_hit in self.scan_string(query, 20) {
            for ref_hit in self.scan_pointers_to(string_hit.address, 30) {
                let Some((region, _)) = self.region_at(ref_hit.address) else {
                    continue;
                };
                if !region.flags.executable {
                    continue;
                }

                results.push(LocateResult {
                    string_address: string_hit.address,
                    ref_site: ref_hit.address,
                    function_start: self.find_function_start(ref_hit.address, 0x600),
                });
                if results.len() >= max_hits {
                    return results;
                }
            }
        }

        results
    }

    pub fn find_vtable(&self, class_name: &str, max_methods: usize) -> VtableEvidence {
        let decorated_name = decorate_class_name(class_name);
        for string_hit in self.scan_string(&decorated_name, 10) {
            let type_descriptor = Address(string_hit.address.0.saturating_sub(8));
            for td_ref in self.scan_pointers_to(type_descriptor, 50) {
                let Some(col_address) = td_ref.address.0.checked_sub(0x0c).map(Address) else {
                    continue;
                };
                if self.read_u32_at(col_address) != Some(0) {
                    continue;
                }

                for col_ref in self.scan_pointers_to(col_address, 50) {
                    let vtable = Address(col_ref.address.0 + 4);
                    let methods = self.vtable_dump(vtable, max_methods);
                    if !methods.is_empty() {
                        return VtableEvidence {
                            class_name: class_name.to_string(),
                            decorated_name,
                            rtti_string: Some(string_hit.address),
                            type_descriptor: Some(type_descriptor),
                            col: Some(col_address),
                            vtable: Some(vtable),
                            methods,
                            error: None,
                        };
                    }
                }
            }
        }

        VtableEvidence {
            class_name: class_name.to_string(),
            decorated_name: decorated_name.clone(),
            rtti_string: None,
            type_descriptor: None,
            col: None,
            vtable: None,
            methods: Vec::new(),
            error: Some(format!(
                "RTTI/vtable evidence not found for {decorated_name}"
            )),
        }
    }

    pub fn vtable_dump(&self, address: Address, count: usize) -> Vec<VtableMethod> {
        let mut methods = Vec::new();
        for index in 0..count {
            let slot = Address(address.0 + (index as u64 * 4));
            let Some(ptr) = self.read_u32_at(slot) else {
                break;
            };
            if ptr == 0 {
                break;
            }

            let method_address = Address(ptr as u64);
            let Some(prologue) = self.read_bytes_at(method_address, 16) else {
                break;
            };
            let instruction = self.disasm_at(method_address, 1).into_iter().next();
            methods.push(VtableMethod {
                index,
                address: method_address,
                prologue: prologue.to_vec(),
                instruction,
            });
        }

        methods
    }

    pub fn runtime_imports(
        &self,
        module_name: Option<&str>,
        max_results: usize,
    ) -> Vec<RuntimeImport> {
        let Some(module) = self.select_module(module_name) else {
            return Vec::new();
        };
        self.parse_imports_for_module(module, max_results)
    }

    pub fn runtime_exports(
        &self,
        module_name: Option<&str>,
        name_contains: Option<&str>,
        max_results: usize,
    ) -> Vec<RuntimeExport> {
        if max_results == 0 {
            return Vec::new();
        }
        let module_needle = module_name.map(str::to_ascii_lowercase);
        let name_needle = name_contains.map(str::to_ascii_lowercase);
        let mut exports = Vec::new();

        for module in &self.backend.modules {
            if let Some(needle) = &module_needle {
                if !module.name.to_ascii_lowercase().contains(needle) {
                    continue;
                }
            }
            for export in self.parse_exports_for_module(module, name_needle.as_deref(), max_results)
            {
                exports.push(export);
                if exports.len() >= max_results {
                    return exports;
                }
            }
        }

        exports
    }

    pub fn resolve_iat_thunks(
        &self,
        module_name: Option<&str>,
        name_contains: Option<&str>,
        max_results: usize,
    ) -> Vec<IatThunk> {
        let needle = name_contains.map(|value| value.to_ascii_lowercase());
        let imports = self.runtime_imports(module_name, max_results);
        let mut thunks = Vec::new();

        for import in imports {
            if let Some(needle) = &needle {
                let haystack = format!("{}!{}", import.dll, import.name).to_ascii_lowercase();
                if !haystack.contains(needle) {
                    continue;
                }
            }
            for region in self.executable_regions() {
                if thunks.len() >= max_results || region.bytes.len() < 6 {
                    break;
                }
                for offset in 0..=(region.bytes.len() - 6) {
                    let bytes = &region.bytes[offset..offset + 6];
                    if bytes[0] != 0xFF || (bytes[1] != 0x25 && bytes[1] != 0x15) {
                        continue;
                    }
                    let address = Address(region.base.0 + offset as u64);
                    let Some(iat) = self.indirect_pointer_operand(address.0, bytes) else {
                        continue;
                    };
                    if iat != import.iat_address {
                        continue;
                    }
                    if let Some(instruction) = self.disasm_at(address, 1).into_iter().next() {
                        thunks.push(IatThunk {
                            import: import.clone(),
                            thunk_address: address,
                            instruction,
                        });
                    }
                    if thunks.len() >= max_results {
                        break;
                    }
                }
            }
        }

        thunks
    }

    pub fn packet_flow_report(
        &self,
        anchors: Vec<(String, Address)>,
        max_callers_per_anchor: usize,
        max_insn: usize,
    ) -> PacketFlowReport {
        let anchors = anchors
            .into_iter()
            .map(|(name, address)| PacketFlowAnchor {
                name,
                address,
                function: self.analyze_function(address, max_insn),
                callers: self.scan_x86_call_sites(address, max_callers_per_anchor),
            })
            .collect();
        PacketFlowReport { anchors }
    }

    pub fn value_scan_start(
        &self,
        value_type: ValueType,
        predicate: ValuePredicate,
        max_results: usize,
    ) -> ValueScanSession {
        let mut candidates = Vec::new();
        if max_results == 0 {
            return ValueScanSession {
                value_type,
                candidates,
            };
        }

        for region in self.readable_regions() {
            if candidates.len() >= max_results {
                break;
            }

            for offset in (0..=region.bytes.len().saturating_sub(value_type.size()))
                .step_by(value_type.size())
            {
                let Some(value) = read_numeric(&region.bytes, offset, value_type) else {
                    continue;
                };
                if !predicate.matches(value) {
                    continue;
                }

                candidates.push(ValueCandidate {
                    address: Address(region.base.0 + offset as u64),
                    value_type,
                    value,
                    previous_value: None,
                });
                if candidates.len() >= max_results {
                    break;
                }
            }
        }

        ValueScanSession {
            value_type,
            candidates,
        }
    }

    pub fn value_scan_refine(
        &self,
        session: &ValueScanSession,
        refinement: ValueRefinement,
    ) -> ValueScanSession {
        let mut candidates = Vec::new();

        for candidate in &session.candidates {
            let Some((region, offset)) = self.region_at(candidate.address) else {
                continue;
            };
            let Some(value) = read_numeric(&region.bytes, offset, session.value_type) else {
                continue;
            };
            if !refinement.matches(candidate.value, value) {
                continue;
            }

            candidates.push(ValueCandidate {
                address: candidate.address,
                value_type: candidate.value_type,
                value,
                previous_value: Some(candidate.value),
            });
        }

        ValueScanSession {
            value_type: session.value_type,
            candidates,
        }
    }

    pub fn value_explain(&self, candidate: &ValueCandidate) -> Option<EvidenceHit> {
        let (region, offset) = self.region_at(candidate.address)?;
        Some(self.hit(HitSpec {
            label: "value_explain",
            address: candidate.address,
            region,
            offset,
            evidence_len: candidate.value_type.size(),
            evidence: EvidenceValue::Numeric {
                type_name: candidate.value_type.name().to_string(),
                value: candidate.value.to_string(),
            },
            next_tools: vec![
                self.next_tool(
                    "scan_pointers_to",
                    "find owners or references for this candidate address",
                    candidate.address,
                ),
                self.next_tool(
                    "mem_read",
                    "read nearby fields to infer the surrounding structure",
                    Address(candidate.address.0.saturating_sub(16)),
                ),
                self.next_tool(
                    "value_track",
                    "sample this candidate over time to verify correlation",
                    candidate.address,
                ),
            ],
        }))
    }

    fn readable_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.backend
            .regions
            .iter()
            .filter(|region| region.flags.readable && !region.flags.guarded)
    }

    fn executable_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.backend
            .regions
            .iter()
            .filter(|region| region.flags.executable && !region.flags.guarded)
    }

    fn region_at(&self, address: Address) -> Option<(&MemoryRegion, usize)> {
        self.backend.regions.iter().find_map(|region| {
            let start = region.base.0;
            let end = start + region.bytes.len() as u64;
            (start <= address.0 && address.0 < end).then(|| (region, (address.0 - start) as usize))
        })
    }

    fn select_module(&self, module_name: Option<&str>) -> Option<&ModuleInfo> {
        match module_name {
            Some(name) => self
                .backend
                .modules
                .iter()
                .find(|module| module.name.eq_ignore_ascii_case(name)),
            None => self.backend.modules.first(),
        }
    }

    fn read_bytes_at(&self, address: Address, size: usize) -> Option<&[u8]> {
        let (region, offset) = self.region_at(address)?;
        let end = offset.checked_add(size)?;
        (end <= region.bytes.len()).then(|| &region.bytes[offset..end])
    }

    fn read_available_bytes_at(&self, address: Address, max_size: usize) -> Option<&[u8]> {
        let (region, offset) = self.region_at(address)?;
        let end = offset.saturating_add(max_size).min(region.bytes.len());
        (end > offset).then(|| &region.bytes[offset..end])
    }

    fn read_u16_at(&self, address: Address) -> Option<u16> {
        let bytes = self.read_bytes_at(address, 2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32_at(&self, address: Address) -> Option<u32> {
        let bytes = self.read_bytes_at(address, 4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64_at(&self, address: Address) -> Option<u64> {
        let bytes = self.read_bytes_at(address, 8)?;
        Some(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_sized_u64_at(&self, address: Address, width: usize) -> Option<u64> {
        match width {
            4 => self.read_u32_at(address).map(|value| value as u64),
            8 => self.read_u64_at(address),
            _ => None,
        }
    }

    fn read_pointer_at(&self, address: Address) -> Option<Address> {
        match self.pointer_width_bytes() {
            4 => self.read_u32_at(address).map(|value| Address(value as u64)),
            8 => self.read_u64_at(address).map(Address),
            _ => None,
        }
    }

    fn pointer_can_represent(&self, address: Address) -> bool {
        self.pointer_width_bytes() == 8 || address.0 <= u32::MAX as u64
    }

    fn pointer_bytes(&self, address: Address) -> Vec<u8> {
        match self.pointer_width_bytes() {
            4 => (address.0 as u32).to_le_bytes().to_vec(),
            8 => address.0.to_le_bytes().to_vec(),
            _ => Vec::new(),
        }
    }

    fn read_c_string_at(&self, address: Address, max_len: usize) -> Option<String> {
        let (region, offset) = self.region_at(address)?;
        let mut end = offset;
        while end < region.bytes.len() && end - offset < max_len {
            let byte = region.bytes[end];
            if byte == 0 {
                break;
            }
            if !(byte == b'\t' || byte == b'\r' || byte == b'\n' || (0x20..=0x7e).contains(&byte)) {
                return None;
            }
            end += 1;
        }
        if end == offset || end >= region.bytes.len() || region.bytes[end] != 0 {
            return None;
        }
        String::from_utf8(region.bytes[offset..end].to_vec()).ok()
    }

    fn direct_or_indirect_target(&self, ip: u64, bytes: &[u8]) -> Option<Address> {
        if bytes.len() >= 5 && (bytes[0] == 0xE8 || bytes[0] == 0xE9) {
            let rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as i64;
            let target = (ip + 5) as i64 + rel;
            return (target >= 0).then_some(Address(target as u64));
        }
        if bytes.len() >= 2 && bytes[0] == 0xEB {
            let rel = bytes[1] as i8 as i64;
            let target = (ip + 2) as i64 + rel;
            return (target >= 0).then_some(Address(target as u64));
        }
        if bytes.len() >= 2 && (0x70..=0x7F).contains(&bytes[0]) {
            let rel = bytes[1] as i8 as i64;
            let target = (ip + 2) as i64 + rel;
            return (target >= 0).then_some(Address(target as u64));
        }
        if bytes.len() >= 6 && bytes[0] == 0x0F && (0x80..=0x8F).contains(&bytes[1]) {
            let rel = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as i64;
            let target = (ip + 6) as i64 + rel;
            return (target >= 0).then_some(Address(target as u64));
        }
        if bytes.len() >= 6 && bytes[0] == 0xFF && (bytes[1] == 0x25 || bytes[1] == 0x15) {
            let pointer = self.indirect_pointer_operand(ip, bytes)?;
            return self.read_pointer_at(pointer);
        }
        None
    }

    fn indirect_pointer_operand(&self, ip: u64, bytes: &[u8]) -> Option<Address> {
        if bytes.len() < 6 || bytes[0] != 0xFF || (bytes[1] != 0x25 && bytes[1] != 0x15) {
            return None;
        }
        if self.target_arch == TargetArch::X86_64 {
            let rel = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as i64;
            let pointer = (ip + 6) as i64 + rel;
            (pointer >= 0).then_some(Address(pointer as u64))
        } else {
            Some(Address(
                u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as u64,
            ))
        }
    }

    fn score_index_table(&self, address: Address, max_entries: usize) -> usize {
        let sample_len = max_entries.min(256);
        let Some(bytes) = self.read_available_bytes_at(address, sample_len) else {
            return 0;
        };
        let index_limit = max_entries.min(256);
        bytes
            .iter()
            .filter(|byte| (**byte as usize) < index_limit)
            .count()
    }

    fn score_jump_table(&self, address: Address, max_entries: usize) -> usize {
        let pointer_width = self.pointer_width_bytes();
        let sample_len = max_entries.min(256).saturating_mul(pointer_width);
        let Some(bytes) = self.read_available_bytes_at(address, sample_len) else {
            return 0;
        };
        bytes
            .chunks_exact(pointer_width)
            .filter_map(|chunk| {
                let value = if pointer_width == 4 {
                    u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64
                } else {
                    u64::from_le_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                        chunk[7],
                    ])
                };
                self.region_at(Address(value))
                    .filter(|(region, _)| region.flags.executable)
            })
            .count()
    }

    fn dispatch_stub_handler(&self, stub: Address) -> Option<Address> {
        let instructions = self.disasm_at(stub, 8);
        instructions.into_iter().find_map(|instruction| {
            let is_transfer =
                instruction.text.starts_with("jmp") || instruction.text.starts_with("call");
            (is_transfer && instruction.call_target.is_some()).then_some(instruction.call_target?)
        })
    }

    fn immediate_address_candidates(&self, bytes: &[u8]) -> Vec<Address> {
        immediate_address_candidates(bytes, self.pointer_width_bytes())
    }

    fn push_string(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() < 5 || bytes[0] != 0x68 {
            return None;
        }
        let address = Address(u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64);
        self.read_c_string_at(address, 256)
            .filter(|text| text.len() >= 3)
    }

    fn push_evidence(&self, instruction: &RuntimeInstruction) -> Option<PushEvidence> {
        let bytes = instruction.bytes.as_slice();
        let (value, width_bits) = if bytes.len() >= 5 && bytes[0] == 0x68 {
            (
                u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64,
                32,
            )
        } else if bytes.len() >= 2 && bytes[0] == 0x6A {
            (bytes[1] as u64, 8)
        } else if bytes.len() >= 4 && bytes[0] == 0x66 && bytes[1] == 0x68 {
            (u16::from_le_bytes([bytes[2], bytes[3]]) as u64, 16)
        } else {
            return None;
        };
        let string = if width_bits == 32 {
            self.read_c_string_at(Address(value), 256)
                .filter(|text| text.len() >= 3)
        } else {
            None
        };
        let packet_name = string
            .as_deref()
            .filter(|text| is_packet_name(text))
            .map(str::to_string);
        Some(PushEvidence {
            instruction: instruction.clone(),
            value,
            width_bits,
            string,
            packet_name,
        })
    }

    fn parse_imports_for_module(
        &self,
        module: &ModuleInfo,
        max_results: usize,
    ) -> Vec<RuntimeImport> {
        let base = module.base.0;
        let dos = Address(base);
        if self.read_u16_at(dos) != Some(0x5A4D) {
            return Vec::new();
        }
        let pe_offset = match self.read_u32_at(Address(base + 0x3C)) {
            Some(value) => value as u64,
            None => return Vec::new(),
        };
        let pe = Address(base + pe_offset);
        if self.read_u32_at(pe) != Some(0x0000_4550) {
            return Vec::new();
        }
        let optional = Address(pe.0 + 24);
        let optional_magic = match self.read_u16_at(optional) {
            Some(value @ (0x10B | 0x20B)) => value,
            _ => return Vec::new(),
        };
        let (import_directory_offset, thunk_width, ordinal_flag) = match optional_magic {
            0x10B => (104u64, 4u64, 0x8000_0000u64),
            0x20B => (120u64, 8u64, 0x8000_0000_0000_0000u64),
            _ => unreachable!(),
        };
        let import_rva = match self.read_u32_at(Address(optional.0 + import_directory_offset)) {
            Some(0) | None => return Vec::new(),
            Some(value) => value as u64,
        };

        let mut imports = Vec::new();
        let mut descriptor = Address(base + import_rva);
        while imports.len() < max_results {
            let original_first_thunk = self.read_u32_at(descriptor).unwrap_or(0);
            let name_rva = self.read_u32_at(Address(descriptor.0 + 12)).unwrap_or(0);
            let first_thunk = self.read_u32_at(Address(descriptor.0 + 16)).unwrap_or(0);
            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }
            let dll = self
                .read_c_string_at(Address(base + name_rva as u64), 256)
                .unwrap_or_else(|| "<unknown>".to_string());
            let lookup_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };
            let mut index = 0u64;
            loop {
                if imports.len() >= max_results {
                    break;
                }
                let lookup = self
                    .read_sized_u64_at(
                        Address(base + lookup_rva as u64 + index * thunk_width),
                        thunk_width as usize,
                    )
                    .unwrap_or(0);
                if lookup == 0 {
                    break;
                }
                let iat_address = Address(base + first_thunk as u64 + index * thunk_width);
                let target = self
                    .read_sized_u64_at(iat_address, thunk_width as usize)
                    .map(Address);
                let (name, ordinal) = if lookup & ordinal_flag != 0 {
                    (
                        format!("#{}", lookup & 0xFFFF),
                        Some((lookup & 0xFFFF) as u16),
                    )
                } else {
                    (
                        self.read_c_string_at(Address(base + lookup + 2), 256)
                            .unwrap_or_else(|| "<unknown>".to_string()),
                        None,
                    )
                };
                imports.push(RuntimeImport {
                    module: module.name.clone(),
                    dll: dll.clone(),
                    name,
                    ordinal,
                    iat_address,
                    target,
                });
                index += 1;
            }
            descriptor = Address(descriptor.0 + 20);
        }

        imports
    }

    fn parse_exports_for_module(
        &self,
        module: &ModuleInfo,
        name_contains: Option<&str>,
        max_results: usize,
    ) -> Vec<RuntimeExport> {
        let base = module.base.0;
        let dos = Address(base);
        if max_results == 0 || self.read_u16_at(dos) != Some(0x5A4D) {
            return Vec::new();
        }
        let pe_offset = match self.read_u32_at(Address(base + 0x3C)) {
            Some(value) => value as u64,
            None => return Vec::new(),
        };
        let pe = Address(base + pe_offset);
        if self.read_u32_at(pe) != Some(0x0000_4550) {
            return Vec::new();
        }
        let optional = Address(pe.0 + 24);
        let export_directory_offset = match self.read_u16_at(optional) {
            Some(0x10B) => 96,
            Some(0x20B) => 112,
            _ => return Vec::new(),
        };
        let export_rva = match self.read_u32_at(Address(optional.0 + export_directory_offset)) {
            Some(0) | None => return Vec::new(),
            Some(value) => value as u64,
        };
        let export_size = self
            .read_u32_at(Address(optional.0 + export_directory_offset + 4))
            .unwrap_or(0) as u64;
        let export_directory = Address(base + export_rva);
        let ordinal_base = self
            .read_u32_at(Address(export_directory.0 + 16))
            .unwrap_or(0);
        let function_count = self
            .read_u32_at(Address(export_directory.0 + 20))
            .unwrap_or(0);
        let name_count = self
            .read_u32_at(Address(export_directory.0 + 24))
            .unwrap_or(0);
        let functions_rva = self
            .read_u32_at(Address(export_directory.0 + 28))
            .unwrap_or(0) as u64;
        let names_rva = self
            .read_u32_at(Address(export_directory.0 + 32))
            .unwrap_or(0) as u64;
        let ordinals_rva = self
            .read_u32_at(Address(export_directory.0 + 36))
            .unwrap_or(0) as u64;
        let needle = name_contains.map(str::to_ascii_lowercase);
        let mut exports = Vec::new();

        for name_index in 0..name_count as u64 {
            if exports.len() >= max_results {
                break;
            }
            let name_rva = self
                .read_u32_at(Address(base + names_rva + name_index * 4))
                .unwrap_or(0) as u64;
            if name_rva == 0 {
                continue;
            }
            let Some(name) = self.read_c_string_at(Address(base + name_rva), 512) else {
                continue;
            };
            if let Some(needle) = &needle {
                if !name.to_ascii_lowercase().contains(needle) {
                    continue;
                }
            }
            let ordinal_index = self
                .read_u16_at(Address(base + ordinals_rva + name_index * 2))
                .unwrap_or(u16::MAX) as u32;
            if ordinal_index >= function_count {
                continue;
            }
            let export_function_rva = self
                .read_u32_at(Address(base + functions_rva + ordinal_index as u64 * 4))
                .unwrap_or(0) as u64;
            if export_function_rva == 0 {
                continue;
            }
            let forwarder = if export_size > 0
                && export_function_rva >= export_rva
                && export_function_rva < export_rva + export_size
            {
                self.read_c_string_at(Address(base + export_function_rva), 512)
            } else {
                None
            };
            exports.push(RuntimeExport {
                module: module.name.clone(),
                name,
                ordinal: ordinal_base + ordinal_index,
                address: Address(base + export_function_rva),
                rva: Rva(export_function_rva),
                forwarder,
            });
        }

        exports
    }

    fn module_at(&self, address: Address) -> Option<ModuleContext> {
        self.backend.modules.iter().find_map(|module| {
            let start = module.base.0;
            let end = start + module.size;
            (start <= address.0 && address.0 < end).then(|| ModuleContext {
                name: module.name.clone(),
                base: module.base,
                rva: Rva(address.0 - module.base.0),
            })
        })
    }

    fn hit(&self, spec: HitSpec<'_>) -> EvidenceHit {
        EvidenceHit {
            address: spec.address,
            label: spec.label.to_string(),
            address_context: AddressContext {
                module: self.module_at(spec.address),
                region: RegionContext {
                    kind: spec.region.kind,
                    flags: spec.region.flags,
                },
            },
            evidence: spec.evidence,
            context: context_window(&spec.region.bytes, spec.offset, spec.evidence_len),
            next_tools: spec.next_tools,
        }
    }

    fn next_tool(&self, tool: &str, reason: &str, address: Address) -> NextToolHint {
        NextToolHint {
            tool: tool.to_string(),
            reason: reason.to_string(),
            arguments: vec![ToolArgument {
                name: "address".to_string(),
                value: format!("0x{:x}", address.0),
            }],
        }
    }
}

impl ValuePredicate {
    fn matches(self, value: NumericValue) -> bool {
        match self {
            Self::ExactU64(expected) => value.as_u64() == expected,
        }
    }
}

impl ValueRefinement {
    fn matches(self, previous: NumericValue, current: NumericValue) -> bool {
        match self {
            Self::ExactU64(expected) => current.as_u64() == expected,
            Self::Changed => current.as_u64() != previous.as_u64(),
            Self::Unchanged => current.as_u64() == previous.as_u64(),
            Self::Increased => current.as_u64() > previous.as_u64(),
            Self::Decreased => current.as_u64() < previous.as_u64(),
        }
    }
}

fn read_numeric(data: &[u8], offset: usize, value_type: ValueType) -> Option<NumericValue> {
    match value_type {
        ValueType::U32 => {
            let bytes = data.get(offset..offset + 4)?;
            Some(NumericValue::U32(u32::from_le_bytes(
                bytes.try_into().ok()?,
            )))
        }
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn is_packet_name(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("C_").or_else(|| text.strip_prefix("S_")) else {
        return false;
    };
    !rest.is_empty()
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn immediate_address_candidates(bytes: &[u8], pointer_width: usize) -> Vec<Address> {
    let mut candidates = Vec::new();
    for window in bytes.windows(4) {
        let value = u32::from_le_bytes([window[0], window[1], window[2], window[3]]) as u64;
        if value >= 0x10000 {
            let address = Address(value);
            if !candidates.contains(&address) {
                candidates.push(address);
            }
        }
    }
    if pointer_width == 8 {
        for window in bytes.windows(8) {
            let value = u64::from_le_bytes([
                window[0], window[1], window[2], window[3], window[4], window[5], window[6],
                window[7],
            ]);
            if value >= 0x10000 {
                let address = Address(value);
                if !candidates.contains(&address) {
                    candidates.push(address);
                }
            }
        }
    }
    candidates
}

fn decorate_class_name(class_name: &str) -> String {
    if class_name.starts_with(".?A") {
        class_name.to_string()
    } else {
        format!(".?AV{class_name}@@")
    }
}

fn is_ret(instruction: &Instruction) -> bool {
    instruction.mnemonic() == Mnemonic::Ret
}

fn branch_kind(instruction: &RuntimeInstruction) -> Option<BranchKind> {
    if instruction.text.starts_with("call") {
        return Some(if instruction.call_target.is_some() {
            BranchKind::Call
        } else {
            BranchKind::UnresolvedIndirect
        });
    }
    if instruction.text.starts_with("jmp") {
        return Some(if instruction.call_target.is_some() {
            BranchKind::Jump
        } else {
            BranchKind::UnresolvedIndirect
        });
    }
    if instruction.text.starts_with('j') && instruction.call_target.is_some() {
        return Some(BranchKind::ConditionalJump);
    }
    None
}

fn context_window(data: &[u8], offset: usize, evidence_len: usize) -> EvidenceContext {
    let before_start = offset.saturating_sub(16);
    let after_start = offset.saturating_add(evidence_len).min(data.len());
    let after_end = after_start.saturating_add(16).min(data.len());
    let preview_start = offset.saturating_sub(24);
    let preview_end = offset
        .saturating_add(evidence_len)
        .saturating_add(24)
        .min(data.len());

    EvidenceContext {
        before: data[before_start..offset].to_vec(),
        after: data[after_start..after_end].to_vec(),
        ascii_preview: ascii_preview(&data[preview_start..preview_end]),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use evidence_core::{
        Address, EvidenceValue, ModuleBase, RegionFlags, RegionKind, Rva, TargetArch,
    };

    fn engine_with_login_region() -> ArgusEngine {
        ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "login.exe".to_string(),
                base: ModuleBase(0x400000),
                size: 0x20000,
            }],
            regions: vec![MemoryRegion {
                base: Address(0x401000),
                bytes: b"\0Login failed\0\xE8\x99\x34".to_vec(),
                kind: RegionKind::Image,
                flags: RegionFlags {
                    readable: true,
                    writable: false,
                    executable: false,
                    guarded: false,
                },
            }],
        })
    }

    #[test]
    fn mem_read_decorates_module_rva_and_region_flags() {
        let engine = engine_with_login_region();

        let hit = engine.mem_read(Address(0x401001), 5).unwrap();

        assert_eq!(hit.address, Address(0x401001));
        assert_eq!(hit.label, "mem_read");
        assert_eq!(hit.address_context.module.unwrap().rva, Rva(0x1001));
        assert!(hit.address_context.region.flags.readable);
        assert_eq!(
            hit.evidence,
            EvidenceValue::Bytes {
                bytes: b"Login".to_vec()
            }
        );
        assert!(hit.context.ascii_preview.contains("Login"));
    }

    #[test]
    fn scan_string_emits_ai_context_and_next_tools() {
        let engine = engine_with_login_region();

        let hits = engine.scan_string("Login", 10);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, Address(0x401001));
        assert_eq!(
            hits[0].evidence,
            EvidenceValue::Utf8 {
                text: "Login".to_string()
            }
        );
        assert!(hits[0].context.ascii_preview.contains("Login failed"));
        assert!(hits[0]
            .next_tools
            .iter()
            .any(|hint| hint.tool == "scan_pointers_to"));
        assert!(hits[0]
            .next_tools
            .iter()
            .any(|hint| hint.tool == "ghydra.functions_decompile"));
    }

    #[test]
    fn scan_bytes_uses_aob_wildcards_and_limits_results() {
        let engine = engine_with_login_region();

        let hits = engine.scan_bytes("E8 ?? 34", 1).unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, Address(0x40100e));
        assert_eq!(hits[0].label, "scan_bytes");
        assert!(hits[0].context.after.is_empty());
    }

    #[test]
    fn scan_pointers_to_returns_pointer_evidence_and_next_tools() {
        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "login.exe".to_string(),
                base: ModuleBase(0x400000),
                size: 0x20000,
            }],
            regions: vec![MemoryRegion {
                base: Address(0x402000),
                bytes: [0x34, 0x12, 0x40, 0x00, 0xff].to_vec(),
                kind: RegionKind::Image,
                flags: RegionFlags {
                    readable: true,
                    writable: false,
                    executable: false,
                    guarded: false,
                },
            }],
        });

        let hits = engine.scan_pointers_to(Address(0x401234), 10);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, Address(0x402000));
        assert_eq!(
            hits[0].evidence,
            EvidenceValue::Pointer {
                target: Address(0x401234)
            }
        );
        assert!(hits[0]
            .next_tools
            .iter()
            .any(|hint| hint.tool == "mem_read"));
    }

    #[test]
    fn scan_pointers_to_finds_64_bit_targets_when_engine_is_x64() {
        let target = Address(0x0000_0001_4000_1000);
        let mut bytes = vec![0xCC; 0x20];
        bytes[0x10..0x18].copy_from_slice(&target.0.to_le_bytes());
        let engine = ArgusEngine::new_for_target(
            InMemoryBackend {
                modules: vec![ModuleInfo {
                    name: "game64.exe".to_string(),
                    base: ModuleBase(0x0000_0001_4000_0000),
                    size: 0x10000,
                }],
                regions: vec![MemoryRegion {
                    base: Address(0x0000_0001_4000_2000),
                    bytes,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: false,
                        guarded: false,
                    },
                }],
            },
            TargetArch::X86_64,
        );

        let hits = engine.scan_pointers_to(target, 4);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, Address(0x0000_0001_4000_2010));
        assert_eq!(hits[0].evidence, EvidenceValue::Pointer { target });
    }

    #[test]
    fn locate_links_string_refs_to_containing_function_evidence() {
        let mut code = vec![0x90; 0x40];
        code[0..3].copy_from_slice(&[0x55, 0x8b, 0xec]);
        code[0x20..0x24].copy_from_slice(&(0x402010_u32).to_le_bytes());
        let mut data = vec![0; 0x10];
        data.extend_from_slice(b"C_LoginRequest\0");

        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "login.exe".to_string(),
                base: ModuleBase(0x400000),
                size: 0x20000,
            }],
            regions: vec![
                MemoryRegion {
                    base: Address(0x401000),
                    bytes: code,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                },
                MemoryRegion {
                    base: Address(0x402000),
                    bytes: data,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: false,
                        guarded: false,
                    },
                },
            ],
        });

        let hits = engine.locate("C_LoginRequest", 8);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].string_address, Address(0x402010));
        assert_eq!(hits[0].ref_site, Address(0x401020));
        assert_eq!(hits[0].function_start, Some(Address(0x401000)));
    }

    #[test]
    fn find_vtable_walks_x86_msvc_rtti_evidence() {
        let mut rtti = vec![0; 0x2010];
        rtti[8..8 + b".?AVCPlayer@@\0".len()].copy_from_slice(b".?AVCPlayer@@\0");
        rtti[0x100c..0x1010].copy_from_slice(&(0x402000_u32).to_le_bytes());
        rtti[0x2000..0x2004].copy_from_slice(&(0x403000_u32).to_le_bytes());
        rtti[0x2004..0x2008].copy_from_slice(&(0x401000_u32).to_le_bytes());

        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "game.exe".to_string(),
                base: ModuleBase(0x400000),
                size: 0x50000,
            }],
            regions: vec![
                MemoryRegion {
                    base: Address(0x401000),
                    bytes: [
                        0x55, 0x8b, 0xec, 0x83, 0xec, 0x04, 0x90, 0x90, 0xc3, 0x90, 0x90, 0x90,
                        0x90, 0x90, 0x90, 0x90,
                    ]
                    .to_vec(),
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                },
                MemoryRegion {
                    base: Address(0x402000),
                    bytes: rtti,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: false,
                        guarded: false,
                    },
                },
            ],
        });

        let evidence = engine.find_vtable("CPlayer", 8);

        assert_eq!(evidence.error, None);
        assert_eq!(evidence.rtti_string, Some(Address(0x402008)));
        assert_eq!(evidence.type_descriptor, Some(Address(0x402000)));
        assert_eq!(evidence.col, Some(Address(0x403000)));
        assert_eq!(evidence.vtable, Some(Address(0x404004)));
        assert_eq!(evidence.methods.len(), 1);
        assert_eq!(evidence.methods[0].address, Address(0x401000));
        assert!(evidence.methods[0]
            .instruction
            .as_ref()
            .map(|instruction| instruction.text.contains("push"))
            .unwrap_or(false));
    }

    #[test]
    fn scan_callers_returns_call_evidence_for_e8_and_e9() {
        let target = Address(0x401100);
        let call_site = Address(0x401000);
        let jump_site = Address(0x401010);
        let call_rel = (target.0 as i64 - (call_site.0 + 5) as i64) as i32;
        let jump_rel = (target.0 as i64 - (jump_site.0 + 5) as i64) as i32;
        let mut code = vec![0xE8];
        code.extend_from_slice(&call_rel.to_le_bytes());
        code.extend_from_slice(&[0; 0x10 - 5]);
        code.push(0xE9);
        code.extend_from_slice(&jump_rel.to_le_bytes());

        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "login.exe".to_string(),
                base: ModuleBase(0x400000),
                size: 0x20000,
            }],
            regions: vec![MemoryRegion {
                base: call_site,
                bytes: code,
                kind: RegionKind::Image,
                flags: RegionFlags {
                    readable: true,
                    writable: false,
                    executable: true,
                    guarded: false,
                },
            }],
        });

        let hits = engine.scan_callers(target, 10);

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].address, call_site);
        assert_eq!(
            hits[0].evidence,
            EvidenceValue::Caller {
                target,
                opcode: 0xE8
            }
        );
        assert_eq!(hits[1].address, jump_site);
        assert_eq!(
            hits[1].evidence,
            EvidenceValue::Caller {
                target,
                opcode: 0xE9
            }
        );
        assert!(hits[0]
            .next_tools
            .iter()
            .any(|hint| hint.tool == "ghydra.functions_decompile"));
    }

    #[test]
    fn scan_callers_returns_indirect_iat_call_evidence() {
        let target = Address(0x402000);
        let call_site = Address(0x401000);
        let iat_slot = Address(0x403000);
        let mut code = vec![0xFF, 0x15];
        code.extend_from_slice(&(iat_slot.0 as u32).to_le_bytes());

        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "login.exe".to_string(),
                base: ModuleBase(0x400000),
                size: 0x5000,
            }],
            regions: vec![
                MemoryRegion {
                    base: call_site,
                    bytes: code,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                },
                MemoryRegion {
                    base: iat_slot,
                    bytes: (target.0 as u32).to_le_bytes().to_vec(),
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: true,
                        executable: false,
                        guarded: false,
                    },
                },
            ],
        });

        let hits = engine.scan_callers(target, 10);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, call_site);
        assert_eq!(
            hits[0].evidence,
            EvidenceValue::IndirectCaller {
                target,
                opcode: 0xFF,
                pointer: iat_slot
            }
        );
    }

    #[test]
    fn disasm_at_adds_call_target_and_push_string_evidence() {
        let mut code = vec![0x55, 0x8B, 0xEC];
        code.extend_from_slice(&[0x68, 0x00, 0x20, 0x40, 0x00]);
        code.push(0xE8);
        code.extend_from_slice(&((0x0040_3000i64 - 0x0040_100D_i64) as i32).to_le_bytes());
        code.push(0xC3);

        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "game.exe".to_string(),
                base: ModuleBase(0x0040_0000),
                size: 0x10000,
            }],
            regions: vec![
                MemoryRegion {
                    base: Address(0x0040_1000),
                    bytes: code,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                },
                MemoryRegion {
                    base: Address(0x0040_2000),
                    bytes: b"HelloPacket\0".to_vec(),
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: false,
                        guarded: false,
                    },
                },
                MemoryRegion {
                    base: Address(0x0040_3000),
                    bytes: vec![0xC3],
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                },
            ],
        });

        let disasm = engine.disasm_at(Address(0x0040_1000), 8);

        assert!(disasm
            .iter()
            .any(|insn| insn.string.as_deref() == Some("HelloPacket")));
        assert!(disasm
            .iter()
            .any(|insn| insn.call_target == Some(Address(0x0040_3000))));
    }

    #[test]
    fn disasm_at_adds_conditional_branch_targets_for_dispatch_ladders() {
        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "game.exe".to_string(),
                base: ModuleBase(0x0040_0000),
                size: 0x10000,
            }],
            regions: vec![MemoryRegion {
                base: Address(0x0040_1000),
                bytes: vec![0x74, 0x05, 0x75, 0xFA, 0xC3],
                kind: RegionKind::Image,
                flags: RegionFlags {
                    readable: true,
                    writable: false,
                    executable: true,
                    guarded: false,
                },
            }],
        });

        let disasm = engine.disasm_at(Address(0x0040_1000), 3);

        assert_eq!(disasm[0].call_target, Some(Address(0x0040_1007)));
        assert_eq!(disasm[1].call_target, Some(Address(0x0040_0FFE)));
    }

    #[test]
    fn disasm_at_resolves_x64_rip_relative_indirect_call_target() {
        let base = 0x0000_0001_4000_0000u64;
        let call = Address(base + 0x1000);
        let target = Address(base + 0x3000);
        let mut code = vec![0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xC3, 0x90];
        code.extend_from_slice(&target.0.to_le_bytes());
        let engine = ArgusEngine::new_for_target(
            InMemoryBackend {
                modules: vec![ModuleInfo {
                    name: "game64.exe".to_string(),
                    base: ModuleBase(base),
                    size: 0x10000,
                }],
                regions: vec![MemoryRegion {
                    base: call,
                    bytes: code,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                }],
            },
            TargetArch::X86_64,
        );

        let disasm = engine.disasm_at(call, 1);

        assert_eq!(disasm.len(), 1);
        assert_eq!(disasm[0].call_target, Some(target));
    }

    #[test]
    fn analyze_function_collects_callees_and_trace_call_chain_walks_up() {
        let target = Address(0x0040_3000);
        let call_site = Address(0x0040_1003);
        let rel = (target.0 as i64 - (call_site.0 + 5) as i64) as i32;
        let mut caller = vec![0x55, 0x8B, 0xEC, 0xE8];
        caller.extend_from_slice(&rel.to_le_bytes());
        caller.push(0xC3);

        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "game.exe".to_string(),
                base: ModuleBase(0x0040_0000),
                size: 0x10000,
            }],
            regions: vec![
                MemoryRegion {
                    base: Address(0x0040_1000),
                    bytes: caller,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                },
                MemoryRegion {
                    base: target,
                    bytes: vec![0x55, 0x8B, 0xEC, 0xC3],
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                },
            ],
        });

        let analyzed = engine.analyze_function(Address(0x0040_1000), 20).unwrap();
        assert_eq!(analyzed.callees, vec![target]);

        let chain = engine.trace_call_chain(target, 2, 4);
        assert_eq!(chain[0].target, target);
        assert_eq!(
            chain[0].callers[0].function_start,
            Some(Address(0x0040_1000))
        );
    }

    #[test]
    fn analyze_send_call_sites_collects_preceding_push_evidence() {
        let target = Address(0x0040_1100);
        let call_site = Address(0x0040_100a);
        let rel = (target.0 as i64 - (call_site.0 + 5) as i64) as i32;
        let mut code = vec![0x55, 0x8B, 0xEC, 0x6A, 0x8A];
        code.extend_from_slice(&[0x68, 0x00, 0x20, 0x40, 0x00]);
        code.push(0xE8);
        code.extend_from_slice(&rel.to_le_bytes());
        code.push(0xC3);

        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "game.exe".to_string(),
                base: ModuleBase(0x0040_0000),
                size: 0x10000,
            }],
            regions: vec![
                MemoryRegion {
                    base: Address(0x0040_1000),
                    bytes: code,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                },
                MemoryRegion {
                    base: Address(0x0040_1100),
                    bytes: vec![0xC3],
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                },
                MemoryRegion {
                    base: Address(0x0040_2000),
                    bytes: b"C_DESTROY_ITEM\0".to_vec(),
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: false,
                        guarded: false,
                    },
                },
            ],
        });

        let evidence = engine.analyze_send_call_sites(target, 8, 8, 0x40);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].call_site.address, call_site);
        assert!(evidence[0]
            .pushes
            .iter()
            .any(|push| push.width_bits == 8 && push.value == 0x8A));
        assert!(evidence[0]
            .pushes
            .iter()
            .any(|push| push.packet_name.as_deref() == Some("C_DESTROY_ITEM")));
    }

    #[test]
    fn dispatch_branches_classify_conditional_and_unresolved_indirect() {
        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "game.exe".to_string(),
                base: ModuleBase(0x0040_0000),
                size: 0x10000,
            }],
            regions: vec![MemoryRegion {
                base: Address(0x0040_1000),
                bytes: vec![0x83, 0xF8, 0x01, 0x74, 0x05, 0xFF, 0xE0, 0xC3],
                kind: RegionKind::Image,
                flags: RegionFlags {
                    readable: true,
                    writable: false,
                    executable: true,
                    guarded: false,
                },
            }],
        });

        let branches = engine
            .dispatch_branches(Address(0x0040_1000), 8)
            .expect("function should disassemble");

        assert_eq!(branches.len(), 2);
        assert_eq!(branches[0].kind, BranchKind::ConditionalJump);
        assert_eq!(
            branches[0].instruction.call_target,
            Some(Address(0x0040_100A))
        );
        assert_eq!(branches[1].kind, BranchKind::UnresolvedIndirect);
        assert_eq!(branches[1].instruction.address, Address(0x0040_1005));
    }

    #[test]
    fn extract_dispatch_tables_maps_opcode_to_stub_and_handler() {
        let dispatcher = Address(0x0040_1000);
        let index_table = Address(0x0040_2000);
        let jump_table = Address(0x0040_3000);
        let stub = Address(0x0040_4000);
        let handler = Address(0x0040_5000);
        let mut dispatcher_code = vec![0xB8];
        dispatcher_code.extend_from_slice(&(index_table.0 as u32).to_le_bytes());
        dispatcher_code.push(0xBB);
        dispatcher_code.extend_from_slice(&(jump_table.0 as u32).to_le_bytes());
        dispatcher_code.push(0xC3);
        let mut index_bytes = vec![0u8; 256];
        index_bytes[0x8A] = 1;
        let mut jump_bytes = vec![0u8; 8];
        jump_bytes[4..8].copy_from_slice(&(stub.0 as u32).to_le_bytes());
        let rel = (handler.0 as i64 - (stub.0 + 5) as i64) as i32;
        let mut stub_bytes = vec![0xE9];
        stub_bytes.extend_from_slice(&rel.to_le_bytes());

        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "game.exe".to_string(),
                base: ModuleBase(0x0040_0000),
                size: 0x20000,
            }],
            regions: vec![
                MemoryRegion {
                    base: dispatcher,
                    bytes: dispatcher_code,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                },
                MemoryRegion {
                    base: index_table,
                    bytes: index_bytes,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: false,
                        guarded: false,
                    },
                },
                MemoryRegion {
                    base: jump_table,
                    bytes: jump_bytes,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: false,
                        guarded: false,
                    },
                },
                MemoryRegion {
                    base: stub,
                    bytes: stub_bytes,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                },
                MemoryRegion {
                    base: handler,
                    bytes: vec![0xC3],
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                },
            ],
        });

        let evidence = engine.extract_dispatch_tables(dispatcher, 8, 256, None, None);
        let entry = evidence
            .entries
            .iter()
            .find(|entry| entry.opcode == 0x8A)
            .unwrap();

        assert_eq!(evidence.index_table, Some(index_table));
        assert_eq!(evidence.jump_table, Some(jump_table));
        assert_eq!(entry.opcode_value_location, Address(index_table.0 + 0x8A));
        assert_eq!(entry.dispatch_index, 1);
        assert_eq!(entry.stub, Some(stub));
        assert_eq!(entry.handler, Some(handler));
    }

    #[test]
    fn extract_dispatch_tables_reads_64_bit_jump_table_slots_when_engine_is_x64() {
        let dispatcher = Address(0x0000_0001_4000_1000);
        let index_table = Address(0x0000_0001_4000_2000);
        let jump_table = Address(0x0000_0001_4000_3000);
        let stub = Address(0x0000_0001_4000_4000);
        let handler = Address(0x0000_0001_4000_5000);
        let mut index_bytes = vec![0u8; 256];
        index_bytes[0x8A] = 1;
        let mut jump_bytes = vec![0u8; 16];
        jump_bytes[8..16].copy_from_slice(&stub.0.to_le_bytes());
        let rel = (handler.0 as i64 - (stub.0 + 5) as i64) as i32;
        let mut stub_bytes = vec![0xE9];
        stub_bytes.extend_from_slice(&rel.to_le_bytes());
        let engine = ArgusEngine::new_for_target(
            InMemoryBackend {
                modules: vec![ModuleInfo {
                    name: "game64.exe".to_string(),
                    base: ModuleBase(0x0000_0001_4000_0000),
                    size: 0x10000,
                }],
                regions: vec![
                    MemoryRegion {
                        base: dispatcher,
                        bytes: vec![0xC3],
                        kind: RegionKind::Image,
                        flags: RegionFlags {
                            readable: true,
                            writable: false,
                            executable: true,
                            guarded: false,
                        },
                    },
                    MemoryRegion {
                        base: index_table,
                        bytes: index_bytes,
                        kind: RegionKind::Image,
                        flags: RegionFlags {
                            readable: true,
                            writable: false,
                            executable: false,
                            guarded: false,
                        },
                    },
                    MemoryRegion {
                        base: jump_table,
                        bytes: jump_bytes,
                        kind: RegionKind::Image,
                        flags: RegionFlags {
                            readable: true,
                            writable: false,
                            executable: false,
                            guarded: false,
                        },
                    },
                    MemoryRegion {
                        base: stub,
                        bytes: stub_bytes,
                        kind: RegionKind::Image,
                        flags: RegionFlags {
                            readable: true,
                            writable: false,
                            executable: true,
                            guarded: false,
                        },
                    },
                    MemoryRegion {
                        base: handler,
                        bytes: vec![0xC3],
                        kind: RegionKind::Image,
                        flags: RegionFlags {
                            readable: true,
                            writable: false,
                            executable: true,
                            guarded: false,
                        },
                    },
                ],
            },
            TargetArch::X86_64,
        );

        let evidence =
            engine.extract_dispatch_tables(dispatcher, 8, 256, Some(index_table), Some(jump_table));
        let entry = evidence
            .entries
            .iter()
            .find(|entry| entry.opcode == 0x8A)
            .unwrap();

        assert_eq!(entry.jump_slot, Some(Address(jump_table.0 + 8)));
        assert_eq!(entry.stub, Some(stub));
        assert_eq!(entry.handler, Some(handler));
    }

    #[test]
    fn runtime_imports_and_iat_thunks_parse_mapped_pe32() {
        let base = 0x0040_0000u64;
        let mut image = vec![0u8; 0x1200];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x94..0x96].copy_from_slice(&(0xE0u16).to_le_bytes());
        image[0x98..0x9A].copy_from_slice(&(0x10Bu16).to_le_bytes());
        image[0x98 + 104..0x98 + 108].copy_from_slice(&(0x200u32).to_le_bytes());
        image[0x98 + 108..0x98 + 112].copy_from_slice(&(0x28u32).to_le_bytes());
        image[0x200..0x204].copy_from_slice(&(0x300u32).to_le_bytes());
        image[0x20c..0x210].copy_from_slice(&(0x250u32).to_le_bytes());
        image[0x210..0x214].copy_from_slice(&(0x350u32).to_le_bytes());
        image[0x250..0x25b].copy_from_slice(b"WS2_32.dll\0");
        image[0x300..0x304].copy_from_slice(&(0x400u32).to_le_bytes());
        image[0x350..0x354].copy_from_slice(&(0x7600_1234u32).to_le_bytes());
        image[0x402..0x407].copy_from_slice(b"send\0");
        image[0x500..0x506].copy_from_slice(&[0xFF, 0x25, 0x50, 0x03, 0x40, 0x00]);

        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "game.exe".to_string(),
                base: ModuleBase(base),
                size: image.len() as u64,
            }],
            regions: vec![MemoryRegion {
                base: Address(base),
                bytes: image,
                kind: RegionKind::Image,
                flags: RegionFlags {
                    readable: true,
                    writable: false,
                    executable: true,
                    guarded: false,
                },
            }],
        });

        let imports = engine.runtime_imports(Some("game.exe"), 10);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].dll, "WS2_32.dll");
        assert_eq!(imports[0].name, "send");
        assert_eq!(imports[0].iat_address, Address(0x0040_0350));
        assert_eq!(imports[0].target, Some(Address(0x7600_1234)));

        let thunks = engine.resolve_iat_thunks(Some("game.exe"), Some("send"), 10);
        assert_eq!(thunks.len(), 1);
        assert_eq!(thunks[0].thunk_address, Address(0x0040_0500));
        assert_eq!(
            thunks[0].instruction.call_target,
            Some(Address(0x7600_1234))
        );
    }

    #[test]
    fn runtime_imports_parse_mapped_pe32_plus_with_64_bit_thunks() {
        let base = 0x0000_0001_4000_0000u64;
        let mut image = vec![0u8; 0x1200];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x94..0x96].copy_from_slice(&(0xF0u16).to_le_bytes());
        image[0x98..0x9A].copy_from_slice(&(0x20Bu16).to_le_bytes());
        image[0x98 + 120..0x98 + 124].copy_from_slice(&(0x200u32).to_le_bytes());
        image[0x98 + 124..0x98 + 128].copy_from_slice(&(0x28u32).to_le_bytes());
        image[0x200..0x204].copy_from_slice(&(0x300u32).to_le_bytes());
        image[0x20c..0x210].copy_from_slice(&(0x250u32).to_le_bytes());
        image[0x210..0x214].copy_from_slice(&(0x350u32).to_le_bytes());
        image[0x250..0x25b].copy_from_slice(b"WS2_32.dll\0");
        image[0x300..0x308].copy_from_slice(&(0x400u64).to_le_bytes());
        image[0x350..0x358].copy_from_slice(&(0x0000_7FFA_1234_5678u64).to_le_bytes());
        image[0x402..0x407].copy_from_slice(b"send\0");
        let iat_instruction = 0x500usize;
        let iat_address = base + 0x350;
        let rip_after = base + iat_instruction as u64 + 6;
        let displacement = (iat_address as i64 - rip_after as i64) as i32;
        image[iat_instruction..iat_instruction + 2].copy_from_slice(&[0xFF, 0x25]);
        image[iat_instruction + 2..iat_instruction + 6]
            .copy_from_slice(&displacement.to_le_bytes());

        let engine = ArgusEngine::new_for_target(
            InMemoryBackend {
                modules: vec![ModuleInfo {
                    name: "game64.exe".to_string(),
                    base: ModuleBase(base),
                    size: image.len() as u64,
                }],
                regions: vec![MemoryRegion {
                    base: Address(base),
                    bytes: image,
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: true,
                        guarded: false,
                    },
                }],
            },
            TargetArch::X86_64,
        );

        let imports = engine.runtime_imports(Some("game64.exe"), 10);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].dll, "WS2_32.dll");
        assert_eq!(imports[0].name, "send");
        assert_eq!(imports[0].iat_address, Address(base + 0x350));
        assert_eq!(imports[0].target, Some(Address(0x0000_7FFA_1234_5678)));

        let thunks = engine.resolve_iat_thunks(Some("game64.exe"), Some("send"), 10);
        assert_eq!(thunks.len(), 1);
        assert_eq!(thunks[0].thunk_address, Address(base + 0x500));
        assert_eq!(
            thunks[0].instruction.call_target,
            Some(Address(0x0000_7FFA_1234_5678))
        );
    }

    #[test]
    fn runtime_exports_parse_mapped_pe32_export_table() {
        let base = 0x7600_0000u64;
        let mut image = vec![0u8; 0x1000];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x94..0x96].copy_from_slice(&(0xE0u16).to_le_bytes());
        image[0x98..0x9A].copy_from_slice(&(0x10Bu16).to_le_bytes());
        image[0x98 + 96..0x98 + 100].copy_from_slice(&(0x200u32).to_le_bytes());
        image[0x98 + 100..0x98 + 104].copy_from_slice(&(0x40u32).to_le_bytes());
        image[0x200 + 12..0x200 + 16].copy_from_slice(&(0x280u32).to_le_bytes());
        image[0x200 + 16..0x200 + 20].copy_from_slice(&(1u32).to_le_bytes());
        image[0x200 + 20..0x200 + 24].copy_from_slice(&(1u32).to_le_bytes());
        image[0x200 + 24..0x200 + 28].copy_from_slice(&(1u32).to_le_bytes());
        image[0x200 + 28..0x200 + 32].copy_from_slice(&(0x300u32).to_le_bytes());
        image[0x200 + 32..0x200 + 36].copy_from_slice(&(0x320u32).to_le_bytes());
        image[0x200 + 36..0x200 + 40].copy_from_slice(&(0x340u32).to_le_bytes());
        image[0x280..0x28b].copy_from_slice(b"WS2_32.dll\0");
        image[0x300..0x304].copy_from_slice(&(0x500u32).to_le_bytes());
        image[0x320..0x324].copy_from_slice(&(0x360u32).to_le_bytes());
        image[0x340..0x342].copy_from_slice(&(0u16).to_le_bytes());
        image[0x360..0x365].copy_from_slice(b"send\0");
        image[0x500] = 0xC3;

        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "WS2_32.dll".to_string(),
                base: ModuleBase(base),
                size: image.len() as u64,
            }],
            regions: vec![MemoryRegion {
                base: Address(base),
                bytes: image,
                kind: RegionKind::Image,
                flags: RegionFlags {
                    readable: true,
                    writable: false,
                    executable: true,
                    guarded: false,
                },
            }],
        });

        let exports = engine.runtime_exports(Some("ws2_32"), Some("send"), 10);

        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].module, "WS2_32.dll");
        assert_eq!(exports[0].name, "send");
        assert_eq!(exports[0].ordinal, 1);
        assert_eq!(exports[0].rva, Rva(0x500));
        assert_eq!(exports[0].address, Address(0x7600_0500));
    }

    #[test]
    fn value_scan_start_finds_typed_u32_candidates() {
        let engine = ArgusEngine::new(InMemoryBackend {
            modules: Vec::new(),
            regions: vec![MemoryRegion {
                base: Address(0x500000),
                bytes: [
                    1u32.to_le_bytes(),
                    100u32.to_le_bytes(),
                    100u32.to_le_bytes(),
                ]
                .concat(),
                kind: RegionKind::Heap,
                flags: RegionFlags {
                    readable: true,
                    writable: true,
                    executable: false,
                    guarded: false,
                },
            }],
        });

        let session = engine.value_scan_start(ValueType::U32, ValuePredicate::ExactU64(100), 10);

        assert_eq!(session.candidates.len(), 2);
        assert_eq!(session.candidates[0].address, Address(0x500004));
        assert_eq!(session.candidates[0].value, NumericValue::U32(100));
    }

    #[test]
    fn value_scan_refine_decreased_keeps_only_decreased_candidates() {
        let first = ArgusEngine::new(InMemoryBackend {
            modules: Vec::new(),
            regions: vec![MemoryRegion {
                base: Address(0x500000),
                bytes: [100u32.to_le_bytes(), 100u32.to_le_bytes()].concat(),
                kind: RegionKind::Heap,
                flags: RegionFlags {
                    readable: true,
                    writable: true,
                    executable: false,
                    guarded: false,
                },
            }],
        });
        let second = ArgusEngine::new(InMemoryBackend {
            modules: Vec::new(),
            regions: vec![MemoryRegion {
                base: Address(0x500000),
                bytes: [90u32.to_le_bytes(), 100u32.to_le_bytes()].concat(),
                kind: RegionKind::Heap,
                flags: RegionFlags {
                    readable: true,
                    writable: true,
                    executable: false,
                    guarded: false,
                },
            }],
        });
        let session = first.value_scan_start(ValueType::U32, ValuePredicate::ExactU64(100), 10);

        let refined = second.value_scan_refine(&session, ValueRefinement::Decreased);

        assert_eq!(refined.candidates.len(), 1);
        assert_eq!(refined.candidates[0].address, Address(0x500000));
        assert_eq!(
            refined.candidates[0].previous_value,
            Some(NumericValue::U32(100))
        );
        assert_eq!(refined.candidates[0].value, NumericValue::U32(90));
    }

    #[test]
    fn value_scan_refine_unchanged_keeps_stable_candidates() {
        let first = ArgusEngine::new(InMemoryBackend {
            modules: Vec::new(),
            regions: vec![MemoryRegion {
                base: Address(0x500000),
                bytes: [100u32.to_le_bytes(), 100u32.to_le_bytes()].concat(),
                kind: RegionKind::Heap,
                flags: RegionFlags {
                    readable: true,
                    writable: true,
                    executable: false,
                    guarded: false,
                },
            }],
        });
        let second = ArgusEngine::new(InMemoryBackend {
            modules: Vec::new(),
            regions: vec![MemoryRegion {
                base: Address(0x500000),
                bytes: [90u32.to_le_bytes(), 100u32.to_le_bytes()].concat(),
                kind: RegionKind::Heap,
                flags: RegionFlags {
                    readable: true,
                    writable: true,
                    executable: false,
                    guarded: false,
                },
            }],
        });
        let session = first.value_scan_start(ValueType::U32, ValuePredicate::ExactU64(100), 10);

        let refined = second.value_scan_refine(&session, ValueRefinement::Unchanged);

        assert_eq!(refined.candidates.len(), 1);
        assert_eq!(refined.candidates[0].address, Address(0x500004));
        assert_eq!(refined.candidates[0].value, NumericValue::U32(100));
    }

    #[test]
    fn value_explain_returns_ai_first_numeric_evidence() {
        let engine = ArgusEngine::new(InMemoryBackend {
            modules: vec![ModuleInfo {
                name: "stats.bin".to_string(),
                base: ModuleBase(0x500000),
                size: 0x1000,
            }],
            regions: vec![MemoryRegion {
                base: Address(0x500000),
                bytes: [
                    50u32.to_le_bytes(),
                    90u32.to_le_bytes(),
                    30u32.to_le_bytes(),
                ]
                .concat(),
                kind: RegionKind::Heap,
                flags: RegionFlags {
                    readable: true,
                    writable: true,
                    executable: false,
                    guarded: false,
                },
            }],
        });

        let hit = engine
            .value_explain(&ValueCandidate {
                address: Address(0x500004),
                value_type: ValueType::U32,
                value: NumericValue::U32(90),
                previous_value: Some(NumericValue::U32(100)),
            })
            .unwrap();

        assert_eq!(hit.address, Address(0x500004));
        assert_eq!(hit.address_context.module.unwrap().rva, Rva(4));
        assert_eq!(
            hit.evidence,
            EvidenceValue::Numeric {
                type_name: "u32".to_string(),
                value: "90".to_string()
            }
        );
        assert!(hit
            .next_tools
            .iter()
            .any(|hint| hint.tool == "scan_pointers_to"));
        assert!(hit.next_tools.iter().any(|hint| hint.tool == "mem_read"));
    }
}
