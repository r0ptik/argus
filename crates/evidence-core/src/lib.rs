#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Address(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ModuleBase(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Rva(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetArch {
    X86,
    X86_64,
}

impl TargetArch {
    pub fn native() -> Self {
        if cfg!(target_arch = "x86_64") {
            Self::X86_64
        } else {
            Self::X86
        }
    }

    pub fn pointer_width_bytes(self) -> usize {
        match self {
            Self::X86 => 4,
            Self::X86_64 => 8,
        }
    }

    pub fn decoder_bitness(self) -> u32 {
        match self {
            Self::X86 => 32,
            Self::X86_64 => 64,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressError {
    AddressBeforeModule {
        address: Address,
        module_base: ModuleBase,
    },
}

impl Address {
    pub fn to_rva(self, module_base: ModuleBase) -> Result<Rva, AddressError> {
        if self.0 < module_base.0 {
            return Err(AddressError::AddressBeforeModule {
                address: self,
                module_base,
            });
        }

        Ok(Rva(self.0 - module_base.0))
    }
}

impl Rva {
    pub fn to_address(self, module_base: ModuleBase) -> Address {
        Address(module_base.0 + self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleContext {
    pub name: String,
    pub base: ModuleBase,
    pub rva: Rva,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionKind {
    Image,
    Heap,
    Stack,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionFlags {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub guarded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionContext {
    pub kind: RegionKind,
    pub flags: RegionFlags,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressContext {
    pub module: Option<ModuleContext>,
    pub region: RegionContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceValue {
    Bytes {
        bytes: Vec<u8>,
    },
    Utf8 {
        text: String,
    },
    Pointer {
        target: Address,
    },
    Caller {
        target: Address,
        opcode: u8,
    },
    IndirectCaller {
        target: Address,
        opcode: u8,
        pointer: Address,
    },
    Numeric {
        type_name: String,
        value: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceContext {
    pub before: Vec<u8>,
    pub after: Vec<u8>,
    pub ascii_preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolArgument {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextToolHint {
    pub tool: String,
    pub reason: String,
    pub arguments: Vec<ToolArgument>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceHit {
    pub address: Address,
    pub label: String,
    pub address_context: AddressContext,
    pub evidence: EvidenceValue,
    pub context: EvidenceContext,
    pub next_tools: Vec<NextToolHint>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_arch_reports_pointer_width_and_decoder_bitness() {
        assert_eq!(TargetArch::X86.pointer_width_bytes(), 4);
        assert_eq!(TargetArch::X86.decoder_bitness(), 32);
        assert_eq!(TargetArch::X86_64.pointer_width_bytes(), 8);
        assert_eq!(TargetArch::X86_64.decoder_bitness(), 64);
    }

    #[test]
    fn converts_address_inside_module_to_rva() {
        let rva = Address(0x401234).to_rva(ModuleBase(0x400000)).unwrap();

        assert_eq!(rva, Rva(0x1234));
    }

    #[test]
    fn rejects_address_before_module_base() {
        let error = Address(0x3fffff).to_rva(ModuleBase(0x400000)).unwrap_err();

        assert_eq!(
            error,
            AddressError::AddressBeforeModule {
                address: Address(0x3fffff),
                module_base: ModuleBase(0x400000),
            }
        );
    }

    #[test]
    fn converts_rva_back_to_address() {
        let address = Rva(0x1234).to_address(ModuleBase(0x400000));

        assert_eq!(address, Address(0x401234));
    }

    #[test]
    fn evidence_hit_carries_ai_context_and_next_tools() {
        let hit = EvidenceHit {
            address: Address(0x401234),
            label: "Login".to_string(),
            address_context: AddressContext {
                module: Some(ModuleContext {
                    name: "login.exe".to_string(),
                    base: ModuleBase(0x400000),
                    rva: Rva(0x1234),
                }),
                region: RegionContext {
                    kind: RegionKind::Image,
                    flags: RegionFlags {
                        readable: true,
                        writable: false,
                        executable: false,
                        guarded: false,
                    },
                },
            },
            evidence: EvidenceValue::Utf8 {
                text: "Login failed".to_string(),
            },
            context: EvidenceContext {
                before: vec![0x00, 0x01],
                after: vec![0x02, 0x03],
                ascii_preview: "..Login failed..".to_string(),
            },
            next_tools: vec![NextToolHint {
                tool: "scan_pointers_to".to_string(),
                reason: "find code or data references to this string".to_string(),
                arguments: vec![ToolArgument {
                    name: "address".to_string(),
                    value: "0x401234".to_string(),
                }],
            }],
        };

        let json = serde_json::to_string(&hit).unwrap();

        assert!(json.contains("\"rva\":4660"));
        assert!(json.contains("\"tool\":\"scan_pointers_to\""));
        assert!(json.contains("\"ascii_preview\":\"..Login failed..\""));
    }
}
