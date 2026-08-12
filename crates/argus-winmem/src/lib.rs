#![cfg(windows)]

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;

use argus_engine::{InMemoryBackend, MemoryRegion, ModuleInfo};
use evidence_core::{Address, ModuleBase, RegionFlags, RegionKind, TargetArch};
use serde::Serialize;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows_sys::Win32::System::ProcessStatus::{
    K32EnumProcessModules, K32GetModuleBaseNameW, K32GetModuleInformation, MODULEINFO,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, IsWow64Process, OpenProcess, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinMemoryError {
    OpenProcess { pid: u32, code: u32 },
    ReadProcessMemory { address: Address, code: u32 },
    WriteProcessMemory { address: Address, code: u32 },
    VirtualProtectEx { address: Address, code: u32 },
    VirtualQueryEx { address: Address, code: u32 },
    EnumProcessModules { code: u32 },
    ProcessSnapshot { code: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MemoryRegionInfo {
    pub base: Address,
    pub size: usize,
    pub kind: RegionKind,
    pub flags: RegionFlags,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub thread_count: u32,
    pub name: String,
}

pub fn processes() -> Result<Vec<ProcessInfo>, WinMemoryError> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(WinMemoryError::ProcessSnapshot { code: last_error() });
    }
    let _snapshot = SnapshotHandle(snapshot);

    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    let ok = unsafe { Process32FirstW(snapshot, &mut entry) };
    if ok == 0 {
        return Err(WinMemoryError::ProcessSnapshot { code: last_error() });
    }

    let mut result = Vec::new();
    loop {
        result.push(ProcessInfo {
            pid: entry.th32ProcessID,
            parent_pid: entry.th32ParentProcessID,
            thread_count: entry.cntThreads,
            name: utf16_z_to_string(&entry.szExeFile),
        });

        let ok = unsafe { Process32NextW(snapshot, &mut entry) };
        if ok == 0 {
            break;
        }
    }

    Ok(result)
}

struct SnapshotHandle(HANDLE);

impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

impl MemoryRegionInfo {
    pub fn contains(self, address: Address) -> bool {
        let start = self.base.0;
        let end = start.saturating_add(self.size as u64);
        start <= address.0 && address.0 < end
    }
}

#[derive(Debug)]
pub struct WinProcess {
    handle: HANDLE,
    pid: u32,
}

impl WinProcess {
    pub fn current() -> Result<Self, WinMemoryError> {
        let pid = unsafe { GetCurrentProcessId() };
        Self::open(pid)
    }

    pub fn open(pid: u32) -> Result<Self, WinMemoryError> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION
                    | PROCESS_VM_READ
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_OPERATION,
                0,
                pid,
            )
        };
        if handle.is_null() {
            return Err(WinMemoryError::OpenProcess {
                pid,
                code: last_error(),
            });
        }

        Ok(Self { handle, pid })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn target_arch(&self) -> TargetArch {
        let mut is_wow64 = 0i32;
        let ok = unsafe { IsWow64Process(self.handle, &mut is_wow64) };
        if ok == 0 {
            return TargetArch::native();
        }

        if is_wow64 != 0 {
            TargetArch::X86
        } else if cfg!(target_arch = "x86_64") {
            TargetArch::X86_64
        } else {
            TargetArch::X86
        }
    }

    pub fn read(&self, address: Address, size: usize) -> Result<Vec<u8>, WinMemoryError> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                address.0 as usize as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                &mut bytes_read,
            )
        };

        if ok == 0 {
            return Err(WinMemoryError::ReadProcessMemory {
                address,
                code: last_error(),
            });
        }

        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    pub fn write(&self, address: Address, bytes: &[u8]) -> Result<usize, WinMemoryError> {
        if bytes.is_empty() {
            return Ok(0);
        }

        let mut old_protect = 0u32;
        let protect_ok = unsafe {
            VirtualProtectEx(
                self.handle,
                address.0 as usize as *const c_void,
                bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
        };
        if protect_ok == 0 {
            return Err(WinMemoryError::VirtualProtectEx {
                address,
                code: last_error(),
            });
        }

        let mut written = 0usize;
        let write_ok = unsafe {
            WriteProcessMemory(
                self.handle,
                address.0 as usize as *const c_void,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                &mut written,
            )
        };

        let mut ignored = 0u32;
        unsafe {
            VirtualProtectEx(
                self.handle,
                address.0 as usize as *const c_void,
                bytes.len(),
                old_protect,
                &mut ignored,
            );
        }

        if write_ok == 0 {
            return Err(WinMemoryError::WriteProcessMemory {
                address,
                code: last_error(),
            });
        }

        Ok(written)
    }

    pub fn query_region(&self, address: Address) -> Result<MemoryRegionInfo, WinMemoryError> {
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        let queried = unsafe {
            VirtualQueryEx(
                self.handle,
                address.0 as usize as *const c_void,
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if queried == 0 {
            return Err(WinMemoryError::VirtualQueryEx {
                address,
                code: last_error(),
            });
        }

        Ok(MemoryRegionInfo {
            base: Address(info.BaseAddress as u64),
            size: info.RegionSize,
            kind: region_kind(info.Type),
            flags: region_flags(info.Protect),
        })
    }

    pub fn snapshot_window(
        &self,
        address: Address,
        before: usize,
        after: usize,
    ) -> Result<InMemoryBackend, WinMemoryError> {
        let region = self.query_region(address)?;
        let region_start = region.base.0;
        let region_end = region_start.saturating_add(region.size as u64);
        let wanted_start = address.0.saturating_sub(before as u64).max(region_start);
        let wanted_end = address.0.saturating_add(after as u64).min(region_end);
        let wanted_len = wanted_end.saturating_sub(wanted_start) as usize;
        let bytes = self.read(Address(wanted_start), wanted_len)?;

        Ok(InMemoryBackend {
            modules: self.modules().unwrap_or_default(),
            regions: vec![MemoryRegion {
                base: Address(wanted_start),
                bytes,
                kind: region.kind,
                flags: region.flags,
            }],
        })
    }

    pub fn snapshot_readable_regions(
        &self,
        max_region_bytes: usize,
        max_total_bytes: usize,
    ) -> Result<InMemoryBackend, WinMemoryError> {
        if max_region_bytes == 0 || max_total_bytes == 0 {
            return Ok(InMemoryBackend {
                modules: self.modules().unwrap_or_default(),
                regions: Vec::new(),
            });
        }

        let mut total_bytes = 0usize;
        let mut regions = Vec::new();
        for region in self.committed_regions()? {
            if total_bytes >= max_total_bytes || !region.flags.readable || region.flags.guarded {
                continue;
            }

            let remaining = max_total_bytes - total_bytes;
            let read_len = region.size.min(max_region_bytes).min(remaining);
            let Ok(bytes) = self.read(region.base, read_len) else {
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

        Ok(InMemoryBackend {
            modules: self.modules().unwrap_or_default(),
            regions,
        })
    }

    pub fn committed_regions(&self) -> Result<Vec<MemoryRegionInfo>, WinMemoryError> {
        let mut out = Vec::new();
        let mut cursor = 0usize;

        loop {
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            let queried = unsafe {
                VirtualQueryEx(
                    self.handle,
                    cursor as *const c_void,
                    &mut info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if queried == 0 {
                break;
            }

            let base = info.BaseAddress as usize;
            let size = info.RegionSize;
            if info.State == MEM_COMMIT && size > 0 {
                out.push(MemoryRegionInfo {
                    base: Address(base as u64),
                    size,
                    kind: region_kind(info.Type),
                    flags: region_flags(info.Protect),
                });
            }

            let next = base.saturating_add(size);
            if next <= cursor || next == usize::MAX {
                break;
            }
            cursor = next;
        }

        Ok(out)
    }

    pub fn modules(&self) -> Result<Vec<ModuleInfo>, WinMemoryError> {
        let mut needed = 0u32;
        let mut handles: Vec<HMODULE> = vec![null_mut(); 1024];
        let ok = unsafe {
            K32EnumProcessModules(
                self.handle,
                handles.as_mut_ptr(),
                (handles.len() * size_of::<HMODULE>()) as u32,
                &mut needed,
            )
        };

        if ok == 0 {
            return Err(WinMemoryError::EnumProcessModules { code: last_error() });
        }

        let count = (needed as usize / size_of::<HMODULE>()).min(handles.len());
        handles.truncate(count);

        let mut modules = Vec::new();
        for handle in handles {
            let mut info: MODULEINFO = unsafe { zeroed() };
            let ok = unsafe {
                K32GetModuleInformation(
                    self.handle,
                    handle,
                    &mut info,
                    size_of::<MODULEINFO>() as u32,
                )
            };
            if ok == 0 || info.lpBaseOfDll.is_null() || info.SizeOfImage == 0 {
                continue;
            }

            modules.push(ModuleInfo {
                name: self.module_name(handle),
                base: ModuleBase(info.lpBaseOfDll as u64),
                size: info.SizeOfImage as u64,
            });
        }

        Ok(modules)
    }

    fn module_name(&self, module: HMODULE) -> String {
        let mut buffer = [0u16; 260];
        let len = unsafe {
            K32GetModuleBaseNameW(
                self.handle,
                module,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        } as usize;

        if len == 0 {
            return "<unknown>".to_string();
        }

        String::from_utf16_lossy(&buffer[..len])
    }
}

impl Drop for WinProcess {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

fn utf16_z_to_string(value: &[u16]) -> String {
    let len = value.iter().position(|ch| *ch == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..len])
}

fn region_kind(kind: u32) -> RegionKind {
    match kind {
        MEM_IMAGE => RegionKind::Image,
        MEM_PRIVATE => RegionKind::Heap,
        _ => RegionKind::Unknown,
    }
}

fn region_flags(protect: u32) -> RegionFlags {
    let base = protect & 0xff;
    RegionFlags {
        readable: is_readable(base),
        writable: matches!(
            base,
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        ),
        executable: matches!(
            base,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        ),
        guarded: protect & PAGE_GUARD != 0,
    }
}

fn is_readable(protect: u32) -> bool {
    !matches!(protect, PAGE_NOACCESS | PAGE_EXECUTE)
        && matches!(
            protect,
            PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_engine::ArgusEngine;
    use evidence_core::{Address, TargetArch};

    static SELF_READ_PROBE: &[u8] = b"ARGUS_WINMEM_SELF_READ";
    static ENGINE_SCAN_PROBE: &[u8] = b"ARGUS_WINMEM_ENGINE_SCAN";

    #[test]
    fn reads_current_process_probe_bytes() {
        let process = WinProcess::current().unwrap();
        let address = Address(SELF_READ_PROBE.as_ptr() as u64);

        let bytes = process.read(address, SELF_READ_PROBE.len()).unwrap();
        let region = process.query_region(address).unwrap();

        assert_eq!(bytes, SELF_READ_PROBE);
        assert!(region.contains(address));
        assert!(region.flags.readable);
        assert!(!region.flags.guarded);
    }

    #[test]
    fn detects_current_process_target_arch() {
        let process = WinProcess::current().unwrap();

        assert_eq!(process.target_arch(), TargetArch::native());
    }

    #[test]
    fn writes_current_process_memory() {
        let process = WinProcess::current().unwrap();
        let mut buffer = *b"ARGUS_WRITE_OLD";
        let address = Address(buffer.as_mut_ptr() as u64);

        let written = process.write(address, b"ARGUS_WRITE_NEW").unwrap();

        assert_eq!(written, 15);
        assert_eq!(&buffer, b"ARGUS_WRITE_NEW");
    }

    #[test]
    fn snapshot_window_feeds_ai_first_engine() {
        let process = WinProcess::current().unwrap();
        let address = Address(ENGINE_SCAN_PROBE.as_ptr() as u64);
        let backend = process
            .snapshot_window(address, 0, ENGINE_SCAN_PROBE.len())
            .unwrap();
        let engine = ArgusEngine::new(backend);

        let hits = engine.scan_string("ARGUS_WINMEM_ENGINE_SCAN", 1);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, address);
        assert!(hits[0].context.ascii_preview.contains("ARGUS_WINMEM"));
    }

    #[test]
    fn lists_current_process_modules() {
        let process = WinProcess::current().unwrap();

        let modules = process.modules().unwrap();

        assert!(!modules.is_empty());
        assert!(modules.iter().any(|module| module.size > 0));
    }

    #[test]
    fn lists_current_process_for_pid_lookup() {
        let current_pid = unsafe { GetCurrentProcessId() };

        let processes = processes().unwrap();

        let current = processes
            .iter()
            .find(|process| process.pid == current_pid)
            .expect("current process should be listed");
        assert!(!current.name.is_empty());
    }

    #[test]
    fn snapshots_readable_regions_with_limits() {
        let process = WinProcess::current().unwrap();

        let backend = process.snapshot_readable_regions(4096, 16 * 1024).unwrap();
        let total_bytes: usize = backend
            .regions
            .iter()
            .map(|region| region.bytes.len())
            .sum();

        assert!(!backend.regions.is_empty());
        assert!(total_bytes <= 16 * 1024);
        assert!(backend
            .regions
            .iter()
            .all(|region| region.bytes.len() <= 4096));
        assert!(backend
            .regions
            .iter()
            .all(|region| region.flags.readable && !region.flags.guarded));
    }
}
