use std::path::{Path, PathBuf};

use evidence_core::TargetArch;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    X86,
    X64,
}

impl Default for Route {
    fn default() -> Self {
        Self::X64
    }
}

pub trait TargetResolver {
    fn arch_for_pid(&self, pid: u32) -> Option<TargetArch>;
    fn arch_for_process_query(&self, query: &str) -> Option<TargetArch>;
}

pub struct WindowsResolver;

impl TargetResolver for WindowsResolver {
    fn arch_for_pid(&self, pid: u32) -> Option<TargetArch> {
        argus_winmem::WinProcess::open(pid)
            .ok()
            .map(|process| process.target_arch())
    }

    fn arch_for_process_query(&self, query: &str) -> Option<TargetArch> {
        let needle = query.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return None;
        }

        let processes = argus_winmem::processes().ok()?;
        processes
            .into_iter()
            .find(|process| process.name.to_ascii_lowercase().contains(&needle))
            .and_then(|process| self.arch_for_pid(process.pid))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterPaths {
    x86: PathBuf,
    x64: PathBuf,
}

impl RouterPaths {
    pub fn from_current_exe() -> std::io::Result<Self> {
        let exe = std::env::current_exe()?;
        Self::from_router_exe(exe)
    }

    pub fn from_router_exe(exe: impl Into<PathBuf>) -> std::io::Result<Self> {
        let exe = exe.into();
        let dir = exe
            .parent()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "router executable has no parent directory",
                )
            })?
            .to_path_buf();

        // In a cargo build the router sits at target/<triple>/release/argus-router.exe,
        // so the other architecture's engine lives two levels up under its own triple.
        // A released install has no such tree, which is why this stays optional.
        let cargo_target_dir = dir.parent().and_then(Path::parent).map(Path::to_path_buf);
        let cargo_target_dir = cargo_target_dir.as_deref();

        Ok(Self {
            x86: resolve_backend(
                &dir,
                cargo_target_dir,
                "ARGUS_ROUTER_X86",
                "argus-rs-x86.exe",
                "i686-pc-windows-msvc",
            ),
            x64: resolve_backend(
                &dir,
                cargo_target_dir,
                "ARGUS_ROUTER_X64",
                "argus-rs-x64.exe",
                "x86_64-pc-windows-msvc",
            ),
        })
    }

    pub fn exe_for_route(&self, route: Route) -> &Path {
        match route {
            Route::X86 => &self.x86,
            Route::X64 => &self.x64,
        }
    }
}

/// Locate one architecture's engine binary.
///
/// Resolution order: an explicit environment override, then an engine sitting next to
/// the router (how a release archive is laid out), then the cargo target tree (how a
/// development build is laid out). If nothing exists yet the sibling path is returned
/// so the failure names the file the user is expected to install.
fn resolve_backend(
    dir: &Path,
    cargo_target_dir: Option<&Path>,
    env_key: &str,
    sibling: &str,
    triple: &str,
) -> PathBuf {
    if let Some(value) = std::env::var_os(env_key) {
        return PathBuf::from(value);
    }

    let side_by_side = dir.join(sibling);
    if side_by_side.is_file() {
        return side_by_side;
    }

    if let Some(target_dir) = cargo_target_dir {
        let dev_path = target_dir.join(triple).join("release").join("argus-rs.exe");
        if dev_path.is_file() {
            return dev_path;
        }
    }

    side_by_side
}

pub fn route_for_request(request: &Value, resolver: &impl TargetResolver) -> Route {
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Route::X64;
    };
    if method != "tools/call" {
        return Route::X64;
    }

    let arguments = request
        .pointer("/params/arguments")
        .or_else(|| request.pointer("/params/_meta/arguments"))
        .unwrap_or(&Value::Null);

    if let Some(pid) = arguments
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
    {
        return route_for_arch(resolver.arch_for_pid(pid));
    }

    for key in ["process", "name", "process_name", "query"] {
        if let Some(query) = arguments.get(key).and_then(Value::as_str) {
            if !query.trim().is_empty() {
                return route_for_arch(resolver.arch_for_process_query(query));
            }
        }
    }

    Route::X64
}

fn route_for_arch(arch: Option<TargetArch>) -> Route {
    match arch {
        Some(TargetArch::X86) => Route::X86,
        Some(TargetArch::X86_64) | None => Route::X64,
    }
}

#[cfg(test)]
mod tests {
    use evidence_core::TargetArch;
    use serde_json::json;

    use crate::{route_for_request, Route, TargetResolver};

    struct FakeResolver;

    impl TargetResolver for FakeResolver {
        fn arch_for_pid(&self, pid: u32) -> Option<TargetArch> {
            match pid {
                32 => Some(TargetArch::X86),
                64 => Some(TargetArch::X86_64),
                _ => None,
            }
        }

        fn arch_for_process_query(&self, query: &str) -> Option<TargetArch> {
            match query {
                "legacy.exe" => Some(TargetArch::X86),
                "modern.exe" => Some(TargetArch::X86_64),
                _ => None,
            }
        }
    }

    #[test]
    fn routes_tool_call_with_32_bit_pid_to_x86_backend() {
        let request = json!({
            "method": "tools/call",
            "params": {
                "name": "mem_read",
                "arguments": {"pid": 32, "address": "0x401000", "size": 16}
            }
        });

        assert_eq!(route_for_request(&request, &FakeResolver), Route::X86);
    }

    #[test]
    fn routes_tool_call_with_64_bit_pid_to_x64_backend() {
        let request = json!({
            "method": "tools/call",
            "params": {
                "name": "mem_modules",
                "arguments": {"pid": 64}
            }
        });

        assert_eq!(route_for_request(&request, &FakeResolver), Route::X64);
    }

    #[test]
    fn routes_process_name_requests_when_pid_is_absent() {
        let request = json!({
            "method": "tools/call",
            "params": {
                "name": "mem_attach",
                "arguments": {"process": "legacy.exe"}
            }
        });

        assert_eq!(route_for_request(&request, &FakeResolver), Route::X86);
    }

    #[test]
    fn defaults_non_targeted_requests_to_x64_backend() {
        let request = json!({
            "method": "tools/call",
            "params": {
                "name": "processes_list",
                "arguments": {"limit": 1}
            }
        });

        assert_eq!(route_for_request(&request, &FakeResolver), Route::X64);
    }
}
