use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use argus_router::{route_for_request, RouterPaths, WindowsResolver};
use serde_json::{json, Value};

fn main() {
    if let Err(err) = run_stdio() {
        eprintln!("argus-router error: {err}");
    }
}

fn run_stdio() -> io::Result<()> {
    let paths = RouterPaths::from_current_exe()?;
    let resolver = WindowsResolver;
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let request = serde_json::from_str::<Value>(&line).ok();
        let route = request
            .as_ref()
            .map(|request| route_for_request(request, &resolver))
            .unwrap_or_default();
        let backend = paths.exe_for_route(route);

        match forward_once(backend, &line) {
            Ok(output) => {
                if !output.stderr.trim().is_empty() {
                    eprintln!("{}", output.stderr.trim_end());
                }
                if output.stdout.is_empty() {
                    if !output.success && request_has_id(request.as_ref()) {
                        let response = error_response(
                            request_id(request.as_ref()),
                            &format!("argus backend exited without response: {backend:?}"),
                        );
                        writeln!(stdout, "{}", serde_json::to_string(&response).unwrap())?;
                    }
                } else {
                    stdout.write_all(&output.stdout)?;
                    if !output.stdout.ends_with(b"\n") {
                        stdout.write_all(b"\n")?;
                    }
                }
                stdout.flush()?;
            }
            Err(err) => {
                if request_has_id(request.as_ref()) {
                    let response = error_response(
                        request_id(request.as_ref()),
                        &format!("failed to run argus backend {backend:?}: {err}"),
                    );
                    writeln!(stdout, "{}", serde_json::to_string(&response).unwrap())?;
                    stdout.flush()?;
                } else {
                    eprintln!("failed to run argus backend {backend:?}: {err}");
                }
            }
        }
    }

    Ok(())
}

struct ForwardOutput {
    stdout: Vec<u8>,
    stderr: String,
    success: bool,
}

fn forward_once(backend: &Path, line: &str) -> io::Result<ForwardOutput> {
    let mut child = Command::new(backend)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "backend stdin was not piped")
        })?;
        writeln!(stdin, "{line}")?;
    }

    let output = child.wait_with_output()?;
    Ok(ForwardOutput {
        stdout: output.stdout,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        success: output.status.success(),
    })
}

fn request_has_id(request: Option<&Value>) -> bool {
    request.and_then(|request| request.get("id")).is_some()
}

fn request_id(request: Option<&Value>) -> Value {
    request
        .and_then(|request| request.get("id").cloned())
        .unwrap_or(Value::Null)
}

fn error_response(id: Value, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32000,
            "message": message
        }
    })
}
