use talos_sdk_macros::talos_module;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;
use serde_json::Value;

#[talos_module(world = "network-node")]
fn run(input: String) -> Result<String, String> {
        use talos::core::logging::{log, Level};

        // ── Parse input ────────────────────────────────────────────────────
        let input_json: Value = serde_json::from_str(&input)
            .map_err(|e| format!("Invalid JSON input: {}", e))?;

        let config = input_json
            .get("config")
            .ok_or("Missing 'config' in input")?;

        let targets: Vec<String> = config
            .get("TARGETS")
            .and_then(|v| v.as_array())
            .ok_or("Missing or invalid 'TARGETS' array in config")?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();

        if targets.is_empty() {
            return Err("'TARGETS' array is empty — nothing to scan".to_string());
        }
        if targets.len() > 256 {
            return Err(format!(
                "Too many targets ({}); limit is 256 per execution",
                targets.len()
            ));
        }

        let timeout_ms = config
            .get("TIMEOUT_MS")
            .and_then(|v| v.as_u64())
            .unwrap_or(500)
            .clamp(50, 10_000);

        let include_banner = config
            .get("INCLUDE_BANNER")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let timeout = Duration::from_millis(timeout_ms);

        log(Level::Info, &format!(
            "Network scan started: {} targets, {}ms timeout, banner={}",
            targets.len(), timeout_ms, include_banner
        ));

        // ── Scan ───────────────────────────────────────────────────────────
        let mut results = Vec::with_capacity(targets.len());
        let mut open_count = 0u64;

        for target in &targets {
            let (open, banner) = probe_tcp(target, timeout, include_banner);
            if open {
                open_count += 1;
                log(Level::Info, &format!("  OPEN   {}", target));
            } else {
                log(Level::Debug, &format!("  CLOSED {}", target));
            }
            results.push(serde_json::json!({
                "target": target,
                "open": open,
                "banner": banner,
            }));
        }

        log(Level::Info, &format!(
            "Scan complete: {}/{} ports open",
            open_count,
            targets.len()
        ));

        // ── Build output ───────────────────────────────────────────────────
        let output = serde_json::json!({
            "results": results,
            "summary": {
                "total": targets.len(),
                "open": open_count,
                "closed": (targets.len() as u64).saturating_sub(open_count),
                "timeout_ms": timeout_ms,
            }
        });

        serde_json::to_string(&output).map_err(|e| format!("Failed to serialise output: {}", e))
    }

fn probe_tcp(target: &str, timeout: Duration, include_banner: bool) -> (bool, Option<String>) {
    let addr = match target.parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(_) => {
            // Try to resolve if it's "host:port" instead of IP:port
            // Just returning false for simplicity if it fails basic parse
            return (false, None);
        }
    };

    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut stream) => {
            stream.set_read_timeout(Some(timeout)).ok();
            
            let mut banner = None;
            if include_banner {
                let mut buf = [0; 1024];
                if let Ok(n) = stream.read(&mut buf) {
                    if n > 0 {
                        let b = String::from_utf8_lossy(&buf[..n]).into_owned();
                        banner = Some(b);
                    }
                }
            }
            (true, banner)
        }
        Err(_) => (false, None),
    }
}
