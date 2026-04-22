use anyhow::{anyhow, Result};
use chrono::Utc;
use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

use crate::core::profile::Profile;
use crate::core::types::{EvasionSummary, Evidence, Finding, ScanMode, ScanResult, Severity};
use crate::web::{evasion, headers, waf};

pub async fn run(target: &str, path: Option<&str>, profile: &Profile) -> Result<ScanResult> {
    let started_at = Utc::now();
    let mut findings: Vec<Finding> = Vec::new();
    let mut techniques_succeeded: Vec<String> = Vec::new();
    let mut detection_gaps: Vec<String> = Vec::new();

    let client = Client::builder()
        .timeout(Duration::from_millis(profile.timeout_ms))
        .danger_accept_invalid_certs(false)
        .build()?;

    let probe_path = normalize_path(path.unwrap_or("/"));
    let base_url = format!("{}{}", target.trim_end_matches('/'), probe_path);

    println!("  {} Detecting WAF/security controls...", "·".dimmed());

    // Step 1 — baseline request to detect WAF
    let ua = headers::random_ua();
    let baseline_resp = client.get(&base_url).header("User-Agent", ua).send().await;

    let baseline_status = baseline_resp
        .as_ref()
        .ok()
        .map(|resp| resp.status().as_u16());

    let waf_result = match baseline_resp {
        Ok(resp) => waf::detect(resp).await,
        Err(err) => {
            return Err(anyhow!(
                "Baseline request to '{}' failed: {}. Target may be offline/unreachable.",
                base_url,
                err
            ))
        }
    };

    if waf_result.detected {
        println!(
            "  {} WAF detected: {}",
            "!".yellow().bold(),
            waf_result.name.as_deref().unwrap_or("Unknown").yellow()
        );
        println!("  {} {}", "·".dimmed(), waf_result.evidence);
    } else {
        println!(
            "  {} No WAF detected in baseline (HTTP {}, {})",
            "·".dimmed(),
            baseline_status.unwrap_or(0),
            waf_result.evidence
        );
    }

    // Step 2 — attempt header bypass variants
    println!(
        "  {} Testing header-based bypass techniques...",
        "·".dimmed()
    );

    let mut request_count = 0usize;
    let mut current_ua = headers::random_ua();

    for (i, variant_headers) in evasion::header_bypass_variants().iter().enumerate() {
        evasion::delay(profile).await;
        request_count += 1;

        if should_rotate_ua(request_count, profile.ua_rotate_every) {
            current_ua = headers::random_ua();
        }
        let lang = headers::random_accept_lang();
        let mut req = client.get(&base_url);

        for (k, v) in headers::build_headers(current_ua, lang) {
            req = req.header(k, v);
        }

        for (k, v) in variant_headers {
            req = req.header(k.as_str(), v.as_str());
        }

        if let Ok(resp) = req.send().await {
            let status = resp.status().as_u16();
            if is_bypass_success(baseline_status, status) {
                let technique = format!("Header bypass variant {}", i + 1);
                let gap = format!(
                    "Baseline HTTP {} changed to HTTP {} using {}",
                    baseline_status.unwrap_or(0),
                    status,
                    variant_headers
                        .iter()
                        .map(|(k, _)| k.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                println!(
                    "  {} {} → HTTP {}",
                    "+".green().bold(),
                    technique,
                    status.to_string().green()
                );

                techniques_succeeded.push(technique.clone());
                detection_gaps.push(gap.clone());

                let curl = build_curl(&base_url, current_ua, variant_headers);
                findings.push(Finding {
                    severity: Severity::Medium,
                    title: "Security control bypass via request headers".into(),
                    description: format!(
                        "Target {} accepted request with modified headers that improved access over baseline.",
                        base_url
                    ),
                    evasion_technique: technique,
                    detection_gap: gap,
                    evidence: Evidence {
                        request: format!("GET {} HTTP/1.1", base_url),
                        response_code: Some(status),
                        response_snippet: None,
                        curl_repro: Some(curl),
                    },
                });
            }
        }
    }

    // Step 3 — path encoding variants
    println!("  {} Testing path encoding variants...", "·".dimmed());

    for encoded_path in evasion::path_encoding_variants(&probe_path) {
        if encoded_path == probe_path {
            continue; // skip baseline
        }
        evasion::delay(profile).await;
        request_count += 1;

        let url = format!("{}{}", target.trim_end_matches('/'), encoded_path);
        if should_rotate_ua(request_count, profile.ua_rotate_every) {
            current_ua = headers::random_ua();
        }

        if let Ok(resp) = client
            .get(&url)
            .header("User-Agent", current_ua)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            if is_bypass_success(baseline_status, status) {
                let technique = format!("Path encoding: {}", encoded_path);
                let gap = format!(
                    "Baseline HTTP {} changed to HTTP {} using encoded path '{}'",
                    baseline_status.unwrap_or(0),
                    status,
                    encoded_path
                );

                println!(
                    "  {} Path encoding bypass → HTTP {}",
                    "+".green().bold(),
                    status.to_string().green()
                );

                techniques_succeeded.push(technique.clone());
                detection_gaps.push(gap.to_string());

                findings.push(Finding {
                    severity: Severity::Medium,
                    title: "WAF path normalization bypass".into(),
                    description: format!(
                        "Encoded path '{}' produced better access than the baseline path.",
                        encoded_path
                    ),
                    evasion_technique: technique,
                    detection_gap: gap,
                    evidence: Evidence {
                        request: format!("GET {} HTTP/1.1", url),
                        response_code: Some(status),
                        response_snippet: None,
                        curl_repro: Some(format!(
                            "curl -s -o /dev/null -w '%{{http_code}}' '{}'",
                            url
                        )),
                    },
                });
            }
        }
    }

    let completed_at = Utc::now();

    println!(
        "\n  {} Scan complete. {} finding(s) recorded.",
        ">>".cyan().bold(),
        findings.len().to_string().yellow()
    );

    Ok(ScanResult {
        mode: ScanMode::Web,
        target: target.into(),
        profile: profile.name.clone(),
        started_at,
        completed_at,
        findings,
        evasion_summary: EvasionSummary {
            waf_detected: waf_result.name,
            techniques_attempted: evasion::all_technique_names(),
            techniques_succeeded,
            detection_gaps,
        },
    })
}

fn build_curl(url: &str, ua: &str, extra_headers: &[(String, String)]) -> String {
    let mut parts = vec![format!(
        "curl -s -o /dev/null -w '%{{http_code}}' '{}'",
        url
    )];
    parts.push(format!("-H 'User-Agent: {}'", ua));
    for (k, v) in extra_headers {
        parts.push(format!("-H '{}: {}'", k, v));
    }
    parts.join(" \\\n  ")
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed)
    }
}

fn is_bypass_success(baseline_status: Option<u16>, variant_status: u16) -> bool {
    match baseline_status {
        Some(status) => status >= 400 && variant_status < 400,
        None => false,
    }
}

fn should_rotate_ua(request_count: usize, rotate_every: usize) -> bool {
    if rotate_every <= 1 {
        return true;
    }
    request_count.is_multiple_of(rotate_every)
}

#[cfg(test)]
mod tests {
    use super::{is_bypass_success, normalize_path, should_rotate_ua};
    use crate::core::profile::Profile;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn normalize_path_handles_missing_slash() {
        assert_eq!(normalize_path("admin"), "/admin");
        assert_eq!(normalize_path("/admin"), "/admin");
        assert_eq!(normalize_path(" /admin "), "/admin");
        assert_eq!(normalize_path(""), "/");
    }

    #[test]
    fn bypass_success_requires_improvement_over_blocked_baseline() {
        assert!(is_bypass_success(Some(403), 200));
        assert!(is_bypass_success(Some(500), 302));
        assert!(!is_bypass_success(Some(200), 200));
        assert!(!is_bypass_success(Some(404), 404));
        assert!(!is_bypass_success(None, 200));
    }

    #[test]
    fn rotate_every_logic_is_stable() {
        assert!(should_rotate_ua(1, 1));
        assert!(!should_rotate_ua(1, 3));
        assert!(!should_rotate_ua(2, 3));
        assert!(should_rotate_ua(3, 3));
    }

    #[tokio::test]
    async fn run_reports_header_bypass_when_baseline_blocked() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test http listener");
        let addr = listener
            .local_addr()
            .expect("test http listener should have local addr");

        let server_task = tokio::spawn(async move {
            // Handle enough requests for one full probe run.
            for _ in 0..24 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };

                let mut buf = vec![0u8; 8192];
                let Ok(n) = socket.read(&mut buf).await else {
                    continue;
                };
                if n == 0 {
                    continue;
                }

                let req = String::from_utf8_lossy(&buf[..n]).to_lowercase();
                let has_bypass_header = req.contains("x-forwarded-for: 127.0.0.1");
                let status = if has_bypass_header { 200 } else { 403 };
                let body = if status == 200 { "ok" } else { "access denied" };
                let resp = format!(
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                    status,
                    if status == 200 { "OK" } else { "Forbidden" },
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let profile = Profile {
            name: "test".into(),
            delay_min_ms: 0,
            delay_max_ms: 0,
            concurrency: 1,
            ua_rotate_every: 1,
            jitter: 0.0,
            timeout_ms: 500,
        };

        let target = format!("http://{}", addr);
        let result = super::run(&target, Some("/admin"), &profile)
            .await
            .expect("web probe should succeed against local test server");

        server_task.abort();

        assert!(
            result
                .findings
                .iter()
                .any(|f| f.title == "Security control bypass via request headers"),
            "expected at least one header bypass finding"
        );
        assert!(
            result
                .evasion_summary
                .techniques_succeeded
                .iter()
                .any(|t| t.to_lowercase().contains("header bypass")),
            "expected header bypass in succeeded techniques"
        );
    }
}
