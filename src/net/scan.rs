use anyhow::{anyhow, Result};
use chrono::Utc;
use colored::Colorize;
use rand::seq::SliceRandom;
use std::collections::BTreeSet;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

use crate::core::profile::Profile;
use crate::core::types::{EvasionSummary, Evidence, Finding, ScanMode, ScanResult, Severity};

/// Parse port spec into list of port numbers
fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    match spec {
        "top100" => Ok(vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389,
            5900, 8080, 8443, 8888, 9090, 9200, 27017,
        ]),
        other => {
            let mut ports = BTreeSet::new();
            let mut invalid_parts = Vec::new();

            for part in other.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }

                if let Some((start, end)) = part.split_once('-') {
                    if let (Ok(s), Ok(e)) = (start.parse::<u16>(), end.parse::<u16>()) {
                        if s == 0 || e == 0 || s > e {
                            invalid_parts.push(part.to_string());
                            continue;
                        }
                        ports.extend(s..=e);
                    } else {
                        invalid_parts.push(part.to_string());
                    }
                } else if let Ok(p) = part.parse::<u16>() {
                    if p == 0 {
                        invalid_parts.push(part.to_string());
                    } else {
                        ports.insert(p);
                    }
                } else {
                    invalid_parts.push(part.to_string());
                }
            }

            if !invalid_parts.is_empty() {
                return Err(anyhow!(
                    "Invalid port spec segment(s): {}. Use values like '80,443' or '1-1024'.",
                    invalid_parts.join(", ")
                ));
            }

            if ports.is_empty() {
                return Err(anyhow!(
                    "No ports to scan from spec '{}'. Use 'top100' or explicit ports/ranges.",
                    spec
                ));
            }

            Ok(ports.into_iter().collect())
        }
    }
}

pub async fn run(target: &str, ports_spec: &str, profile: &Profile) -> Result<ScanResult> {
    let started_at = Utc::now();
    let mut findings: Vec<Finding> = Vec::new();
    let mut techniques_succeeded: Vec<String> = Vec::new();
    let mut detection_gaps: Vec<String> = Vec::new();

    let mut ports = parse_ports(ports_spec)?;

    // Randomize port order — avoids sequential scan detection
    let mut rng = rand::thread_rng();
    ports.shuffle(&mut rng);

    println!(
        "  {} Scanning {} ports on {} (randomized order, {} profile, concurrency setting {})...",
        "·".dimmed(),
        ports.len(),
        target.yellow(),
        profile.name,
        profile.concurrency
    );

    let concurrency = profile.concurrency.max(1);
    for batch in ports.chunks(concurrency) {
        let mut tasks = JoinSet::new();

        for &port in batch {
            let target = target.to_string();
            let delay_min_ms = profile.delay_min_ms;
            let delay_max_ms = profile.delay_max_ms;
            let jitter_factor = profile.jitter;
            let timeout_ms = profile.timeout_ms;

            tasks.spawn(async move {
                let delay_ms = randomized_delay_ms(delay_min_ms, delay_max_ms, jitter_factor);
                sleep(Duration::from_millis(delay_ms)).await;

                let addr = format!("{}:{}", target, port);
                let is_open = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false);

                (port, is_open)
            });
        }

        while let Some(task_result) = tasks.join_next().await {
            let Ok((port, is_open)) = task_result else {
                continue;
            };

            if !is_open {
                continue;
            }

            println!(
                "  {} Port {} open",
                "+".green().bold(),
                port.to_string().green()
            );

            let service = common_service(port);
            let technique: String = "Randomized-order low-rate TCP connect scan".into();
            let gap = format!(
                "Port {} discovered via slow randomized probing — sequential fast scanners \
                 would trigger IDS threshold detection before reaching this port",
                port
            );

            techniques_succeeded.push(technique.clone());
            detection_gaps.push(gap.clone());

            findings.push(Finding {
                severity: port_severity(port),
                title: format!("Open port {}/tcp ({})", port, service),
                description: format!(
                    "Port {}/tcp is open on {}. Service: {}.",
                    port, target, service
                ),
                evasion_technique: technique,
                detection_gap: gap,
                evidence: Evidence {
                    request: format!("TCP connect → {}:{}", target, port),
                    response_code: None,
                    response_snippet: None,
                    curl_repro: Some(format!(
                        "# Verify open port\nnc -zv {} {} 2>&1",
                        target, port
                    )),
                },
            });
        }
    }

    let completed_at = Utc::now();

    println!(
        "\n  {} Scan complete. {}/{} ports open.",
        ">>".cyan().bold(),
        findings.len().to_string().yellow(),
        ports.len()
    );

    Ok(ScanResult {
        mode: ScanMode::Net,
        target: target.into(),
        profile: profile.name.clone(),
        started_at,
        completed_at,
        findings,
        evasion_summary: EvasionSummary {
            waf_detected: None,
            techniques_attempted: vec![
                "Randomized port order".into(),
                "Low-rate probe timing".into(),
                "Jittered inter-probe delay".into(),
            ],
            techniques_succeeded,
            detection_gaps,
        },
    })
}

fn common_service(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        3306 => "MySQL",
        3389 => "RDP",
        5900 => "VNC",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        _ => "Unknown",
    }
}

fn port_severity(port: u16) -> Severity {
    match port {
        23 | 3389 | 5900 => Severity::High,
        21 | 445 | 27017 | 9200 => Severity::Medium,
        22 | 80 | 443 => Severity::Info,
        _ => Severity::Low,
    }
}

fn randomized_delay_ms(delay_min_ms: u64, delay_max_ms: u64, jitter_factor: f64) -> u64 {
    use rand::Rng;
    let mut r = rand::thread_rng();
    let base = r.gen_range(delay_min_ms..=delay_max_ms);
    let jitter = (base as f64 * jitter_factor * r.gen::<f64>()) as u64;
    base + jitter
}

#[cfg(test)]
mod tests {
    use super::{parse_ports, run};
    use crate::core::profile::Profile;
    use std::time::{Duration, Instant};
    use tokio::net::TcpListener;

    #[test]
    fn parse_ports_accepts_ranges_and_dedupes() {
        let ports = parse_ports("80,443,1000-1002,443").expect("expected valid ports");
        assert_eq!(ports, vec![80, 443, 1000, 1001, 1002]);
    }

    #[test]
    fn parse_ports_rejects_invalid_values() {
        let err = parse_ports("0,22,10-1,bad").expect_err("expected invalid port spec");
        let msg = err.to_string();
        assert!(msg.contains("Invalid port spec segment(s)"));
    }

    #[tokio::test]
    async fn run_finds_open_local_port() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind local tcp listener");
        let port = listener
            .local_addr()
            .expect("listener should have a local addr")
            .port();

        let accept_task = tokio::spawn(async move {
            // Accept one connection so the connect check can succeed.
            let _ = listener.accept().await;
        });

        let profile = Profile {
            name: "test".into(),
            delay_min_ms: 0,
            delay_max_ms: 0,
            concurrency: 1,
            ua_rotate_every: 1,
            jitter: 0.0,
            timeout_ms: 200,
        };

        let result = run("127.0.0.1", &port.to_string(), &profile)
            .await
            .expect("scan should succeed");

        accept_task.abort();

        assert_eq!(result.findings.len(), 1, "expected one open port finding");
        assert!(
            result.findings[0].title.contains(&port.to_string()),
            "finding should reference scanned open port"
        );
    }

    #[tokio::test]
    async fn higher_concurrency_reduces_scan_time_under_delay() {
        let ports = "65001-65006";
        let slow_profile = Profile {
            name: "test-slow".into(),
            delay_min_ms: 50,
            delay_max_ms: 50,
            concurrency: 1,
            ua_rotate_every: 1,
            jitter: 0.0,
            timeout_ms: 50,
        };
        let fast_profile = Profile {
            name: "test-fast".into(),
            delay_min_ms: 50,
            delay_max_ms: 50,
            concurrency: 3,
            ua_rotate_every: 1,
            jitter: 0.0,
            timeout_ms: 50,
        };

        let t1 = Instant::now();
        let _ = run("127.0.0.1", ports, &slow_profile)
            .await
            .expect("sequential-like scan should run");
        let slow_elapsed = t1.elapsed();

        let t2 = Instant::now();
        let _ = run("127.0.0.1", ports, &fast_profile)
            .await
            .expect("concurrent scan should run");
        let fast_elapsed = t2.elapsed();

        assert!(
            fast_elapsed + Duration::from_millis(60) < slow_elapsed,
            "expected concurrency to reduce runtime (slow={:?}, fast={:?})",
            slow_elapsed,
            fast_elapsed
        );
    }
}
