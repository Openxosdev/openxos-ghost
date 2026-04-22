use rand::Rng;
use std::time::Duration;
use tokio::time::sleep;

use crate::core::profile::Profile;

/// Apply randomized delay based on profile settings
pub async fn delay(profile: &Profile) {
    let mut rng = rand::thread_rng();
    let base = rng.gen_range(profile.delay_min_ms..=profile.delay_max_ms);
    let jitter = (base as f64 * profile.jitter * rng.gen::<f64>()) as u64;
    let total = base + jitter;
    sleep(Duration::from_millis(total)).await;
}

/// HTTP header injection bypass variants to try
pub fn header_bypass_variants() -> Vec<Vec<(String, String)>> {
    vec![
        // X-Forwarded-For spoofing
        vec![
            ("X-Forwarded-For".into(), "127.0.0.1".into()),
            ("X-Real-IP".into(), "127.0.0.1".into()),
        ],
        // Internal IP simulation
        vec![
            ("X-Originating-IP".into(), "10.0.0.1".into()),
            ("X-Remote-IP".into(), "10.0.0.1".into()),
            ("X-Client-IP".into(), "10.0.0.1".into()),
        ],
        // Host header manipulation
        vec![
            ("X-Host".into(), "localhost".into()),
            ("X-Forwarded-Host".into(), "localhost".into()),
        ],
        // Custom referrer spoofing
        vec![("Referer".into(), "https://google.com/".into())],
    ]
}

/// URL encoding variants for path probing
pub fn path_encoding_variants(path: &str) -> Vec<String> {
    vec![
        path.to_string(),
        path.replace('/', "%2F"),
        path.replace('/', "/./"),
        format!("{}%20", path),
        format!("{}/", path),
        path.to_uppercase(),
        path.to_lowercase(),
    ]
}

/// Techniques attempted — used in evasion summary report
pub fn all_technique_names() -> Vec<String> {
    vec![
        "User-Agent rotation".into(),
        "Request timing jitter".into(),
        "X-Forwarded-For header injection".into(),
        "Internal IP simulation".into(),
        "Host header manipulation".into(),
        "Referrer spoofing".into(),
        "URL path encoding variants".into(),
    ]
}
