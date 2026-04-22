use rand::seq::SliceRandom;
use rand::thread_rng;

/// Realistic browser user-agents for rotation
static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
];

/// Accept-Language values to rotate
static ACCEPT_LANGS: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,fr;q=0.5",
    "en-US,en;q=0.9,de;q=0.8",
];

pub fn random_ua() -> &'static str {
    USER_AGENTS
        .choose(&mut thread_rng())
        .unwrap_or(&USER_AGENTS[0])
}

pub fn random_accept_lang() -> &'static str {
    ACCEPT_LANGS
        .choose(&mut thread_rng())
        .unwrap_or(&ACCEPT_LANGS[0])
}

/// Build a realistic-looking header set for a request
pub fn build_headers(ua: &str, accept_lang: &str) -> Vec<(String, String)> {
    vec![
        ("User-Agent".into(), ua.into()),
        (
            "Accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
                .into(),
        ),
        ("Accept-Language".into(), accept_lang.into()),
        ("Accept-Encoding".into(), "gzip, deflate, br".into()),
        ("Connection".into(), "keep-alive".into()),
        ("Upgrade-Insecure-Requests".into(), "1".into()),
        ("Cache-Control".into(), "max-age=0".into()),
    ]
}
