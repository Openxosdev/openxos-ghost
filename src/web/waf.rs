use reqwest::Response;

/// Known WAF signatures in response headers or body
static WAF_SIGNATURES: &[(&str, &str)] = &[
    ("server", "cloudflare"),
    ("server", "awselb"),
    ("x-sucuri-id", ""),
    ("x-firewall-protection", ""),
    ("x-waf-status", ""),
    ("x-cache", "HIT from akamai"),
    ("server", "imperva"),
    ("x-iinfo", ""), // Imperva Incapsula
    ("x-cdn", "imperva"),
    ("x-amzn-requestid", ""), // AWS
    ("x-azure-ref", ""),      // Azure Front Door
];

static WAF_BODY_SIGNATURES: &[(&str, &str)] = &[
    ("cloudflare", "Cloudflare"),
    ("403 forbidden", "Generic WAF"),
    ("access denied", "Generic WAF"),
    ("blocked by", "Generic WAF"),
    ("security check", "Generic WAF"),
    ("ddos protection", "DDoS Protection"),
    ("ray id:", "Cloudflare"),
    ("incident id:", "Imperva"),
];

pub struct WafDetectionResult {
    pub detected: bool,
    pub name: Option<String>,
    pub evidence: String,
}

pub async fn detect(response: Response) -> WafDetectionResult {
    // Check response headers
    for (header_name, signature) in WAF_SIGNATURES {
        if let Some(val) = response.headers().get(*header_name) {
            let val_str = val.to_str().unwrap_or("").to_lowercase();
            if signature.is_empty() || val_str.contains(signature) {
                let name = waf_name_from_header(header_name, &val_str);
                return WafDetectionResult {
                    detected: true,
                    name: Some(name.clone()),
                    evidence: format!(
                        "Header '{}: {}' matched WAF signature",
                        header_name, val_str
                    ),
                };
            }
        }
    }

    if let Ok(body) = response.text().await {
        let lowered = body.to_lowercase();
        for (signature, name) in WAF_BODY_SIGNATURES {
            if lowered.contains(signature) {
                return WafDetectionResult {
                    detected: true,
                    name: Some((*name).to_string()),
                    evidence: format!("Response body contained '{}' signature", signature),
                };
            }
        }
    }

    WafDetectionResult {
        detected: false,
        name: None,
        evidence: "No WAF signatures detected in headers/body".into(),
    }
}

fn waf_name_from_header(header: &str, value: &str) -> String {
    if header == "server" && value.contains("cloudflare") {
        return "Cloudflare".into();
    }
    if header == "server" && value.contains("awselb") {
        return "AWS ELB".into();
    }
    if header == "x-sucuri-id" {
        return "Sucuri".into();
    }
    if header == "x-iinfo" || (header == "x-cdn" && value.contains("imperva")) {
        return "Imperva Incapsula".into();
    }
    if header == "x-azure-ref" {
        return "Azure Front Door".into();
    }
    "Unknown WAF".into()
}
