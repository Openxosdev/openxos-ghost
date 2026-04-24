use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    /// Delay range between requests in milliseconds
    pub delay_min_ms: u64,
    pub delay_max_ms: u64,
    /// Max concurrent connections
    pub concurrency: usize,
    /// Rotate user-agent every N requests
    pub ua_rotate_every: usize,
    /// Jitter factor applied to timing (0.0 - 1.0)
    pub jitter: f64,
    /// TCP connect timeout in milliseconds
    pub timeout_ms: u64,
}

impl Profile {
    pub fn slow() -> Self {
        Self {
            name: "slow".into(),
            delay_min_ms: 3000,
            delay_max_ms: 8000,
            concurrency: 1,
            ua_rotate_every: 1,
            jitter: 0.8,
            timeout_ms: 10000,
        }
    }

    pub fn medium() -> Self {
        Self {
            name: "medium".into(),
            delay_min_ms: 500,
            delay_max_ms: 2000,
            concurrency: 3,
            ua_rotate_every: 3,
            jitter: 0.5,
            timeout_ms: 5000,
        }
    }

    pub fn aggressive() -> Self {
        Self {
            name: "aggressive".into(),
            delay_min_ms: 100,
            delay_max_ms: 400,
            concurrency: 10,
            ua_rotate_every: 5,
            jitter: 0.2,
            timeout_ms: 3000,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.delay_min_ms > self.delay_max_ms {
            return Err(anyhow!(
                "Invalid profile '{}': delay_min_ms ({}) must be <= delay_max_ms ({})",
                self.name,
                self.delay_min_ms,
                self.delay_max_ms
            ));
        }
        if self.concurrency == 0 {
            return Err(anyhow!(
                "Invalid profile '{}': concurrency must be >= 1",
                self.name
            ));
        }
        if self.ua_rotate_every == 0 {
            return Err(anyhow!(
                "Invalid profile '{}': ua_rotate_every must be >= 1",
                self.name
            ));
        }
        if !(0.0..=1.0).contains(&self.jitter) {
            return Err(anyhow!(
                "Invalid profile '{}': jitter must be between 0.0 and 1.0",
                self.name
            ));
        }
        if self.timeout_ms == 0 {
            return Err(anyhow!(
                "Invalid profile '{}': timeout_ms must be >= 1",
                self.name
            ));
        }
        Ok(())
    }
}

pub fn load(name: &str) -> Result<Profile> {
    // Check if name is a file path first
    if Path::new(name).exists() {
        return load_from_file(name);
    }

    let profile = match name {
        "slow" => Profile::slow(),
        "medium" => Profile::medium(),
        "aggressive" => Profile::aggressive(),
        other => Err(anyhow!(
            "Unknown profile '{}'. Use: slow | medium | aggressive, or a path to a YAML file",
            other
        ))?,
    };

    profile.validate()?;
    Ok(profile)
}

/// Load a custom profile from a YAML file
pub fn load_from_file(path: &str) -> Result<Profile> {
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow!("Failed to read profile file '{}': {}", path, e))?;

    let profile: Profile = serde_yaml::from_str(&content)
        .map_err(|e| anyhow!("Failed to parse profile YAML in '{}': {}", path, e))?;

    profile.validate()?;

    // If no name provided, use filename
    if profile.name.is_empty() {
        let filename = Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("custom");
        return Ok(Profile {
            name: filename.to_string(),
            delay_min_ms: profile.delay_min_ms,
            delay_max_ms: profile.delay_max_ms,
            concurrency: profile.concurrency,
            ua_rotate_every: profile.ua_rotate_every,
            jitter: profile.jitter,
            timeout_ms: profile.timeout_ms,
        });
    }

    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::Profile;

    #[test]
    fn built_in_profiles_are_valid() {
        Profile::slow()
            .validate()
            .expect("slow profile must be valid");
        Profile::medium()
            .validate()
            .expect("medium profile must be valid");
        Profile::aggressive()
            .validate()
            .expect("aggressive profile must be valid");
    }

    #[test]
    fn validate_rejects_invalid_ranges() {
        let mut p = Profile::slow();
        p.delay_min_ms = 10;
        p.delay_max_ms = 5;
        let err = p.validate().expect_err("expected invalid delay range");
        assert!(err.to_string().contains("delay_min_ms"));
    }

    #[test]
    fn validate_rejects_invalid_limits() {
        let mut p = Profile::slow();
        p.concurrency = 0;
        let err = p.validate().expect_err("expected invalid concurrency");
        assert!(err.to_string().contains("concurrency"));

        let mut p = Profile::slow();
        p.ua_rotate_every = 0;
        let err = p.validate().expect_err("expected invalid ua_rotate_every");
        assert!(err.to_string().contains("ua_rotate_every"));

        let mut p = Profile::slow();
        p.jitter = 1.5;
        let err = p.validate().expect_err("expected invalid jitter");
        assert!(err.to_string().contains("jitter"));

        let mut p = Profile::slow();
        p.timeout_ms = 0;
        let err = p.validate().expect_err("expected invalid timeout_ms");
        assert!(err.to_string().contains("timeout_ms"));
    }

    #[test]
    fn yaml_profile_loading_works() {
        let yaml = r#"
name: test-yaml
delay_min_ms: 100
delay_max_ms: 500
concurrency: 2
ua_rotate_every: 3
jitter: 0.5
timeout_ms: 5000
"#;
        let profile = serde_yaml::from_str::<Profile>(yaml).expect("should parse YAML");
        assert_eq!(profile.name, "test-yaml");
        assert_eq!(profile.delay_min_ms, 100);
        assert_eq!(profile.delay_max_ms, 500);
    }
}
