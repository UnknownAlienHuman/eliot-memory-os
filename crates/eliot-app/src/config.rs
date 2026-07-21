use anyhow::{Context, Result};
use eliot_types::GovernorConfig;
use std::path::Path;

pub fn load_config(path: &Path) -> Result<GovernorConfig> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let config: GovernorConfig =
        toml::from_str(&content).with_context(|| format!("parse config {}", path.display()))?;
    config.validate()?;
    Ok(config)
}
