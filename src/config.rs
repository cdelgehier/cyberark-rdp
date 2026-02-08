use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Ignore TLS certificate errors (like /cert:ignore in xfreerdp)
    #[serde(default = "default_true")]
    pub cert_ignore: bool,

    /// Allow dynamic window resize
    #[serde(default)]
    pub resize: bool,

    /// Default desktop width
    #[serde(default = "default_width")]
    pub default_width: u16,

    /// Default desktop height
    #[serde(default = "default_height")]
    pub default_height: u16,
}

fn default_true() -> bool {
    true
}
fn default_width() -> u16 {
    1280
}
fn default_height() -> u16 {
    1024
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cert_ignore: true,
            resize: false,
            default_width: 1280,
            default_height: 1024,
        }
    }
}

impl Config {
    /// Returns the config directory path (~/.config/cyberark-rdp/)
    pub fn config_dir() -> Result<PathBuf> {
        let proj = ProjectDirs::from("", "", "cyberark-rdp")
            .context("could not determine config directory")?;
        Ok(proj.config_dir().to_path_buf())
    }

    /// Returns the config file path
    pub fn config_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.yaml"))
    }

    /// Load config from disk, or return defaults if not found
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if path.exists() {
            let contents = fs::read_to_string(&path)
                .with_context(|| format!("failed to read config: {}", path.display()))?;
            let config: Config = serde_yaml::from_str(&contents)
                .with_context(|| format!("failed to parse config: {}", path.display()))?;
            Ok(config)
        } else {
            let config = Config::default();
            config.save()?;
            Ok(config)
        }
    }

    /// Save current config to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let yaml = serde_yaml::to_string(self)?;
        fs::write(&path, yaml)?;
        Ok(())
    }
}
