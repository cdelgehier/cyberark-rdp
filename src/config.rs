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

    /// Default desktop width (deprecated, use preferences.resolution)
    #[serde(default = "default_width")]
    pub default_width: u16,

    /// Default desktop height (deprecated, use preferences.resolution)
    #[serde(default = "default_height")]
    pub default_height: u16,

    /// User preferences
    #[serde(default)]
    pub preferences: Preferences,

    /// Cached data (password, etc.)
    #[serde(default)]
    pub cache: Cache,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preferences {
    /// Last used resolution (e.g. "1920x1080")
    #[serde(default = "default_resolution")]
    pub resolution: String,

    /// Enable clipboard redirection by default
    #[serde(default)]
    pub clipboard: bool,

    /// Map local drives by default
    #[serde(default)]
    pub map_drives: bool,

    /// Delete .rdp file after connection by default
    #[serde(default)]
    pub burn_after_reading: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Cache {
    /// Cached password (temporary until keychain implementation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Timestamp when password was cached (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_cached_at: Option<String>,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            resolution: default_resolution(),
            clipboard: false,
            map_drives: false,
            burn_after_reading: false,
        }
    }
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
fn default_resolution() -> String {
    "1440x900".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cert_ignore: true,
            resize: false,
            default_width: 1280,
            default_height: 1024,
            preferences: Preferences::default(),
            cache: Cache::default(),
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
        tracing::info!("Config saved to: {}", path.display());
        Ok(())
    }

    /// Parse resolution string like "1920x1080" into (width, height)
    #[allow(dead_code)] // Will be used when resolution dropdown is implemented
    pub fn parse_resolution(res: &str) -> Option<(u16, u16)> {
        let parts: Vec<&str> = res.split('x').collect();
        if parts.len() != 2 {
            return None;
        }

        let width = parts[0].parse().ok()?;
        let height = parts[1].parse().ok()?;

        Some((width, height))
    }
}

/// Common resolution presets for the dropdown
#[allow(dead_code)] // Will be used when resolution dropdown is implemented
pub const RESOLUTIONS: &[&str] = &[
    "1024x768",
    "1280x720",
    "1280x1024",
    "1366x768",
    "1440x900",
    "1600x900",
    "1920x1080",
    "1920x1200",
    "2560x1440",
    "2560x1600",
    "3840x2160",
];
