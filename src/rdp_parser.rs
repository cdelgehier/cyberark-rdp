use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Parsed RDP file content
#[derive(Debug)]
pub struct RdpFile {
    /// Raw key-value entries from the .rdp file
    entries: HashMap<String, RdpValue>,
}

#[derive(Debug, Clone)]
pub enum RdpValue {
    Integer(i64),
    String(String),
}

#[allow(dead_code)]
impl RdpFile {
    /// Parse a .rdp file from disk
    ///
    /// RDP files use the format: `key:type:value`
    /// where type is `i` for integer or `s` for string
    pub fn parse(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read RDP file: {}", path.display()))?;

        let mut entries = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Format: key:type:value
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() < 3 {
                tracing::warn!("skipping malformed RDP line: {}", line);
                continue;
            }

            let key = parts[0].to_lowercase();
            let typ = parts[1];
            let val = parts[2];

            let value = match typ {
                "i" => match val.parse::<i64>() {
                    Ok(n) => RdpValue::Integer(n),
                    Err(_) => {
                        tracing::warn!("invalid integer value for key '{}': {}", key, val);
                        continue;
                    }
                },
                "s" => RdpValue::String(val.to_string()),
                _ => {
                    tracing::warn!("unknown type '{}' for key '{}'", typ, key);
                    continue;
                }
            };

            entries.insert(key, value);
        }

        Ok(Self { entries })
    }

    /// Get the full address (hostname:port or just hostname)
    pub fn full_address(&self) -> Option<&str> {
        match self.entries.get("full address") {
            Some(RdpValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get the hostname (without port)
    pub fn hostname(&self) -> Option<String> {
        self.full_address()
            .map(|addr| addr.split(':').next().unwrap_or(addr).to_string())
    }

    /// Get the port (default 3389)
    /// Get gateway hostname if configured
    pub fn gateway_hostname(&self) -> Option<&str> {
        self.get_str("gatewayhostname")
    }

    /// Get gateway usage method (0 = no gateway, 1 = use gateway)
    pub fn gateway_usage(&self) -> bool {
        matches!(self.get_int("gatewayusagemethod"), Some(1))
    }

    /// Get gateway access token (username for gateway auth)
    pub fn gateway_access_token(&self) -> Option<&str> {
        self.get_str("gatewayaccesstoken")
    }

    pub fn port(&self) -> u16 {
        // Try "server port" first
        if let Some(RdpValue::Integer(p)) = self.entries.get("server port") {
            return *p as u16;
        }
        // Then try parsing from full address
        if let Some(addr) = self.full_address()
            && let Some(port_str) = addr.split(':').nth(1)
            && let Ok(p) = port_str.parse::<u16>()
        {
            return p;
        }
        3389
    }

    /// Get the username if present
    pub fn username(&self) -> Option<&str> {
        match self.entries.get("username") {
            Some(RdpValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get the domain if present
    pub fn domain(&self) -> Option<&str> {
        match self.entries.get("domain") {
            Some(RdpValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get desktop width
    pub fn desktop_width(&self) -> Option<u16> {
        match self.entries.get("desktopwidth") {
            Some(RdpValue::Integer(n)) => Some(*n as u16),
            _ => None,
        }
    }

    /// Get desktop height
    pub fn desktop_height(&self) -> Option<u16> {
        match self.entries.get("desktopheight") {
            Some(RdpValue::Integer(n)) => Some(*n as u16),
            _ => None,
        }
    }

    /// Check if CredSSP/NLA should be enabled
    /// Returns true if EnableCredSspSupport is 1, false if 0, None if not present
    pub fn enable_credssp(&self) -> Option<bool> {
        match self.entries.get("enablecredsspsupport") {
            Some(RdpValue::Integer(n)) => Some(*n != 0),
            _ => None,
        }
    }

    /// Get the alternate shell (used by CyberArk for PSM token)
    pub fn alternate_shell(&self) -> Option<&str> {
        match self.entries.get("alternate shell") {
            Some(RdpValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get an integer value by key
    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.entries.get(&key.to_lowercase()) {
            Some(RdpValue::Integer(n)) => Some(*n),
            _ => None,
        }
    }

    /// Get a string value by key
    pub fn get_str(&self, key: &str) -> Option<&str> {
        match self.entries.get(&key.to_lowercase()) {
            Some(RdpValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get all entries (for debugging)
    pub fn entries(&self) -> &HashMap<String, RdpValue> {
        &self.entries
    }

    /// Extract SSO token from alternate shell parameter
    /// Format: "/sso <token> /sso_type rdp_file"
    pub fn sso_token(&self) -> Option<&str> {
        let alt_shell = self.get_str("alternate shell")?;

        // Parse: "/sso TOKEN /sso_type rdp_file"
        for (i, part) in alt_shell.split_whitespace().enumerate() {
            if part == "/sso" {
                // Next element is the token
                return alt_shell.split_whitespace().nth(i + 1);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_basic_rdp() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "full address:s:server.example.com:3389").unwrap();
        writeln!(f, "username:s:testuser").unwrap();
        writeln!(f, "domain:s:CORP").unwrap();
        writeln!(f, "desktopwidth:i:1024").unwrap();
        writeln!(f, "desktopheight:i:768").unwrap();
        writeln!(f, "screen mode id:i:2").unwrap();

        let rdp = RdpFile::parse(f.path()).unwrap();

        assert_eq!(rdp.hostname().unwrap(), "server.example.com");
        assert_eq!(rdp.port(), 3389);
        assert_eq!(rdp.username().unwrap(), "testuser");
        assert_eq!(rdp.domain().unwrap(), "CORP");
        assert_eq!(rdp.desktop_width().unwrap(), 1024);
        assert_eq!(rdp.desktop_height().unwrap(), 768);
    }
}
