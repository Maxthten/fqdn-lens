//! Non-secret local configuration for the V0.4 application service.
//!
//! Credentials deliberately have no representation in this module.  The
//! on-disk TOML file is intended to be inspectable and back-up friendly.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const CONFIG_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DisplayLanguage {
    #[default]
    ZhCn,
    EnUs,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportLanguage {
    #[default]
    ZhCn,
    EnUs,
    Bilingual,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePreference {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub concurrency: Option<usize>,
    #[serde(default)]
    pub cache_ttl_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub schema_version: u32,
    #[serde(default)]
    pub display_language: DisplayLanguage,
    #[serde(default)]
    pub report_language: ReportLanguage,
    #[serde(default)]
    pub show_low_frequency_fallback_sources: bool,
    #[serde(default)]
    pub export_directory: Option<PathBuf>,
    #[serde(default)]
    pub user_agent_suffix: Option<String>,
    #[serde(default)]
    pub sources: BTreeMap<String, SourcePreference>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            display_language: DisplayLanguage::ZhCn,
            report_language: ReportLanguage::ZhCn,
            show_low_frequency_fallback_sources: false,
            export_directory: None,
            user_agent_suffix: None,
            sources: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppPaths {
    pub data_dir: PathBuf,
    pub config_file: PathBuf,
    pub database_file: PathBuf,
    pub exports_dir: PathBuf,
    pub logs_dir: PathBuf,
}

impl AppPaths {
    /// Builds the documented Windows layout below `%LOCALAPPDATA%\\FQDN Lens`.
    pub fn from_local_app_data() -> Result<Self, ConfigError> {
        let local_app_data = env::var_os("LOCALAPPDATA").ok_or(ConfigError::MissingLocalAppData)?;
        Ok(Self::in_data_dir(
            PathBuf::from(local_app_data).join("FQDN Lens"),
        ))
    }

    #[must_use]
    pub fn in_data_dir(data_dir: PathBuf) -> Self {
        Self {
            config_file: data_dir.join("config.toml"),
            database_file: data_dir.join("fqdn-lens.db"),
            exports_dir: data_dir.join("exports"),
            logs_dir: data_dir.join("logs"),
            data_dir,
        }
    }

    #[must_use]
    pub fn with_database_file(mut self, database_file: PathBuf) -> Self {
        self.database_file = database_file;
        self
    }

    pub fn ensure_directories(&self) -> Result<(), ConfigError> {
        fs::create_dir_all(&self.data_dir)?;
        fs::create_dir_all(&self.exports_dir)?;
        fs::create_dir_all(&self.logs_dir)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("LOCALAPPDATA is not available")]
    MissingLocalAppData,
    #[error("configuration I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("configuration is not valid TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("configuration could not be serialized: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("configuration schema version {0} is not supported")]
    UnsupportedSchema(u32),
}

impl AppConfig {
    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let value: Self = toml::from_str(&fs::read_to_string(path)?)?;
        if value.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedSchema(value.schema_version));
        }
        Ok(value)
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    #[must_use]
    pub fn export_directory<'a>(&'a self, paths: &'a AppPaths) -> &'a Path {
        self.export_directory
            .as_deref()
            .unwrap_or(&paths.exports_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_configuration_has_no_credential_fields() {
        let encoded = toml::to_string(&AppConfig::default()).expect("serialize config");
        assert!(!encoded.to_ascii_lowercase().contains("token"));
        assert!(!encoded.to_ascii_lowercase().contains("api_key"));
        assert!(!encoded.to_ascii_lowercase().contains("authorization"));
    }

    #[test]
    fn unknown_secret_shaped_key_is_rejected() {
        let input = "schema_version = 1\napi_key = 'must-not-be-config'\n";
        assert!(toml::from_str::<AppConfig>(input).is_err());
    }
}
