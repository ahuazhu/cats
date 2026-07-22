//! Adapter factory ports and opaque key/value configuration.
//!
//! Cats statically links its current adapters. Composition roots select an
//! adapter by name and construct it through these factory ports; this is not a
//! dynamic shared-library ABI.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use crate::{BlobStore, MetadataStore};

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("malformed adapter option {0:?}; expected key=value")]
    MalformedOption(String),
    #[error("duplicate adapter option {0:?}")]
    DuplicateOption(String),
    #[error("adapter {adapter:?} requires option {option:?}")]
    MissingOption {
        adapter: &'static str,
        option: &'static str,
    },
    #[error("adapter {adapter:?} received unsupported option(s): {options:?}")]
    UnsupportedOptions {
        adapter: &'static str,
        options: Vec<String>,
    },
    #[error("adapter {adapter:?} configuration is invalid: {message}")]
    InvalidConfig {
        adapter: &'static str,
        message: String,
    },
    #[error("unknown {kind} adapter {name:?}; available adapters: {available:?}")]
    UnknownAdapter {
        kind: &'static str,
        name: String,
        available: Vec<&'static str>,
    },
    #[error("adapter {adapter:?} failed to open: {message}")]
    Open {
        adapter: &'static str,
        message: String,
    },
}

/// Opaque adapter configuration passed through core components unchanged.
///
/// `Debug` intentionally prints keys only. Credentials are forbidden here,
/// but values may still contain sensitive topology or tenant information.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AdapterConfig {
    options: BTreeMap<String, String>,
}

/// One named adapter and its opaque configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterSelection {
    pub name: String,
    pub config: AdapterConfig,
}

impl AdapterSelection {
    pub fn new(name: impl Into<String>, config: AdapterConfig) -> Self {
        Self {
            name: name.into(),
            config,
        }
    }
}

impl fmt::Debug for AdapterConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterConfig")
            .field("keys", &self.options.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl AdapterConfig {
    pub fn from_cli(values: impl IntoIterator<Item = String>) -> Result<Self, AdapterError> {
        let mut options = BTreeMap::new();
        for value in values {
            let Some((key, option_value)) = value.split_once('=') else {
                return Err(AdapterError::MalformedOption(value));
            };
            if key.is_empty() || option_value.is_empty() {
                return Err(AdapterError::MalformedOption(value));
            }
            if options
                .insert(key.to_string(), option_value.to_string())
                .is_some()
            {
                return Err(AdapterError::DuplicateOption(key.to_string()));
            }
        }
        Ok(Self { options })
    }

    pub fn from_pairs<I, K, V>(values: I) -> Result<Self, AdapterError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut options = BTreeMap::new();
        for (key, value) in values {
            let key = key.into();
            let value = value.into();
            if key.is_empty() || value.is_empty() {
                return Err(AdapterError::MalformedOption(format!("{key}={value}")));
            }
            if options.insert(key.clone(), value).is_some() {
                return Err(AdapterError::DuplicateOption(key));
            }
        }
        Ok(Self { options })
    }

    pub fn required(
        &self,
        adapter: &'static str,
        option: &'static str,
    ) -> Result<&str, AdapterError> {
        self.options
            .get(option)
            .map(String::as_str)
            .ok_or(AdapterError::MissingOption { adapter, option })
    }

    pub fn optional(&self, option: &str) -> Option<&str> {
        self.options.get(option).map(String::as_str)
    }

    pub fn ensure_only(
        &self,
        adapter: &'static str,
        supported: &[&str],
    ) -> Result<(), AdapterError> {
        let supported: BTreeSet<&str> = supported.iter().copied().collect();
        let unknown = self
            .options
            .keys()
            .filter(|key| !supported.contains(key.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if unknown.is_empty() {
            Ok(())
        } else {
            Err(AdapterError::UnsupportedOptions {
                adapter,
                options: unknown,
            })
        }
    }

    pub fn to_cli(&self) -> Vec<String> {
        self.options
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect()
    }
}

/// Factory port implemented by each concrete blob-store adapter crate.
pub trait BlobStoreFactory: Send + Sync {
    fn name(&self) -> &'static str;
    fn open(&self, config: &AdapterConfig) -> Result<Arc<dyn BlobStore>, AdapterError>;
}

/// Factory port implemented by each concrete metadata-store adapter crate.
pub trait MetadataStoreFactory: Send + Sync {
    fn name(&self) -> &'static str;
    fn open(&self, config: &AdapterConfig) -> Result<Arc<dyn MetadataStore>, AdapterError>;
}

pub fn open_blob_store(
    name: &str,
    config: &AdapterConfig,
    factories: &[&dyn BlobStoreFactory],
) -> Result<Arc<dyn BlobStore>, AdapterError> {
    factories
        .iter()
        .find(|factory| factory.name() == name)
        .map(|factory| factory.open(config))
        .unwrap_or_else(|| {
            Err(AdapterError::UnknownAdapter {
                kind: "blob-store",
                name: name.to_string(),
                available: factories.iter().map(|factory| factory.name()).collect(),
            })
        })
}

pub fn open_metadata_store(
    name: &str,
    config: &AdapterConfig,
    factories: &[&dyn MetadataStoreFactory],
) -> Result<Arc<dyn MetadataStore>, AdapterError> {
    factories
        .iter()
        .find(|factory| factory.name() == name)
        .map(|factory| factory.open(config))
        .unwrap_or_else(|| {
            Err(AdapterError::UnknownAdapter {
                kind: "metadata-store",
                name: name.to_string(),
                available: factories.iter().map(|factory| factory.name()).collect(),
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_rejects_malformed_and_duplicate_options() {
        assert!(matches!(
            AdapterConfig::from_cli(["missing-separator".to_string()]),
            Err(AdapterError::MalformedOption(_))
        ));
        assert!(matches!(
            AdapterConfig::from_cli(["root=a".to_string(), "root=b".to_string()]),
            Err(AdapterError::DuplicateOption(_))
        ));
    }

    #[test]
    fn debug_output_redacts_values() {
        let config = AdapterConfig::from_cli(["token=secret-value".to_string()]).unwrap();
        let output = format!("{config:?}");
        assert!(output.contains("token"));
        assert!(!output.contains("secret-value"));
    }
}
