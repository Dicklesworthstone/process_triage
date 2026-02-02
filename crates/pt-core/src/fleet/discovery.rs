//! Fleet discovery providers.
//!
//! This module defines a common discovery interface and a static inventory
//! provider backed by a file on disk.

use crate::fleet::inventory::{load_inventory_from_path, FleetInventory, InventoryError};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors returned by discovery providers.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("inventory error: {0}")]
    Inventory(#[from] InventoryError),
    #[error("discovery error: {0}")]
    Other(String),
}

/// Fleet discovery provider interface.
pub trait InventoryProvider {
    /// Provider name used for logs/telemetry.
    fn name(&self) -> &str;
    /// Discover hosts and return a normalized fleet inventory.
    fn discover(&self) -> Result<FleetInventory, DiscoveryError>;
}

/// Static inventory provider reading from a config file.
#[derive(Debug, Clone)]
pub struct StaticInventoryProvider {
    path: PathBuf,
}

impl StaticInventoryProvider {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn from_path(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl InventoryProvider for StaticInventoryProvider {
    fn name(&self) -> &str {
        "static"
    }

    fn discover(&self) -> Result<FleetInventory, DiscoveryError> {
        Ok(load_inventory_from_path(&self.path)?)
    }
}
