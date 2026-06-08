//! Runtime context and on-disk locations. Everything REO persists — license,
//! config, telemetry history — lives under one local directory and never
//! leaves it.

use crate::license::License;
use std::path::PathBuf;

pub struct Context {
    /// Cloud fallback opt-in for THIS session only. Never persisted.
    pub cloud: bool,
    /// Local data root (license, telemetry db, downloaded model).
    pub data_dir: PathBuf,
    pub license: License,
}

impl Context {
    pub fn load(cloud: bool) -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("reo");
        let _ = std::fs::create_dir_all(&data_dir);

        let license = License::load(&data_dir);
        Context {
            cloud,
            data_dir,
            license,
        }
    }

    pub fn model_dir(&self) -> PathBuf {
        self.data_dir.join("models")
    }
}
