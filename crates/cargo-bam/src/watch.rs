//! `notify`-backed recursive source/manifest watcher, incremental rebuilder, signer, and atomic
//! stager (`cargo bam watch`), delegated to [`bamabi_build::watch`].

use crate::CliError;
use bamabi_build::scaffold::ModLanguage;
pub use bamabi_build::watch::{
    DEFAULT_DEBOUNCE_MS, DEFAULT_POLL_MS, FileFingerprint, WatchConfig, WatchCycleResult,
    WatchSnapshot,
};
use std::path::Path;

/// Stateful `notify`-backed + mtime-gated watcher and incremental builder for guest mods
/// (`cargo bam watch`).
#[derive(Debug)]
pub struct WatchRunner(bamabi_build::watch::WatchRunner);

impl WatchRunner {
    /// Creates a new [`WatchRunner`] after validating configuration, signing key availability,
    /// and guest mod project structure.
    pub fn new(config: WatchConfig) -> Result<Self, CliError> {
        bamabi_build::watch::WatchRunner::new(config)
            .map(Self)
            .map_err(Into::into)
    }

    /// Returns the resolved guest mod project directory.
    #[must_use]
    pub fn project_dir(&self) -> &Path {
        self.0.project_dir()
    }

    /// Returns the detected guest language.
    #[must_use]
    pub const fn language(&self) -> ModLanguage {
        self.0.language()
    }

    /// Returns the canonical mod ID used when staging into `--out-dir/<mod_id>/`.
    #[must_use]
    pub fn mod_id(&self) -> &str {
        self.0.mod_id()
    }

    /// Returns the number of completed build cycles so far.
    #[must_use]
    pub const fn cycles_completed(&self) -> usize {
        self.0.cycles_completed()
    }

    /// Captures a deterministic [`WatchSnapshot`] of all watched source and manifest files.
    pub fn snapshot(&self) -> Result<WatchSnapshot, CliError> {
        self.0.snapshot().map_err(Into::into)
    }

    /// Runs the initial build, sign, and atomic stage cycle (`cycle == 1`).
    pub fn run_initial_build(&mut self) -> Result<WatchCycleResult, CliError> {
        self.0.run_initial_build().map_err(Into::into)
    }

    /// Checks `notify` events and `(len, mtime)` metadata and triggers a rebuild/sign/atomic-stage
    /// cycle if any watched source or manifest file changed since the last build.
    pub fn poll_and_rebuild_if_changed(&mut self) -> Result<Option<WatchCycleResult>, CliError> {
        self.0.poll_and_rebuild_if_changed().map_err(Into::into)
    }

    /// Runs the `notify`-backed debounced watch loop until `--once` / `--max-cycles` is satisfied.
    pub fn run(&mut self) -> Result<Vec<WatchCycleResult>, CliError> {
        self.0.run().map_err(Into::into)
    }
}

/// Convenience entrypoint creating a [`WatchRunner`] and executing [`WatchRunner::run`].
pub fn run_watch(config: WatchConfig) -> Result<Vec<WatchCycleResult>, CliError> {
    bamabi_build::watch::run_watch(config).map_err(Into::into)
}
