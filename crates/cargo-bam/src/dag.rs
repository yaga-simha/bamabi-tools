//! `mod.toml` SemVer validation, discovery, and Kahn topological sort (`cargo bam check-mods`),
//! delegated to [`bamabi_build::dag`].

use crate::CliError;
pub use bamabi_build::dag::{ValidatedModManifest, host_abi_semver};
use std::path::Path;

/// Discovers `dir/mod.toml` and `dir/*/mod.toml`, validates all SemVer constraints, detects
/// dependency cycles via Kahn's algorithm, and returns the topological load order.
pub fn check_mods_dir(dir: &Path) -> Result<Vec<ValidatedModManifest>, CliError> {
    bamabi_build::dag::check_mods_dir(dir).map_err(Into::into)
}
