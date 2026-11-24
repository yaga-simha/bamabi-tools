//! Toolchain, ABI `0.4.0` layout, embedded SDK parity, and mod-directory DAG diagnostics
//! (`cargo bam doctor`), delegated to [`bamabi_build::doctor`].

use crate::CliError;
pub use bamabi_build::doctor::{
    DoctorReport, RECOMMENDED_ZIG_MAX_MINOR, RECOMMENDED_ZIG_MIN_MINOR, ToolCheck,
    inspect_environment,
};
use std::path::Path;

/// Runs [`inspect_environment`] and optionally validates a mods directory via [`crate::dag::check_mods_dir`].
pub fn run_doctor(mods_dir: Option<&Path>, require_c: bool) -> Result<DoctorReport, CliError> {
    bamabi_build::doctor::run_doctor(mods_dir, require_c).map_err(Into::into)
}
