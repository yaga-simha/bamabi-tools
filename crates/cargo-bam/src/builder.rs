//! Mod build and staging (`cargo bam build`), delegated to [`bamabi_build::builder`].

use crate::CliError;
pub use bamabi_build::builder::{BuildOptions, BuildOutput};
use std::path::Path;

/// Builds a guest mod project (Rust, C99, C++17, Zig, or `[build].command`), validates `mod.toml`
/// metadata if present, and optionally stages into `out_dir/<mod_id>/`.
pub fn build_mod(
    manifest_path: Option<&Path>,
    dir: Option<&Path>,
    release: bool,
    out_dir: Option<&Path>,
) -> Result<BuildOutput, CliError> {
    bamabi_build::builder::build_mod(manifest_path, dir, release, out_dir).map_err(Into::into)
}

/// Builds, stages into `out_dir/<mod_id>/`, and optionally signs a guest mod artifact.
pub fn build_mod_with_signing(
    manifest_path: Option<&Path>,
    dir: Option<&Path>,
    release: bool,
    out_dir: Option<&Path>,
    sign_key: Option<&Path>,
    sign_namespace: &str,
) -> Result<BuildOutput, CliError> {
    bamabi_build::builder::build_mod_with_signing(
        manifest_path,
        dir,
        release,
        out_dir,
        sign_key,
        sign_namespace,
    )
    .map_err(Into::into)
}

/// Builds, optionally stages, and optionally signs a guest mod using [`BuildOptions`].
pub fn build_mod_with_options(options: &BuildOptions<'_>) -> Result<BuildOutput, CliError> {
    bamabi_build::builder::build_mod_with_options(options).map_err(Into::into)
}
