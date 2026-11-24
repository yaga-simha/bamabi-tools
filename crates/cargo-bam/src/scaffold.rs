//! Guest mod project scaffolding (`cargo bam new`), delegated to [`bamabi_build::scaffold`].

use crate::CliError;
pub use bamabi_build::scaffold::{
    DEFAULT_GUEST_SDK_GIT_BRANCH, DEFAULT_GUEST_SDK_GIT_URL, ModLanguage,
};
use std::path::{Path, PathBuf};

/// Scaffolds a new buildable `bamabi` guest mod project in `parent_dir/<name>`.
pub fn scaffold_new_mod(
    name: &str,
    lang: ModLanguage,
    parent_dir: &Path,
    guest_sdk_path: Option<&Path>,
) -> Result<PathBuf, CliError> {
    bamabi_build::scaffold::scaffold_new_mod(name, lang, parent_dir, guest_sdk_path)
        .map_err(Into::into)
}

/// Scaffolds a new buildable `bamabi` guest mod project in `parent_dir/<name>` with optional
/// local path or custom Git URL override for `bamabi_guest`.
pub fn scaffold_new_mod_with_git(
    name: &str,
    lang: ModLanguage,
    parent_dir: &Path,
    guest_sdk_path: Option<&Path>,
    guest_sdk_git: Option<&str>,
) -> Result<PathBuf, CliError> {
    bamabi_build::scaffold::scaffold_new_mod_with_git(
        name,
        lang,
        parent_dir,
        guest_sdk_path,
        guest_sdk_git,
    )
    .map_err(Into::into)
}
