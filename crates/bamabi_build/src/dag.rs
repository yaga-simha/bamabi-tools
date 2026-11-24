//! `mod.toml` SemVer validation, discovery, and Kahn topological sort, delegated to
//! [`bamabi_manifest`].

use crate::BuildError;
use bamabi_manifest::{ModBuildConfig, ModCapabilities, ModTargetConfig};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub use bamabi_manifest::host_abi_semver;

/// Validated `mod.toml` manifest with parsed SemVer fields and optional build/target/capability
/// sections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedModManifest {
    /// Canonical mod ID (`[mod].id` or `[mod].name`).
    pub id: String,
    /// Parsed SemVer version.
    pub version: semver::Version,
    /// Optional host ABI SemVer requirement.
    pub abi_version: Option<semver::VersionReq>,
    /// Optional explicit library filename (`[mod].entry` / `[mod].library`).
    pub entry: Option<String>,
    /// Optional guest language (`[mod].language`).
    pub language: Option<String>,
    /// Required SemVer dependencies.
    pub dependencies: BTreeMap<String, semver::VersionReq>,
    /// Optional SemVer dependencies.
    pub optional_dependencies: BTreeMap<String, semver::VersionReq>,
    /// Optional target-specific shared-library entries (`[targets.<triple>]`).
    pub targets: BTreeMap<String, ModTargetConfig>,
    /// Optional custom build configuration (`[build]`).
    pub build: Option<ModBuildConfig>,
    /// Optional declarative capability and permission metadata (`[capabilities]`).
    pub capabilities: Option<ModCapabilities>,
    /// Source `mod.toml` path.
    pub manifest_path: PathBuf,
}

impl From<bamabi_manifest::ModTomlManifest> for ValidatedModManifest {
    fn from(m: bamabi_manifest::ModTomlManifest) -> Self {
        Self {
            id: m.name,
            version: m.version,
            abi_version: m.abi_version,
            entry: m.entry,
            language: m.language,
            dependencies: m.dependencies,
            optional_dependencies: m.optional_dependencies,
            targets: m.targets,
            build: m.build,
            capabilities: m.capabilities,
            manifest_path: m.manifest_path,
        }
    }
}

impl ValidatedModManifest {
    /// Parses and SemVer-validates a `mod.toml` file from disk, including host ABI compatibility.
    pub fn from_file(path: &Path) -> Result<Self, BuildError> {
        let m = bamabi_manifest::ModTomlManifest::from_file(path)
            .map_err(|e| BuildError::InvalidManifest(e.to_string()))?;
        m.validate_abi_compatibility()
            .map_err(|e| BuildError::InvalidManifest(e.to_string()))?;
        Ok(m.into())
    }

    /// Parses and SemVer-validates a `mod.toml` string, including host ABI compatibility.
    pub fn parse_str(toml_str: &str, path: &Path) -> Result<Self, BuildError> {
        let m = bamabi_manifest::ModTomlManifest::parse_str(toml_str, path)
            .map_err(|e| BuildError::InvalidManifest(e.to_string()))?;
        m.validate_abi_compatibility()
            .map_err(|e| BuildError::InvalidManifest(e.to_string()))?;
        Ok(m.into())
    }

    /// Returns the declared entry path for `target_triple`, falling back to [`Self::entry`].
    #[must_use]
    pub fn entry_for_target(&self, target_triple: &str) -> Option<&str> {
        self.targets
            .get(target_triple)
            .map(|t| t.entry.as_str())
            .or(self.entry.as_deref())
    }
}

/// Discovers `dir/mod.toml` and `dir/*/mod.toml`, validates all SemVer constraints, detects
/// dependency cycles via Kahn's algorithm, and returns the topological load order.
pub fn check_mods_dir(dir: &Path) -> Result<Vec<ValidatedModManifest>, BuildError> {
    if !dir.is_dir() {
        return Err(BuildError::InvalidArgument(format!(
            "mods directory does not exist: {}",
            dir.display()
        )));
    }
    let ordered = bamabi_manifest::check_mods_dir_strict(dir).map_err(|e| match e {
        bamabi_manifest::ManifestError::CycleQuarantined { cycle_members } => {
            BuildError::InvalidManifest(format!(
                "dependency cycle detected among mods: {}",
                cycle_members.join(", ")
            ))
        }
        other => BuildError::InvalidManifest(other.to_string()),
    })?;
    Ok(ordered.into_iter().map(Into::into).collect())
}
