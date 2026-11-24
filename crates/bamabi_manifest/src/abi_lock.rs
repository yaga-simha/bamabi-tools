//! Canonical `abi-lock.toml` + `Cargo.lock` + `bamabi_sys::ABI_VERSION` + `bevy_version`
//! parser and parity validator reusable across all federated `bamabi` `xtask` crates.

use crate::MAX_MANIFEST_BYTES;
use bamabi_sys::ABI_VERSION;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Canonical GitHub repository URL for Layer-0 `bamabi-wire`.
pub const CANONICAL_WIRE_GIT_URL: &str = "https://github.com/yaga-simha/bamabi-wire.git";

/// Canonical `Cargo.lock` git source prefix for `bamabi-wire` on `branch = "main"`.
pub const CANONICAL_WIRE_LOCK_SOURCE_PREFIX: &str =
    "git+https://github.com/yaga-simha/bamabi-wire.git?branch=main#";

/// `[project]` section inside `abi-lock.toml`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiLockProject {
    /// Repository or workspace name (e.g., `"bamabi-wire"`, `"bamabi-tools"`, `"bamabi-strata"`).
    pub name: String,
    /// Federation layer index (`0..=4`).
    pub layer: u32,
}

/// `[abi]` section inside `abi-lock.toml`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiLockAbi {
    /// Packed hexadecimal ABI version (e.g., `"0x0004_0000"`).
    pub bam_abi_version: String,
    /// Canonical C-ABI symbol prefix (e.g., `"bamabi"`).
    pub c_symbol_prefix: String,
    /// Workspace crate SemVer version string (e.g., `"0.4.0"`).
    pub workspace_version: String,
    /// Target Bevy version string (e.g., `"0.20.1"`).
    pub bevy_version: String,
    /// Minimum supported Rust version (e.g., `"1.95"`).
    pub rust_version: String,
    /// Rust edition (e.g., `"2024"`).
    pub edition: String,
    /// Optional pinned `bamabi-wire` Git commit SHA (`40` or `7..=40` hex characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_rev: Option<String>,
}

/// Parsed `abi-lock.toml` manifest with built-in validation against `bamabi_sys::ABI_VERSION`,
/// workspace `Cargo.toml`, `Cargo.lock`, and `bevy_version`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiLockManifest {
    /// `[project]` metadata.
    pub project: AbiLockProject,
    /// `[abi]` contract metadata.
    pub abi: AbiLockAbi,
}

/// Resolution mode observed for `bamabi_sys` inside a `Cargo.lock` file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireLockSource {
    /// Layer-0 workspace (`bamabi-wire`) where `bamabi_sys` is a local workspace member.
    LocalWorkspace,
    /// Patched via local sibling `[patch]` overlay (path dependency, no `source` field in `Cargo.lock`).
    LocalOverlayPatch,
    /// Canonical GitHub `bamabi-wire.git?branch=main#<rev>` source.
    CanonicalGit {
        /// Locked Git commit SHA from `Cargo.lock`.
        rev: String,
    },
}

/// Summary produced by [`AbiLockManifest::validate_cargo_lock_str`] and
/// [`AbiLockManifest::validate_cargo_lock_file`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CargoLockParityReport {
    /// Version of `bamabi_sys` found in `Cargo.lock` (if present).
    pub bamabi_sys_version: Option<String>,
    /// Resolution source of `bamabi_sys` in `Cargo.lock` (if present).
    pub wire_source: Option<WireLockSource>,
    /// Distinct Bevy crate versions observed in `Cargo.lock`.
    pub observed_bevy_versions: BTreeSet<String>,
}

/// Summary produced by [`AbiLockManifest::validate_workspace`] and
/// [`AbiLockManifest::validate_files`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiLockValidationReport {
    /// Parsed `u32` ABI version matching `bamabi_sys::ABI_VERSION`.
    pub abi_version: u32,
    /// Parity report from `Cargo.lock` (if checked).
    pub cargo_lock: Option<CargoLockParityReport>,
}

/// Errors returned by [`AbiLockManifest`] parsing and validation.
#[derive(Debug)]
pub enum AbiLockError {
    /// Filesystem I/O failure reading `abi-lock.toml`, `Cargo.toml`, or `Cargo.lock`.
    Io {
        /// File path where I/O failed.
        path: PathBuf,
        /// Underlying OS I/O error.
        source: std::io::Error,
    },
    /// TOML parse failure.
    TomlParse {
        /// File path of malformed TOML.
        path: PathBuf,
        /// Underlying `toml` error.
        source: Box<toml::de::Error>,
    },
    /// Semantic validation failure on `abi-lock.toml` fields.
    InvalidField {
        /// File path of `abi-lock.toml`.
        path: PathBuf,
        /// Field name.
        field: String,
        /// Validation failure detail.
        detail: String,
    },
    /// `abi-lock.toml` `bam_abi_version` disagrees with compiled `bamabi_sys::ABI_VERSION`.
    AbiVersionMismatch {
        /// Expected ABI version from `bamabi_sys::ABI_VERSION`.
        expected: u32,
        /// Parsed ABI version from `abi-lock.toml`.
        found: u32,
    },
    /// `Cargo.toml` `[workspace.package]` field disagrees with `abi-lock.toml`.
    WorkspaceMismatch {
        /// Path to `Cargo.toml`.
        path: PathBuf,
        /// Mismatched field name.
        field: String,
        /// Expected value from `abi-lock.toml`.
        expected: String,
        /// Actual value found in `Cargo.toml`.
        found: String,
    },
    /// `Cargo.lock` disagrees with `abi-lock.toml` (`bamabi_sys`, `wire_rev`, or `bevy_version`).
    CargoLockMismatch {
        /// Path to `Cargo.lock`.
        path: PathBuf,
        /// Mismatch description.
        detail: String,
    },
    /// Cross-repository `abi-lock.toml` parity mismatch.
    CrossRepoMismatch {
        /// Repository name with mismatch.
        repo: String,
        /// Mismatched `[abi]` key.
        key: String,
        /// Baseline value.
        expected: String,
        /// Actual value.
        found: String,
    },
}

impl fmt::Display for AbiLockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "I/O error reading '{}': {source}", path.display())
            }
            Self::TomlParse { path, source } => {
                write!(f, "failed to parse TOML '{}': {source}", path.display())
            }
            Self::InvalidField {
                path,
                field,
                detail,
            } => {
                write!(f, "invalid `{field}` in '{}': {detail}", path.display())
            }
            Self::AbiVersionMismatch { expected, found } => {
                write!(
                    f,
                    "abi-lock.toml bam_abi_version 0x{found:08X} does not match bamabi_sys::ABI_VERSION 0x{expected:08X}"
                )
            }
            Self::WorkspaceMismatch {
                path,
                field,
                expected,
                found,
            } => {
                write!(
                    f,
                    "{} [workspace.package].{field} ({found:?}) != abi-lock.toml ({expected:?})",
                    path.display()
                )
            }
            Self::CargoLockMismatch { path, detail } => {
                write!(
                    f,
                    "Cargo.lock parity error in '{}': {detail}",
                    path.display()
                )
            }
            Self::CrossRepoMismatch {
                repo,
                key,
                expected,
                found,
            } => {
                write!(
                    f,
                    "abi-lock.toml parity mismatch in '{repo}' for [abi].{key}: expected {expected:?}, found {found:?}"
                )
            }
        }
    }
}

impl std::error::Error for AbiLockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::TomlParse { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

fn read_bounded_utf8(path: &Path, max_bytes: u64) -> Result<String, AbiLockError> {
    let file = std::fs::File::open(path).map_err(|source| AbiLockError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let meta = file.metadata().map_err(|source| AbiLockError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !meta.is_file() {
        return Err(AbiLockError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "expected regular file"),
        });
    }
    if meta.len() > max_bytes {
        return Err(AbiLockError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("file exceeds maximum allowed size ({max_bytes} bytes)"),
            ),
        });
    }
    let cap = usize::try_from(meta.len()).unwrap_or(4096);
    let mut raw = Vec::with_capacity(cap);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|source| AbiLockError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if raw.len() as u64 > max_bytes {
        return Err(AbiLockError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("file exceeded maximum size ({max_bytes} bytes)"),
            ),
        });
    }
    String::from_utf8(raw).map_err(|_| AbiLockError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, "file is not valid UTF-8"),
    })
}

fn parse_hex_abi_version(raw: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    let hex_body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .ok_or_else(|| format!("expected `0x`-prefixed hex ABI version, got {raw:?}"))?;
    let clean: String = hex_body.chars().filter(|&c| c != '_').collect();
    if clean.is_empty() || clean.len() > 8 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid hex ABI version {raw:?}"));
    }
    u32::from_str_radix(&clean, 16).map_err(|e| format!("invalid hex ABI version {raw:?}: {e}"))
}

fn is_valid_git_rev(rev: &str) -> bool {
    (7..=40).contains(&rev.len()) && rev.bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Deserialize)]
struct RawCargoTomlWorkspace {
    workspace: Option<RawWorkspaceSection>,
}

#[derive(Deserialize)]
struct RawWorkspaceSection {
    package: Option<RawWorkspacePackage>,
}

#[derive(Deserialize)]
struct RawWorkspacePackage {
    version: Option<String>,
    edition: Option<String>,
    #[serde(rename = "rust-version")]
    rust_version: Option<String>,
}

#[derive(Deserialize)]
struct RawCargoLock {
    #[serde(default)]
    package: Vec<RawCargoLockPackage>,
}

#[derive(Deserialize)]
struct RawCargoLockPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

fn is_tracked_bevy_crate(name: &str) -> bool {
    name == "bevy" || name.starts_with("bevy_")
}

impl AbiLockManifest {
    /// Parses and validates an `abi-lock.toml` document from `toml_str`.
    pub fn parse_str(toml_str: &str, path: impl AsRef<Path>) -> Result<Self, AbiLockError> {
        let p = path.as_ref().to_path_buf();
        let parsed: Self = toml::from_str(toml_str).map_err(|source| AbiLockError::TomlParse {
            path: p.clone(),
            source: Box::new(source),
        })?;
        parsed.validate_syntax(&p)?;
        Ok(parsed)
    }

    /// Reads (bounded by [`MAX_MANIFEST_BYTES`]) and parses an `abi-lock.toml` file from disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, AbiLockError> {
        let p = path.as_ref();
        let content = read_bounded_utf8(p, MAX_MANIFEST_BYTES)?;
        Self::parse_str(&content, p)
    }

    /// Serializes this `abi-lock.toml` manifest to a canonical TOML string.
    pub fn to_toml_string(&self) -> Result<String, AbiLockError> {
        self.validate_syntax(Path::new("abi-lock.toml"))?;
        toml::to_string_pretty(self).map_err(|e| AbiLockError::Io {
            path: PathBuf::from("abi-lock.toml"),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
        })
    }

    fn validate_syntax(&self, path: &Path) -> Result<(), AbiLockError> {
        if self.project.name.trim().is_empty() {
            return Err(AbiLockError::InvalidField {
                path: path.to_path_buf(),
                field: "project.name".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        parse_hex_abi_version(&self.abi.bam_abi_version).map_err(|detail| {
            AbiLockError::InvalidField {
                path: path.to_path_buf(),
                field: "abi.bam_abi_version".to_owned(),
                detail,
            }
        })?;
        if self.abi.c_symbol_prefix.trim().is_empty()
            || !self
                .abi
                .c_symbol_prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(AbiLockError::InvalidField {
                path: path.to_path_buf(),
                field: "abi.c_symbol_prefix".to_owned(),
                detail: "must be a non-empty ASCII identifier".to_owned(),
            });
        }
        semver::Version::parse(self.abi.workspace_version.trim()).map_err(|e| {
            AbiLockError::InvalidField {
                path: path.to_path_buf(),
                field: "abi.workspace_version".to_owned(),
                detail: e.to_string(),
            }
        })?;
        semver::Version::parse(self.abi.bevy_version.trim()).map_err(|e| {
            AbiLockError::InvalidField {
                path: path.to_path_buf(),
                field: "abi.bevy_version".to_owned(),
                detail: e.to_string(),
            }
        })?;
        if self.abi.rust_version.trim().is_empty() {
            return Err(AbiLockError::InvalidField {
                path: path.to_path_buf(),
                field: "abi.rust_version".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        if self.abi.edition.trim().is_empty() {
            return Err(AbiLockError::InvalidField {
                path: path.to_path_buf(),
                field: "abi.edition".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        if let Some(ref rev) = self.abi.wire_rev
            && !is_valid_git_rev(rev)
        {
            return Err(AbiLockError::InvalidField {
                path: path.to_path_buf(),
                field: "abi.wire_rev".to_owned(),
                detail: format!("expected 7..=40 hex git revision, got {rev:?}"),
            });
        }
        Ok(())
    }

    /// Parses [`AbiLockAbi::bam_abi_version`] into a packed `u32` ABI version word.
    pub fn parsed_abi_version(&self) -> Result<u32, AbiLockError> {
        parse_hex_abi_version(&self.abi.bam_abi_version).map_err(|detail| {
            AbiLockError::InvalidField {
                path: PathBuf::from("abi-lock.toml"),
                field: "abi.bam_abi_version".to_owned(),
                detail,
            }
        })
    }

    /// Parses [`AbiLockAbi::workspace_version`] as a [`semver::Version`].
    pub fn parsed_workspace_version(&self) -> Result<semver::Version, AbiLockError> {
        semver::Version::parse(self.abi.workspace_version.trim()).map_err(|e| {
            AbiLockError::InvalidField {
                path: PathBuf::from("abi-lock.toml"),
                field: "abi.workspace_version".to_owned(),
                detail: e.to_string(),
            }
        })
    }

    /// Parses [`AbiLockAbi::bevy_version`] as a [`semver::Version`].
    pub fn parsed_bevy_version(&self) -> Result<semver::Version, AbiLockError> {
        semver::Version::parse(self.abi.bevy_version.trim()).map_err(|e| {
            AbiLockError::InvalidField {
                path: PathBuf::from("abi-lock.toml"),
                field: "abi.bevy_version".to_owned(),
                detail: e.to_string(),
            }
        })
    }

    /// Verifies [`AbiLockAbi::bam_abi_version`] equals [`bamabi_sys::ABI_VERSION`] and checks an
    /// optional expected Bevy version string.
    pub fn validate_abi_sys(
        &self,
        expected_bevy_version: Option<&str>,
    ) -> Result<u32, AbiLockError> {
        let found = self.parsed_abi_version()?;
        if found != ABI_VERSION {
            return Err(AbiLockError::AbiVersionMismatch {
                expected: ABI_VERSION,
                found,
            });
        }
        if let Some(expected_bevy) = expected_bevy_version
            && self.abi.bevy_version != expected_bevy
        {
            return Err(AbiLockError::InvalidField {
                path: PathBuf::from("abi-lock.toml"),
                field: "abi.bevy_version".to_owned(),
                detail: format!(
                    "expected Bevy version {expected_bevy:?}, found {:?}",
                    self.abi.bevy_version
                ),
            });
        }
        Ok(found)
    }

    /// Compares all six shared `[abi]` fields against `baseline`.
    pub fn check_parity_with(&self, baseline: &Self) -> Result<(), AbiLockError> {
        let pairs = [
            (
                "bam_abi_version",
                &baseline.abi.bam_abi_version,
                &self.abi.bam_abi_version,
            ),
            (
                "c_symbol_prefix",
                &baseline.abi.c_symbol_prefix,
                &self.abi.c_symbol_prefix,
            ),
            (
                "workspace_version",
                &baseline.abi.workspace_version,
                &self.abi.workspace_version,
            ),
            (
                "bevy_version",
                &baseline.abi.bevy_version,
                &self.abi.bevy_version,
            ),
            (
                "rust_version",
                &baseline.abi.rust_version,
                &self.abi.rust_version,
            ),
            ("edition", &baseline.abi.edition, &self.abi.edition),
        ];
        for (key, exp, act) in pairs {
            if exp != act {
                return Err(AbiLockError::CrossRepoMismatch {
                    repo: self.project.name.clone(),
                    key: key.to_owned(),
                    expected: exp.clone(),
                    found: act.clone(),
                });
            }
        }
        Ok(())
    }

    /// Validates a workspace `Cargo.toml`'s `[workspace.package]` fields (`version`, `edition`,
    /// `rust-version`) against this `abi-lock.toml`.
    pub fn validate_workspace_cargo_toml_str(
        &self,
        cargo_toml_str: &str,
        cargo_toml_path: impl AsRef<Path>,
    ) -> Result<(), AbiLockError> {
        let p = cargo_toml_path.as_ref();
        let parsed: RawCargoTomlWorkspace =
            toml::from_str(cargo_toml_str).map_err(|source| AbiLockError::TomlParse {
                path: p.to_path_buf(),
                source: Box::new(source),
            })?;
        let ws_pkg = parsed.workspace.and_then(|w| w.package).ok_or_else(|| {
            AbiLockError::WorkspaceMismatch {
                path: p.to_path_buf(),
                field: "workspace.package".to_owned(),
                expected: "present".to_owned(),
                found: "missing".to_owned(),
            }
        })?;

        let check_field = |field: &str, expected: &str, actual: Option<&str>| {
            let found = actual.unwrap_or("<missing>");
            if found != expected {
                return Err(AbiLockError::WorkspaceMismatch {
                    path: p.to_path_buf(),
                    field: field.to_owned(),
                    expected: expected.to_owned(),
                    found: found.to_owned(),
                });
            }
            Ok(())
        };

        check_field(
            "version",
            &self.abi.workspace_version,
            ws_pkg.version.as_deref(),
        )?;
        check_field("edition", &self.abi.edition, ws_pkg.edition.as_deref())?;
        check_field(
            "rust-version",
            &self.abi.rust_version,
            ws_pkg.rust_version.as_deref(),
        )?;
        Ok(())
    }

    /// Validates `Cargo.lock` contents against this `abi-lock.toml` (`bamabi_sys` version/source,
    /// optional `wire_rev`, and `bevy*` crate version parity).
    pub fn validate_cargo_lock_str(
        &self,
        cargo_lock_str: &str,
        lock_path: impl AsRef<Path>,
        expected_bevy_version: Option<&str>,
    ) -> Result<CargoLockParityReport, AbiLockError> {
        let p = lock_path.as_ref();
        let lock: RawCargoLock =
            toml::from_str(cargo_lock_str).map_err(|source| AbiLockError::TomlParse {
                path: p.to_path_buf(),
                source: Box::new(source),
            })?;

        let mut bamabi_sys_matches: Vec<&RawCargoLockPackage> = Vec::new();
        let mut observed_bevy_versions = BTreeSet::new();

        for pkg in &lock.package {
            if pkg.name == "bamabi_sys" {
                bamabi_sys_matches.push(pkg);
            }
            if is_tracked_bevy_crate(&pkg.name) {
                observed_bevy_versions.insert(pkg.version.clone());
            }
        }

        if bamabi_sys_matches.len() > 1 {
            return Err(AbiLockError::CargoLockMismatch {
                path: p.to_path_buf(),
                detail: format!(
                    "multiple `bamabi_sys` entries ({}) found in Cargo.lock",
                    bamabi_sys_matches.len()
                ),
            });
        }

        let (bamabi_sys_version, wire_source) = match bamabi_sys_matches.first() {
            Some(sys_pkg) => {
                if sys_pkg.version != self.abi.workspace_version {
                    return Err(AbiLockError::CargoLockMismatch {
                        path: p.to_path_buf(),
                        detail: format!(
                            "`bamabi_sys` version {:?} != abi-lock.toml workspace_version {:?}",
                            sys_pkg.version, self.abi.workspace_version
                        ),
                    });
                }
                let wire_src = if self.project.layer == 0 {
                    if sys_pkg.source.is_some() {
                        return Err(AbiLockError::CargoLockMismatch {
                            path: p.to_path_buf(),
                            detail: "Layer-0 `bamabi_sys` must not have an external `source` in Cargo.lock"
                                .to_owned(),
                        });
                    }
                    WireLockSource::LocalWorkspace
                } else {
                    match sys_pkg.source.as_deref() {
                        None => WireLockSource::LocalOverlayPatch,
                        Some(src) => {
                            let Some(rev_raw) = src.strip_prefix(CANONICAL_WIRE_LOCK_SOURCE_PREFIX)
                            else {
                                return Err(AbiLockError::CargoLockMismatch {
                                    path: p.to_path_buf(),
                                    detail: format!(
                                        "`bamabi_sys` has non-canonical source {src:?} (expected prefix {CANONICAL_WIRE_LOCK_SOURCE_PREFIX:?})"
                                    ),
                                });
                            };
                            let rev = rev_raw.split(['&', ' ']).next().unwrap_or("");
                            if !is_valid_git_rev(rev) {
                                return Err(AbiLockError::CargoLockMismatch {
                                    path: p.to_path_buf(),
                                    detail: format!(
                                        "invalid `bamabi_sys` git revision {rev:?} in Cargo.lock"
                                    ),
                                });
                            }
                            if let Some(expected_rev) = self.abi.wire_rev.as_deref()
                                && rev != expected_rev
                            {
                                return Err(AbiLockError::CargoLockMismatch {
                                    path: p.to_path_buf(),
                                    detail: format!(
                                        "`bamabi_sys` commit {rev:?} != abi-lock.toml wire_rev {expected_rev:?}"
                                    ),
                                });
                            }
                            WireLockSource::CanonicalGit {
                                rev: rev.to_owned(),
                            }
                        }
                    }
                };
                (Some(sys_pkg.version.clone()), Some(wire_src))
            }
            None => (None, None),
        };

        let target_bevy = expected_bevy_version.unwrap_or(self.abi.bevy_version.as_str());
        if observed_bevy_versions.len() > 1 {
            let list: Vec<&str> = observed_bevy_versions.iter().map(String::as_str).collect();
            return Err(AbiLockError::CargoLockMismatch {
                path: p.to_path_buf(),
                detail: format!(
                    "multiple Bevy versions found in Cargo.lock: {}",
                    list.join(", ")
                ),
            });
        }
        if let Some(found_bevy) = observed_bevy_versions.iter().next()
            && found_bevy != target_bevy
        {
            return Err(AbiLockError::CargoLockMismatch {
                path: p.to_path_buf(),
                detail: format!(
                    "Cargo.lock Bevy version {found_bevy:?} != expected {target_bevy:?}"
                ),
            });
        }

        Ok(CargoLockParityReport {
            bamabi_sys_version,
            wire_source,
            observed_bevy_versions,
        })
    }

    /// Reads and validates a `Cargo.lock` file on disk against this `abi-lock.toml`.
    pub fn validate_cargo_lock_file(
        &self,
        lock_path: impl AsRef<Path>,
        expected_bevy_version: Option<&str>,
    ) -> Result<CargoLockParityReport, AbiLockError> {
        // Cargo.lock can exceed 1 MiB in Bevy workspaces; allow up to 16 MiB.
        const MAX_CARGO_LOCK_BYTES: u64 = 16 * 1024 * 1024;
        let p = lock_path.as_ref();
        let content = read_bounded_utf8(p, MAX_CARGO_LOCK_BYTES)?;
        self.validate_cargo_lock_str(&content, p, expected_bevy_version)
    }

    /// Validates `abi-lock.toml` against `bamabi_sys::ABI_VERSION`, `Cargo.toml`, optional
    /// `Cargo.lock`, and optional expected `bevy_version`.
    pub fn validate_files(
        abi_lock_path: impl AsRef<Path>,
        cargo_toml_path: impl AsRef<Path>,
        cargo_lock_path: Option<&Path>,
        expected_bevy_version: Option<&str>,
    ) -> Result<AbiLockValidationReport, AbiLockError> {
        let manifest = Self::from_file(abi_lock_path)?;
        let abi_version = manifest.validate_abi_sys(expected_bevy_version)?;

        let cargo_toml_p = cargo_toml_path.as_ref();
        let cargo_toml_str = read_bounded_utf8(cargo_toml_p, MAX_MANIFEST_BYTES)?;
        manifest.validate_workspace_cargo_toml_str(&cargo_toml_str, cargo_toml_p)?;

        let cargo_lock = match cargo_lock_path {
            Some(lock_p) => Some(manifest.validate_cargo_lock_file(lock_p, expected_bevy_version)?),
            None => None,
        };

        Ok(AbiLockValidationReport {
            abi_version,
            cargo_lock,
        })
    }

    /// Convenience helper for `xtask` crates: validates `<ws>/abi-lock.toml`, `<ws>/Cargo.toml`,
    /// and `<ws>/Cargo.lock` (if present).
    pub fn validate_workspace(
        workspace_root: impl AsRef<Path>,
        expected_bevy_version: Option<&str>,
    ) -> Result<AbiLockValidationReport, AbiLockError> {
        let ws = workspace_root.as_ref();
        let abi_lock_path = ws.join("abi-lock.toml");
        let cargo_toml_path = ws.join("Cargo.toml");
        let lock_candidate = ws.join("Cargo.lock");
        let cargo_lock_path = lock_candidate.is_file().then_some(lock_candidate.as_path());
        Self::validate_files(
            abi_lock_path,
            cargo_toml_path,
            cargo_lock_path,
            expected_bevy_version,
        )
    }
}
