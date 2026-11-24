#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Zero-Bevy `mod.toml` manifest parser, SemVer validator, and Kahn topological dependency DAG
//! resolver shared between `bamabi_host` (`bamabi-core`) and `cargo-bam` (`bamabi-tools`).
//!
//! Part of Layer 1 (`bamabi-tools`), `bamabi_manifest` depends only on [`bamabi_sys`] (from
//! Layer 0 `bamabi-wire`), `semver`, `serde`, and `toml`, enforcing `#![forbid(unsafe_code)]`.
//!
//! ## Core Components
//!
//! - [`ModTomlManifest`]: Bounded `mod.toml` parser, serializer, builder, and host ABI SemVer
//!   compatibility validator against [`bamabi_sys`].
//! - [`AbiLockManifest`]: Canonical `abi-lock.toml` + `Cargo.lock` + `bamabi_sys::ABI_VERSION` +
//!   `bevy_version` parity validator reusable across all federated `xtask` crates.
//! - [`validate_mod_id`] & [`validate_manifest_entry_path`]: Lexical and anti-symlink path
//!   confinement guards rejecting traversal, control bytes, NTFS streams, and Windows reserved names.
//! - [`resolve_dependency_dag`] & [`ManifestDagResolution`]: Deterministic Kahn topological
//!   load-order sorter for required and optional SemVer mod dependencies.

pub mod abi_lock;

pub use abi_lock::{
    AbiLockAbi, AbiLockError, AbiLockManifest, AbiLockProject, AbiLockValidationReport,
    CANONICAL_WIRE_GIT_URL, CANONICAL_WIRE_LOCK_SOURCE_PREFIX, CargoLockParityReport,
    WireLockSource,
};

use bamabi_sys::{ABI_VERSION_MAJOR, ABI_VERSION_MINOR, ABI_VERSION_PATCH};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Maximum `mod.toml` file size (`1 MiB`) accepted by [`ModTomlManifest::from_file`].
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Maximum byte length accepted for a canonical `[mod].id` identifier.
pub const MAX_MOD_ID_LEN: usize = 128;

/// Maximum byte length accepted for a relative POSIX `[mod].entry` / `[mod].library` path.
pub const MAX_ENTRY_PATH_LEN: usize = 1024;

/// Maximum directory nesting depth accepted for a relative POSIX `[mod].entry` path.
pub const MAX_ENTRY_PATH_DEPTH: usize = 32;

/// Returns `true` if `segment` (or its stem before the first `.`) is a Windows reserved DOS device
/// name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, ASCII case-insensitive).
#[must_use]
fn is_windows_reserved_device_name(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or(segment);
    let bytes = stem.as_bytes();
    match bytes.len() {
        3 => {
            stem.eq_ignore_ascii_case("CON")
                || stem.eq_ignore_ascii_case("PRN")
                || stem.eq_ignore_ascii_case("AUX")
                || stem.eq_ignore_ascii_case("NUL")
        }
        4 => {
            let prefix = &stem[..3];
            let digit = bytes[3];
            (prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT"))
                && matches!(digit, b'1'..=b'9')
        }
        _ => false,
    }
}

/// Validates a canonical `[mod].id` identifier against path traversal, separators, control bytes,
/// NTFS alternate data streams, and Windows reserved device names.
///
/// Valid IDs are 1..=[`MAX_MOD_ID_LEN`] ASCII bytes matching `[A-Za-z0-9_][A-Za-z0-9_-]*` and must
/// not be a Windows reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`).
pub fn validate_mod_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("mod identifier must not be empty".to_owned());
    }
    if id.len() > MAX_MOD_ID_LEN {
        return Err(format!(
            "mod identifier length ({}) exceeds maximum ({MAX_MOD_ID_LEN})",
            id.len()
        ));
    }
    if id.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err("mod identifier must not contain NUL or ASCII control characters".to_owned());
    }
    if id.starts_with('-') {
        return Err("mod identifier must not start with '-'".to_owned());
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("mod identifier may only contain ASCII letters, digits, '_' or '-'".to_owned());
    }
    if is_windows_reserved_device_name(id) {
        return Err(format!(
            "mod identifier '{id}' is a Windows reserved device name"
        ));
    }
    Ok(())
}

/// Validates a `[mod].entry` / `[mod].library` relative POSIX path against traversal (`..`, `.`),
/// absolute paths, Windows drive/UNC prefixes, NUL/control bytes, NTFS ADS (`:`), trailing dots or
/// spaces, excessive length/depth, and Windows reserved device names.
pub fn validate_manifest_entry_path(entry: &str) -> Result<(), String> {
    if entry.is_empty() {
        return Err("entry path must not be empty".to_owned());
    }
    if entry.len() > MAX_ENTRY_PATH_LEN {
        return Err(format!(
            "entry path length ({}) exceeds maximum ({MAX_ENTRY_PATH_LEN})",
            entry.len()
        ));
    }
    if entry.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err("entry path must not contain NUL or ASCII control characters".to_owned());
    }
    if entry.starts_with('/') || entry.ends_with('/') {
        return Err(
            "entry path must be a relative file path without leading or trailing '/'".to_owned(),
        );
    }
    if entry.contains('\\') {
        return Err(
            "entry path must use POSIX '/' separators and must not contain '\\'".to_owned(),
        );
    }
    if entry.contains(':') {
        return Err(
            "entry path must not contain ':' (drive prefixes and NTFS alternate data streams are forbidden)"
                .to_owned(),
        );
    }

    let mut depth = 0usize;
    for seg in entry.split('/') {
        depth += 1;
        if depth > MAX_ENTRY_PATH_DEPTH {
            return Err(format!(
                "entry path exceeds maximum directory depth ({MAX_ENTRY_PATH_DEPTH})"
            ));
        }
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(format!("entry path contains invalid segment '{seg}'"));
        }
        if seg.ends_with('.') || seg.ends_with(' ') {
            return Err(format!(
                "entry path segment '{seg}' must not end with '.' or space"
            ));
        }
        if is_windows_reserved_device_name(seg) {
            return Err(format!(
                "entry path segment '{seg}' uses a Windows reserved device name"
            ));
        }
    }
    Ok(())
}

fn invalid_manifest_input(path: PathBuf, detail: impl Into<String>) -> ManifestError {
    ManifestError::Io {
        path,
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, detail.into()),
    }
}

fn permission_denied(path: PathBuf, detail: impl Into<String>) -> ManifestError {
    ManifestError::Io {
        path,
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, detail.into()),
    }
}

/// Validates a `[targets.<triple>]` target triple identifier (e.g. `"x86_64-unknown-linux-gnu"`).
pub fn validate_target_triple(triple: &str) -> Result<(), String> {
    if triple.is_empty() {
        return Err("target triple must not be empty".to_owned());
    }
    if triple.len() > MAX_MOD_ID_LEN {
        return Err(format!(
            "target triple length ({}) exceeds maximum ({MAX_MOD_ID_LEN})",
            triple.len()
        ));
    }
    if triple.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err("target triple must not contain NUL or ASCII control characters".to_owned());
    }
    if triple.starts_with('-') || triple.starts_with('.') || triple.contains("..") {
        return Err("target triple must not start with '-' or '.' or contain '..'".to_owned());
    }
    if !triple
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(
            "target triple may only contain ASCII letters, digits, '_', '-', or '.'".to_owned(),
        );
    }
    Ok(())
}

/// Validates a `[capabilities]` capability, permission, or flag identifier.
pub fn validate_capability_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("capability identifier must not be empty".to_owned());
    }
    if name.len() > MAX_MOD_ID_LEN {
        return Err(format!(
            "capability identifier length ({}) exceeds maximum ({MAX_MOD_ID_LEN})",
            name.len()
        ));
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(
            "capability identifier must not contain NUL or ASCII control characters".to_owned(),
        );
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
    {
        return Err(
            "capability identifier may only contain ASCII letters, digits, '_', '-', '.', or ':'"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_relative_subpath(raw: &str, label: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if raw.len() > MAX_ENTRY_PATH_LEN {
        return Err(format!(
            "{label} length ({}) exceeds maximum ({MAX_ENTRY_PATH_LEN})",
            raw.len()
        ));
    }
    if raw.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(format!(
            "{label} must not contain NUL or ASCII control characters"
        ));
    }
    if raw.starts_with('/') || raw.contains('\\') || raw.contains(':') {
        return Err(format!(
            "{label} must be a relative POSIX path without '\\' or ':'"
        ));
    }
    for seg in raw.split('/') {
        if seg.is_empty() || seg == ".." {
            return Err(format!("{label} contains invalid segment '{seg}'"));
        }
    }
    Ok(())
}

fn validate_sha256_hex(raw: &str) -> Result<(), String> {
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("sha256 digest must be exactly 64 hexadecimal characters".to_owned());
    }
    Ok(())
}

/// Host ABI SemVer version derived from [`bamabi_sys::ABI_VERSION`].
#[inline]
#[must_use]
pub fn host_abi_semver() -> semver::Version {
    semver::Version::new(
        u64::from(ABI_VERSION_MAJOR),
        u64::from(ABI_VERSION_MINOR),
        u64::from(ABI_VERSION_PATCH),
    )
}

/// Target-specific entry configuration under `[targets.<triple>]` in `mod.toml`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModTargetConfig {
    /// Relative POSIX path to the target shared library inside the mod directory / `.bampack`.
    pub entry: String,
    /// Optional expected lowercase SHA-256 hex digest for the target binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl ModTargetConfig {
    /// Creates a target entry configuration for `entry`.
    #[must_use]
    pub fn new(entry: impl Into<String>) -> Self {
        Self {
            entry: entry.into(),
            sha256: None,
        }
    }

    /// Attaches an optional expected SHA-256 hex digest.
    #[must_use]
    pub fn with_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.sha256 = Some(sha256.into());
        self
    }
}

/// Custom build configuration under `[build]` in `mod.toml`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModBuildConfig {
    /// Optional custom build command executed by `bamabi_build` / `cargo bam build`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Optional explicit argument list passed to [`Self::command`] without shell expansion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Optional relative working directory inside the mod project root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    /// Optional relative POSIX path to the produced shared library artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    /// Extra environment variables injected when executing [`Self::command`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Additional relative paths watched by `cargo bam watch`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub watch_paths: Vec<String>,
}

impl ModBuildConfig {
    /// Creates a [`ModBuildConfig`] executing `command`.
    #[must_use]
    pub fn with_command(command: impl Into<String>) -> Self {
        Self {
            command: Some(command.into()),
            ..Self::default()
        }
    }

    /// Returns `true` when all fields are unset / empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.command.is_none()
            && self.args.is_empty()
            && self.working_dir.is_none()
            && self.output.is_none()
            && self.env.is_empty()
            && self.watch_paths.is_empty()
    }
}

/// Declarative host capability and permission requirements under `[capabilities]` in `mod.toml`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModCapabilities {
    /// Host capabilities required by this mod.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub required: BTreeSet<String>,
    /// Host capabilities optionally used by this mod.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub optional: BTreeSet<String>,
    /// Named permissions requested by this mod.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub permissions: BTreeSet<String>,
    /// Boolean capability flags.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub flags: BTreeMap<String, bool>,
}

impl ModCapabilities {
    /// Returns `true` when no capabilities, permissions, or flags are declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.required.is_empty()
            && self.optional.is_empty()
            && self.permissions.is_empty()
            && self.flags.is_empty()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RawModToml {
    #[serde(rename = "mod")]
    mod_section: RawModSection,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    dependencies: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    targets: BTreeMap<String, ModTargetConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    build: Option<ModBuildConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capabilities: Option<ModCapabilities>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RawModSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    abi_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    library: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    language: Option<String>,
}

/// Parsed declarative `mod.toml` manifest with validated SemVer version and dependency bounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModTomlManifest {
    /// Canonical mod identifier (`[mod].id` if present, otherwise `[mod].name`).
    pub name: String,
    /// Optional human-readable display name when both `id` and `name` are provided.
    pub display_name: Option<String>,
    /// Parsed SemVer version from `[mod].version`.
    pub version: semver::Version,
    /// Optional SemVer requirement against the host ABI version (`[mod].abi_version`).
    pub abi_version: Option<semver::VersionReq>,
    /// Optional entry shared-library path (`[mod].entry` or `[mod].library`).
    pub entry: Option<String>,
    /// Optional guest language identifier (`[mod].language`, e.g. `"rust"`, `"c99"`, `"cpp17"`, `"zig"`).
    pub language: Option<String>,
    /// Required dependencies (`<mod_name> = "<semver_req>"`).
    pub dependencies: BTreeMap<String, semver::VersionReq>,
    /// Optional dependencies (`<mod_name> = "<semver_req>"`).
    pub optional_dependencies: BTreeMap<String, semver::VersionReq>,
    /// Optional per-target shared-library entries (`[targets.<triple>]`).
    pub targets: BTreeMap<String, ModTargetConfig>,
    /// Optional custom build configuration (`[build]`).
    pub build: Option<ModBuildConfig>,
    /// Optional declarative capability and permission metadata (`[capabilities]`).
    pub capabilities: Option<ModCapabilities>,
    /// Filesystem path of the parsed `mod.toml`.
    pub manifest_path: PathBuf,
}

/// Fluent builder for constructing validated [`ModTomlManifest`] instances.
#[derive(Clone, Debug, Serialize)]
pub struct ModTomlManifestBuilder {
    id: String,
    display_name: Option<String>,
    version: semver::Version,
    abi_version: Option<semver::VersionReq>,
    entry: Option<String>,
    language: Option<String>,
    dependencies: BTreeMap<String, semver::VersionReq>,
    optional_dependencies: BTreeMap<String, semver::VersionReq>,
    targets: BTreeMap<String, ModTargetConfig>,
    build: Option<ModBuildConfig>,
    capabilities: Option<ModCapabilities>,
    manifest_path: PathBuf,
}

impl ModTomlManifestBuilder {
    /// Sets the optional human-readable display name (`[mod].name`).
    #[must_use]
    pub fn display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    /// Sets the optional host ABI SemVer requirement (`[mod].abi_version`).
    #[must_use]
    pub fn abi_version(mut self, req: semver::VersionReq) -> Self {
        self.abi_version = Some(req);
        self
    }

    /// Sets the optional entry shared-library path (`[mod].entry`).
    #[must_use]
    pub fn entry(mut self, entry: impl Into<String>) -> Self {
        self.entry = Some(entry.into());
        self
    }

    /// Sets the optional guest language identifier (`[mod].language`).
    #[must_use]
    pub fn language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }

    /// Adds a required dependency constraint (`[dependencies]`).
    #[must_use]
    pub fn dependency(mut self, mod_id: impl Into<String>, req: semver::VersionReq) -> Self {
        self.dependencies.insert(mod_id.into(), req);
        self
    }

    /// Adds an optional dependency constraint (`[optional_dependencies]`).
    #[must_use]
    pub fn optional_dependency(
        mut self,
        mod_id: impl Into<String>,
        req: semver::VersionReq,
    ) -> Self {
        self.optional_dependencies.insert(mod_id.into(), req);
        self
    }

    /// Adds a target-specific entry (`[targets.<triple>]`).
    #[must_use]
    pub fn target(mut self, triple: impl Into<String>, target: ModTargetConfig) -> Self {
        self.targets.insert(triple.into(), target);
        self
    }

    /// Sets the `[build]` section.
    #[must_use]
    pub fn build_config(mut self, build: ModBuildConfig) -> Self {
        self.build = Some(build);
        self
    }

    /// Sets the `[capabilities]` section.
    #[must_use]
    pub fn capabilities(mut self, capabilities: ModCapabilities) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    /// Sets the filesystem path associated with this manifest (defaults to `"mod.toml"`).
    #[must_use]
    pub fn manifest_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.manifest_path = path.into();
        self
    }

    /// Validates all fields and constructs a [`ModTomlManifest`].
    pub fn build(self) -> Result<ModTomlManifest, ManifestError> {
        let manifest = ModTomlManifest {
            name: self.id,
            display_name: self.display_name,
            version: self.version,
            abi_version: self.abi_version,
            entry: self.entry,
            language: self.language,
            dependencies: self.dependencies,
            optional_dependencies: self.optional_dependencies,
            targets: self.targets,
            build: self.build,
            capabilities: self.capabilities,
            manifest_path: self.manifest_path,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

fn validate_build_config(build: &ModBuildConfig, path: &Path) -> Result<(), ManifestError> {
    if let Some(ref cmd) = build.command {
        if cmd.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err(invalid_manifest_input(
                path.to_path_buf(),
                "[build].command must not contain NUL or ASCII control characters",
            ));
        }
        if cmd.trim().is_empty() {
            return Err(invalid_manifest_input(
                path.to_path_buf(),
                "[build].command must not be empty",
            ));
        }
    }
    for arg in &build.args {
        if arg.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err(invalid_manifest_input(
                path.to_path_buf(),
                "[build].args must not contain NUL or ASCII control characters",
            ));
        }
    }
    if let Some(ref wd) = build.working_dir
        && let Err(reason) = validate_relative_subpath(wd, "[build].working_dir")
    {
        return Err(invalid_manifest_input(path.to_path_buf(), reason));
    }
    if let Some(ref out) = build.output
        && let Err(reason) = validate_manifest_entry_path(out)
    {
        return Err(invalid_manifest_input(
            path.to_path_buf(),
            format!("invalid [build].output '{out}': {reason}"),
        ));
    }
    for (k, v) in &build.env {
        if k.is_empty()
            || k.contains('=')
            || k.bytes().any(|b| b < 0x20 || b == 0x7F)
            || v.bytes().any(|b| b < 0x20 || b == 0x7F)
        {
            return Err(invalid_manifest_input(
                path.to_path_buf(),
                format!("invalid [build].env entry '{k}'"),
            ));
        }
    }
    for wp in &build.watch_paths {
        if let Err(reason) = validate_relative_subpath(wp, "[build].watch_paths") {
            return Err(invalid_manifest_input(path.to_path_buf(), reason));
        }
    }
    Ok(())
}

fn validate_capabilities(caps: &ModCapabilities, path: &Path) -> Result<(), ManifestError> {
    for cap in caps
        .required
        .iter()
        .chain(caps.optional.iter())
        .chain(caps.permissions.iter())
        .chain(caps.flags.keys())
    {
        if let Err(reason) = validate_capability_name(cap) {
            return Err(invalid_manifest_input(
                path.to_path_buf(),
                format!("invalid capability '{cap}': {reason}"),
            ));
        }
    }
    Ok(())
}

fn host_target_triple_candidates() -> &'static [&'static str] {
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    {
        &["x86_64-unknown-linux-gnu"]
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
    {
        &["x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu"]
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
    {
        &["aarch64-unknown-linux-gnu"]
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "musl"))]
    {
        &["aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu"]
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        &["x86_64-apple-darwin"]
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        &["aarch64-apple-darwin"]
    }
    #[cfg(all(target_arch = "x86_64", target_os = "windows", target_env = "msvc"))]
    {
        &["x86_64-pc-windows-msvc", "x86_64-pc-windows-gnu"]
    }
    #[cfg(all(target_arch = "x86_64", target_os = "windows", target_env = "gnu"))]
    {
        &["x86_64-pc-windows-gnu", "x86_64-pc-windows-msvc"]
    }
    #[cfg(all(target_arch = "aarch64", target_os = "windows", target_env = "msvc"))]
    {
        &["aarch64-pc-windows-msvc"]
    }
    #[cfg(not(any(
        all(
            target_arch = "x86_64",
            target_os = "linux",
            any(target_env = "gnu", target_env = "musl")
        ),
        all(
            target_arch = "aarch64",
            target_os = "linux",
            any(target_env = "gnu", target_env = "musl")
        ),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "macos"),
        all(
            target_arch = "x86_64",
            target_os = "windows",
            any(target_env = "msvc", target_env = "gnu")
        ),
        all(target_arch = "aarch64", target_os = "windows", target_env = "msvc"),
    )))]
    {
        &[]
    }
}

impl ModTomlManifest {
    /// Returns a fluent [`ModTomlManifestBuilder`] for constructing a validated manifest.
    #[must_use]
    pub fn builder(id: impl Into<String>, version: semver::Version) -> ModTomlManifestBuilder {
        ModTomlManifestBuilder {
            id: id.into(),
            display_name: None,
            version,
            abi_version: None,
            entry: None,
            language: None,
            dependencies: BTreeMap::new(),
            optional_dependencies: BTreeMap::new(),
            targets: BTreeMap::new(),
            build: None,
            capabilities: None,
            manifest_path: PathBuf::from("mod.toml"),
        }
    }

    /// Canonical mod identifier (`[mod].id` if present, otherwise `[mod].name`).
    #[inline]
    #[must_use]
    pub fn id(&self) -> &str {
        &self.name
    }

    /// Validates all identifiers, entry paths, targets, build configuration, and capabilities.
    pub fn validate(&self) -> Result<(), ManifestError> {
        let path = &self.manifest_path;
        if let Err(reason) = validate_mod_id(&self.name) {
            return Err(invalid_manifest_input(
                path.clone(),
                format!("invalid [mod].id '{}': {reason}", self.name),
            ));
        }
        if let Some(ref disp) = self.display_name
            && disp.bytes().any(|b| b < 0x20 || b == 0x7F)
        {
            return Err(invalid_manifest_input(
                path.clone(),
                "[mod].name must not contain NUL or ASCII control characters",
            ));
        }
        if let Some(ref entry) = self.entry
            && let Err(reason) = validate_manifest_entry_path(entry)
        {
            return Err(invalid_manifest_input(
                path.clone(),
                format!("invalid [mod].entry '{entry}': {reason}"),
            ));
        }
        if let Some(ref lang) = self.language
            && lang.bytes().any(|b| b < 0x20 || b == 0x7F)
        {
            return Err(invalid_manifest_input(
                path.clone(),
                "[mod].language must not contain NUL or ASCII control characters",
            ));
        }
        for dep in self
            .dependencies
            .keys()
            .chain(self.optional_dependencies.keys())
        {
            if let Err(reason) = validate_mod_id(dep) {
                return Err(invalid_manifest_input(
                    path.clone(),
                    format!("invalid dependency identifier '{dep}': {reason}"),
                ));
            }
        }
        for (triple, target) in &self.targets {
            if let Err(reason) = validate_target_triple(triple) {
                return Err(invalid_manifest_input(
                    path.clone(),
                    format!("invalid [targets.{triple}]: {reason}"),
                ));
            }
            if let Err(reason) = validate_manifest_entry_path(&target.entry) {
                return Err(invalid_manifest_input(
                    path.clone(),
                    format!(
                        "invalid [targets.{triple}].entry '{}': {reason}",
                        target.entry
                    ),
                ));
            }
            if let Some(ref sha) = target.sha256
                && let Err(reason) = validate_sha256_hex(sha)
            {
                return Err(invalid_manifest_input(
                    path.clone(),
                    format!("invalid [targets.{triple}].sha256: {reason}"),
                ));
            }
        }
        if let Some(ref build) = self.build {
            validate_build_config(build, path)?;
        }
        if let Some(ref caps) = self.capabilities {
            validate_capabilities(caps, path)?;
        }
        Ok(())
    }

    /// Serializes this manifest into a canonical `mod.toml` TOML document string.
    pub fn to_toml_string(&self) -> Result<String, ManifestError> {
        self.validate()?;
        let dependencies = self
            .dependencies
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        let optional_dependencies = self
            .optional_dependencies
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        let build = self.build.clone().filter(|b| !b.is_empty());
        let capabilities = self.capabilities.clone().filter(|c| !c.is_empty());
        let raw = RawModToml {
            mod_section: RawModSection {
                id: Some(self.name.clone()),
                name: self.display_name.clone(),
                version: self.version.to_string(),
                abi_version: self.abi_version.as_ref().map(ToString::to_string),
                entry: self.entry.clone(),
                library: None,
                language: self.language.clone(),
            },
            dependencies,
            optional_dependencies,
            targets: self.targets.clone(),
            build,
            capabilities,
        };
        toml::to_string_pretty(&raw).map_err(|err| {
            invalid_manifest_input(
                self.manifest_path.clone(),
                format!("failed to serialize mod.toml: {err}"),
            )
        })
    }

    /// Alias for [`Self::to_toml_string`].
    #[inline]
    pub fn to_toml(&self) -> Result<String, ManifestError> {
        self.to_toml_string()
    }

    /// Returns the declared entry path for `target_triple` (`[targets.<triple>].entry`), falling
    /// back to `[mod].entry` when no target-specific entry is present.
    #[must_use]
    pub fn entry_for_target(&self, target_triple: &str) -> Option<&str> {
        self.targets
            .get(target_triple)
            .map(|t| t.entry.as_str())
            .or(self.entry.as_deref())
    }

    /// Parses and SemVer-validates a `mod.toml` document from `toml_str`.
    pub fn parse_str(
        toml_str: &str,
        manifest_path: impl AsRef<Path>,
    ) -> Result<Self, ManifestError> {
        let path = manifest_path.as_ref().to_path_buf();
        let raw: RawModToml =
            toml::from_str(toml_str).map_err(|source| ManifestError::TomlParse {
                path: path.clone(),
                source: Box::new(source),
            })?;

        let normalize_raw_field =
            |opt: Option<String>, label: &str| -> Result<Option<String>, ManifestError> {
                match opt {
                    None => Ok(None),
                    Some(raw_val) => {
                        if raw_val.bytes().any(|b| b < 0x20 || b == 0x7F) {
                            return Err(invalid_manifest_input(
                                path.clone(),
                                format!("{label} must not contain NUL or ASCII control characters"),
                            ));
                        }
                        if raw_val.trim().is_empty() {
                            Ok(None)
                        } else {
                            Ok(Some(raw_val))
                        }
                    }
                }
            };

        let raw_id = normalize_raw_field(raw.mod_section.id, "[mod].id")?;
        let raw_name = normalize_raw_field(raw.mod_section.name, "[mod].name")?;

        let (name, display_name) = match (raw_id, raw_name) {
            (Some(id), Some(name)) => {
                let disp = (id != name).then_some(name.trim().to_string());
                (id, disp)
            }
            (Some(id), None) => (id, None),
            (None, Some(name)) => (name, None),
            (None, None) => return Err(ManifestError::MissingModName { path }),
        };

        if let Err(reason) = validate_mod_id(&name) {
            return Err(invalid_manifest_input(
                path,
                format!("invalid [mod].id '{name}': {reason}"),
            ));
        }

        let version = semver::Version::parse(raw.mod_section.version.trim()).map_err(|source| {
            ManifestError::InvalidVersion {
                path: path.clone(),
                raw: raw.mod_section.version.clone(),
                source,
            }
        })?;

        let abi_version = match raw.mod_section.abi_version {
            Some(raw_abi) => {
                let req = semver::VersionReq::parse(raw_abi.trim()).map_err(|source| {
                    ManifestError::InvalidAbiVersion {
                        path: path.clone(),
                        raw: raw_abi,
                        source,
                    }
                })?;
                Some(req)
            }
            None => None,
        };

        let entry = match raw.mod_section.entry.or(raw.mod_section.library) {
            Some(raw_entry) => {
                if let Err(reason) = validate_manifest_entry_path(&raw_entry) {
                    return Err(invalid_manifest_input(
                        path,
                        format!("invalid [mod].entry '{raw_entry}': {reason}"),
                    ));
                }
                Some(raw_entry)
            }
            None => None,
        };

        let language = raw
            .mod_section
            .language
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let mut dependencies = BTreeMap::new();
        for (dep, req_str) in raw.dependencies {
            if let Err(reason) = validate_mod_id(&dep) {
                return Err(invalid_manifest_input(
                    path,
                    format!("invalid dependency identifier '{dep}': {reason}"),
                ));
            }
            let req = semver::VersionReq::parse(req_str.trim()).map_err(|source| {
                ManifestError::InvalidDependencyReq {
                    path: path.clone(),
                    mod_name: name.clone(),
                    dependency: dep.clone(),
                    raw: req_str,
                    source,
                }
            })?;
            dependencies.insert(dep, req);
        }

        let mut optional_dependencies = BTreeMap::new();
        for (dep, req_str) in raw.optional_dependencies {
            if let Err(reason) = validate_mod_id(&dep) {
                return Err(invalid_manifest_input(
                    path,
                    format!("invalid optional dependency identifier '{dep}': {reason}"),
                ));
            }
            let req = semver::VersionReq::parse(req_str.trim()).map_err(|source| {
                ManifestError::InvalidDependencyReq {
                    path: path.clone(),
                    mod_name: name.clone(),
                    dependency: dep.clone(),
                    raw: req_str,
                    source,
                }
            })?;
            optional_dependencies.insert(dep, req);
        }

        let mut targets = BTreeMap::new();
        for (triple, mut target) in raw.targets {
            if let Err(reason) = validate_target_triple(&triple) {
                return Err(invalid_manifest_input(
                    path,
                    format!("invalid [targets.{triple}]: {reason}"),
                ));
            }
            if let Err(reason) = validate_manifest_entry_path(&target.entry) {
                return Err(invalid_manifest_input(
                    path,
                    format!(
                        "invalid [targets.{triple}].entry '{}': {reason}",
                        target.entry
                    ),
                ));
            }
            if let Some(ref mut sha) = target.sha256 {
                let normalized = sha.trim().to_ascii_lowercase();
                if let Err(reason) = validate_sha256_hex(&normalized) {
                    return Err(invalid_manifest_input(
                        path,
                        format!("invalid [targets.{triple}].sha256: {reason}"),
                    ));
                }
                *sha = normalized;
            }
            targets.insert(triple, target);
        }

        let build = raw.build.filter(|b| !b.is_empty());
        if let Some(ref b) = build {
            validate_build_config(b, &path)?;
        }

        let capabilities = raw.capabilities.filter(|c| !c.is_empty());
        if let Some(ref caps) = capabilities {
            validate_capabilities(caps, &path)?;
        }

        Ok(Self {
            name,
            display_name,
            version,
            abi_version,
            entry,
            language,
            dependencies,
            optional_dependencies,
            targets,
            build,
            capabilities,
            manifest_path: path,
        })
    }

    /// Reads (bounded by [`MAX_MANIFEST_BYTES`]) and parses a `mod.toml` file from disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ManifestError> {
        let p = path.as_ref();
        let file = std::fs::File::open(p).map_err(|source| ManifestError::Io {
            path: p.to_path_buf(),
            source,
        })?;
        let meta = file.metadata().map_err(|source| ManifestError::Io {
            path: p.to_path_buf(),
            source,
        })?;
        if !meta.is_file() {
            return Err(invalid_manifest_input(
                p.to_path_buf(),
                "manifest path is not a regular file",
            ));
        }
        if meta.len() > MAX_MANIFEST_BYTES {
            return Err(invalid_manifest_input(
                p.to_path_buf(),
                format!(
                    "manifest file size ({} bytes) exceeds maximum ({MAX_MANIFEST_BYTES} bytes)",
                    meta.len()
                ),
            ));
        }
        let mut raw = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(4096));
        file.take(MAX_MANIFEST_BYTES.saturating_add(1))
            .read_to_end(&mut raw)
            .map_err(|source| ManifestError::Io {
                path: p.to_path_buf(),
                source,
            })?;
        if raw.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(invalid_manifest_input(
                p.to_path_buf(),
                format!("manifest file exceeded maximum size ({MAX_MANIFEST_BYTES} bytes)"),
            ));
        }
        let contents = String::from_utf8(raw).map_err(|_| {
            invalid_manifest_input(p.to_path_buf(), "manifest file is not valid UTF-8")
        })?;
        Self::parse_str(&contents, p)
    }

    /// Checks `[mod].abi_version` (when specified) against [`host_abi_semver`].
    pub fn validate_abi_compatibility(&self) -> Result<(), ManifestError> {
        if let Some(ref req) = self.abi_version {
            let host_abi = host_abi_semver();
            if !req.matches(&host_abi) {
                return Err(ManifestError::IncompatibleAbiVersion {
                    path: self.manifest_path.clone(),
                    mod_name: self.name.clone(),
                    required: req.clone(),
                    host_abi,
                });
            }
        }
        Ok(())
    }

    /// Resolves the shared-library path for `target_triple` (or host defaults when `None`)
    /// relative to `manifest_path.parent()`, rejecting path traversal, unsafe identifiers,
    /// symlinks, and escapes outside the mod root.
    pub fn resolve_library_path_for_target(
        &self,
        target_triple: Option<&str>,
    ) -> Result<PathBuf, ManifestError> {
        if let Err(reason) = validate_mod_id(&self.name) {
            return Err(invalid_manifest_input(
                self.manifest_path.clone(),
                format!("invalid [mod].id '{}': {reason}", self.name),
            ));
        }

        let base_dir = self
            .manifest_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        if let Some(triple) = target_triple
            && let Some(target_cfg) = self.targets.get(triple)
        {
            if let Err(reason) = validate_manifest_entry_path(&target_cfg.entry) {
                return Err(invalid_manifest_input(
                    self.manifest_path.clone(),
                    format!(
                        "invalid [targets.{triple}].entry '{}': {reason}",
                        target_cfg.entry
                    ),
                ));
            }
            let segments: Vec<&str> = target_cfg.entry.split('/').collect();
            return resolve_confined_regular_file(base_dir, &segments, &self.name);
        }

        if let Some(ref entry) = self.entry {
            if let Err(reason) = validate_manifest_entry_path(entry) {
                return Err(invalid_manifest_input(
                    self.manifest_path.clone(),
                    format!("invalid [mod].entry '{entry}': {reason}"),
                ));
            }
            let segments: Vec<&str> = entry.split('/').collect();
            return resolve_confined_regular_file(base_dir, &segments, &self.name);
        }

        for candidate_triple in host_target_triple_candidates() {
            if let Some(target_cfg) = self.targets.get(*candidate_triple) {
                if let Err(reason) = validate_manifest_entry_path(&target_cfg.entry) {
                    return Err(invalid_manifest_input(
                        self.manifest_path.clone(),
                        format!(
                            "invalid [targets.{candidate_triple}].entry '{}': {reason}",
                            target_cfg.entry
                        ),
                    ));
                }
                let segments: Vec<&str> = target_cfg.entry.split('/').collect();
                match resolve_confined_regular_file(base_dir, &segments, &self.name) {
                    Ok(p) => return Ok(p),
                    Err(ManifestError::MissingLibrary { .. }) => {}
                    Err(err) => return Err(err),
                }
            }
        }

        let ext = std::env::consts::DLL_EXTENSION;
        let prefix = std::env::consts::DLL_PREFIX;
        let preferred_prefixed_name = format!("{prefix}{}.{ext}", self.name);
        match resolve_confined_regular_file(base_dir, &[&preferred_prefixed_name], &self.name) {
            Ok(p) => return Ok(p),
            Err(ManifestError::MissingLibrary { .. }) => {}
            Err(err) => return Err(err),
        }

        let preferred_plain_name = format!("{}.{ext}", self.name);
        if preferred_plain_name != preferred_prefixed_name {
            match resolve_confined_regular_file(base_dir, &[&preferred_plain_name], &self.name) {
                Ok(p) => return Ok(p),
                Err(ManifestError::MissingLibrary { .. }) => {}
                Err(err) => return Err(err),
            }
        }

        if let Ok(entries) = std::fs::read_dir(base_dir) {
            let mut candidates: Vec<PathBuf> = Vec::new();
            let mut raw_paths: Vec<PathBuf> =
                entries.filter_map(Result::ok).map(|e| e.path()).collect();
            raw_paths.sort();

            for candidate in raw_paths {
                let has_ext = candidate
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e == ext);
                if !has_ext {
                    continue;
                }
                let meta = match std::fs::symlink_metadata(&candidate) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if meta.file_type().is_symlink() {
                    return Err(permission_denied(
                        candidate,
                        format!(
                            "mod '{}' library candidate is a symlink (rejected)",
                            self.name
                        ),
                    ));
                }
                if meta.is_file() {
                    verify_canonical_confinement(base_dir, &candidate, &self.name)?;
                    candidates.push(candidate);
                }
            }
            if candidates.len() == 1 {
                return Ok(candidates.remove(0));
            }
        }

        Err(ManifestError::MissingLibrary {
            mod_name: self.name.clone(),
            path: base_dir.join(preferred_prefixed_name),
        })
    }

    /// Resolves the shared-library path for this manifest relative to `manifest_path.parent()`,
    /// rejecting path traversal, unsafe identifiers, symlinks, and escapes outside the mod root.
    pub fn resolve_library_path(&self) -> Result<PathBuf, ManifestError> {
        self.resolve_library_path_for_target(None)
    }
}

fn verify_canonical_confinement(
    base_dir: &Path,
    candidate: &Path,
    mod_name: &str,
) -> Result<(), ManifestError> {
    let canon_base = std::fs::canonicalize(base_dir).map_err(|source| ManifestError::Io {
        path: base_dir.to_path_buf(),
        source,
    })?;
    let canon_candidate = std::fs::canonicalize(candidate).map_err(|source| ManifestError::Io {
        path: candidate.to_path_buf(),
        source,
    })?;
    if !canon_candidate.starts_with(&canon_base) {
        return Err(permission_denied(
            candidate.to_path_buf(),
            format!(
                "mod '{mod_name}' resolved library '{}' escapes mod root '{}'",
                canon_candidate.display(),
                canon_base.display()
            ),
        ));
    }
    Ok(())
}

fn resolve_confined_regular_file(
    base_dir: &Path,
    segments: &[&str],
    mod_name: &str,
) -> Result<PathBuf, ManifestError> {
    let mut cur = base_dir.to_path_buf();
    let mut last_meta: Option<std::fs::Metadata> = None;
    for seg in segments {
        cur.push(seg);
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(permission_denied(
                        cur,
                        format!("mod '{mod_name}' library path traverses or points to a symlink"),
                    ));
                }
                last_meta = Some(meta);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut full = base_dir.to_path_buf();
                for s in segments {
                    full.push(s);
                }
                return Err(ManifestError::MissingLibrary {
                    mod_name: mod_name.to_owned(),
                    path: full,
                });
            }
            Err(source) => {
                return Err(ManifestError::Io { path: cur, source });
            }
        }
    }

    let Some(meta) = last_meta else {
        return Err(invalid_manifest_input(
            base_dir.to_path_buf(),
            format!("mod '{mod_name}' entry path has no segments"),
        ));
    };
    if !meta.is_file() {
        return Err(ManifestError::MissingLibrary {
            mod_name: mod_name.to_owned(),
            path: cur,
        });
    }
    verify_canonical_confinement(base_dir, &cur, mod_name)?;
    Ok(cur)
}

/// Pure manifest parsing, SemVer validation, and dependency DAG diagnostics.
#[derive(Debug)]
pub enum ManifestError {
    /// Filesystem I/O failure reading a directory or `mod.toml`.
    Io {
        /// Path where the I/O operation failed.
        path: PathBuf,
        /// Underlying OS I/O error.
        source: std::io::Error,
    },
    /// TOML syntax or schema failure parsing `mod.toml`.
    TomlParse {
        /// Path to the malformed `mod.toml`.
        path: PathBuf,
        /// Underlying `toml` parse error.
        source: Box<toml::de::Error>,
    },
    /// Neither `[mod].id` nor `[mod].name` was specified (or both were empty).
    MissingModName {
        /// Path to the invalid `mod.toml`.
        path: PathBuf,
    },
    /// `[mod].version` failed SemVer parsing.
    InvalidVersion {
        /// Path to `mod.toml`.
        path: PathBuf,
        /// Raw version string.
        raw: String,
        /// Underlying `semver` error.
        source: semver::Error,
    },
    /// `[mod].abi_version` failed SemVer requirement parsing.
    InvalidAbiVersion {
        /// Path to `mod.toml`.
        path: PathBuf,
        /// Raw ABI version string.
        raw: String,
        /// Underlying `semver` error.
        source: semver::Error,
    },
    /// `[mod].abi_version` does not match the host's ABI version.
    IncompatibleAbiVersion {
        /// Path to `mod.toml`.
        path: PathBuf,
        /// Canonical mod name.
        mod_name: String,
        /// Required host ABI version requirement.
        required: semver::VersionReq,
        /// Host ABI version.
        host_abi: semver::Version,
    },
    /// A dependency entry in `[dependencies]` or `[optional_dependencies]` failed SemVer parsing.
    InvalidDependencyReq {
        /// Path to `mod.toml`.
        path: PathBuf,
        /// Canonical mod name.
        mod_name: String,
        /// Dependency name.
        dependency: String,
        /// Raw SemVer requirement string.
        raw: String,
        /// Underlying `semver` error.
        source: semver::Error,
    },
    /// Two discovered `mod.toml` files declared the same canonical mod name.
    DuplicateModName {
        /// Duplicate mod name.
        mod_name: String,
        /// First manifest path seen.
        first_path: PathBuf,
        /// Conflicting second manifest path.
        second_path: PathBuf,
    },
    /// Expected native shared-library file was not found.
    MissingLibrary {
        /// Canonical mod name.
        mod_name: String,
        /// Expected library path.
        path: PathBuf,
    },
    /// A required dependency is missing (or failed earlier validation/load).
    MissingDependency {
        /// Dependent mod name.
        mod_name: String,
        /// Missing dependency name.
        dependency: String,
        /// Required SemVer constraint.
        required: semver::VersionReq,
    },
    /// A dependency exists but its version does not satisfy the SemVer requirement.
    IncompatibleDependencyVersion {
        /// Dependent mod name.
        mod_name: String,
        /// Dependency name.
        dependency: String,
        /// Required SemVer constraint.
        required: semver::VersionReq,
        /// Version found.
        found: semver::Version,
    },
    /// One or more mods formed (or depended on) a dependency cycle and were quarantined.
    CycleQuarantined {
        /// Sorted list of quarantined mod names involved in or blocked by the cycle.
        cycle_members: Vec<String>,
    },
    /// No `mod.toml` manifests were discovered inside `dir` (for strict CLI directory checks).
    NoManifestsFound {
        /// Directory scanned for `mod.toml` files.
        dir: PathBuf,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "I/O error reading '{}': {source}", path.display())
            }
            Self::TomlParse { path, source } => {
                write!(f, "failed to parse '{}': {source}", path.display())
            }
            Self::MissingModName { path } => {
                write!(
                    f,
                    "manifest '{}' is missing [mod].id / [mod].name",
                    path.display()
                )
            }
            Self::InvalidVersion { path, raw, source } => {
                write!(
                    f,
                    "manifest '{}' has invalid SemVer version '{raw}': {source}",
                    path.display()
                )
            }
            Self::InvalidAbiVersion { path, raw, source } => {
                write!(
                    f,
                    "manifest '{}' has invalid abi_version '{raw}': {source}",
                    path.display()
                )
            }
            Self::IncompatibleAbiVersion {
                mod_name,
                required,
                host_abi,
                ..
            } => {
                write!(
                    f,
                    "mod '{mod_name}' requires host ABI '{required}', but host ABI is '{host_abi}'"
                )
            }
            Self::InvalidDependencyReq {
                mod_name,
                dependency,
                raw,
                source,
                ..
            } => {
                write!(
                    f,
                    "mod '{mod_name}' has invalid SemVer requirement '{raw}' for dependency '{dependency}': {source}"
                )
            }
            Self::DuplicateModName {
                mod_name,
                first_path,
                second_path,
            } => {
                write!(
                    f,
                    "duplicate mod '{mod_name}' declared in '{}' and '{}'",
                    first_path.display(),
                    second_path.display()
                )
            }
            Self::MissingLibrary { mod_name, path } => {
                write!(
                    f,
                    "mod '{mod_name}' library not found at '{}'",
                    path.display()
                )
            }
            Self::MissingDependency {
                mod_name,
                dependency,
                required,
            } => {
                write!(
                    f,
                    "mod '{mod_name}' is missing required dependency '{dependency}' ({required})"
                )
            }
            Self::IncompatibleDependencyVersion {
                mod_name,
                dependency,
                required,
                found,
            } => {
                write!(
                    f,
                    "mod '{mod_name}' requires '{dependency}' {required}, found {found}"
                )
            }
            Self::CycleQuarantined { cycle_members } => {
                write!(
                    f,
                    "quarantined cyclic dependency subgraph: {}",
                    cycle_members.join(", ")
                )
            }
            Self::NoManifestsFound { dir } => {
                write!(f, "no `mod.toml` manifests found in '{}'", dir.display())
            }
        }
    }
}

impl std::error::Error for ManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::TomlParse { source, .. } => Some(source.as_ref()),
            Self::InvalidVersion { source, .. }
            | Self::InvalidAbiVersion { source, .. }
            | Self::InvalidDependencyReq { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Result of running SemVer validation and Kahn's topological sort over discovered manifests.
#[derive(Debug)]
pub struct ManifestDagResolution {
    /// Valid, acyclic manifests ordered so every dependency precedes its dependents.
    pub load_order: Vec<ModTomlManifest>,
    /// Sorted canonical names of mods quarantined because they form or depend on a cycle.
    pub quarantined_cycles: Vec<String>,
    /// Deterministic validation, duplicate, SemVer mismatch, and cycle-quarantine diagnostics.
    pub diagnostics: Vec<ManifestError>,
}

/// Resolves SemVer compatibility and runs Kahn's topological sort over `manifests`.
///
/// Any dependency cycle is isolated and recorded in [`ManifestDagResolution::quarantined_cycles`]
/// and [`ManifestDagResolution::diagnostics`] (`CycleQuarantined`) without panicking and without
/// blocking independent acyclic mods from appearing in [`ManifestDagResolution::load_order`].
pub fn resolve_dependency_dag(
    manifests: Vec<ModTomlManifest>,
    already_loaded: &BTreeMap<String, semver::Version>,
) -> ManifestDagResolution {
    let mut diagnostics = Vec::new();
    let mut candidates: BTreeMap<String, ModTomlManifest> = BTreeMap::new();
    let host_abi = host_abi_semver();

    for manifest in manifests {
        if let Some(existing) = candidates.get(&manifest.name) {
            diagnostics.push(ManifestError::DuplicateModName {
                mod_name: manifest.name.clone(),
                first_path: existing.manifest_path.clone(),
                second_path: manifest.manifest_path.clone(),
            });
            continue;
        }
        if let Some(ref abi_req) = manifest.abi_version
            && !abi_req.matches(&host_abi)
        {
            diagnostics.push(ManifestError::IncompatibleAbiVersion {
                path: manifest.manifest_path.clone(),
                mod_name: manifest.name.clone(),
                required: abi_req.clone(),
                host_abi: host_abi.clone(),
            });
            continue;
        }
        candidates.insert(manifest.name.clone(), manifest);
    }

    // Fixed-point validation so missing/incompatible dependencies propagate deterministically.
    loop {
        let mut to_remove: Vec<(String, ManifestError)> = Vec::new();
        for (name, manifest) in &candidates {
            let mut failed_err: Option<ManifestError> = None;

            for (dep, req) in &manifest.dependencies {
                let found_ver = candidates
                    .get(dep)
                    .map(|m| &m.version)
                    .or_else(|| already_loaded.get(dep));
                match found_ver {
                    None => {
                        failed_err = Some(ManifestError::MissingDependency {
                            mod_name: name.clone(),
                            dependency: dep.clone(),
                            required: req.clone(),
                        });
                        break;
                    }
                    Some(ver) if !req.matches(ver) => {
                        failed_err = Some(ManifestError::IncompatibleDependencyVersion {
                            mod_name: name.clone(),
                            dependency: dep.clone(),
                            required: req.clone(),
                            found: ver.clone(),
                        });
                        break;
                    }
                    Some(_) => {}
                }
            }

            if failed_err.is_none() {
                for (opt_dep, req) in &manifest.optional_dependencies {
                    let found_ver = candidates
                        .get(opt_dep)
                        .map(|m| &m.version)
                        .or_else(|| already_loaded.get(opt_dep));
                    if let Some(ver) = found_ver
                        && !req.matches(ver)
                    {
                        failed_err = Some(ManifestError::IncompatibleDependencyVersion {
                            mod_name: name.clone(),
                            dependency: opt_dep.clone(),
                            required: req.clone(),
                            found: ver.clone(),
                        });
                        break;
                    }
                }
            }

            if let Some(err) = failed_err {
                to_remove.push((name.clone(), err));
            }
        }

        if to_remove.is_empty() {
            break;
        }
        for (name, err) in to_remove {
            candidates.remove(&name);
            diagnostics.push(err);
        }
    }

    // Build DAG edges (`dependency -> dependent`) across `candidates`.
    let mut in_degree: BTreeMap<String, usize> =
        candidates.keys().map(|k| (k.clone(), 0usize)).collect();
    let mut dependents: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for (name, manifest) in &candidates {
        let mut unique_deps: BTreeSet<&str> = BTreeSet::new();
        for dep in manifest.dependencies.keys() {
            if candidates.contains_key(dep) {
                unique_deps.insert(dep.as_str());
            }
        }
        for opt_dep in manifest.optional_dependencies.keys() {
            if candidates.contains_key(opt_dep) {
                unique_deps.insert(opt_dep.as_str());
            }
        }

        for dep in unique_deps {
            dependents
                .entry(dep.to_string())
                .or_default()
                .insert(name.clone());
            if let Some(deg) = in_degree.get_mut(name) {
                *deg += 1;
            }
        }
    }

    // Kahn's topological sort with deterministic lexicographical ordering.
    let mut ready: BTreeSet<String> = in_degree
        .iter()
        .filter(|&(_, &deg)| deg == 0)
        .map(|(k, _)| k.clone())
        .collect();

    let mut load_order = Vec::with_capacity(candidates.len());
    while let Some(name) = ready.pop_first() {
        if let Some(manifest) = candidates.get(&name) {
            load_order.push(manifest.clone());
        }
        if let Some(children) = dependents.get(&name) {
            for child in children {
                if let Some(deg) = in_degree.get_mut(child) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        ready.insert(child.clone());
                    }
                }
            }
        }
    }

    let quarantined_cycles: Vec<String> = in_degree
        .iter()
        .filter(|&(_, &deg)| deg > 0)
        .map(|(k, _)| k.clone())
        .collect();

    if !quarantined_cycles.is_empty() {
        diagnostics.push(ManifestError::CycleQuarantined {
            cycle_members: quarantined_cycles.clone(),
        });
    }

    ManifestDagResolution {
        load_order,
        quarantined_cycles,
        diagnostics,
    }
}

/// Discovers `mod.toml` manifests inside `dir` (checking `dir/mod.toml` and `dir/*/mod.toml`).
pub fn discover_mod_manifests(
    dir: &Path,
) -> Result<(Vec<ModTomlManifest>, Vec<ManifestError>), ManifestError> {
    let entries = std::fs::read_dir(dir).map_err(|source| ManifestError::Io {
        path: dir.to_path_buf(),
        source,
    })?;

    let mut manifest_paths = Vec::new();
    let root_manifest = dir.join("mod.toml");
    if root_manifest.is_file() {
        manifest_paths.push(root_manifest);
    }

    let mut subdirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    subdirs.sort();

    for sub in subdirs {
        let candidate = sub.join("mod.toml");
        if candidate.is_file() {
            manifest_paths.push(candidate);
        }
    }

    let mut manifests = Vec::with_capacity(manifest_paths.len());
    let mut errors = Vec::new();
    for path in manifest_paths {
        match ModTomlManifest::from_file(&path) {
            Ok(m) => manifests.push(m),
            Err(e) => errors.push(e),
        }
    }

    Ok((manifests, errors))
}

/// Strict directory validator used by `cargo bam check-mods`: discovers all `mod.toml` files
/// under `dir`, fails on the first parse/ABI/dependency/cycle error or empty directory, and returns
/// the validated manifests in deterministic Kahn topological load order.
pub fn check_mods_dir_strict(dir: &Path) -> Result<Vec<ModTomlManifest>, ManifestError> {
    if !dir.is_dir() {
        return Err(ManifestError::Io {
            path: dir.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("mods directory does not exist: {}", dir.display()),
            ),
        });
    }

    let (manifests, parse_errors) = discover_mod_manifests(dir)?;
    if let Some(first_err) = parse_errors.into_iter().next() {
        return Err(first_err);
    }
    if manifests.is_empty() {
        return Err(ManifestError::NoManifestsFound {
            dir: dir.to_path_buf(),
        });
    }

    let resolution = resolve_dependency_dag(manifests, &BTreeMap::new());
    if let Some(first_diag) = resolution.diagnostics.into_iter().next() {
        return Err(first_diag);
    }
    Ok(resolution.load_order)
}

/// Computes the forward topological order `[root_id, ...dependents]` of `root_id` and all
/// transitive active dependents given `(id -> &dependencies)` and `(name -> id)` lookups.
///
/// - For cascading **unload**, iterate the returned slice in **reverse** (`C -> B -> A`).
/// - For cascading **reload**, save & unload in **reverse** (`C -> B -> A`), then reload &
///   restore in **forward** (`A -> B -> C`) order.
pub fn compute_cascading_order<'a, Id, F>(
    root_id: Id,
    active_ids: &BTreeSet<Id>,
    id_by_name: &BTreeMap<String, Id>,
    deps_for_id: F,
) -> Vec<Id>
where
    Id: Ord + Copy,
    F: Fn(Id) -> Option<&'a [String]>,
{
    if deps_for_id(root_id).is_none() {
        return vec![root_id];
    }

    let mut reverse_edges: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
    for &dep_id in active_ids {
        let Some(deps) = deps_for_id(dep_id) else {
            continue;
        };
        for dep_name in deps {
            if let Some(&provider_id) = id_by_name.get(dep_name)
                && active_ids.contains(&provider_id)
            {
                reverse_edges.entry(provider_id).or_default().insert(dep_id);
            }
        }
    }

    let mut affected: BTreeSet<Id> = BTreeSet::new();
    let mut queue = VecDeque::new();
    affected.insert(root_id);
    queue.push_back(root_id);
    while let Some(curr) = queue.pop_front() {
        if let Some(children) = reverse_edges.get(&curr) {
            for &child in children {
                if affected.insert(child) {
                    queue.push_back(child);
                }
            }
        }
    }

    let mut in_degree: BTreeMap<Id, usize> = affected.iter().map(|&id| (id, 0usize)).collect();
    let mut sub_edges: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
    for &id in &affected {
        if let Some(children) = reverse_edges.get(&id) {
            for &child in children {
                if affected.contains(&child)
                    && sub_edges.entry(id).or_default().insert(child)
                    && let Some(deg) = in_degree.get_mut(&child)
                {
                    *deg += 1;
                }
            }
        }
    }

    let mut ready: BTreeSet<Id> = in_degree
        .iter()
        .filter_map(|(&id, &deg)| (deg == 0).then_some(id))
        .collect();
    let mut order = Vec::with_capacity(affected.len());
    while let Some(id) = ready.pop_first() {
        order.push(id);
        if let Some(children) = sub_edges.get(&id) {
            for &child in children {
                if let Some(deg) = in_degree.get_mut(&child) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        ready.insert(child);
                    }
                }
            }
        }
    }

    for id in affected {
        if !order.contains(&id) {
            order.push(id);
        }
    }
    order
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parse_and_validate_manifest_fields_and_language() {
        let host = host_abi_semver();
        let valid = format!(
            r#"
[mod]
id = "core_physics"
name = "Core Physics"
version = "1.2.3"
abi_version = "^{host}"
entry = "libcore_physics.so"
language = "rust"

[dependencies]
math = "^1.0"

[optional_dependencies]
debug_draw = ">=0.1.0"
"#
        );
        let parsed = ModTomlManifest::parse_str(&valid, "mods/core/mod.toml").unwrap();
        assert_eq!(parsed.id(), "core_physics");
        assert_eq!(parsed.display_name.as_deref(), Some("Core Physics"));
        assert_eq!(parsed.version, semver::Version::new(1, 2, 3));
        assert_eq!(parsed.language.as_deref(), Some("rust"));
        assert_eq!(parsed.entry.as_deref(), Some("libcore_physics.so"));
        assert!(parsed.validate_abi_compatibility().is_ok());
    }

    #[test]
    fn dag_resolves_order_quarantines_cycles_and_check_strict_rejects_errors() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::create_dir_all(dir.join("base")).unwrap();
        std::fs::create_dir_all(dir.join("app")).unwrap();
        std::fs::create_dir_all(dir.join("cyc_a")).unwrap();
        std::fs::create_dir_all(dir.join("cyc_b")).unwrap();

        let host = host_abi_semver();
        std::fs::write(
            dir.join("base/mod.toml"),
            format!("[mod]\nid = \"base\"\nversion = \"1.0.0\"\nabi_version = \"^{host}\"\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("app/mod.toml"),
            "[mod]\nid = \"app\"\nversion = \"0.2.0\"\n\n[dependencies]\nbase = \"^1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("cyc_a/mod.toml"),
            "[mod]\nid = \"cyc_a\"\nversion = \"1.0.0\"\n\n[dependencies]\ncyc_b = \"^1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("cyc_b/mod.toml"),
            "[mod]\nid = \"cyc_b\"\nversion = \"1.0.0\"\n\n[dependencies]\ncyc_a = \"^1.0\"\n",
        )
        .unwrap();

        let (manifests, parse_errs) = discover_mod_manifests(dir).unwrap();
        assert!(parse_errs.is_empty());
        let res = resolve_dependency_dag(manifests, &BTreeMap::new());
        let loaded_names: Vec<&str> = res.load_order.iter().map(|m| m.id()).collect();
        assert_eq!(loaded_names, vec!["base", "app"]);
        assert_eq!(res.quarantined_cycles, vec!["cyc_a", "cyc_b"]);

        let strict_err = check_mods_dir_strict(dir).unwrap_err();
        assert!(matches!(strict_err, ManifestError::CycleQuarantined { .. }));
    }

    #[test]
    fn builder_serialize_to_toml_roundtrip_with_targets_build_and_capabilities() {
        let host = host_abi_semver();
        let mut caps = ModCapabilities::default();
        caps.required.insert("assets".to_owned());
        caps.optional.insert("audio".to_owned());
        caps.permissions.insert("fs_read".to_owned());
        caps.flags.insert("deterministic".to_owned(), true);

        let mut build = ModBuildConfig::with_command("make");
        build.args = vec!["release".to_owned()];
        build.working_dir = Some("native".to_owned());
        build.output = Some("bin/libdemo.so".to_owned());
        build.env.insert("OPT".to_owned(), "2".to_owned());
        build.watch_paths = vec!["native/src".to_owned()];

        let built = ModTomlManifest::builder("demo_mod", semver::Version::new(0, 4, 0))
            .display_name("Demo Mod")
            .abi_version(semver::VersionReq::parse(&format!("^{host}")).unwrap())
            .language("c99")
            .dependency("core_mod", semver::VersionReq::parse("^1.0").unwrap())
            .optional_dependency("ui_mod", semver::VersionReq::parse(">=0.1.0").unwrap())
            .target(
                "x86_64-unknown-linux-gnu",
                ModTargetConfig::new("bin/x86_64-unknown-linux-gnu/libdemo_mod.so")
                    .with_sha256("a".repeat(64)),
            )
            .target(
                "aarch64-apple-darwin",
                ModTargetConfig::new("bin/aarch64-apple-darwin/libdemo_mod.dylib"),
            )
            .build_config(build)
            .capabilities(caps)
            .build()
            .expect("builder should validate cleanly");

        let toml_text = built.to_toml_string().expect("serialize mod.toml");
        assert!(toml_text.contains("[targets.x86_64-unknown-linux-gnu]"));
        assert!(toml_text.contains("[build]"));
        assert!(toml_text.contains("[capabilities]"));

        let reparsed = ModTomlManifest::parse_str(&toml_text, &built.manifest_path)
            .expect("round-trip parse_str");
        assert_eq!(reparsed, built);
        assert_eq!(
            reparsed.entry_for_target("aarch64-apple-darwin"),
            Some("bin/aarch64-apple-darwin/libdemo_mod.dylib")
        );

        // Ensure `serde::Serialize` works directly on `ModTomlManifest` and nested types.
        let as_toml_value = toml::Value::try_from(&reparsed).expect("ModTomlManifest Serialize");
        assert_eq!(as_toml_value["name"].as_str(), Some("demo_mod"));
    }

    #[test]
    fn resolve_library_path_for_target_resolves_target_specific_binary() {
        let tmp = TempDir::new().unwrap();
        let mod_dir = tmp.path().join("multi_mod");
        let bin_linux = mod_dir.join("bin/x86_64-unknown-linux-gnu");
        std::fs::create_dir_all(&bin_linux).unwrap();
        let linux_lib = bin_linux.join("libmulti_mod.so");
        std::fs::write(&linux_lib, b"elf-stub").unwrap();

        let manifest = ModTomlManifest::builder("multi_mod", semver::Version::new(1, 0, 0))
            .target(
                "x86_64-unknown-linux-gnu",
                ModTargetConfig::new("bin/x86_64-unknown-linux-gnu/libmulti_mod.so"),
            )
            .manifest_path(mod_dir.join("mod.toml"))
            .build()
            .unwrap();

        assert_eq!(
            manifest
                .resolve_library_path_for_target(Some("x86_64-unknown-linux-gnu"))
                .unwrap(),
            linux_lib
        );
    }

    #[test]
    fn abi_lock_manifest_validates_workspace_sys_cargo_lock_and_bevy_version() {
        let ws_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let report = AbiLockManifest::validate_workspace(&ws_root, Some("0.20.1"))
            .expect("bamabi-tools workspace abi-lock.toml must validate");
        assert_eq!(report.abi_version, bamabi_sys::ABI_VERSION);

        let lock_manifest = AbiLockManifest::from_file(ws_root.join("abi-lock.toml")).unwrap();
        let canonical_lock = format!(
            r#"
[[package]]
name = "bamabi_sys"
version = "{}"
source = "git+https://github.com/yaga-simha/bamabi-wire.git?branch=main#0123456789abcdef0123456789abcdef01234567"

[[package]]
name = "bevy_ecs"
version = "{}"
"#,
            lock_manifest.abi.workspace_version, lock_manifest.abi.bevy_version
        );
        let parity = lock_manifest
            .validate_cargo_lock_str(&canonical_lock, "Cargo.lock", Some("0.20.1"))
            .unwrap();
        assert_eq!(
            parity.wire_source,
            Some(WireLockSource::CanonicalGit {
                rev: "0123456789abcdef0123456789abcdef01234567".to_owned()
            })
        );

        // Wrong Bevy version in Cargo.lock fails
        let bad_bevy_lock = r#"
[[package]]
name = "bevy_ecs"
version = "0.19.0"
"#;
        assert!(matches!(
            lock_manifest.validate_cargo_lock_str(bad_bevy_lock, "Cargo.lock", Some("0.20.1")),
            Err(AbiLockError::CargoLockMismatch { .. })
        ));

        // Mismatched ABI version fails against bamabi_sys::ABI_VERSION
        let wrong_abi = lock_manifest
            .to_toml_string()
            .unwrap()
            .replace(&lock_manifest.abi.bam_abi_version, "0x0003_0000");
        let parsed_wrong = AbiLockManifest::parse_str(&wrong_abi, "abi-lock.toml").unwrap();
        assert!(matches!(
            parsed_wrong.validate_abi_sys(None),
            Err(AbiLockError::AbiVersionMismatch { .. })
        ));
    }
}
