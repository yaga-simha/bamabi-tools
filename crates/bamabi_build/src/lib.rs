#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Reusable, `#![forbid(unsafe_code)]`, zero-Bevy build, compiler-discovery, signing, `.bampack`
//! packaging, SDK export, and `notify`-backed watch library for `bamabi` (`ABI 0.4.0`).
//!
//! Part of Layer 1 (`bamabi-tools`), `bamabi_build` depends strictly on Layer 0
//! (`bamabi-wire`: [`bamabi_sys`] and [`bamabi_sdk_gen`]) alongside [`bamabi_manifest`],
//! [`bamabi_trust`], and `notify`, with zero Bevy dependencies and `#![forbid(unsafe_code)]`.
//!
//! ## Provided Modules
//!
//! - [`builder`]: Compiler/toolchain discovery (C99/C++17/Zig + MSVC `cl.exe`/`clang-cl`/`vswhere`),
//!   `[build] command` execution, and atomic shared-library staging.
//! - [`pack`]: Deterministic `.bampack` archive creation (including multi-target `[targets.<triple>]`
//!   and unsigned dev bundles), cryptographic verification, and unverified inspection.
//! - [`watch`]: `notify` event-driven + mtime-gated incremental rebuilder, signer, and atomic stager.
//! - [`signing`]: Ed25519 key loading, OpenSSH `SSHSIG` `.sig` signing, and trust-policy verification.
//! - [`dag`]: Multi-mod `mod.toml` SemVer validation and Kahn topological sort.
//! - [`doctor`]: Host ABI `0.4.0` layout, toolchain, and embedded SDK header parity diagnostics.
//! - [`scaffold`]: Project scaffolding for Rust, ISO C99, C++17, and Zig guest mods.
//! - [`sdk`]: Polyglot `bamabi.h`, `bamabi.hpp`, and `bamabi.zig` SDK header exporter.

pub mod builder;
pub mod dag;
pub mod doctor;
pub mod pack;
pub mod scaffold;
pub mod sdk;
pub mod signing;
pub mod watch;

use bamabi_manifest::{validate_manifest_entry_path, validate_mod_id};
use dag::ValidatedModManifest;
use scaffold::ModLanguage;
use serde::Deserialize;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

/// Typed error returned by [`bamabi_build`](crate) operations.
#[derive(Debug, Error)]
pub enum BuildError {
    /// Invalid argument, path, or identifier.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Target directory already exists.
    #[error("target directory already exists: {}", .0.display())]
    AlreadyExists(PathBuf),
    /// Invalid or missing `mod.toml` / `Cargo.toml`.
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    /// External compiler/build command failed.
    #[error("build command failed: {0}")]
    Command(String),
    /// Cryptographic keygen/signing/verification failure.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Underlying filesystem I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Resolved metadata for a guest mod project directory.
#[derive(Debug, Clone)]
pub struct ResolvedProject {
    /// Mod project root directory.
    pub project_dir: PathBuf,
    /// Optional path to `mod.toml` inside [`Self::project_dir`].
    pub mod_toml_path: Option<PathBuf>,
    /// Validated `mod.toml` manifest when present.
    pub manifest: Option<ValidatedModManifest>,
    /// Detected guest implementation language.
    pub language: ModLanguage,
    /// Canonical mod identifier (`[mod].id` or directory fallback).
    pub mod_id: String,
    /// Sanitized shared-library filename stem (without OS prefix/extension).
    pub lib_stem: String,
}

/// Returns the `(prefix, extension)` dynamic-library naming convention for the current host OS.
#[must_use]
pub const fn dylib_naming() -> (&'static str, &'static str) {
    if cfg!(target_os = "windows") {
        ("", "dll")
    } else if cfg!(target_os = "macos") {
        ("lib", "dylib")
    } else {
        ("lib", "so")
    }
}

/// Returns the `(prefix, extension)` dynamic-library naming convention for `target_triple`.
#[must_use]
pub fn dylib_naming_for_target(target_triple: &str) -> (&'static str, &'static str) {
    let lower = target_triple.to_ascii_lowercase();
    if lower.contains("windows") {
        if lower.contains("gnu") {
            ("lib", "dll")
        } else {
            ("", "dll")
        }
    } else if lower.contains("apple") || lower.contains("darwin") {
        ("lib", "dylib")
    } else {
        ("lib", "so")
    }
}

pub(crate) fn parse_rustc_host_triple(verbose_output: &str) -> Option<String> {
    verbose_output.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("host:")
            .map(str::trim)
            .filter(|triple| !triple.is_empty())
            .map(str::to_owned)
    })
}

/// Returns the active Rust host target triple (via `rustc -vV`, cached, or `<arch>-<os>` fallback).
#[must_use]
pub fn host_target_triple() -> &'static str {
    static HOST_TRIPLE: OnceLock<String> = OnceLock::new();
    HOST_TRIPLE
        .get_or_init(|| {
            if let Ok(output) = Command::new("rustc").arg("-vV").output()
                && output.status.success()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(triple) = parse_rustc_host_triple(&stdout) {
                    return triple;
                }
            }
            format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
        })
        .as_str()
}

/// Reads a regular file from disk bounded by `max_bytes`, failing cleanly on directories/FIFOs
/// or oversized files.
pub fn read_file_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, BuildError> {
    let file = fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(BuildError::InvalidArgument(format!(
            "{label} '{}' is not a regular file",
            path.display()
        )));
    }
    if meta.len() > max_bytes {
        return Err(BuildError::InvalidArgument(format!(
            "{label} '{}' ({} bytes) exceeds limit ({max_bytes} bytes)",
            path.display(),
            meta.len()
        )));
    }
    let cap = usize::try_from(meta.len()).unwrap_or(0);
    let mut buf = Vec::with_capacity(cap);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > max_bytes {
        return Err(BuildError::InvalidArgument(format!(
            "{label} '{}' exceeded limit ({max_bytes} bytes) while reading",
            path.display()
        )));
    }
    Ok(buf)
}

/// Validates `mod_id` and safely creates/verifies `<stage_root>/<mod_id>` without allowing
/// traversal, unsafe identifiers, symlink escapes, or writes outside `stage_root`.
pub fn validated_stage_dir(stage_root: &Path, mod_id: &str) -> Result<PathBuf, BuildError> {
    validate_mod_id(mod_id).map_err(|reason| {
        BuildError::InvalidManifest(format!(
            "refusing to stage unsafe mod identifier '{mod_id}': {reason}"
        ))
    })?;

    if let Ok(meta) = fs::symlink_metadata(stage_root)
        && meta.file_type().is_symlink()
    {
        return Err(BuildError::InvalidArgument(format!(
            "staging root must not be a symlink: {}",
            stage_root.display()
        )));
    }
    fs::create_dir_all(stage_root)?;
    let canon_root = fs::canonicalize(stage_root)?;

    let stage_dir = stage_root.join(mod_id);
    if let Ok(meta) = fs::symlink_metadata(&stage_dir)
        && meta.file_type().is_symlink()
    {
        return Err(BuildError::InvalidArgument(format!(
            "staging directory must not be a symlink: {}",
            stage_dir.display()
        )));
    }
    fs::create_dir_all(&stage_dir)?;
    let canon_stage = fs::canonicalize(&stage_dir)?;
    if !canon_stage.starts_with(&canon_root) || canon_stage == canon_root {
        return Err(BuildError::InvalidManifest(format!(
            "staging directory '{}' escapes staging root '{}'",
            canon_stage.display(),
            canon_root.display()
        )));
    }
    Ok(stage_dir)
}

/// Safely creates/verifies a relative POSIX path inside `stage_dir`, rejecting symlinks and
/// canonical path escapes.
pub fn validated_staged_file_path(
    stage_dir: &Path,
    rel_posix: &str,
) -> Result<PathBuf, BuildError> {
    validate_manifest_entry_path(rel_posix).map_err(|reason| {
        BuildError::InvalidManifest(format!("invalid staged entry path '{rel_posix}': {reason}"))
    })?;
    let canon_stage = fs::canonicalize(stage_dir)?;
    let mut cur = stage_dir.to_path_buf();
    let segments: Vec<&str> = rel_posix.split('/').collect();
    if let Some((&file_name, parent_segs)) = segments.split_last() {
        for seg in parent_segs {
            cur.push(seg);
            if let Ok(meta) = fs::symlink_metadata(&cur) {
                if meta.file_type().is_symlink() {
                    return Err(BuildError::InvalidArgument(format!(
                        "staged subdirectory must not be a symlink: {}",
                        cur.display()
                    )));
                }
                if !meta.is_dir() {
                    return Err(BuildError::InvalidArgument(format!(
                        "staged parent path is not a directory: {}",
                        cur.display()
                    )));
                }
            } else {
                fs::create_dir(&cur)?;
            }
            let canon_cur = fs::canonicalize(&cur)?;
            if !canon_cur.starts_with(&canon_stage) {
                return Err(BuildError::InvalidManifest(format!(
                    "staged parent directory '{}' escapes staging directory '{}'",
                    canon_cur.display(),
                    canon_stage.display()
                )));
            }
        }
        cur.push(file_name);
        if let Ok(meta) = fs::symlink_metadata(&cur)
            && meta.file_type().is_symlink()
        {
            return Err(BuildError::InvalidArgument(format!(
                "staged file target must not be a symlink: {}",
                cur.display()
            )));
        }
        return Ok(cur);
    }
    Err(BuildError::InvalidManifest(format!(
        "empty staged entry path '{rel_posix}'"
    )))
}

#[derive(Deserialize)]
struct CargoTomlPartial {
    package: Option<CargoPackagePartial>,
    lib: Option<CargoLibPartial>,
}

#[derive(Deserialize)]
struct CargoPackagePartial {
    name: String,
}

#[derive(Deserialize)]
struct CargoLibPartial {
    name: Option<String>,
}

/// Parses `Cargo.toml` to extract the sanitized shared-library stem (`[lib].name` or `[package].name`).
pub fn detect_rust_crate_stem(cargo_toml: &Path) -> Result<String, BuildError> {
    let raw = read_file_bounded(
        cargo_toml,
        bamabi_manifest::MAX_MANIFEST_BYTES,
        "Cargo.toml",
    )?;
    let content = String::from_utf8(raw).map_err(|_| {
        BuildError::InvalidManifest(format!("{} is not valid UTF-8", cargo_toml.display()))
    })?;
    let parsed: CargoTomlPartial = toml::from_str(&content)
        .map_err(|e| BuildError::InvalidManifest(format!("{}: {e}", cargo_toml.display())))?;
    let name = parsed
        .lib
        .and_then(|l| l.name)
        .or_else(|| parsed.package.map(|p| p.name))
        .ok_or_else(|| {
            BuildError::InvalidManifest(format!(
                "{} is missing `[package].name`",
                cargo_toml.display()
            ))
        })?;
    let stem = name.replace('-', "_");
    validate_mod_id(&stem).map_err(|reason| {
        BuildError::InvalidManifest(format!(
            "{} has unsafe crate name '{name}': {reason}",
            cargo_toml.display()
        ))
    })?;
    Ok(stem)
}

fn parse_language_str(raw: &str) -> Option<ModLanguage> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "rust" | "rs" => Some(ModLanguage::Rust),
        "c" | "c99" => Some(ModLanguage::C99),
        "cpp" | "c++" | "cpp17" | "c++17" => Some(ModLanguage::Cpp17),
        "zig" => Some(ModLanguage::Zig),
        _ => None,
    }
}

/// Resolves project root, `mod.toml`, language, mod ID, and library stem from `--manifest-path`
/// or `--dir`.
pub fn resolve_project_info(
    manifest_path: Option<&Path>,
    dir: Option<&Path>,
) -> Result<ResolvedProject, BuildError> {
    let (project_dir, mod_toml_path) = if let Some(mp) = manifest_path {
        let file_name = mp.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name == "mod.toml" {
            let pdir = mp
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            (pdir, Some(mp.to_path_buf()))
        } else if file_name == "Cargo.toml" {
            let pdir = mp
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            let candidate = pdir.join("mod.toml");
            (pdir, candidate.is_file().then_some(candidate))
        } else {
            return Err(BuildError::InvalidArgument(format!(
                "--manifest-path must point to `mod.toml` or `Cargo.toml`, got {}",
                mp.display()
            )));
        }
    } else {
        let pdir = dir.unwrap_or_else(|| Path::new(".")).to_path_buf();
        let candidate = pdir.join("mod.toml");
        (pdir, candidate.is_file().then_some(candidate))
    };

    let manifest = if let Some(ref mp) = mod_toml_path {
        Some(ValidatedModManifest::from_file(mp)?)
    } else {
        None
    };

    let cargo_toml = project_dir.join("Cargo.toml");
    let explicit_lang = manifest
        .as_ref()
        .and_then(|m| m.language.as_deref())
        .and_then(parse_language_str);

    let language = if let Some(lang) = explicit_lang {
        lang
    } else if cargo_toml.is_file() {
        ModLanguage::Rust
    } else if project_dir.join("build.zig").is_file() {
        ModLanguage::Zig
    } else if project_dir.join("src/mod.cpp").is_file() || project_dir.join("mod.cpp").is_file() {
        ModLanguage::Cpp17
    } else if project_dir.join("src/mod.c").is_file() || project_dir.join("mod.c").is_file() {
        ModLanguage::C99
    } else {
        return Err(BuildError::InvalidManifest(format!(
            "could not determine mod language in {} (missing `mod.toml`, `Cargo.toml`, `build.zig`, `src/mod.c`, or `src/mod.cpp`)",
            project_dir.display()
        )));
    };

    let mod_id = match manifest.as_ref() {
        Some(m) => {
            validate_mod_id(&m.id).map_err(|reason| {
                BuildError::InvalidManifest(format!("invalid [mod].id '{}': {reason}", m.id))
            })?;
            if let Some(ref entry) = m.entry {
                validate_manifest_entry_path(entry).map_err(|reason| {
                    BuildError::InvalidManifest(format!("invalid [mod].entry '{entry}': {reason}"))
                })?;
            }
            m.id.clone()
        }
        None => {
            let derived = project_dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("bam_mod")
                .to_owned();
            validate_mod_id(&derived).map_err(|reason| {
                BuildError::InvalidManifest(format!(
                    "derived mod identifier '{derived}' from '{}' is unsafe: {reason} (add an explicit [mod].id in mod.toml)",
                    project_dir.display()
                ))
            })?;
            derived
        }
    };

    let lib_stem = if language == ModLanguage::Rust && cargo_toml.is_file() {
        detect_rust_crate_stem(&cargo_toml)?
    } else {
        let stem = manifest
            .as_ref()
            .and_then(|m| m.entry.clone())
            .map(|e| {
                Path::new(&e)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&mod_id)
                    .trim_start_matches("lib")
                    .to_owned()
            })
            .unwrap_or_else(|| mod_id.clone())
            .replace('-', "_");
        validate_mod_id(&stem).map_err(|reason| {
            BuildError::InvalidManifest(format!(
                "derived library stem '{stem}' is unsafe: {reason}"
            ))
        })?;
        stem
    };

    Ok(ResolvedProject {
        project_dir,
        mod_toml_path,
        manifest,
        language,
        mod_id,
        lib_stem,
    })
}

/// Atomically writes `bytes` to `dest` via a unique sibling temporary file (`create_new`,
/// `write_all`, `flush`, `sync_all`, `rename`), preventing partial-file reads by hot-reload watchers.
pub fn atomic_write_bytes(dest: &Path, bytes: &[u8]) -> Result<(), BuildError> {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let base_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("artifact");
    let pid = std::process::id();

    let (mut file, tmp_path) = loop {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{base_name}.bamtmp.{pid}.{seq}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(f) => break (f, candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(BuildError::Io(err)),
        }
    };

    let write_res = file
        .write_all(bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(BuildError::Io(err));
    }

    if let Err(err) = fs::rename(&tmp_path, dest) {
        let _ = fs::remove_file(&tmp_path);
        return Err(BuildError::Io(err));
    }
    Ok(())
}
