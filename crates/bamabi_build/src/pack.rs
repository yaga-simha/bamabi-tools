//! Deterministic `.bampack` archive creation (including optional multi-target `[targets.<triple>]`
//! and unsigned dev bundles) and cryptographic verification, using [`bamabi_trust`].

use crate::builder;
use crate::scaffold::ModLanguage;
use crate::signing::build_trust_policy;
use crate::{
    BuildError, ResolvedProject, atomic_write_bytes, dylib_naming, host_target_triple,
    read_file_bounded, resolve_project_info,
};
use bamabi_manifest::{MAX_MANIFEST_BYTES, validate_mod_id, validate_target_triple};
use bamabi_trust::{
    BAMPACK_MAGIC, BamPackBuilder, BamPackEntry, Certificate, CertificateValidityPolicy,
    DEFAULT_MAX_MOD_BINARY_BYTES, HashAlg, MAX_BAMPACK_ENTRIES, MAX_BAMPACK_PATH_DEPTH,
    MAX_SIGNATURE_SIDECAR_BYTES, ModTrustPolicy, PublicKey, VerifiedBamPack,
    parse_bampack_entries_unverified, validate_bampack_entry_path,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Default OpenSSH `SSHSIG` domain-separation namespace for `.bampack` archives.
pub const DEFAULT_BAMPACK_NAMESPACE: &str = bamabi_trust::DEFAULT_BAMPACK_NAMESPACE;

/// Configuration for [`pack_mod`].
#[derive(Clone, Debug)]
pub struct PackOptions {
    /// Optional explicit path to `mod.toml` or `Cargo.toml`.
    pub manifest_path: Option<PathBuf>,
    /// Optional project directory containing `mod.toml` / `Cargo.toml`.
    pub dir: Option<PathBuf>,
    /// Build (or locate) the release artifact instead of debug.
    pub release: bool,
    /// Optional explicit output `.bampack` file path.
    pub out: Option<PathBuf>,
    /// Optional OpenSSH Ed25519 private key used to sign the `.bampack` archive.
    pub key: Option<PathBuf>,
    /// Optional OpenSSH Ed25519 certificate (`*-cert.pub`) paired with [`Self::key`].
    pub cert: Option<PathBuf>,
    /// `SSHSIG` domain-separation namespace used when signing the archive.
    pub namespace: String,
    /// Optional explicit assets directory to bundle under `assets/`.
    pub assets_dir: Option<PathBuf>,
    /// Skip compiling the mod and locate an existing shared library artifact instead.
    pub skip_build: bool,
    /// Explicit multi-target shared library overrides (`<triple> -> <library_path>`).
    pub target_artifacts: BTreeMap<String, PathBuf>,
    /// Automatically include any `[targets.<triple>]` binaries present on disk under `project_dir`.
    pub include_targets: bool,
    /// Explicitly mark this archive as an unsigned development bundle (rejects `key`).
    pub dev_unsigned: bool,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            manifest_path: None,
            dir: None,
            release: false,
            out: None,
            key: None,
            cert: None,
            namespace: DEFAULT_BAMPACK_NAMESPACE.to_owned(),
            assets_dir: None,
            skip_build: false,
            target_artifacts: BTreeMap::new(),
            include_targets: true,
            dev_unsigned: false,
        }
    }
}

/// Summary returned by [`pack_mod`].
#[derive(Clone, Debug)]
pub struct PackOutput {
    /// Path where the `.bampack` archive was written.
    pub output_path: PathBuf,
    /// Canonical mod identifier from `mod.toml`.
    pub mod_id: String,
    /// Mod SemVer string from `mod.toml`.
    pub version: String,
    /// Detected guest language.
    pub language: ModLanguage,
    /// Relative POSIX path of the primary shared library inside the archive.
    pub library_entry: String,
    /// Relative POSIX paths mapped for each target triple (`<triple> -> <archive_path>`).
    pub target_entries: BTreeMap<String, String>,
    /// Ordered relative POSIX paths of all entries packed in the archive.
    pub entry_paths: Vec<String>,
    /// `true` if the archive was cryptographically signed via `key`.
    pub signed: bool,
    /// `SSHSIG` namespace used for signing (or configured default when unsigned).
    pub namespace: String,
    /// Signer SHA-256 fingerprint when [`Self::signed`] is `true`.
    pub signer_fingerprint: Option<String>,
    /// Lowercase hex SHA-256 digest of the final `.bampack` file bytes.
    pub archive_sha256: String,
}

fn validate_posix_rel_path(path: &str) -> Result<(), BuildError> {
    validate_bampack_entry_path(path).map_err(BuildError::InvalidArgument)
}

fn validate_path_segment(segment: &str) -> Result<(), BuildError> {
    if segment.contains('/') {
        return Err(BuildError::InvalidArgument(format!(
            "unsafe asset path segment '{segment}'"
        )));
    }
    validate_bampack_entry_path(segment).map_err(BuildError::InvalidArgument)
}

fn collect_assets_recursive(
    current_dir: &Path,
    rel_prefix: &str,
    depth: usize,
    entries: &mut BTreeMap<String, Vec<u8>>,
    seen_lower: &mut BTreeSet<String>,
    total_bytes: &mut u64,
) -> Result<(), BuildError> {
    if depth >= MAX_BAMPACK_PATH_DEPTH {
        return Err(BuildError::InvalidArgument(format!(
            "assets directory exceeds maximum nesting depth ({MAX_BAMPACK_PATH_DEPTH}): {}",
            current_dir.display()
        )));
    }

    let mut children: Vec<(String, PathBuf)> = Vec::new();
    for entry_res in fs::read_dir(current_dir)? {
        let entry = entry_res?;
        let os_name = entry.file_name();
        let name = os_name.to_str().ok_or_else(|| {
            BuildError::InvalidArgument(format!(
                "non-UTF-8 asset filename under {}",
                current_dir.display()
            ))
        })?;
        validate_path_segment(name)?;
        children.push((name.to_owned(), entry.path()));
    }
    children.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, path) in children {
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            return Err(BuildError::InvalidArgument(format!(
                "symlink rejected while packing assets: {}",
                path.display()
            )));
        }
        let rel_posix = format!("{rel_prefix}/{name}");
        validate_posix_rel_path(&rel_posix)?;

        if meta.is_dir() {
            let lower_dir = rel_posix.to_lowercase();
            if seen_lower.contains(&lower_dir) {
                return Err(BuildError::InvalidArgument(format!(
                    "asset directory '{rel_posix}' collides case-insensitively with an existing file entry"
                )));
            }
            collect_assets_recursive(
                &path,
                &rel_posix,
                depth + 1,
                entries,
                seen_lower,
                total_bytes,
            )?;
        } else if meta.is_file() {
            if entries.len() >= MAX_BAMPACK_ENTRIES {
                return Err(BuildError::InvalidArgument(format!(
                    "archive exceeds MAX_BAMPACK_ENTRIES ({MAX_BAMPACK_ENTRIES})"
                )));
            }
            let remaining = DEFAULT_MAX_MOD_BINARY_BYTES.saturating_sub(*total_bytes);
            let data = read_file_bounded(&path, remaining, "asset file")?;
            let next_total = total_bytes.checked_add(data.len() as u64).ok_or_else(|| {
                BuildError::InvalidArgument("archive total size overflows u64".to_owned())
            })?;
            if next_total > DEFAULT_MAX_MOD_BINARY_BYTES {
                return Err(BuildError::InvalidArgument(format!(
                    "archive total size ({next_total} bytes) exceeds limit ({DEFAULT_MAX_MOD_BINARY_BYTES} bytes)"
                )));
            }
            if !seen_lower.insert(rel_posix.to_lowercase()) {
                return Err(BuildError::InvalidArgument(format!(
                    "duplicate or case-colliding archive entry path '{rel_posix}'"
                )));
            }
            *total_bytes = next_total;
            entries.insert(rel_posix, data);
        } else {
            return Err(BuildError::InvalidArgument(format!(
                "unsupported non-regular file in assets: {}",
                path.display()
            )));
        }
    }

    Ok(())
}

fn collect_optional_assets(
    project_dir: &Path,
    explicit_assets_dir: Option<&Path>,
    entries: &mut BTreeMap<String, Vec<u8>>,
    seen_lower: &mut BTreeSet<String>,
    total_bytes: &mut u64,
) -> Result<(), BuildError> {
    let assets_root = match explicit_assets_dir {
        Some(dir) => {
            let meta = fs::symlink_metadata(dir).map_err(|e| {
                BuildError::InvalidArgument(format!(
                    "assets directory {} is not accessible: {e}",
                    dir.display()
                ))
            })?;
            if meta.file_type().is_symlink() {
                return Err(BuildError::InvalidArgument(format!(
                    "assets directory must not be a symlink: {}",
                    dir.display()
                )));
            }
            if !meta.is_dir() {
                return Err(BuildError::InvalidArgument(format!(
                    "assets path is not a directory: {}",
                    dir.display()
                )));
            }
            Some(dir.to_path_buf())
        }
        None => {
            let default_dir = project_dir.join("assets");
            match fs::symlink_metadata(&default_dir) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(BuildError::InvalidArgument(format!(
                            "project assets directory must not be a symlink: {}",
                            default_dir.display()
                        )));
                    }
                    if !meta.is_dir() {
                        return Err(BuildError::InvalidArgument(format!(
                            "project assets path is not a directory: {}",
                            default_dir.display()
                        )));
                    }
                    Some(default_dir)
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(BuildError::Io(err)),
            }
        }
    };

    if let Some(root) = assets_root {
        collect_assets_recursive(&root, "assets", 1, entries, seen_lower, total_bytes)?;
    }
    Ok(())
}

fn locate_prebuilt_library(
    project: &ResolvedProject,
    release: bool,
) -> Result<PathBuf, BuildError> {
    let (prefix, ext) = dylib_naming();
    let profile_dir = if release { "release" } else { "debug" };
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(manifest) = &project.manifest {
        if let Some(entry) = &manifest.entry {
            validate_posix_rel_path(entry)?;
            candidates.push(project.project_dir.join(entry));
        }
        if let Some(build_out) = manifest.build.as_ref().and_then(|b| b.output.as_deref()) {
            validate_posix_rel_path(build_out)?;
            candidates.push(project.project_dir.join(build_out));
        }
        let host_triple = host_target_triple();
        if let Some(target_cfg) = manifest.targets.get(host_triple) {
            validate_posix_rel_path(&target_cfg.entry)?;
            candidates.push(project.project_dir.join(&target_cfg.entry));
        }
    }

    let expected_name = format!("{prefix}{}.{ext}", project.lib_stem);
    match project.language {
        ModLanguage::Rust => {
            let target_root = env::var("CARGO_TARGET_DIR")
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| project.project_dir.join("target"));
            candidates.push(target_root.join(profile_dir).join(&expected_name));
            let mod_id_stem = project.mod_id.replace('-', "_");
            let alt_name = format!("{prefix}{mod_id_stem}.{ext}");
            if alt_name != expected_name {
                candidates.push(target_root.join(profile_dir).join(&alt_name));
            }
        }
        ModLanguage::C99 | ModLanguage::Cpp17 => {
            candidates.push(
                project
                    .project_dir
                    .join("target")
                    .join(profile_dir)
                    .join(&expected_name),
            );
        }
        ModLanguage::Zig => {
            candidates.push(
                project
                    .project_dir
                    .join("zig-out")
                    .join("lib")
                    .join(&expected_name),
            );
            candidates.push(
                project
                    .project_dir
                    .join("zig-out")
                    .join("bin")
                    .join(&expected_name),
            );
        }
    }

    // Fallback for pre-staged mod directories (`<dir>/mod.toml` + `<dir>/<lib>`).
    candidates.push(project.project_dir.join(&expected_name));
    let plain_name = format!("{}.{ext}", project.lib_stem);
    if plain_name != expected_name {
        candidates.push(project.project_dir.join(&plain_name));
    }

    for candidate in &candidates {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }

    let searched: Vec<String> = candidates.iter().map(|p| p.display().to_string()).collect();
    Err(BuildError::Command(format!(
        "could not locate prebuilt shared library with `--skip-build` (searched: {}; run without `--skip-build` to compile first)",
        searched.join(", ")
    )))
}

/// Encodes an unsigned development `.bampack` archive (`sig_len == 0` trailer) from an ordered
/// entry map via [`BamPackBuilder::build_unsigned`].
pub fn encode_unsigned_bampack(entries: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, BuildError> {
    let mut builder = BamPackBuilder::new();
    for (path, data) in entries {
        validate_posix_rel_path(path)?;
        builder = builder
            .add_entry(path.clone(), data.clone())
            .map_err(|e| BuildError::InvalidArgument(e.to_string()))?;
    }
    builder
        .build_unsigned()
        .map_err(|e| BuildError::InvalidArgument(e.to_string()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn validate_reserved_archive_path(entry: &str, label: &str) -> Result<(), BuildError> {
    validate_posix_rel_path(entry)?;
    let lower = entry.to_lowercase();
    if lower == "mod.toml" || lower == "assets" || lower.starts_with("assets/") {
        return Err(BuildError::InvalidManifest(format!(
            "`{label}` ('{entry}') collides with reserved archive paths"
        )));
    }
    Ok(())
}

fn insert_archive_entry(
    entries: &mut BTreeMap<String, Vec<u8>>,
    seen_lower: &mut BTreeSet<String>,
    total_bytes: &mut u64,
    archive_path: String,
    bytes: Vec<u8>,
) -> Result<(), BuildError> {
    if entries.len() >= MAX_BAMPACK_ENTRIES {
        return Err(BuildError::InvalidArgument(format!(
            "archive exceeds MAX_BAMPACK_ENTRIES ({MAX_BAMPACK_ENTRIES})"
        )));
    }
    let next_total = total_bytes.checked_add(bytes.len() as u64).ok_or_else(|| {
        BuildError::InvalidArgument("archive total size overflows u64".to_owned())
    })?;
    if next_total > DEFAULT_MAX_MOD_BINARY_BYTES {
        return Err(BuildError::InvalidArgument(format!(
            "archive total size ({next_total} bytes) exceeds limit ({DEFAULT_MAX_MOD_BINARY_BYTES} bytes)"
        )));
    }
    if !seen_lower.insert(archive_path.to_lowercase()) {
        return Err(BuildError::InvalidManifest(format!(
            "duplicate or case-colliding archive entry path '{archive_path}'"
        )));
    }
    *total_bytes = next_total;
    entries.insert(archive_path, bytes);
    Ok(())
}

/// Builds (unless `options.skip_build` is set) and packages a guest mod into a deterministic
/// `.bampack` archive, optionally bundling multi-target `[targets.<triple>]` entries and
/// optionally signing with an Ed25519 key (and optional OpenSSH certificate).
pub fn pack_mod(options: &PackOptions) -> Result<PackOutput, BuildError> {
    if options.namespace.is_empty() {
        return Err(BuildError::InvalidArgument(
            "`--namespace` must not be empty".to_owned(),
        ));
    }
    if options.dev_unsigned && options.key.is_some() {
        return Err(BuildError::InvalidArgument(
            "`--dev` / unsigned bundle mode cannot be combined with `--key`".to_owned(),
        ));
    }
    if options.cert.is_some() && options.key.is_none() {
        return Err(BuildError::InvalidArgument(
            "`--cert` requires `--key <ed25519_key>`".to_owned(),
        ));
    }

    let project = resolve_project_info(options.manifest_path.as_deref(), options.dir.as_deref())?;
    let Some(mod_toml_path) = project.mod_toml_path.as_ref() else {
        return Err(BuildError::InvalidManifest(format!(
            "`mod.toml` is required to pack a `.bampack` archive (not found in {})",
            project.project_dir.display()
        )));
    };
    let manifest = project.manifest.as_ref().ok_or_else(|| {
        BuildError::InvalidManifest(format!("failed to parse {}", mod_toml_path.display()))
    })?;
    validate_mod_id(&manifest.id).map_err(|reason| {
        BuildError::InvalidManifest(format!("invalid [mod].id '{}': {reason}", manifest.id))
    })?;

    let manifest_meta = fs::symlink_metadata(mod_toml_path)?;
    if manifest_meta.file_type().is_symlink() {
        return Err(BuildError::InvalidArgument(format!(
            "`mod.toml` must not be a symlink: {}",
            mod_toml_path.display()
        )));
    }
    let manifest_bytes = read_file_bounded(mod_toml_path, MAX_MANIFEST_BYTES, "mod.toml")?;

    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut seen_lower: BTreeSet<String> = BTreeSet::new();
    let mut total_bytes: u64 = manifest_bytes.len() as u64;
    if total_bytes > DEFAULT_MAX_MOD_BINARY_BYTES {
        return Err(BuildError::InvalidArgument(format!(
            "archive total size ({total_bytes} bytes) exceeds limit ({DEFAULT_MAX_MOD_BINARY_BYTES} bytes)"
        )));
    }
    seen_lower.insert("mod.toml".to_owned());
    entries.insert("mod.toml".to_owned(), manifest_bytes);

    let mut target_entries: BTreeMap<String, String> = BTreeMap::new();

    // 1. Explicit `--target-artifact <triple>=<path>` overrides.
    for (triple, src_path) in &options.target_artifacts {
        validate_target_triple(triple).map_err(BuildError::InvalidArgument)?;
        let meta = fs::symlink_metadata(src_path)?;
        if meta.file_type().is_symlink() {
            return Err(BuildError::InvalidArgument(format!(
                "target artifact for '{triple}' must not be a symlink: {}",
                src_path.display()
            )));
        }
        let bytes = read_file_bounded(
            src_path,
            DEFAULT_MAX_MOD_BINARY_BYTES.saturating_sub(total_bytes),
            &format!("target artifact ({triple})"),
        )?;
        if bytes.is_empty() {
            return Err(BuildError::InvalidArgument(format!(
                "target artifact for '{triple}' ({}) is empty",
                src_path.display()
            )));
        }
        let archive_path = if let Some(target_cfg) = manifest.targets.get(triple) {
            if let Some(ref expected_sha) = target_cfg.sha256 {
                let actual = sha256_hex(&bytes);
                if &actual != expected_sha {
                    return Err(BuildError::InvalidManifest(format!(
                        "[targets.{triple}].sha256 mismatch: expected {expected_sha}, got {actual}"
                    )));
                }
            }
            target_cfg.entry.clone()
        } else {
            let file_name = src_path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| {
                    BuildError::InvalidArgument(format!(
                        "target artifact path has invalid UTF-8 filename: {}",
                        src_path.display()
                    ))
                })?;
            validate_path_segment(file_name)?;
            format!("bin/{triple}/{file_name}")
        };
        validate_reserved_archive_path(&archive_path, &format!("targets.{triple}.entry"))?;
        insert_archive_entry(
            &mut entries,
            &mut seen_lower,
            &mut total_bytes,
            archive_path.clone(),
            bytes,
        )?;
        target_entries.insert(triple.clone(), archive_path);
    }

    // 2. Configured `[targets.<triple>]` binaries present on disk under `project_dir`.
    if options.include_targets {
        for (triple, target_cfg) in &manifest.targets {
            if target_entries.contains_key(triple) {
                continue;
            }
            validate_reserved_archive_path(&target_cfg.entry, &format!("targets.{triple}.entry"))?;
            let disk_path = project.project_dir.join(&target_cfg.entry);
            match fs::symlink_metadata(&disk_path) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(BuildError::InvalidArgument(format!(
                            "target artifact for '{triple}' must not be a symlink: {}",
                            disk_path.display()
                        )));
                    }
                    if meta.is_file() {
                        let bytes = read_file_bounded(
                            &disk_path,
                            DEFAULT_MAX_MOD_BINARY_BYTES.saturating_sub(total_bytes),
                            &format!("target artifact ({triple})"),
                        )?;
                        if bytes.is_empty() {
                            return Err(BuildError::InvalidArgument(format!(
                                "target artifact for '{triple}' ({}) is empty",
                                disk_path.display()
                            )));
                        }
                        if let Some(ref expected_sha) = target_cfg.sha256 {
                            let actual = sha256_hex(&bytes);
                            if &actual != expected_sha {
                                return Err(BuildError::InvalidManifest(format!(
                                    "[targets.{triple}].sha256 mismatch: expected {expected_sha}, got {actual}"
                                )));
                            }
                        }
                        insert_archive_entry(
                            &mut entries,
                            &mut seen_lower,
                            &mut total_bytes,
                            target_cfg.entry.clone(),
                            bytes,
                        )?;
                        target_entries.insert(triple.clone(), target_cfg.entry.clone());
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(BuildError::Io(err)),
            }
        }
    }

    // 3. Primary / host shared library (unless `--skip-build` and multi-target entries already satisfy it).
    let library_entry =
        if options.skip_build && !target_entries.is_empty() && manifest.entry.is_none() {
            let host_triple = host_target_triple();
            if let Some(host_entry) = target_entries.get(host_triple) {
                host_entry.clone()
            } else if let Ok(prebuilt) = locate_prebuilt_library(&project, options.release) {
                let file_name = prebuilt
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| {
                        BuildError::InvalidArgument(format!(
                            "shared library path has invalid UTF-8 filename: {}",
                            prebuilt.display()
                        ))
                    })?;
                validate_path_segment(file_name)?;
                if !seen_lower.contains(&file_name.to_lowercase()) {
                    let lib_bytes = read_file_bounded(
                        &prebuilt,
                        DEFAULT_MAX_MOD_BINARY_BYTES.saturating_sub(total_bytes),
                        "shared library",
                    )?;
                    if lib_bytes.is_empty() {
                        return Err(BuildError::InvalidArgument(format!(
                            "shared library {} is empty",
                            prebuilt.display()
                        )));
                    }
                    insert_archive_entry(
                        &mut entries,
                        &mut seen_lower,
                        &mut total_bytes,
                        file_name.to_owned(),
                        lib_bytes,
                    )?;
                }
                file_name.to_owned()
            } else {
                target_entries
                    .values()
                    .next()
                    .cloned()
                    .ok_or_else(|| BuildError::Command("no target entries found".to_owned()))?
            }
        } else {
            let library_path = if options.skip_build {
                locate_prebuilt_library(&project, options.release)?
            } else {
                let built = builder::build_mod(
                    options.manifest_path.as_deref(),
                    options.dir.as_deref(),
                    options.release,
                    None,
                )?;
                built.library_path
            };

            let lib_meta = fs::symlink_metadata(&library_path)?;
            if lib_meta.file_type().is_symlink() {
                return Err(BuildError::InvalidArgument(format!(
                    "built shared library must not be a symlink: {}",
                    library_path.display()
                )));
            }

            let host_triple = host_target_triple();
            let entry_name = if let Some(entry) = &manifest.entry {
                validate_reserved_archive_path(entry, "[mod].entry")?;
                entry.clone()
            } else if let Some(target_cfg) = manifest.targets.get(host_triple) {
                validate_reserved_archive_path(&target_cfg.entry, "[targets.<host>].entry")?;
                target_cfg.entry.clone()
            } else {
                let file_name = library_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| {
                        BuildError::InvalidArgument(format!(
                            "shared library path has invalid UTF-8 filename: {}",
                            library_path.display()
                        ))
                    })?;
                validate_path_segment(file_name)?;
                file_name.to_owned()
            };

            if !seen_lower.contains(&entry_name.to_lowercase()) {
                let lib_bytes = read_file_bounded(
                    &library_path,
                    DEFAULT_MAX_MOD_BINARY_BYTES.saturating_sub(total_bytes),
                    "shared library",
                )?;
                if lib_bytes.is_empty() {
                    return Err(BuildError::InvalidArgument(format!(
                        "shared library {} is empty",
                        library_path.display()
                    )));
                }
                insert_archive_entry(
                    &mut entries,
                    &mut seen_lower,
                    &mut total_bytes,
                    entry_name.clone(),
                    lib_bytes,
                )?;
            }
            entry_name
        };

    collect_optional_assets(
        &project.project_dir,
        options.assets_dir.as_deref(),
        &mut entries,
        &mut seen_lower,
        &mut total_bytes,
    )?;

    let entry_paths: Vec<String> = entries.keys().cloned().collect();

    let mut builder = BamPackBuilder::new();
    for (path, data) in &entries {
        builder = builder
            .add_entry(path.clone(), data.clone())
            .map_err(|e| BuildError::Crypto(e.to_string()))?;
    }

    let (archive_bytes, signed, signer_fingerprint) = if let Some(key_path) = &options.key {
        let signing_key = crate::signing::load_ed25519_private_key(key_path)?;
        let bytes = if let Some(cert_path) = &options.cert {
            let cert_raw =
                read_file_bounded(cert_path, MAX_SIGNATURE_SIDECAR_BYTES, "certificate")?;
            let cert_text = String::from_utf8(cert_raw).map_err(|_| {
                BuildError::Crypto(format!(
                    "certificate {} is not valid UTF-8",
                    cert_path.display()
                ))
            })?;
            let trimmed_cert = cert_text.trim();
            let bytes = builder
                .build_signed_with_openssh_certificate(
                    &signing_key,
                    trimmed_cert,
                    &options.namespace,
                )
                .map_err(|e| BuildError::Crypto(e.to_string()))?;

            // Self-verify freshly produced certificate-signed archive via `bamabi_trust`.
            if let Ok(parsed_cert) = Certificate::from_openssh(trimmed_cert) {
                let ca_openssh = PublicKey::from(parsed_cert.signature_key().clone())
                    .to_openssh()
                    .map_err(|e| BuildError::Crypto(e.to_string()))?;
                let policy = ModTrustPolicy::from_ca_openssh(&ca_openssh)
                    .map_err(|e| BuildError::Crypto(e.to_string()))?
                    .with_namespace(&options.namespace)
                    .map_err(|e| BuildError::Crypto(e.to_string()))?
                    .with_validity_policy(CertificateValidityPolicy::IgnoreTimestamps);
                policy
                    .verify_bampack_bytes(&bytes)
                    .map_err(|e| BuildError::Crypto(format!("self-verification failed: {e}")))?;
            } else {
                parse_bampack_entries_unverified(&bytes, DEFAULT_MAX_MOD_BINARY_BYTES)
                    .map_err(|e| BuildError::Crypto(format!("self-verification failed: {e}")))?;
            }
            bytes
        } else {
            let bytes = builder
                .build_signed_with_key(&signing_key, &options.namespace)
                .map_err(|e| BuildError::Crypto(e.to_string()))?;
            let pub_openssh = signing_key
                .public_key()
                .to_openssh()
                .map_err(|e| BuildError::Crypto(e.to_string()))?;
            let policy = ModTrustPolicy::from_public_key_openssh(&pub_openssh)
                .map_err(|e| BuildError::Crypto(e.to_string()))?
                .with_namespace(&options.namespace)
                .map_err(|e| BuildError::Crypto(e.to_string()))?;
            policy
                .verify_bampack_bytes(&bytes)
                .map_err(|e| BuildError::Crypto(format!("self-verification failed: {e}")))?;
            bytes
        };

        let fp = signing_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        (bytes, true, Some(fp))
    } else {
        let bytes = builder
            .build_unsigned()
            .map_err(|e| BuildError::Crypto(e.to_string()))?;
        (bytes, false, None)
    };

    let output_path = match &options.out {
        Some(path) => path.clone(),
        None => {
            let profile_dir = if options.release { "release" } else { "debug" };
            let file_name = format!("{}-{}.bampack", manifest.id, manifest.version);
            validate_path_segment(&file_name)?;
            project
                .project_dir
                .join("target")
                .join(profile_dir)
                .join(file_name)
        }
    };
    atomic_write_bytes(&output_path, &archive_bytes)?;

    Ok(PackOutput {
        output_path,
        mod_id: manifest.id.clone(),
        version: manifest.version.to_string(),
        language: project.language,
        library_entry,
        target_entries,
        entry_paths,
        signed,
        namespace: options.namespace.clone(),
        signer_fingerprint,
        archive_sha256: sha256_hex(&archive_bytes),
    })
}

/// Returns `true` if `path` has a `.bampack` extension or starts with [`BAMPACK_MAGIC`].
#[must_use]
pub fn is_bampack_file(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("bampack"))
    {
        return true;
    }
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic).is_ok() && &magic == BAMPACK_MAGIC
}

/// Verifies a signed `.bampack` archive file against pinned Ed25519 `.pub` keys and/or CA `.pub`
/// keys using [`bamabi_trust::ModTrustPolicy`].
pub fn verify_bampack_file(
    archive_path: &Path,
    pubkey_paths: &[PathBuf],
    ca_key_paths: &[PathBuf],
    required_principal: Option<&str>,
    namespace: &str,
) -> Result<VerifiedBamPack, BuildError> {
    verify_bampack_file_with_krl(
        archive_path,
        pubkey_paths,
        ca_key_paths,
        &[],
        required_principal,
        namespace,
    )
}

/// Verifies a signed `.bampack` archive file against pinned Ed25519 `.pub` keys, CA `.pub` keys,
/// and optional binary `SSHKRL` revocation lists using [`bamabi_trust::ModTrustPolicy`].
pub fn verify_bampack_file_with_krl(
    archive_path: &Path,
    pubkey_paths: &[PathBuf],
    ca_key_paths: &[PathBuf],
    krl_paths: &[PathBuf],
    required_principal: Option<&str>,
    namespace: &str,
) -> Result<VerifiedBamPack, BuildError> {
    let policy = build_trust_policy(
        pubkey_paths,
        ca_key_paths,
        krl_paths,
        required_principal,
        namespace,
    )?;
    policy
        .verify_bampack_file(archive_path)
        .map_err(|e| BuildError::Crypto(e.to_string()))
}

/// Parses and integrity-checks a `.bampack` archive's framing and per-entry SHA-256 digests,
/// returning `(entries, has_signature_trailer)`.
///
/// This does **not** perform cryptographic signature verification; use [`verify_bampack_file`] or
/// [`ModTrustPolicy::verify_bampack_bytes`] for trust verification.
pub fn inspect_bampack_entries(
    archive_bytes: &[u8],
) -> Result<(Vec<BamPackEntry>, bool), BuildError> {
    parse_bampack_entries_unverified(archive_bytes, DEFAULT_MAX_MOD_BINARY_BYTES)
        .map_err(|e| BuildError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bamabi_trust::generate_ed25519_keypair;
    use tempfile::TempDir;

    #[test]
    fn unsigned_wire_prefix_matches_bampack_builder_exactly() {
        let mut entries = BTreeMap::new();
        entries.insert("assets/config.json".to_owned(), b"{\"ok\":true}".to_vec());
        entries.insert("libdemo.so".to_owned(), vec![1, 2, 3, 4, 5]);
        entries.insert(
            "mod.toml".to_owned(),
            b"[mod]\nid = \"demo\"\nversion = \"1.0.0\"\n".to_vec(),
        );

        let unsigned = encode_unsigned_bampack(&entries).unwrap();
        let (parsed_entries, has_sig) = inspect_bampack_entries(&unsigned).unwrap();
        assert!(!has_sig);
        assert_eq!(parsed_entries.len(), 3);
        assert_eq!(parsed_entries[0].path, "assets/config.json");
        assert_eq!(parsed_entries[1].path, "libdemo.so");
        assert_eq!(parsed_entries[2].path, "mod.toml");

        let key = generate_ed25519_keypair(Some("unit")).unwrap();
        let mut builder = BamPackBuilder::new();
        for (p, data) in &entries {
            builder = builder.add_entry(p.clone(), data.clone()).unwrap();
        }
        let signed = builder
            .build_signed_with_key(&key, DEFAULT_BAMPACK_NAMESPACE)
            .unwrap();

        let unsigned_body_len = unsigned.len() - 4;
        assert_eq!(&unsigned[..unsigned_body_len], &signed[..unsigned_body_len]);
        assert_eq!(&unsigned[unsigned_body_len..], &0u32.to_le_bytes());

        let (_, signed_has_sig) = inspect_bampack_entries(&signed).unwrap();
        assert!(signed_has_sig);
    }

    #[test]
    fn pack_mod_supports_multi_target_entries_and_unsigned_dev_bundles() {
        let tmp = TempDir::new().unwrap();
        let proj = tmp.path().join("multi_pack_mod");
        fs::create_dir_all(proj.join("bin/x86_64-unknown-linux-gnu")).unwrap();
        fs::create_dir_all(proj.join("bin/aarch64-apple-darwin")).unwrap();

        let linux_bytes = b"\x7fELF-linux-stub";
        let mac_bytes = b"\xcf\xfa\xed\xfe-mac-stub";
        fs::write(
            proj.join("bin/x86_64-unknown-linux-gnu/libmulti_pack_mod.so"),
            linux_bytes,
        )
        .unwrap();
        fs::write(
            proj.join("bin/aarch64-apple-darwin/libmulti_pack_mod.dylib"),
            mac_bytes,
        )
        .unwrap();

        let mod_toml = r#"
[mod]
id = "multi_pack_mod"
version = "0.4.0"
language = "c99"

[targets.x86_64-unknown-linux-gnu]
entry = "bin/x86_64-unknown-linux-gnu/libmulti_pack_mod.so"

[targets.aarch64-apple-darwin]
entry = "bin/aarch64-apple-darwin/libmulti_pack_mod.dylib"
"#;
        fs::write(proj.join("mod.toml"), mod_toml).unwrap();

        let out_path = tmp.path().join("multi_dev.bampack");
        let packed = pack_mod(&PackOptions {
            dir: Some(proj),
            out: Some(out_path.clone()),
            skip_build: true,
            dev_unsigned: true,
            ..PackOptions::default()
        })
        .unwrap();
        assert!(!packed.signed);
        assert_eq!(packed.target_entries.len(), 2);
        assert!(
            packed
                .entry_paths
                .contains(&"bin/x86_64-unknown-linux-gnu/libmulti_pack_mod.so".to_owned())
        );
        assert!(
            packed
                .entry_paths
                .contains(&"bin/aarch64-apple-darwin/libmulti_pack_mod.dylib".to_owned())
        );

        let raw = fs::read(&out_path).unwrap();
        let (entries, has_sig) = inspect_bampack_entries(&raw).unwrap();
        assert!(!has_sig);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn rejects_path_traversal_and_unsafe_segments() {
        assert!(validate_posix_rel_path("../escape").is_err());
        assert!(validate_posix_rel_path("assets/../secret").is_err());
        assert!(validate_posix_rel_path("/abs/path").is_err());
        assert!(validate_posix_rel_path("assets\\win").is_err());
        assert!(validate_posix_rel_path("C:evil").is_err());
        assert!(validate_posix_rel_path("assets/foo:ads:$DATA").is_err());
        assert!(validate_posix_rel_path("assets/CON.txt").is_err());
        assert!(validate_posix_rel_path("assets/ok/file.png").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn collect_assets_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let assets = tmp.path().join("assets");
        fs::create_dir_all(&assets).unwrap();
        let secret = tmp.path().join("secret.txt");
        fs::write(&secret, b"do-not-leak").unwrap();
        symlink(&secret, assets.join("link.txt")).unwrap();

        let mut entries = BTreeMap::new();
        let mut seen_lower = BTreeSet::new();
        let mut total_bytes = 0u64;
        let err = collect_optional_assets(
            tmp.path(),
            None,
            &mut entries,
            &mut seen_lower,
            &mut total_bytes,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink rejection error, got: {err}"
        );
    }

    #[test]
    fn rejects_case_insensitive_asset_duplicates() {
        let mut entries = BTreeMap::new();
        let mut seen_lower = BTreeSet::new();
        let mut total_bytes = 0u64;
        seen_lower.insert("assets/hero.png".to_owned());

        let tmp = TempDir::new().unwrap();
        let assets = tmp.path().join("assets");
        fs::create_dir_all(&assets).unwrap();
        fs::write(assets.join("HERO.PNG"), b"dup").unwrap();

        let err = collect_optional_assets(
            tmp.path(),
            None,
            &mut entries,
            &mut seen_lower,
            &mut total_bytes,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("case-colliding") || err.to_string().contains("duplicate"),
            "unexpected error: {err}"
        );
    }
}
