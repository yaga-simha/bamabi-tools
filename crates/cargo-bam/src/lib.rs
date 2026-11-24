#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Library implementation for the `cargo-bam` modding CLI toolchain (`ABI 0.4.0`), delegating
//! core build, packaging, compiler discovery, signing, and `notify` watch logic to
//! [`bamabi_build`].
//!
//! Part of Layer 1 (`bamabi-tools`), `cargo-bam` depends strictly on Layer 0
//! (`bamabi-wire`: [`bamabi_sys`] and [`bamabi_sdk_gen`]) alongside [`bamabi_manifest`],
//! [`bamabi_trust`], and [`bamabi_build`], with zero Bevy dependencies and `#![forbid(unsafe_code)]`.
//!
//! ## Provided Modules
//!
//! - [`scaffold`]: `cargo bam new` project generator for Rust (`bamabi_guest` via
//!   `https://github.com/yaga-simha/bamabi-wire.git`, or `--guest-sdk-path` / `--guest-sdk-git`),
//!   ISO C99, C++17, and Zig guest mods.
//! - [`sdk`]: Polyglot `bamabi.h`, `bamabi.hpp`, and `bamabi.zig` SDK header exporter.
//! - [`builder`]: Compiler/toolchain discovery, `[build] command`, and shared-library staging (`cargo bam build`).
//! - [`pack`]: Deterministic `.bampack` archive builder and verifier (`cargo bam pack`).
//! - [`watch`]: `notify` event-driven + mtime-gated incremental rebuild/sign/stage loop (`cargo bam watch`).
//! - [`dag`]: Multi-mod `mod.toml` validation and Kahn topological sorting (`cargo bam check-mods`).
//! - [`doctor`]: Host ABI `0.4.0` and Rust/C99/C++17/Zig toolchain diagnostics (`cargo bam doctor`).
//! - [`signing`]: OpenSSH Ed25519 key generation, detached `.sig` signing, and verification.

pub mod builder;
pub mod dag;
pub mod doctor;
pub mod pack;
pub mod scaffold;
pub mod sdk;
pub mod signing;
pub mod watch;

use bamabi_build::BuildError;
use clap::{Parser, Subcommand, ValueEnum};
use scaffold::ModLanguage;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use thiserror::Error;

/// Typed error returned by `cargo-bam` CLI operations.
#[derive(Debug, Error)]
pub enum CliError {
    /// Invalid CLI argument or identifier.
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

impl From<BuildError> for CliError {
    fn from(err: BuildError) -> Self {
        match err {
            BuildError::InvalidArgument(msg) => Self::InvalidArgument(msg),
            BuildError::AlreadyExists(path) => Self::AlreadyExists(path),
            BuildError::InvalidManifest(msg) => Self::InvalidManifest(msg),
            BuildError::Command(msg) => Self::Command(msg),
            BuildError::Crypto(msg) => Self::Crypto(msg),
            BuildError::Io(io) => Self::Io(io),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum CliModLanguage {
    Rust,
    C99,
    Cpp17,
    Zig,
}

impl From<CliModLanguage> for ModLanguage {
    fn from(lang: CliModLanguage) -> Self {
        match lang {
            CliModLanguage::Rust => Self::Rust,
            CliModLanguage::C99 => Self::C99,
            CliModLanguage::Cpp17 => Self::Cpp17,
            CliModLanguage::Zig => Self::Zig,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "cargo-bam",
    bin_name = "cargo bam",
    version,
    about = "Build, scaffold, package, watch, export SDK headers, and sign bamabi guest mods"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scaffold a new buildable guest mod project (Rust, C99, C++17, or Zig).
    New {
        /// Mod crate/library name.
        name: String,
        /// Target guest implementation language.
        #[arg(long, value_enum, default_value_t = CliModLanguage::Rust)]
        lang: CliModLanguage,
        /// Parent directory in which `<name>` will be created.
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        /// Optional local path to `crates/bamabi_guest` for Rust mods (overrides the default `bamabi-wire` git dependency).
        #[arg(long)]
        guest_sdk_path: Option<PathBuf>,
        /// Optional Git repository URL for `bamabi_guest` in Rust mods (defaults to `https://github.com/yaga-simha/bamabi-wire.git`, branch `main`).
        #[arg(long, conflicts_with = "guest_sdk_path")]
        guest_sdk_git: Option<String>,
    },
    /// Export `bamabi.h`, `bamabi.hpp`, and `bamabi.zig` SDK headers.
    #[command(visible_alias = "header")]
    ExportSdk {
        /// Output directory for exported headers.
        #[arg(long)]
        out: PathBuf,
    },
    /// Build a guest mod shared library and optionally stage it alongside `mod.toml` (and `.sig`).
    Build {
        /// Explicit path to `mod.toml` or `Cargo.toml`.
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        /// Project directory containing `mod.toml` / `Cargo.toml`.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Build with release optimizations.
        #[arg(long)]
        release: bool,
        /// Optional staging root directory (`<out-dir>/<mod_id>/` with library, `mod.toml`, and optional `.sig`).
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Optional OpenSSH Ed25519 private key to detach-sign the built shared library.
        #[arg(long)]
        sign_key: Option<PathBuf>,
        /// `SSHSIG` namespace used when `--sign-key` is passed.
        #[arg(long, default_value = signing::DEFAULT_NAMESPACE)]
        sign_namespace: String,
        /// Optional target triple for cross-compiled Rust / multi-target builds.
        #[arg(long)]
        target: Option<String>,
    },
    /// Package a guest mod (`mod.toml`, shared library, optional `[targets.<triple>]`, and `assets/`) into a deterministic `.bampack` archive.
    Pack {
        /// Project directory containing `mod.toml` / `Cargo.toml`.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Explicit path to `mod.toml` or `Cargo.toml`.
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        /// Build (or locate) the release artifact.
        #[arg(long)]
        release: bool,
        /// Output `.bampack` file path (defaults to `<project>/target/<profile>/<mod_id>-<version>.bampack`).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Optional OpenSSH Ed25519 private key to sign the `.bampack` archive.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Optional OpenSSH Ed25519 certificate (`*-cert.pub`) paired with `--key`.
        #[arg(long)]
        cert: Option<PathBuf>,
        /// `SSHSIG` namespace used when signing the `.bampack` archive.
        #[arg(long, default_value = pack::DEFAULT_BAMPACK_NAMESPACE)]
        namespace: String,
        /// Optional assets directory to bundle under `assets/` (defaults to `<project>/assets` if present).
        #[arg(long)]
        assets_dir: Option<PathBuf>,
        /// Skip building and locate an already-built shared library instead.
        #[arg(long)]
        skip_build: bool,
        /// Explicit multi-target artifact entry (`<target_triple>=<path>`), repeatable.
        #[arg(long = "target-artifact")]
        target_artifacts: Vec<String>,
        /// Explicitly produce an unsigned development `.bampack` bundle.
        #[arg(long, conflicts_with = "key")]
        dev: bool,
    },
    /// Watch guest mod sources/manifests via `notify` + mtime gating, rebuild incrementally, sign, and atomically stage for hot-reload.
    Watch {
        /// Project directory containing `mod.toml` / `Cargo.toml`.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Explicit path to `mod.toml` or `Cargo.toml`.
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        /// Build with release optimizations.
        #[arg(long)]
        release: bool,
        /// Optional staging root directory (`<out-dir>/<mod_id>/`) watched by `ModHotReloadPlugin`.
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Optional OpenSSH Ed25519 private key to detach-sign every rebuilt shared library.
        #[arg(long)]
        key: Option<PathBuf>,
        /// `SSHSIG` namespace used when `--key` is passed.
        #[arg(long, default_value = signing::DEFAULT_NAMESPACE)]
        namespace: String,
        /// Fallback check / `notify` wait interval in milliseconds.
        #[arg(long, default_value_t = watch::DEFAULT_POLL_MS)]
        poll_ms: u64,
        /// Run a single build/sign/stage cycle and exit.
        #[arg(long, conflicts_with = "max_cycles")]
        once: bool,
        /// Stop after completing `<n>` build cycles (initial build is cycle `1`).
        #[arg(long)]
        max_cycles: Option<usize>,
    },
    /// Validate `mod.toml` manifests, SemVer dependencies, and topological load order in `<dir>`.
    CheckMods {
        /// Mods directory containing `mod.toml` or `<mod>/mod.toml` subdirectories.
        dir: PathBuf,
    },
    /// Diagnose host ABI `0.4.0` layout, Rust/MSVC/Clang/GCC/Zig toolchains, SDK header parity, and optional mods directory.
    Doctor {
        /// Optional mods directory to validate during the diagnostic pass.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Fail if a C99 or C++17 compiler is not available on PATH.
        #[arg(long)]
        require_c: bool,
    },
    /// Generate an OpenSSH Ed25519 keypair (`<out>` + `<out>.pub`).
    Keygen {
        /// Output private key path prefix.
        #[arg(long)]
        out: PathBuf,
        /// Optional OpenSSH key comment.
        #[arg(long)]
        comment: Option<String>,
    },
    /// Sign a built guest mod shared library with an OpenSSH `SSHSIG` `.sig` sidecar.
    Sign {
        /// Signer OpenSSH Ed25519 private key.
        #[arg(long)]
        key: PathBuf,
        /// Optional explicit `.sig` output path (defaults to `<mod_path>.sig`).
        #[arg(long)]
        out: Option<PathBuf>,
        /// `SSHSIG` namespace.
        #[arg(long, default_value = signing::DEFAULT_NAMESPACE)]
        namespace: String,
        /// Path to the guest mod shared library.
        mod_path: PathBuf,
    },
    /// Verify a guest mod shared library (`.sig`/`.bam_sig`) or signed `.bampack` archive against trusted `.pub` or CA keys.
    Verify {
        /// Trusted OpenSSH Ed25519 `.pub` key(s).
        #[arg(long = "pubkey")]
        pubkeys: Vec<PathBuf>,
        /// Trusted OpenSSH Ed25519 Certificate Authority `.pub` key(s).
        #[arg(long = "ca")]
        ca_keys: Vec<PathBuf>,
        /// Optional binary OpenSSH Key Revocation List (`.krl`) file(s).
        #[arg(long = "krl")]
        krls: Vec<PathBuf>,
        /// Optional required certificate principal when verifying CA-signed artifacts.
        #[arg(long)]
        principal: Option<String>,
        /// Optional explicit `.sig` path (loose libraries only; defaults to `<mod_path>.sig`).
        #[arg(long)]
        sig: Option<PathBuf>,
        /// Expected `SSHSIG` namespace (defaults to `bamabi.pack.v1` for `.bampack` or `bamabi.v1` for libraries).
        #[arg(long)]
        namespace: Option<String>,
        /// Path to the guest mod shared library or `.bampack` archive.
        mod_path: PathBuf,
    },
}

fn parse_target_artifact_arg(raw: &str) -> Result<(String, PathBuf), CliError> {
    let Some((triple, path)) = raw.split_once('=') else {
        return Err(CliError::InvalidArgument(format!(
            "--target-artifact must use `<triple>=<path>` format, got {raw:?}"
        )));
    };
    let triple = triple.trim();
    let path = path.trim();
    if triple.is_empty() || path.is_empty() {
        return Err(CliError::InvalidArgument(format!(
            "--target-artifact must have non-empty triple and path, got {raw:?}"
        )));
    }
    Ok((triple.to_owned(), PathBuf::from(path)))
}

fn normalize_cargo_subcommand_args<I, T>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut raw: Vec<OsString> = args.into_iter().map(Into::into).collect();
    if raw.len() >= 2 && raw[1] == "bam" {
        raw.remove(1);
    }
    raw
}

/// Runs the `cargo-bam` CLI and returns a typed [`CliError`] on failure.
pub fn run_cli<I, T>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let normalized = normalize_cargo_subcommand_args(args);
    let cli = Cli::try_parse_from(normalized).map_err(|e| {
        if e.use_stderr() {
            CliError::InvalidArgument(e.to_string())
        } else {
            e.print().ok();
            CliError::InvalidArgument(String::new())
        }
    });

    let cli = match cli {
        Ok(c) => c,
        Err(CliError::InvalidArgument(msg)) if msg.is_empty() => return Ok(()),
        Err(e) => return Err(e),
    };

    match cli.command {
        Commands::New {
            name,
            lang,
            dir,
            guest_sdk_path,
            guest_sdk_git,
        } => {
            let lang: ModLanguage = lang.into();
            let created = scaffold::scaffold_new_mod_with_git(
                &name,
                lang,
                &dir,
                guest_sdk_path.as_deref(),
                guest_sdk_git.as_deref(),
            )?;
            println!("Created {lang} guest mod at {}", created.display());
            Ok(())
        }
        Commands::ExportSdk { out } => {
            let files = sdk::export_sdk(&out)?;
            println!("Exported {} SDK file(s) to {}", files.len(), out.display());
            Ok(())
        }
        Commands::Build {
            manifest_path,
            dir,
            release,
            out_dir,
            sign_key,
            sign_namespace,
            target,
        } => {
            let out = builder::build_mod_with_options(&builder::BuildOptions {
                manifest_path: manifest_path.as_deref(),
                dir: dir.as_deref(),
                release,
                out_dir: out_dir.as_deref(),
                sign_key: sign_key.as_deref(),
                sign_namespace: &sign_namespace,
                target: target.as_deref(),
            })?;
            println!(
                "Built {} mod library at {}",
                out.language,
                out.library_path.display()
            );
            if let Some(sig) = out.signature_path {
                println!("  signature: {}", sig.display());
            }
            Ok(())
        }
        Commands::Pack {
            dir,
            manifest_path,
            release,
            out,
            key,
            cert,
            namespace,
            assets_dir,
            skip_build,
            target_artifacts,
            dev,
        } => {
            let mut parsed_targets = BTreeMap::new();
            for raw in target_artifacts {
                let (triple, path) = parse_target_artifact_arg(&raw)?;
                if parsed_targets.insert(triple.clone(), path).is_some() {
                    return Err(CliError::InvalidArgument(format!(
                        "duplicate --target-artifact entry for '{triple}'"
                    )));
                }
            }
            let opts = pack::PackOptions {
                manifest_path,
                dir,
                release,
                out,
                key,
                cert,
                namespace,
                assets_dir,
                skip_build,
                target_artifacts: parsed_targets,
                include_targets: true,
                dev_unsigned: dev,
            };
            let res = pack::pack_mod(&opts)?;
            println!(
                "Packed {} mod '{} {}' ({} entries) -> {}",
                res.language,
                res.mod_id,
                res.version,
                res.entry_paths.len(),
                res.output_path.display()
            );
            println!("  sha256:    {}", res.archive_sha256);
            if let Some(fp) = res.signer_fingerprint {
                println!(
                    "  signed:    yes (signer {fp}, namespace {})",
                    res.namespace
                );
            } else {
                println!(
                    "  signed:    no (unsigned dev bundle; pass `--key <ed25519_key>` to sign)"
                );
            }
            Ok(())
        }
        Commands::Watch {
            dir,
            manifest_path,
            release,
            out_dir,
            key,
            namespace,
            poll_ms,
            once,
            max_cycles,
        } => {
            let debounce_ms = poll_ms.min(watch::DEFAULT_DEBOUNCE_MS);
            let config = watch::WatchConfig {
                manifest_path,
                dir,
                release,
                out_dir,
                sign_key: key,
                namespace,
                poll_interval: Duration::from_millis(poll_ms),
                debounce: Duration::from_millis(debounce_ms),
                once,
                max_cycles,
            };
            let _cycles = watch::run_watch(config)?;
            Ok(())
        }
        Commands::CheckMods { dir } => {
            let order = dag::check_mods_dir(&dir)?;
            println!(
                "Validated {} mod manifest(s) in topological load order:",
                order.len()
            );
            for (idx, m) in order.iter().enumerate() {
                println!("  {}. {} {}", idx + 1, m.id, m.version);
            }
            Ok(())
        }
        Commands::Doctor { dir, require_c } => {
            let report = doctor::run_doctor(dir.as_deref(), require_c)?;
            println!(
                "cargo-bam doctor (host ABI {} / {}, target {}, {}-slot BamHostApi {} B)",
                report.host_abi_version,
                report.abi_version_hex,
                report.host_target_triple,
                report.host_api_slots,
                report.host_api_size
            );
            for check in &report.tools {
                let status = if check.available {
                    "ok"
                } else if check.required {
                    "MISSING"
                } else {
                    "absent (optional)"
                };
                println!("  [{status}] {}: {}", check.name, check.detail);
            }
            if let Some(mods) = &report.validated_mods {
                let names: Vec<String> = mods
                    .iter()
                    .map(|m| format!("{}@{}", m.id, m.version))
                    .collect();
                println!(
                    "  [ok] validated_mods: {} manifest(s) in DAG order ({})",
                    mods.len(),
                    names.join(" -> ")
                );
            }
            Ok(())
        }
        Commands::Keygen { out, comment } => {
            let res = signing::generate_keypair(&out, comment.as_deref())?;
            println!("Generated Ed25519 keypair: {}", res.private_key.display());
            println!("  public:      {}", res.public_key.display());
            println!("  fingerprint: {}", res.fingerprint);
            Ok(())
        }
        Commands::Sign {
            key,
            out,
            namespace,
            mod_path,
        } => {
            let res = signing::sign_mod_file(&key, &mod_path, out.as_deref(), &namespace)?;
            println!("Signed mod: {}", res.signature_path.display());
            println!("  signer_fp: {}", res.signer_fingerprint);
            println!("  sha256:    {}", res.binary_sha256);
            Ok(())
        }
        Commands::Verify {
            pubkeys,
            ca_keys,
            krls,
            principal,
            sig,
            namespace,
            mod_path,
        } => {
            if pack::is_bampack_file(&mod_path) {
                if sig.is_some() {
                    return Err(CliError::InvalidArgument(
                        "`--sig` is only valid for detached shared-library signatures, not `.bampack` archives"
                            .to_owned(),
                    ));
                }
                let ns = namespace
                    .as_deref()
                    .unwrap_or(pack::DEFAULT_BAMPACK_NAMESPACE);
                let verified = pack::verify_bampack_file_with_krl(
                    &mod_path,
                    &pubkeys,
                    &ca_keys,
                    &krls,
                    principal.as_deref(),
                    ns,
                )?;
                println!(
                    "Verified .bampack archive (signer {}, {} entries)",
                    verified.signature.signer_fingerprint,
                    verified.entries.len()
                );
                Ok(())
            } else {
                let ns = namespace.as_deref().unwrap_or(signing::DEFAULT_NAMESPACE);
                let fp = signing::verify_mod_file_with_trust(
                    &mod_path,
                    sig.as_deref(),
                    &pubkeys,
                    &ca_keys,
                    &krls,
                    principal.as_deref(),
                    ns,
                )?;
                println!("Verified mod signature (signer {fp})");
                Ok(())
            }
        }
    }
}

/// Executes the `cargo-bam` CLI with the provided raw command-line arguments.
pub fn run_from_args<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match run_cli(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("cargo-bam error: {err}");
            ExitCode::FAILURE
        }
    }
}
