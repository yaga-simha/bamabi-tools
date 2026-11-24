//! Deterministic `.bampack` archive creation and cryptographic verification (`cargo bam pack` /
//! `cargo bam verify`), delegated to [`bamabi_build::pack`].

use crate::CliError;
pub use bamabi_build::pack::{DEFAULT_BAMPACK_NAMESPACE, PackOptions, PackOutput, is_bampack_file};
use bamabi_trust::{BamPackEntry, VerifiedBamPack};
use std::path::{Path, PathBuf};

/// Builds (unless `options.skip_build` is set) and packages a guest mod into a deterministic
/// `.bampack` archive, optionally bundling multi-target `[targets.<triple>]` entries and
/// optionally signing with an Ed25519 key (and optional OpenSSH certificate).
pub fn pack_mod(options: &PackOptions) -> Result<PackOutput, CliError> {
    bamabi_build::pack::pack_mod(options).map_err(Into::into)
}

/// Verifies a signed `.bampack` archive file against pinned Ed25519 `.pub` keys and/or CA `.pub`
/// keys using [`bamabi_trust::ModTrustPolicy`].
pub fn verify_bampack_file(
    archive_path: &Path,
    pubkey_paths: &[PathBuf],
    ca_key_paths: &[PathBuf],
    required_principal: Option<&str>,
    namespace: &str,
) -> Result<VerifiedBamPack, CliError> {
    bamabi_build::pack::verify_bampack_file(
        archive_path,
        pubkey_paths,
        ca_key_paths,
        required_principal,
        namespace,
    )
    .map_err(Into::into)
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
) -> Result<VerifiedBamPack, CliError> {
    bamabi_build::pack::verify_bampack_file_with_krl(
        archive_path,
        pubkey_paths,
        ca_key_paths,
        krl_paths,
        required_principal,
        namespace,
    )
    .map_err(Into::into)
}

/// Parses and integrity-checks a `.bampack` archive's framing and per-entry SHA-256 digests,
/// returning `(entries, has_signature_trailer)`.
pub fn inspect_bampack_entries(
    archive_bytes: &[u8],
) -> Result<(Vec<BamPackEntry>, bool), CliError> {
    bamabi_build::pack::inspect_bampack_entries(archive_bytes).map_err(Into::into)
}
