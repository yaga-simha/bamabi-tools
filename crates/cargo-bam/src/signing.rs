//! Pure-Rust Ed25519 keygen, OpenSSH `SSHSIG` `.sig` detached signing, and strict verification,
//! delegated to [`bamabi_build::signing`].

use crate::CliError;
pub use bamabi_build::signing::{DEFAULT_NAMESPACE, KeygenOutput, SignOutput, default_sig_path};
use bamabi_trust::Fingerprint;
use std::path::{Path, PathBuf};

/// Generates an Ed25519 OpenSSH keypair (`<out>` + `<out>.pub`).
pub fn generate_keypair(
    out_prefix: &Path,
    comment: Option<&str>,
) -> Result<KeygenOutput, CliError> {
    bamabi_build::signing::generate_keypair(out_prefix, comment).map_err(Into::into)
}

/// Signs `mod_path` into a detached OpenSSH `SSHSIG` `.sig` file (written atomically).
pub fn sign_mod_file(
    key_path: &Path,
    mod_path: &Path,
    out_sig: Option<&Path>,
    namespace: &str,
) -> Result<SignOutput, CliError> {
    bamabi_build::signing::sign_mod_file(key_path, mod_path, out_sig, namespace).map_err(Into::into)
}

/// Verifies `mod_path` against its detached `SSHSIG` `.sig` sidecar (or embedded `.bam_sig`),
/// supporting pinned public keys, CA certificates, optional binary `SSHKRL` revocation lists, and
/// required certificate principals.
pub fn verify_mod_file_with_trust(
    mod_path: &Path,
    sig_path: Option<&Path>,
    pubkey_paths: &[PathBuf],
    ca_key_paths: &[PathBuf],
    krl_paths: &[PathBuf],
    required_principal: Option<&str>,
    namespace: &str,
) -> Result<String, CliError> {
    bamabi_build::signing::verify_mod_file_with_trust(
        mod_path,
        sig_path,
        pubkey_paths,
        ca_key_paths,
        krl_paths,
        required_principal,
        namespace,
    )
    .map_err(Into::into)
}

/// Verifies `mod_path` against its detached `SSHSIG` `.sig` sidecar and pinned OpenSSH Ed25519
/// public keys (`pubkey_paths`), or falls back to embedded `.bam_sig` if `sig_path` is `None` and
/// no sidecar file exists.
pub fn verify_mod_file(
    mod_path: &Path,
    sig_path: Option<&Path>,
    pubkey_paths: &[PathBuf],
    namespace: &str,
) -> Result<Fingerprint, CliError> {
    bamabi_build::signing::verify_mod_file(mod_path, sig_path, pubkey_paths, namespace)
        .map_err(Into::into)
}
