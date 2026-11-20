# `bamabi_trust`

Pure-Rust, zero-Bevy (`#![forbid(unsafe_code)]`) cryptographic trust and archive verification engine for `bamabi` (`v0.3.0`, Layer 1 in [`bamabi-tools`](../../README.md)).

## Capabilities

- **Detached OpenSSH `SSHSIG` Signatures (`.sig`):** Verifies Ed25519 signatures over arbitrary shared library byte slices with strict Curve25519 key/scalar validation (`ed25519-dalek` `verify_strict`).
- **Ed25519 CA Certificates & Validity Windows:** Validates `ssh-ed25519-cert-v01@openssh.com` certificates against trusted Root CA keys, authorized principal bindings, serial numbers, and validity timestamps (`CertificateValidityPolicy`).
- **Authority-Scoped OpenSSH `PROTOCOL.krl` (`SSHKRL`) Revocation Lists:** Parses and builds (`KrlBuilder`) binary KRLs and detached `SSHSIG`-signed KRL bundles with monotonic anti-rollback version checks and explicit KRL signer authority scoping (`DEFAULT_KRL_SIGNER_PRINCIPAL = "krl-signer"`, `add_krl_signer_openssh` / `add_krl_signer_file`).
- **Embedded `.bam_sig` Binary Sections:** Extracts, embeds, and verifies `SSHSIG` payloads directly inside ELF (`__bam_sig` / `.bam_sig`), Mach-O (`__DATA,__bam_sig`), and PE (`.bam_sig`) binaries.
- **Verified `.bampack` Mod Bundles & Hardened Extraction:** Packages, verifies, and safely extracts deterministic signed mod distribution archives (`BamPackBuilder`, `VerifiedBamPack::extract_to_dir`, `extract_to_dir_with_limits` with entry-count, path-depth, and uncompressed-byte limits plus symlink/path-traversal rejection), produced by `cargo bam pack` and verified by `cargo bam verify` and `ModTrustPolicy`.

## Usage

```toml
[dependencies]
# Verification-only (minimal dependency tree; excludes ssh-key RSA/p256/getrandom)
bamabi_trust = { git = "https://github.com/yaga-simha/bamabi-tools.git", branch = "main" }

# Or enable OpenSSH Ed25519 keygen and certificate issuance helpers:
# bamabi_trust = { git = "https://github.com/yaga-simha/bamabi-tools.git", branch = "main", features = ["keygen"] }
```

> **Security Note:** `bamabi_trust` intentionally compiles `ssh-key` with `default-features = false, features = ["std", "ed25519"]` so optional `rsa` (`RUSTSEC-2023-0071`), `p256`, and `crypto-bigint` dependencies remain disabled.

## Verification

```bash
cargo test -p bamabi_trust --no-default-features
cargo test -p bamabi_trust --all-features
cargo clippy -p bamabi_trust --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p bamabi_trust --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc -p bamabi_trust --no-deps --all-features
```

See [`bamabi-wire/spec.md`](https://github.com/yaga-simha/bamabi-wire/blob/main/spec.md) and [`bamabi-core/docs/ARCHITECTURE.md`](https://github.com/yaga-simha/bamabi-core/blob/main/docs/ARCHITECTURE.md) for the load-time verification workflow and threat model.
