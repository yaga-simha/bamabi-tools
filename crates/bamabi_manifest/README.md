# `bamabi_manifest`

Zero-Bevy (`#![forbid(unsafe_code)]`) `mod.toml` manifest parser, path/symlink validator, SemVer checker, and Kahn topological dependency DAG resolver for `bamabi` (`v0.3.0`, Layer 1 in [`bamabi-tools`](../../README.md)).

## Responsibilities

- **`ModTomlManifest` Parser & Path/Symlink Hardening:** Parses `[mod]` metadata (`id`, `name`, `version`, `abi_version`, `language`, `entry`/`library`), `[dependencies]`, and `[optional_dependencies]` from `mod.toml` files without depending on Bevy, enforcing safe mod identifiers (`validate_mod_id`), relative entry paths (`validate_manifest_entry_path`), and rejecting path traversal, root escapes, and symlinked mod binaries/paths.
- **ABI SemVer Compatibility:** Checks optional `[mod].abi_version` requirements against host `bamabi_sys::ABI_VERSION` (`0.3.0`, from [`bamabi-wire`](https://github.com/yaga-simha/bamabi-wire)) using Cargo-compatible SemVer matching.
- **`resolve_dependency_dag` & `ManifestDagResolution`:** Validates required and optional SemVer dependency ranges across a directory of mods, rejects missing required dependencies and dependency cycles with structured `ManifestError` diagnostics, and computes deterministic topological load order via Kahn's algorithm (shared by `bamabi_host`, `bamabi_bridges` `TopologicalOverlay`, `bamabi_watcher`, and [`cargo-bam`](../cargo-bam/README.md)).

## Usage

```toml
[dependencies]
bamabi_manifest = { git = "https://github.com/yaga-simha/bamabi-tools.git", branch = "main" }
```

## Verification

```bash
cargo test -p bamabi_manifest --all-features
cargo clippy -p bamabi_manifest --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p bamabi_manifest --no-deps --all-features
```
