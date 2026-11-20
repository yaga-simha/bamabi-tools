# Agent Guide: `bamabi_manifest`

Crate guide for **`bamabi_manifest`** (`v0.3.0`, ABI `0x0003_0000`) — zero-Bevy `mod.toml` parser, path/symlink validator, SemVer checker, and Kahn topological DAG resolver.

---

## 1. Crate Identity
- **Name:** `bamabi_manifest` (`version = "0.3.0"`, `edition = "2024"`, MSRV `1.95`)
- **Role:** Shared non-Bevy manifest & dependency graph layer used by `bamabi_host`, `bamabi_bridges` (`TopologicalOverlay`), `bamabi_watcher`, and `cargo-bam`.

---

## 2. Safety & Dependency Boundaries
- **Safety:** **`#![forbid(unsafe_code)]`** at crate root.
- **Zero Bevy Dependencies:** Allowed dependencies are `bamabi_sys`, `semver`, `serde`, and `toml` ONLY (`tempfile` in `[dev-dependencies]`). **NEVER** add any `bevy*` dependency.

---

## 3. Owned Surface & Security Guards
- **`ModTomlManifest` (`src/lib.rs`):** Parses `[mod]` (`id`, `name`, `version`, `abi_version`, `language`, `entry`/`library`), `[dependencies]`, and `[optional_dependencies]`, enforcing bounded file reads (`MAX_MANIFEST_BYTES = 1 MiB`) and Cargo-compatible SemVer checking against `bamabi_sys::ABI_VERSION_*` (`0.3.0`).
- **Path & Identifier Hardening:** `validate_mod_id` and `validate_manifest_entry_path` reject `..`/`.` traversal, absolute/backslash/UNC paths, Windows drive prefixes, NTFS ADS (`:`), NUL/control bytes, trailing dots/spaces, and Windows reserved names; `resolve_library_path` enforces per-segment `symlink_metadata` anti-symlink checks and canonical root confinement.
- **Topological DAG Sorter:** `ModDependencyGraph` resolves required and optional SemVer ranges via Kahn's algorithm, rejecting cycles and missing/incompatible dependencies with structured `ManifestError` variants.

---

## 4. Strict Engineering Rules
1. **Strict Path Confinement:** All manifest IDs, entry paths, and library resolutions MUST validate lexically via `validate_mod_id` / `validate_manifest_entry_path` AND reject symlink escapes outside the mod directory.
2. **Error Compatibility:** Preserve structured `ManifestError` variants consumed by `bamabi_host::mod_dag` and `cargo-bam::dag`.
3. **Zero Panics on Untrusted `mod.toml`:** Reject malformed UTF-8/TOML, oversized files (`> MAX_MANIFEST_BYTES`), and invalid paths via `Result<_, ManifestError>` without `.unwrap()` or `.expect()`.

---

## 5. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo tree | sed 's/ (.*//' | grep -v bamabi | grep -i bevy   # MUST print NOTHING
typos
```

---

## 6. Workspace Coordination
1. **Layer 0 Upstream Dependency:** `bamabi_manifest` is a Layer 1 member of `bamabi-tools` and depends on `bamabi_sys` from `https://github.com/yaga-simha/bamabi-wire.git` (`branch = "main"`), configured in `../../Cargo.toml`.
2. **Local Sibling Overrides:** When iterating locally alongside a sibling `../bamabi-wire` checkout, enable the `bamabi-dev-overlay` Cargo `[patch]` config via `python3 ../../../bamabi-dev-overlay/overlay.py enable` and disable it before committing `Cargo.lock`.
3. **Downstream Consumers:** Verify any `ManifestError` or `ModTomlManifest` changes against `cargo-bam` (`bamabi-tools`) and `bamabi_host` (`mod_dag.rs`), `bamabi_bridges` (`TopologicalOverlay`), and `bamabi_watcher`.
