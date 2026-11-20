# `bamabi-tools`

Layer 1 (**zero-Bevy**, `#![forbid(unsafe_code)]`) cryptographic trust, manifest DAG resolution, and developer CLI toolchain for the federated **`bamabi`** (`ABI 0.3.0`, `v0.3.0`) native modding framework for Bevy ECS (`v0.20.1`).

Refactored from the original [`bevy_mod_abi`](https://github.com/yaga-simha/bevy_mod_abi) monorepo into a strictly acyclic 5-repository DAG plus [`bamabi-dev-overlay`](https://github.com/yaga-simha/bamabi-dev-overlay), `bamabi-tools` depends strictly on Layer 0 ([`bamabi-wire`](https://github.com/yaga-simha/bamabi-wire)) via `git = "https://github.com/yaga-simha/bamabi-wire.git"` (`branch = "main"`) and zero `bevy_*` crates, keeping signing, packaging, manifest validation, and the `cargo-bam` CLI fast to compile and standalone in headless CI pipelines.

## Workspace Crates

| Crate | Safety Policy | Layer 0 Deps | Responsibilities |
|---|---|---|---|
| [`bamabi_trust`](crates/bamabi_trust/README.md) | `#![forbid(unsafe_code)]` | None | Pure-Rust Ed25519 `SSHSIG` (`.sig` and embedded `.bam_sig` in ELF/Mach-O/PE), OpenSSH CA certificates, authority-scoped `SSHKRL` revocation lists, and hardened `.bampack` archives (`BamPackBuilder`, `VerifiedBamPack::extract_to_dir`) |
| [`bamabi_manifest`](crates/bamabi_manifest/README.md) | `#![forbid(unsafe_code)]` | `bamabi_sys` | `mod.toml` parser, hardened ID/entry path and symlink validation (`validate_mod_id`, `validate_manifest_entry_path`), ABI SemVer checks against `0.3.0`, and Kahn topological DAG sorter (`resolve_dependency_dag`) |
| [`cargo-bam`](crates/cargo-bam/README.md) | `#![forbid(unsafe_code)]` | `bamabi_sys`, `bamabi_sdk_gen` + `bamabi_trust`, `bamabi_manifest` | Standalone CLI (`cargo bam` / `cargo-bam`) for scaffolding, building, watching, packaging, signing, verifying, and diagnosing Rust/C99/C++17/Zig guest mods |

## `cargo-bam` Subcommands

| Subcommand | Purpose |
|---|---|
| `new` | Scaffold a Rust, C99, C++17, or Zig guest mod project (`--lang rust` defaults to `bamabi-wire` git dependency; override with `--guest-sdk-path` or `--guest-sdk-git`) |
| `export-sdk` (`header`) | Export `bamabi.h`, `bamabi.hpp`, and `bamabi.zig` SDK headers |
| `build` | Build a Rust/C99/C++17/Zig guest shared library, optionally staging and signing (`.sig`) |
| `pack` | Build and package a deterministic `.bampack` archive with optional Ed25519 signature and scoped `assets/` |
| `watch` | Poll guest sources, rebuild, optionally sign, and atomically stage for host hot reload |
| `check-mods` | Validate `mod.toml` manifests, ABI `0.3.0` compatibility, and print Kahn topological load order |
| `doctor` | Inspect host ABI, Rust/C/C++/Zig toolchains, embedded SDK parity, and optional mods directory health |
| `keygen` / `sign` / `verify` | Generate OpenSSH Ed25519 keys, detach-sign libraries, and verify `.so`/`.dylib`/`.dll` or `.bampack` bundles |

## Standalone Usage & Installation

`bamabi-tools` builds and runs completely standalone with zero sibling checkouts required.

### Install `cargo-bam`

```bash
# Directly from GitHub
cargo install --git https://github.com/yaga-simha/bamabi-tools.git cargo-bam

# Or from a local checkout
cargo install --path crates/cargo-bam
```

### Depend on `bamabi_trust` or `bamabi_manifest`

Downstream crates can depend directly on the Layer 1 Git repository:

```toml
[dependencies]
bamabi_trust = { git = "https://github.com/yaga-simha/bamabi-tools.git", branch = "main" }
bamabi_manifest = { git = "https://github.com/yaga-simha/bamabi-tools.git", branch = "main" }
```

Enable `features = ["keygen"]` on `bamabi_trust` if OpenSSH Ed25519 key generation or CA certificate issuance is needed (`ssh-key/getrandom`).

## Local & CI Verification

All checks run standalone inside `bamabi-tools` with zero sibling repositories required:

```bash
# Formatting, clippy (default + all-features), and rustdoc (default + all-features)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

# Verify strict #![forbid(unsafe_code)] and zero-Bevy isolation (must print nothing)
for f in crates/bamabi_trust/src/lib.rs crates/bamabi_manifest/src/lib.rs crates/cargo-bam/src/lib.rs crates/cargo-bam/src/main.rs; do
  grep -q '#!\[forbid(unsafe_code)\]' "$f"
done
cargo tree --workspace | sed 's/ (.*//' | grep -v bamabi | grep -i bevy

# Unit, no-default-features, integration, and doc tests
cargo test -p bamabi_trust --no-default-features
cargo test --workspace --all-features
cargo test --doc --all-features

# CLI smoke checks: toolchain probe (including C99/C++17) & polyglot SDK header export
cargo run -p cargo-bam -- doctor --require-c
cargo run -p cargo-bam -- header --out target/ci_sdk_check

# Spellcheck and dependency/license/source audit
typos
cargo deny --all-features check advisories licenses bans sources
```

> **Note (`BAM_GUEST_CRATE_DIR`):** `cargo-bam` integration tests automatically pass `--guest-sdk-path` if `BAM_GUEST_CRATE_DIR` is set or a sibling `../bamabi-wire/crates/bamabi_guest` directory exists, and otherwise exercise the default `https://github.com/yaga-simha/bamabi-wire.git` dependency end-to-end.

## Federated `bamabi` Repositories

| Layer | Repository | Role |
|---|---|---|
| **0** | [`bamabi-wire`](https://github.com/yaga-simha/bamabi-wire) | Zero-Bevy ABI wire contract (`spec.md`), derives, `include/bamabi.h`, and Rust guest SDK |
| **1** | **[`bamabi-tools`](https://github.com/yaga-simha/bamabi-tools)** *(this repo)* | Zero-Bevy Ed25519 trust, manifest DAG resolver, and `cargo-bam` CLI |
| **2** | [`bamabi-core`](https://github.com/yaga-simha/bamabi-core) | Headless `bevy_ecs` + `bevy_app` host runtime (`bamabi_host_sys`, `bamabi_host`, `bamabi_watcher`) and `docs/ARCHITECTURE.md` |
| **3** | [`bamabi`](https://github.com/yaga-simha/bamabi) | Bevy `0.20.1` companion bridges/render/reflect crates and sole canonical `bamabi` host facade |
| **4** | [`bamabi-showcase`](https://github.com/yaga-simha/bamabi-showcase) | Top-level integration repo: runnable examples (`01`–`10`), benchmarks (`docs/BENCHMARKS.md`), fuzzing, mdBook guide (`docs/book/`), and `xtask` |
| **Overlay** | [`bamabi-dev-overlay`](https://github.com/yaga-simha/bamabi-dev-overlay) | Multi-repo `abi-lock.toml` / standalone-git consistency verifier (`sync_check.py`) and local sibling `[patch]` overlay (`overlay.py`) |

## Multi-Repo Local Development (`bamabi-dev-overlay`)

When iterating on `bamabi-tools` alongside sibling checkouts (`bamabi-wire`, `bamabi-core`, `bamabi`, `bamabi-showcase`) under a common parent directory, use [`bamabi-dev-overlay`](https://github.com/yaga-simha/bamabi-dev-overlay) instead of editing tracked `Cargo.toml` dependencies:

```bash
# Verify ABI lockfiles, versions, licenses, and strict GitHub dependency hygiene across all repos
python3 ../bamabi-dev-overlay/sync_check.py --strict-git

# Temporarily patch upstream github.com/yaga-simha/*.git deps to local sibling paths
python3 ../bamabi-dev-overlay/overlay.py enable
python3 ../bamabi-dev-overlay/overlay.py status --strict

# Disable the local overlay before committing or testing standalone builds (Cargo.lock hygiene)
python3 ../bamabi-dev-overlay/overlay.py disable
```

> **Note (`Cargo.lock` hygiene):** Never commit `Cargo.lock` changes generated while `[patch]` is enabled; `Cargo.lock` must retain `git+https://github.com/yaga-simha/bamabi-wire.git?branch=main#...` sources for standalone CI.

## License

Dual-licensed under `MIT OR Apache-2.0` ([`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE)).
