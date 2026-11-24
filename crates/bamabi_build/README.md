# `bamabi_build`

Safe (`#![forbid(unsafe_code)]`), zero-Bevy guest mod build, compiler discovery, signing, `.bampack` packaging, SDK export, and `notify`-backed watch library for `bamabi` (`v0.4.0`, Layer 1 in [`bamabi-tools`](../../README.md)).

## Modules

- **`builder`:** Rust (`cargo`), ISO C99, C++17, Zig, MSVC `cl.exe`/`clang-cl`/`vswhere` discovery, `[build] command` execution, and atomic staging.
- **`pack`:** Deterministic `.bampack` archive creation (including optional `[targets.<triple>]` multi-target entries and unsigned dev bundles), verification, and inspection.
- **`watch`:** `notify` event-driven + mtime-gated incremental rebuilder, signer, and atomic stager.
- **`signing`:** Ed25519 private-key loading, detached `.sig` signing, and strict `ModTrustPolicy` verification (enable the `keygen` feature for `generate_keypair`).
- **`dag`:** `mod.toml` validation and Kahn topological sort via `bamabi_manifest`.
- **`doctor`:** Host ABI `0.4.0` layout, toolchain, and embedded SDK header parity diagnostics.
- **`scaffold` / `sdk`:** Rust/C99/C++17/Zig guest mod templates and `bamabi.h` / `bamabi.hpp` / `bamabi.zig` header export.
