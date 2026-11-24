//! `notify`-backed recursive source/manifest watcher with mtime/size gating, incremental
//! rebuilder, signer, and atomic stager for host `ModHotReloadPlugin` workflows.

use crate::builder;
use crate::scaffold::ModLanguage;
use crate::signing::{self, DEFAULT_NAMESPACE};
use crate::{
    BuildError, ResolvedProject, atomic_write_bytes, read_file_bounded, resolve_project_info,
    validated_stage_dir,
};
use bamabi_manifest::MAX_MANIFEST_BYTES;
use bamabi_trust::{DEFAULT_MAX_MOD_BINARY_BYTES, sign_mod_bytes_with_key};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant, UNIX_EPOCH};

/// Default fallback / event wait timeout in milliseconds (`250 ms`).
pub const DEFAULT_POLL_MS: u64 = 250;

/// Default quiet-window debounce duration in milliseconds (`100 ms`).
pub const DEFAULT_DEBOUNCE_MS: u64 = 100;

/// Maximum individual source file size (`16 MiB`) hashed during fingerprinting.
const MAX_HASHED_SOURCE_BYTES: u64 = 16 * 1024 * 1024;

/// Directories always excluded from recursive source watching and fingerprinting.
const IGNORED_DIRS: &[&str] = &[
    "target",
    "zig-out",
    ".zig-cache",
    "zig-cache",
    ".git",
    "node_modules",
];

/// Configuration for [`WatchRunner`] / [`run_watch`].
#[derive(Clone, Debug)]
pub struct WatchConfig {
    /// Optional explicit path to `mod.toml` or `Cargo.toml`.
    pub manifest_path: Option<PathBuf>,
    /// Optional project directory containing `mod.toml` / `Cargo.toml`.
    pub dir: Option<PathBuf>,
    /// Build with release optimizations.
    pub release: bool,
    /// Optional staging root directory (`<out-dir>/<mod_id>/`) watched by `ModHotReloadPlugin`.
    pub out_dir: Option<PathBuf>,
    /// Optional OpenSSH Ed25519 private key to detach-sign every rebuilt library.
    pub sign_key: Option<PathBuf>,
    /// `SSHSIG` namespace used when [`Self::sign_key`] is set.
    pub namespace: String,
    /// Fallback metadata check interval / `notify` wait timeout.
    pub poll_interval: Duration,
    /// Quiet-window debounce duration before rebuilding after a detected change.
    pub debounce: Duration,
    /// Run only the initial build/sign/stage cycle and return immediately.
    pub once: bool,
    /// Optional upper bound on total completed build cycles (initial build is cycle `1`).
    pub max_cycles: Option<usize>,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            manifest_path: None,
            dir: None,
            release: false,
            out_dir: None,
            sign_key: None,
            namespace: DEFAULT_NAMESPACE.to_owned(),
            poll_interval: Duration::from_millis(DEFAULT_POLL_MS),
            debounce: Duration::from_millis(DEFAULT_DEBOUNCE_MS),
            once: false,
            max_cycles: None,
        }
    }
}

/// Deterministic fingerprint of a single watched source or manifest file (`mtime`, byte length,
/// and SHA-256 content digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileFingerprint {
    /// File length in bytes.
    pub len: u64,
    /// Modification timestamp seconds since `UNIX_EPOCH` (`0` if unavailable).
    pub modified_secs: u64,
    /// Modification timestamp sub-second nanoseconds (`0` if unavailable).
    pub modified_nanos: u32,
    /// SHA-256 content digest (`[0; 32]` only if file exceeds `MAX_HASHED_SOURCE_BYTES`).
    pub sha256: [u8; 32],
}

/// Ordered snapshot of all watched source and manifest files in a guest mod project.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WatchSnapshot {
    /// Sorted map of relative file paths to their fingerprints.
    pub files: BTreeMap<PathBuf, FileFingerprint>,
}

impl WatchSnapshot {
    /// Returns the sorted list of relative paths that were added, modified, or removed between
    /// `self` and `newer`.
    #[must_use]
    pub fn diff_paths(&self, newer: &Self) -> Vec<PathBuf> {
        let mut changed = Vec::new();
        for (path, fp) in &newer.files {
            if self.files.get(path) != Some(fp) {
                changed.push(path.clone());
            }
        }
        for path in self.files.keys() {
            if !newer.files.contains_key(path) {
                changed.push(path.clone());
            }
        }
        changed.sort();
        changed
    }
}

/// Outcome of a single completed build / sign / atomic-stage cycle in [`WatchRunner`].
#[derive(Clone, Debug)]
pub struct WatchCycleResult {
    /// 1-based build cycle number (`1` for initial build, `2+` for change-triggered rebuilds).
    pub cycle: usize,
    /// Detected guest language.
    pub language: ModLanguage,
    /// Canonical mod ID used for staging (`<out-dir>/<mod_id>/`).
    pub mod_id: String,
    /// Path to the built (or atomically staged) shared library.
    pub library_path: PathBuf,
    /// Atomically staged `mod.toml` path when `out_dir` and `mod.toml` are present.
    pub staged_manifest_path: Option<PathBuf>,
    /// Atomically staged `.sig` sidecar path when `sign_key` is configured.
    pub signature_path: Option<PathBuf>,
    /// Relative paths that triggered this rebuild (empty on initial cycle `1`).
    pub changed_files: Vec<PathBuf>,
}

fn should_watch_file(language: ModLanguage, rel_path: &Path, extra_watch_paths: &[String]) -> bool {
    let Some(file_name) = rel_path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if file_name.starts_with('.') || file_name.ends_with('~') || file_name.ends_with(".swp") {
        return false;
    }
    if rel_path.components().count() == 1 && file_name == "mod.toml" {
        return true;
    }
    if extra_watch_paths.iter().any(|wp| {
        let wp_path = Path::new(wp);
        rel_path == wp_path || rel_path.starts_with(wp_path)
    }) {
        return true;
    }

    let ext = rel_path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    let in_src = rel_path
        .components()
        .next()
        .and_then(|c| c.as_os_str().to_str())
        .is_some_and(|first| first == "src");

    match language {
        ModLanguage::Rust => {
            if rel_path.components().count() == 1 && matches!(file_name, "Cargo.toml" | "build.rs")
            {
                return true;
            }
            in_src && matches!(ext.as_deref(), Some("rs"))
        }
        ModLanguage::C99 => matches!(ext.as_deref(), Some("c" | "h")),
        ModLanguage::Cpp17 => matches!(
            ext.as_deref(),
            Some("cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" | "h" | "c")
        ),
        ModLanguage::Zig => {
            if rel_path.components().count() == 1
                && matches!(file_name, "build.zig" | "build.zig.zon")
            {
                return true;
            }
            matches!(ext.as_deref(), Some("zig" | "h" | "c"))
        }
    }
}

fn file_stat_tuple(meta: &fs::Metadata) -> (u64, u64, u32) {
    let len = meta.len();
    let (modified_secs, modified_nanos) = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or((0, 0), |d| (d.as_secs(), d.subsec_nanos()));
    (len, modified_secs, modified_nanos)
}

fn fingerprint_file_gated(
    path: &Path,
    meta: &fs::Metadata,
    cached: Option<&FileFingerprint>,
    force_rehash: bool,
) -> Result<FileFingerprint, BuildError> {
    let (len, modified_secs, modified_nanos) = file_stat_tuple(meta);

    if !force_rehash
        && let Some(prev) = cached
        && prev.len == len
        && prev.modified_secs == modified_secs
        && prev.modified_nanos == modified_nanos
    {
        return Ok(prev.clone());
    }

    let sha256 = if len <= MAX_HASHED_SOURCE_BYTES {
        let bytes = fs::read(path)?;
        Sha256::digest(&bytes).into()
    } else {
        [0u8; 32]
    };

    Ok(FileFingerprint {
        len,
        modified_secs,
        modified_nanos,
        sha256,
    })
}

fn is_excluded_out_dir(candidate: &Path, excluded_out_dir: Option<&Path>) -> bool {
    let Some(excluded) = excluded_out_dir else {
        return false;
    };
    if candidate == excluded {
        return true;
    }
    if let (Ok(canon_cand), Ok(canon_excl)) =
        (fs::canonicalize(candidate), fs::canonicalize(excluded))
    {
        return canon_cand == canon_excl;
    }
    false
}

struct SnapshotScanCtx<'a> {
    root: &'a Path,
    language: ModLanguage,
    extra_watch_paths: &'a [String],
    excluded_out_dir: Option<&'a Path>,
    previous: Option<&'a WatchSnapshot>,
    dirty_paths: &'a BTreeSet<PathBuf>,
    dirty_all: bool,
}

fn collect_snapshot_recursive(
    ctx: &SnapshotScanCtx<'_>,
    current: &Path,
    out: &mut BTreeMap<PathBuf, FileFingerprint>,
) -> Result<(), BuildError> {
    let mut entries: Vec<PathBuf> = Vec::new();
    for entry_res in fs::read_dir(current)? {
        let entry = entry_res?;
        entries.push(entry.path());
    }
    entries.sort();

    for path in entries {
        if is_excluded_out_dir(&path, ctx.excluded_out_dir) {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let Ok(rel) = path.strip_prefix(ctx.root) else {
            continue;
        };
        if meta.is_dir() {
            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if IGNORED_DIRS.contains(&dir_name) {
                continue;
            }
            collect_snapshot_recursive(ctx, &path, out)?;
        } else if meta.is_file() && should_watch_file(ctx.language, rel, ctx.extra_watch_paths) {
            let cached = ctx.previous.and_then(|s| s.files.get(rel));
            let force_rehash = ctx.dirty_all || ctx.dirty_paths.contains(rel);
            let fp = fingerprint_file_gated(&path, &meta, cached, force_rehash)?;
            out.insert(rel.to_path_buf(), fp);
        }
    }
    Ok(())
}

/// Lightweight metadata-only scan (zero file reads or SHA-256 hashing) checking if any watched
/// file was added, removed, or changed `(len, mtime)` relative to `previous`.
fn has_metadata_changes_recursive(
    root: &Path,
    current: &Path,
    language: ModLanguage,
    extra_watch_paths: &[String],
    excluded_out_dir: Option<&Path>,
    previous: &WatchSnapshot,
    seen_count: &mut usize,
) -> bool {
    let Ok(rd) = fs::read_dir(current) else {
        return false;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if is_excluded_out_dir(&path, excluded_out_dir) {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let Ok(rel) = path.strip_prefix(root) else {
            continue;
        };
        if meta.is_dir() {
            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if IGNORED_DIRS.contains(&dir_name) {
                continue;
            }
            if has_metadata_changes_recursive(
                root,
                &path,
                language,
                extra_watch_paths,
                excluded_out_dir,
                previous,
                seen_count,
            ) {
                return true;
            }
        } else if meta.is_file() && should_watch_file(language, rel, extra_watch_paths) {
            *seen_count += 1;
            let Some(prev) = previous.files.get(rel) else {
                return true;
            };
            let (len, modified_secs, modified_nanos) = file_stat_tuple(&meta);
            if prev.len != len
                || prev.modified_secs != modified_secs
                || prev.modified_nanos != modified_nanos
            {
                return true;
            }
        }
    }
    false
}

/// Stateful `notify`-backed + mtime-gated watcher and incremental builder for guest mods.
///
/// Designed for both CLI invocation ([`WatchRunner::run`]) and deterministic programmatic tests
/// ([`WatchRunner::run_initial_build`] + [`WatchRunner::poll_and_rebuild_if_changed`]).
pub struct WatchRunner {
    config: WatchConfig,
    project: ResolvedProject,
    canon_project_dir: PathBuf,
    last_snapshot: Option<WatchSnapshot>,
    cycles_completed: usize,
    _watcher: Option<RecommendedWatcher>,
    event_rx: Option<Receiver<notify::Result<Event>>>,
}

impl std::fmt::Debug for WatchRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchRunner")
            .field("config", &self.config)
            .field("project", &self.project)
            .field("cycles_completed", &self.cycles_completed)
            .field("has_notify_watcher", &self._watcher.is_some())
            .finish()
    }
}

impl WatchRunner {
    /// Creates a new [`WatchRunner`] after validating configuration, signing key availability,
    /// guest mod project structure, and initializing a `notify` filesystem watcher.
    pub fn new(config: WatchConfig) -> Result<Self, BuildError> {
        if config.poll_interval.is_zero() {
            return Err(BuildError::InvalidArgument(
                "`--poll-ms` must be at least 1 ms".to_owned(),
            ));
        }
        if config.max_cycles == Some(0) {
            return Err(BuildError::InvalidArgument(
                "`--max-cycles` must be >= 1".to_owned(),
            ));
        }
        if config.sign_key.is_some() && config.namespace.is_empty() {
            return Err(BuildError::InvalidArgument(
                "`--namespace` must not be empty when `--key` is provided".to_owned(),
            ));
        }
        if let Some(key_path) = &config.sign_key {
            let _ = signing::load_ed25519_private_key(key_path)?;
        }

        let project = resolve_project_info(config.manifest_path.as_deref(), config.dir.as_deref())?;
        let canon_project_dir =
            fs::canonicalize(&project.project_dir).unwrap_or_else(|_| project.project_dir.clone());

        let (tx, rx) = mpsc::channel();
        let watcher = match notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        }) {
            Ok(mut w) => {
                if w.watch(&project.project_dir, RecursiveMode::Recursive)
                    .is_ok()
                {
                    Some(w)
                } else {
                    None
                }
            }
            Err(_) => None,
        };
        let event_rx = watcher.as_ref().map(|_| rx);

        Ok(Self {
            config,
            project,
            canon_project_dir,
            last_snapshot: None,
            cycles_completed: 0,
            _watcher: watcher,
            event_rx,
        })
    }

    /// Returns the resolved guest mod project directory.
    #[must_use]
    pub fn project_dir(&self) -> &Path {
        &self.project.project_dir
    }

    /// Returns the detected guest language.
    #[must_use]
    pub const fn language(&self) -> ModLanguage {
        self.project.language
    }

    /// Returns the canonical mod ID used when staging into `out_dir/<mod_id>/`.
    #[must_use]
    pub fn mod_id(&self) -> &str {
        &self.project.mod_id
    }

    /// Returns the number of completed build cycles so far.
    #[must_use]
    pub const fn cycles_completed(&self) -> usize {
        self.cycles_completed
    }

    /// Returns `true` if a `notify` OS filesystem watcher is active.
    #[must_use]
    pub const fn has_notify_watcher(&self) -> bool {
        self._watcher.is_some()
    }

    fn extra_watch_paths(&self) -> &[String] {
        self.project
            .manifest
            .as_ref()
            .and_then(|m| m.build.as_ref())
            .map(|b| b.watch_paths.as_slice())
            .unwrap_or(&[])
    }

    fn classify_event(&self, ev: &Event, dirty_paths: &mut BTreeSet<PathBuf>) -> bool {
        if ev.kind.is_access() {
            return false;
        }
        let mut relevant = false;
        for raw_path in &ev.paths {
            let rel = raw_path
                .strip_prefix(&self.canon_project_dir)
                .or_else(|_| raw_path.strip_prefix(&self.project.project_dir));
            let Ok(rel) = rel else {
                continue;
            };
            if is_excluded_out_dir(raw_path, self.config.out_dir.as_deref()) {
                continue;
            }
            if rel.components().any(|c| {
                c.as_os_str()
                    .to_str()
                    .is_some_and(|s| IGNORED_DIRS.contains(&s))
            }) {
                continue;
            }
            if should_watch_file(self.project.language, rel, self.extra_watch_paths()) {
                dirty_paths.insert(rel.to_path_buf());
                relevant = true;
            } else if raw_path.is_dir() || !raw_path.exists() {
                relevant = true;
            }
        }
        relevant
    }

    fn drain_notify_events(&self) -> (bool, BTreeSet<PathBuf>) {
        let mut dirty_paths = BTreeSet::new();
        let mut any_relevant = false;
        if let Some(ref rx) = self.event_rx {
            while let Ok(res) = rx.try_recv() {
                if let Ok(ev) = res
                    && self.classify_event(&ev, &mut dirty_paths)
                {
                    any_relevant = true;
                }
            }
        }
        (any_relevant, dirty_paths)
    }

    /// Captures a deterministic [`WatchSnapshot`] of all watched source and manifest files,
    /// reusing cached SHA-256 digests when `(len, mtime)` is unchanged and `notify` has not
    /// flagged the file dirty.
    pub fn snapshot(&self) -> Result<WatchSnapshot, BuildError> {
        let (_, dirty_paths) = self.drain_notify_events();
        self.snapshot_with_dirty(&dirty_paths, false)
    }

    fn snapshot_with_dirty(
        &self,
        dirty_paths: &BTreeSet<PathBuf>,
        dirty_all: bool,
    ) -> Result<WatchSnapshot, BuildError> {
        let mut files = BTreeMap::new();
        let ctx = SnapshotScanCtx {
            root: &self.project.project_dir,
            language: self.project.language,
            extra_watch_paths: self.extra_watch_paths(),
            excluded_out_dir: self.config.out_dir.as_deref(),
            previous: self.last_snapshot.as_ref(),
            dirty_paths,
            dirty_all,
        };
        collect_snapshot_recursive(&ctx, &self.project.project_dir, &mut files)?;
        Ok(WatchSnapshot { files })
    }

    fn has_metadata_changes(&self) -> bool {
        let Some(ref prev) = self.last_snapshot else {
            return true;
        };
        let mut seen_count = 0usize;
        let changed = has_metadata_changes_recursive(
            &self.project.project_dir,
            &self.project.project_dir,
            self.project.language,
            self.extra_watch_paths(),
            self.config.out_dir.as_deref(),
            prev,
            &mut seen_count,
        );
        changed || seen_count != prev.files.len()
    }

    fn execute_build_and_stage(
        &mut self,
        changed_files: Vec<PathBuf>,
    ) -> Result<WatchCycleResult, BuildError> {
        // Re-resolve manifest metadata on every cycle so edits to `mod.toml` are validated and picked up.
        self.project = resolve_project_info(
            self.config.manifest_path.as_deref(),
            self.config.dir.as_deref(),
        )?;

        let built = builder::build_mod(
            self.config.manifest_path.as_deref(),
            self.config.dir.as_deref(),
            self.config.release,
            None,
        )?;

        let lib_bytes = read_file_bounded(
            &built.library_path,
            DEFAULT_MAX_MOD_BINARY_BYTES,
            "built shared library",
        )?;
        if lib_bytes.is_empty() {
            return Err(BuildError::Command(format!(
                "built shared library {} is empty",
                built.library_path.display()
            )));
        }

        let sig_pem = if let Some(key_path) = &self.config.sign_key {
            let signing_key = signing::load_ed25519_private_key(key_path)?;
            Some(
                sign_mod_bytes_with_key(&signing_key, &self.config.namespace, &lib_bytes)
                    .map_err(|e| BuildError::Crypto(e.to_string()))?,
            )
        } else {
            None
        };

        let (final_lib_path, staged_manifest_path, signature_path) =
            if let Some(stage_root) = &self.config.out_dir {
                let stage_dir = validated_stage_dir(stage_root, &self.project.mod_id)?;

                // 1. Stage `mod.toml` atomically (only rewrite if missing or changed to avoid
                //    redundant `ModHotReloadPlugin` triggers when only code changed).
                let staged_manifest = if let Some(manifest_src) = &self.project.mod_toml_path {
                    let manifest_bytes =
                        read_file_bounded(manifest_src, MAX_MANIFEST_BYTES, "mod.toml")?;
                    let dest_manifest = stage_dir.join("mod.toml");
                    let needs_write =
                        read_file_bounded(&dest_manifest, MAX_MANIFEST_BYTES, "staged mod.toml")
                            .map(|existing| existing != manifest_bytes)
                            .unwrap_or(true);
                    if needs_write {
                        atomic_write_bytes(&dest_manifest, &manifest_bytes)?;
                    }
                    Some(dest_manifest)
                } else {
                    None
                };

                let file_name = built.library_path.file_name().ok_or_else(|| {
                    BuildError::Command("built artifact has no filename".to_owned())
                })?;
                let staged_lib = stage_dir.join(file_name);

                // 2. Stage `.sig` atomically BEFORE the shared library so `ModHotReloadPlugin`
                //    sees the matching signature immediately when the new binary appears.
                let staged_sig = if let Some(pem) = sig_pem {
                    let sig_dest = signing::default_sig_path(&staged_lib);
                    atomic_write_bytes(&sig_dest, pem.as_bytes())?;
                    Some(sig_dest)
                } else {
                    None
                };

                // 3. Stage the shared library atomically LAST (temp file + rename).
                atomic_write_bytes(&staged_lib, &lib_bytes)?;

                (staged_lib, staged_manifest, staged_sig)
            } else {
                let sig_path = if let Some(pem) = sig_pem {
                    let sig_dest = signing::default_sig_path(&built.library_path);
                    atomic_write_bytes(&sig_dest, pem.as_bytes())?;
                    Some(sig_dest)
                } else {
                    None
                };
                (built.library_path, None, sig_path)
            };

        self.cycles_completed += 1;
        Ok(WatchCycleResult {
            cycle: self.cycles_completed,
            language: built.language,
            mod_id: self.project.mod_id.clone(),
            library_path: final_lib_path,
            staged_manifest_path,
            signature_path,
            changed_files,
        })
    }

    /// Runs the initial build, sign, and atomic stage cycle (`cycle == 1`), snapshotting sources
    /// prior to compilation so edits made mid-build are detected on the next check.
    pub fn run_initial_build(&mut self) -> Result<WatchCycleResult, BuildError> {
        let (_, _) = self.drain_notify_events();
        let baseline = self.snapshot_with_dirty(&BTreeSet::new(), true)?;
        let result = self.execute_build_and_stage(Vec::new())?;
        self.last_snapshot = Some(baseline);
        Ok(result)
    }

    /// Checks `notify` events + file `(len, mtime)` metadata and triggers a rebuild/sign/atomic-stage
    /// cycle if any watched source or manifest file changed since the last build.
    pub fn poll_and_rebuild_if_changed(&mut self) -> Result<Option<WatchCycleResult>, BuildError> {
        let Some(previous) = self.last_snapshot.clone() else {
            return self.run_initial_build().map(Some);
        };
        let (any_relevant, dirty_paths) = self.drain_notify_events();
        if !any_relevant && !self.has_metadata_changes() {
            return Ok(None);
        }
        let current = self.snapshot_with_dirty(&dirty_paths, false)?;
        let changed = previous.diff_paths(&current);
        if changed.is_empty() {
            return Ok(None);
        }
        let result = self.execute_build_and_stage(changed)?;
        self.last_snapshot = Some(current);
        Ok(Some(result))
    }

    fn wait_for_debounced_change(&self) -> BTreeSet<PathBuf> {
        let mut dirty_paths = BTreeSet::new();
        loop {
            let triggered = if let Some(ref rx) = self.event_rx {
                match rx.recv_timeout(self.config.poll_interval) {
                    Ok(Ok(ev)) => self.classify_event(&ev, &mut dirty_paths),
                    Ok(Err(_)) | Err(RecvTimeoutError::Timeout) => self.has_metadata_changes(),
                    Err(RecvTimeoutError::Disconnected) => {
                        std::thread::sleep(self.config.poll_interval);
                        self.has_metadata_changes()
                    }
                }
            } else {
                std::thread::sleep(self.config.poll_interval);
                self.has_metadata_changes()
            };

            if !triggered {
                continue;
            }

            if !self.config.debounce.is_zero()
                && let Some(ref rx) = self.event_rx
            {
                let mut last_event = Instant::now();
                loop {
                    let elapsed = last_event.elapsed();
                    if elapsed >= self.config.debounce {
                        break;
                    }
                    let remaining = self.config.debounce - elapsed;
                    match rx.recv_timeout(remaining) {
                        Ok(Ok(ev)) => {
                            if self.classify_event(&ev, &mut dirty_paths) {
                                last_event = Instant::now();
                            }
                        }
                        Ok(Err(_)) => {}
                        Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
                    }
                }
            } else if !self.config.debounce.is_zero() {
                std::thread::sleep(self.config.debounce);
            }

            return dirty_paths;
        }
    }

    /// Runs the `notify`-backed, mtime-gated, debounced watch loop until `--once` / `--max-cycles`
    /// is satisfied (or forever if neither bound is configured).
    pub fn run(&mut self) -> Result<Vec<WatchCycleResult>, BuildError> {
        let target_cycles = if self.config.once {
            Some(1)
        } else {
            self.config.max_cycles
        };
        let mut results = Vec::new();

        match self.run_initial_build() {
            Ok(first) => {
                print_cycle_summary(&first);
                results.push(first);
            }
            Err(err) => {
                if target_cycles.is_some() {
                    return Err(err);
                }
                self.last_snapshot = Some(self.snapshot_with_dirty(&BTreeSet::new(), true)?);
                eprintln!("cargo-bam watch: initial build failed (waiting for edits): {err}");
            }
        }

        if target_cycles.is_some_and(|max| self.cycles_completed >= max) {
            return Ok(results);
        }

        loop {
            let dirty_paths = self.wait_for_debounced_change();
            let current = self.snapshot_with_dirty(&dirty_paths, false)?;
            let changed = self
                .last_snapshot
                .as_ref()
                .map_or_else(Vec::new, |prev| prev.diff_paths(&current));
            if changed.is_empty() {
                continue;
            }

            match self.execute_build_and_stage(changed) {
                Ok(cycle_res) => {
                    self.last_snapshot = Some(current);
                    print_cycle_summary(&cycle_res);
                    results.push(cycle_res);
                    if target_cycles.is_some_and(|max| self.cycles_completed >= max) {
                        return Ok(results);
                    }
                }
                Err(err) => {
                    // Advance snapshot so we do not spin-rebuild identical broken sources.
                    self.last_snapshot = Some(current);
                    eprintln!("cargo-bam watch: rebuild failed (waiting for edits): {err}");
                }
            }
        }
    }
}

fn print_cycle_summary(res: &WatchCycleResult) {
    if res.changed_files.is_empty() {
        println!(
            "[watch cycle {}] built {} mod '{}' -> {}",
            res.cycle,
            res.language,
            res.mod_id,
            res.library_path.display()
        );
    } else {
        let files: Vec<String> = res
            .changed_files
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        println!(
            "[watch cycle {}] rebuilt {} mod '{}' (changed: {}) -> {}",
            res.cycle,
            res.language,
            res.mod_id,
            files.join(", "),
            res.library_path.display()
        );
    }
    if let Some(sig) = &res.signature_path {
        println!("  signature: {}", sig.display());
    }
}

/// Convenience entrypoint creating a [`WatchRunner`] and executing [`WatchRunner::run`].
pub fn run_watch(config: WatchConfig) -> Result<Vec<WatchCycleResult>, BuildError> {
    let mut runner = WatchRunner::new(config)?;
    runner.run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bamabi_manifest::host_abi_semver;
    use tempfile::TempDir;

    #[test]
    fn should_watch_file_filters_by_language_and_ignores_temp_files() {
        assert!(should_watch_file(
            ModLanguage::Rust,
            Path::new("mod.toml"),
            &[]
        ));
        assert!(should_watch_file(
            ModLanguage::Rust,
            Path::new("Cargo.toml"),
            &[]
        ));
        assert!(should_watch_file(
            ModLanguage::Rust,
            Path::new("src/lib.rs"),
            &[]
        ));
        assert!(should_watch_file(
            ModLanguage::Rust,
            Path::new("src/nested/mod.rs"),
            &[]
        ));
        assert!(!should_watch_file(
            ModLanguage::Rust,
            Path::new("Cargo.lock"),
            &[]
        ));
        assert!(!should_watch_file(
            ModLanguage::Rust,
            Path::new("src/.lib.rs.swp"),
            &[]
        ));

        assert!(should_watch_file(
            ModLanguage::C99,
            Path::new("src/mod.c"),
            &[]
        ));
        assert!(should_watch_file(
            ModLanguage::C99,
            Path::new("include/bamabi.h"),
            &[]
        ));
        assert!(!should_watch_file(
            ModLanguage::C99,
            Path::new("target/debug/libfoo.so"),
            &[]
        ));

        assert!(should_watch_file(
            ModLanguage::Cpp17,
            Path::new("src/mod.cpp"),
            &[]
        ));
        assert!(should_watch_file(
            ModLanguage::Cpp17,
            Path::new("include/bamabi.hpp"),
            &[]
        ));

        assert!(should_watch_file(
            ModLanguage::Zig,
            Path::new("build.zig"),
            &[]
        ));
        assert!(should_watch_file(
            ModLanguage::Zig,
            Path::new("src/root.zig"),
            &[]
        ));
        assert!(should_watch_file(
            ModLanguage::Zig,
            Path::new("mod.toml"),
            &[]
        ));
        assert!(should_watch_file(
            ModLanguage::Rust,
            Path::new("shaders/glow.wesl"),
            &["shaders".to_owned()]
        ));
    }

    #[test]
    fn snapshot_detects_same_length_content_change_and_ignores_target_dir() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("src")).unwrap();
        fs::create_dir_all(tmp.path().join("target/debug")).unwrap();
        let host = host_abi_semver();
        fs::write(
            tmp.path().join("mod.toml"),
            format!(
                "[mod]\nid = \"snap_c\"\nversion = \"0.1.0\"\nabi_version = \"^{host}\"\nlanguage = \"c99\"\n"
            ),
        )
        .unwrap();
        fs::write(tmp.path().join("src/mod.c"), "int val = 1;\n").unwrap();
        fs::write(tmp.path().join("target/debug/ignored.c"), "int x = 0;\n").unwrap();

        let runner = WatchRunner::new(WatchConfig {
            dir: Some(tmp.path().to_path_buf()),
            ..WatchConfig::default()
        })
        .unwrap();

        let snap1 = runner.snapshot().unwrap();
        assert!(snap1.files.contains_key(Path::new("mod.toml")));
        assert!(snap1.files.contains_key(Path::new("src/mod.c")));
        assert!(
            !snap1
                .files
                .contains_key(Path::new("target/debug/ignored.c"))
        );

        // Same-length, immediate edit must still produce a distinct fingerprint via SHA-256!
        fs::write(tmp.path().join("src/mod.c"), "int val = 2;\n").unwrap();
        let snap2 = runner.snapshot().unwrap();
        let diff = snap1.diff_paths(&snap2);
        assert_eq!(diff, vec![PathBuf::from("src/mod.c")]);
    }

    #[test]
    fn mtime_gating_skips_reading_unchanged_files() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("cached.c");
        fs::write(&file_path, "int x = 1;\n").unwrap();
        let meta = fs::symlink_metadata(&file_path).unwrap();
        let (len, modified_secs, modified_nanos) = file_stat_tuple(&meta);

        let sentinel = [0xAB; 32];
        let cached = FileFingerprint {
            len,
            modified_secs,
            modified_nanos,
            sha256: sentinel,
        };
        let fp_gated = fingerprint_file_gated(&file_path, &meta, Some(&cached), false).unwrap();
        assert_eq!(
            fp_gated.sha256, sentinel,
            "unchanged (len, mtime) must reuse cached digest without re-hashing"
        );

        let fp_forced = fingerprint_file_gated(&file_path, &meta, Some(&cached), true).unwrap();
        assert_ne!(fp_forced.sha256, sentinel);
    }
}
