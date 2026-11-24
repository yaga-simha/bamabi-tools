//! Mod compiler/linker discovery (Rust, C99, C++17, Zig, and MSVC `cl.exe`/`clang-cl`/`vswhere`),
//! `[build] command` execution, and atomic shared-library staging.

use crate::scaffold::ModLanguage;
use crate::signing::{self, DEFAULT_NAMESPACE};
use crate::{
    BuildError, ResolvedProject, atomic_write_bytes, detect_rust_crate_stem, dylib_naming,
    dylib_naming_for_target, host_target_triple, read_file_bounded, resolve_project_info,
    validated_stage_dir, validated_staged_file_path,
};
use bamabi_manifest::{MAX_MANIFEST_BYTES, ModBuildConfig, validate_manifest_entry_path};
use bamabi_trust::{DEFAULT_MAX_MOD_BINARY_BYTES, sign_mod_bytes_with_key};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(windows)]
use std::sync::OnceLock;

/// Configuration for building a guest mod via [`build_mod_with_options`].
#[derive(Debug, Clone)]
pub struct BuildOptions<'a> {
    /// Explicit path to `mod.toml` or `Cargo.toml`.
    pub manifest_path: Option<&'a Path>,
    /// Project directory containing `mod.toml` / `Cargo.toml`.
    pub dir: Option<&'a Path>,
    /// Build with release optimizations.
    pub release: bool,
    /// Optional staging root directory (`<out_dir>/<mod_id>/`).
    pub out_dir: Option<&'a Path>,
    /// Optional OpenSSH Ed25519 private key to detach-sign the built library.
    pub sign_key: Option<&'a Path>,
    /// `SSHSIG` namespace used when [`Self::sign_key`] is `Some`.
    pub sign_namespace: &'a str,
    /// Optional target triple override (e.g., `"x86_64-unknown-linux-gnu"`).
    pub target: Option<&'a str>,
}

impl Default for BuildOptions<'_> {
    fn default() -> Self {
        Self {
            manifest_path: None,
            dir: None,
            release: false,
            out_dir: None,
            sign_key: None,
            sign_namespace: DEFAULT_NAMESPACE,
            target: None,
        }
    }
}

/// Configuration for constructing a native C99/C11 or C++17 shared-library compiler command
/// via [`build_c_mod_command`] or [`build_cpp17_mod_command`].
#[derive(Debug, Clone, Copy)]
pub struct NativeCompilerCommandConfig<'a> {
    /// Compiler executable or driver name (e.g., `"clang"`, `"gcc"`, `"cl.exe"`, `"clang-cl"`).
    pub compiler: &'a str,
    /// Mod project root directory.
    pub project_dir: &'a Path,
    /// Include directory containing `bamabi.h` / `bamabi.hpp`.
    pub include_dir: &'a Path,
    /// Intermediate build directory for `.obj` / `.lib` artifacts.
    pub build_dir: &'a Path,
    /// Sanitized shared-library stem (used for MSVC `.obj` / `.lib` filenames).
    pub lib_stem: &'a str,
    /// Source file path (`src/mod.c` or `src/mod.cpp`).
    pub source_path: &'a Path,
    /// Output shared-library path.
    pub output_path: &'a Path,
    /// Whether to compile with release optimizations (`/O2` / `-O2`).
    pub release: bool,
}

/// Result returned by [`build_mod`], [`build_mod_with_signing`], and [`build_mod_with_options`].
#[derive(Debug, Clone)]
pub struct BuildOutput {
    /// Detected guest language.
    pub language: ModLanguage,
    /// Built shared library path (staged if `out_dir` was provided, otherwise build output).
    pub library_path: PathBuf,
    /// Staged `mod.toml` path if `mod.toml` existed and `out_dir` was provided.
    pub staged_manifest_path: Option<PathBuf>,
    /// Detached `.sig` sidecar path if `sign_key` was provided.
    pub signature_path: Option<PathBuf>,
}

/// Returns `true` if `tool` uses MSVC-style flags (`cl`, `cl.exe`, `clang-cl`, `clang-cl.exe`).
#[must_use]
pub fn is_msvc_style_driver(tool: &str) -> bool {
    let file_name = Path::new(tool)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(tool);
    let stem = file_name
        .strip_suffix(".exe")
        .or_else(|| file_name.strip_suffix(".EXE"))
        .unwrap_or(file_name);
    stem.eq_ignore_ascii_case("cl") || stem.eq_ignore_ascii_case("clang-cl")
}

/// Returns `true` if `tool` is Microsoft's plain `cl` / `cl.exe` compiler driver.
#[must_use]
pub fn is_plain_cl_driver(tool: &str) -> bool {
    let file_name = Path::new(tool)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(tool);
    let stem = file_name
        .strip_suffix(".exe")
        .or_else(|| file_name.strip_suffix(".EXE"))
        .unwrap_or(file_name);
    stem.eq_ignore_ascii_case("cl")
}

fn msvc_path_arg(prefix: &str, path: &Path) -> OsString {
    let mut arg = OsString::from(prefix);
    arg.push(path.as_os_str());
    arg
}

/// Returns `true` if `key` is a Windows MSVC/SDK environment variable captured from `vcvars`.
#[must_use]
pub fn is_msvc_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "PATH"
            | "INCLUDE"
            | "EXTERNAL_INCLUDE"
            | "LIB"
            | "LIBPATH"
            | "PLATFORM"
            | "DEVENVDIR"
            | "VISUALSTUDIOVERSION"
            | "PREFERREDTOOLARCHITECTURE"
            | "UCRTVERSION"
            | "UNIVERSALCRTSDKDIR"
            | "VCINSTALLDIR"
            | "VSINSTALLDIR"
            | "NETFXSDKDIR"
    ) || upper.starts_with("VSCMD_")
        || upper.starts_with("VCTOOLS")
        || upper.starts_with("WINDOWSSDK")
}

/// Parses `set` stdout emitted after invoking `vcvars64.bat` / `vcvarsall.bat`, keeping MSVC keys.
#[must_use]
pub fn parse_vcvars_env_output(stdout: &str) -> Vec<(String, String)> {
    let mut vars: Vec<(String, String)> = Vec::new();
    for raw_line in stdout.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('=') {
            continue;
        }
        let Some((raw_key, value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        if key.is_empty() || !is_msvc_env_key(key) {
            continue;
        }
        let normalized_key = if key.eq_ignore_ascii_case("PATH") {
            "PATH".to_owned()
        } else if key.eq_ignore_ascii_case("INCLUDE") {
            "INCLUDE".to_owned()
        } else if key.eq_ignore_ascii_case("LIB") {
            "LIB".to_owned()
        } else if key.eq_ignore_ascii_case("LIBPATH") {
            "LIBPATH".to_owned()
        } else {
            key.to_owned()
        };
        if let Some(existing) = vars
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(&normalized_key))
        {
            existing.1 = value.to_owned();
        } else {
            vars.push((normalized_key, value.to_owned()));
        }
    }
    vars
}

/// Returns ordered `(bat_path, optional_arg)` candidates under a Visual Studio installation root.
#[must_use]
pub fn msvc_vcvars_bat_candidates(
    install_root: &Path,
    arch: &str,
) -> Vec<(PathBuf, Option<&'static str>)> {
    let aux_build = install_root.join("VC").join("Auxiliary").join("Build");
    match arch {
        "x86" => vec![
            (aux_build.join("vcvars32.bat"), None),
            (aux_build.join("vcvarsall.bat"), Some("x86")),
        ],
        "aarch64" => vec![
            (aux_build.join("vcvarsall.bat"), Some("arm64")),
            (aux_build.join("vcvars64.bat"), None),
        ],
        _ => vec![
            (aux_build.join("vcvars64.bat"), None),
            (aux_build.join("vcvarsall.bat"), Some("x64")),
        ],
    }
}

/// Searches `path_value` (`PATH`-separated directory list) for `exe_name` (or `<exe_name>.exe`).
#[must_use]
pub fn find_exe_in_path_list(exe_name: &str, path_value: &str) -> Option<PathBuf> {
    let has_exe_ext = Path::new(exe_name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("exe"));
    for dir in env::split_paths(path_value) {
        let direct = dir.join(exe_name);
        if direct.is_file() {
            return Some(direct);
        }
        if !has_exe_ext {
            let with_exe = dir.join(format!("{exe_name}.exe"));
            if with_exe.is_file() {
                return Some(with_exe);
            }
        }
    }
    None
}

/// Probes common Visual Studio Installer locations and `PATH` for `vswhere.exe`.
#[must_use]
pub fn probe_vswhere_path() -> Option<PathBuf> {
    for env_key in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(base) = env::var_os(env_key) {
            let candidate = PathBuf::from(base)
                .join("Microsoft Visual Studio")
                .join("Installer")
                .join("vswhere.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    if let Some(path_val) = env::var_os("PATH") {
        return find_exe_in_path_list("vswhere.exe", &path_val.to_string_lossy());
    }
    None
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct MsvcEnv {
    vars: Vec<(String, String)>,
    cl_exe: Option<PathBuf>,
}

#[cfg(windows)]
fn find_vs_install_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut vswhere_bins = Vec::new();
    for env_key in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(base) = env::var_os(env_key) {
            let candidate = PathBuf::from(base)
                .join("Microsoft Visual Studio")
                .join("Installer")
                .join("vswhere.exe");
            if candidate.is_file() && !vswhere_bins.contains(&candidate) {
                vswhere_bins.push(candidate);
            }
        }
    }
    vswhere_bins.push(PathBuf::from("vswhere.exe"));

    let required_component = if cfg!(target_arch = "aarch64") {
        "Microsoft.VisualStudio.Component.VC.Tools.ARM64"
    } else {
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
    };
    let queries: [&[&str]; 2] = [
        &[
            "-latest",
            "-products",
            "*",
            "-requires",
            required_component,
            "-property",
            "installationPath",
        ],
        &[
            "-latest",
            "-products",
            "*",
            "-prerelease",
            "-requires",
            required_component,
            "-property",
            "installationPath",
        ],
    ];

    for vswhere in &vswhere_bins {
        for query in &queries {
            let Ok(out) = Command::new(vswhere).args(*query).output() else {
                continue;
            };
            if !out.status.success() {
                continue;
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let path = PathBuf::from(trimmed);
                    if path.is_dir() && !roots.contains(&path) {
                        roots.push(path);
                    }
                }
            }
            if !roots.is_empty() {
                return roots;
            }
        }
    }

    if let Some(vs_dir) = env::var_os("VSINSTALLDIR") {
        let path = PathBuf::from(vs_dir);
        if path.is_dir() && !roots.contains(&path) {
            roots.push(path);
        }
    }
    for env_key in ["ProgramFiles", "ProgramFiles(x86)"] {
        let Some(base) = env::var_os(env_key) else {
            continue;
        };
        for year in ["2022", "2019"] {
            for edition in ["Enterprise", "Professional", "Community", "BuildTools"] {
                let cand = PathBuf::from(&base)
                    .join("Microsoft Visual Studio")
                    .join(year)
                    .join(edition);
                if cand.is_dir() && !roots.contains(&cand) {
                    roots.push(cand);
                }
            }
        }
    }

    roots
}

#[cfg(windows)]
fn capture_vcvars_env(bat_path: &Path, bat_arg: Option<&str>) -> Option<MsvcEnv> {
    use std::os::windows::process::CommandExt;

    let comspec = env::var_os("COMSPEC").unwrap_or_else(|| OsString::from("cmd.exe"));
    let mut cmd = Command::new(comspec);
    cmd.env("VSCMD_SKIP_SENDTELEMETRY", "1")
        .env("BAM_VCVARS_BAT", bat_path)
        .args(["/D", "/S", "/C"]);
    match bat_arg {
        Some(arg) => {
            cmd.raw_arg(format!(
                "\"call \"%BAM_VCVARS_BAT%\" {arg} >NUL 2>&1 && set\""
            ));
        }
        None => {
            cmd.raw_arg("\"call \"%BAM_VCVARS_BAT%\" >NUL 2>&1 && set\"");
        }
    }

    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let vars = parse_vcvars_env_output(&stdout);

    let path_val = vars
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.as_str())?;
    let has_include = vars
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("INCLUDE") && !v.is_empty());
    let has_lib = vars
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("LIB") && !v.is_empty());
    if !has_include || !has_lib {
        return None;
    }

    let cl_exe = find_exe_in_path_list("cl.exe", path_val);
    Some(MsvcEnv { vars, cl_exe })
}

#[cfg(windows)]
fn cached_msvc_env() -> Option<&'static MsvcEnv> {
    static MSVC_ENV: OnceLock<Option<MsvcEnv>> = OnceLock::new();
    MSVC_ENV
        .get_or_init(|| {
            for install_root in find_vs_install_roots() {
                for (bat_path, bat_arg) in
                    msvc_vcvars_bat_candidates(&install_root, env::consts::ARCH)
                {
                    if bat_path.is_file()
                        && let Some(captured) = capture_vcvars_env(&bat_path, bat_arg)
                    {
                        return Some(captured);
                    }
                }
            }
            None
        })
        .as_ref()
}

/// Constructs a [`Command`] for `program`, automatically populating MSVC `INCLUDE`/`LIB`/`PATH`
/// via `vswhere.exe` + `vcvars` on Windows when needed.
#[must_use]
pub fn msvc_command(program: &str) -> Command {
    #[cfg(windows)]
    if is_msvc_style_driver(program) {
        let has_include = env::var_os("INCLUDE").is_some_and(|v| !v.is_empty());
        let has_lib = env::var_os("LIB").is_some_and(|v| !v.is_empty());
        let explicit_path = Path::new(program).components().count() > 1;
        let direct_driver_ok = if !is_plain_cl_driver(program) {
            true
        } else if explicit_path {
            Path::new(program).is_file()
        } else {
            env::var("PATH")
                .ok()
                .and_then(|path_val| find_exe_in_path_list(program, &path_val))
                .is_some()
        };

        if !(has_include && has_lib && direct_driver_ok)
            && let Some(msvc_env) = cached_msvc_env()
        {
            let mut cmd = if is_plain_cl_driver(program) && !explicit_path {
                match &msvc_env.cl_exe {
                    Some(cl_path) => Command::new(cl_path),
                    None => Command::new(program),
                }
            } else {
                Command::new(program)
            };
            for (k, v) in &msvc_env.vars {
                cmd.env(k, v);
            }
            return cmd;
        }
    }
    Command::new(program)
}

/// Probes `program` for availability and returns its first non-empty version/banner line.
#[must_use]
pub fn probe_compiler_banner(program: &str) -> Option<String> {
    let output = if is_plain_cl_driver(program) {
        msvc_command(program).output().ok()?
    } else {
        msvc_command(program).arg("--version").output().ok()?
    };
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() || (is_plain_cl_driver(program) && !stderr.is_empty()) {
        let first_line = if is_plain_cl_driver(program) {
            stderr
                .lines()
                .next()
                .filter(|l| !l.trim().is_empty())
                .or_else(|| stdout.lines().next().filter(|l| !l.trim().is_empty()))
        } else {
            stdout
                .lines()
                .next()
                .filter(|l| !l.trim().is_empty())
                .or_else(|| stderr.lines().next().filter(|l| !l.trim().is_empty()))
        }
        .unwrap_or("ok");
        Some(format!("{program}: {first_line}"))
    } else {
        None
    }
}

/// Ordered candidate list of C99/C11 compilers (`$CC` first, then platform defaults).
#[must_use]
pub fn c_candidates() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(cc) = env::var("CC") {
        let trimmed = cc.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_owned());
        }
    }
    #[cfg(target_os = "windows")]
    let defaults = ["cl.exe", "cl", "clang", "clang-cl", "gcc", "cc"];
    #[cfg(not(target_os = "windows"))]
    let defaults = ["clang", "gcc", "cc"];
    for cand in defaults {
        if !out.iter().any(|existing| existing == cand) {
            out.push(cand.to_owned());
        }
    }
    out
}

/// Ordered candidate list of C++17 compilers (`$CXX` first, then platform defaults).
#[must_use]
pub fn cxx_candidates() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(cxx) = env::var("CXX") {
        let trimmed = cxx.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_owned());
        }
    }
    #[cfg(target_os = "windows")]
    let defaults = ["cl.exe", "cl", "clang++", "clang-cl", "g++", "c++"];
    #[cfg(not(target_os = "windows"))]
    let defaults = ["clang++", "g++", "c++"];
    for cand in defaults {
        if !out.iter().any(|existing| existing == cand) {
            out.push(cand.to_owned());
        }
    }
    out
}

/// Discovers the highest-priority available C compiler from [`c_candidates`], or falls back to
/// the first candidate.
#[must_use]
pub fn c_compiler() -> String {
    let candidates = c_candidates();
    for cand in &candidates {
        if probe_compiler_banner(cand).is_some() {
            return cand.clone();
        }
    }
    candidates
        .into_iter()
        .next()
        .unwrap_or_else(|| "cc".to_owned())
}

/// Discovers the highest-priority available C++ compiler from [`cxx_candidates`], or falls back
/// to the first candidate.
#[must_use]
pub fn cxx_compiler() -> String {
    let candidates = cxx_candidates();
    for cand in &candidates {
        if probe_compiler_banner(cand).is_some() {
            return cand.clone();
        }
    }
    candidates
        .into_iter()
        .next()
        .unwrap_or_else(|| "c++".to_owned())
}

fn cargo_bin() -> String {
    env::var("CARGO")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "cargo".to_owned())
}

fn run_command(cmd: &mut Command, label: &str) -> Result<(), BuildError> {
    let output = cmd
        .output()
        .map_err(|e| BuildError::Command(format!("failed to launch `{label}`: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(BuildError::Command(format!(
            "`{label}` exited with {}\n{stdout}\n{stderr}",
            output.status
        )));
    }
    Ok(())
}

fn find_first_existing(project_dir: &Path, candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(|rel| project_dir.join(rel))
        .find(|p| p.is_file())
}

/// Constructs a strict C99/C11 shared-library compilation [`Command`] from `cfg`.
#[must_use]
pub fn build_c_mod_command(cfg: &NativeCompilerCommandConfig<'_>) -> Command {
    let mut cmd = msvc_command(cfg.compiler);
    cmd.current_dir(cfg.project_dir);
    if is_msvc_style_driver(cfg.compiler) {
        let obj_path = cfg.build_dir.join(format!("{}.c.obj", cfg.lib_stem));
        let implib_path = cfg.build_dir.join(format!("{}.c.lib", cfg.lib_stem));
        cmd.args(["/nologo", "/LD", "/TC", "/std:c11", "/W4", "/WX"])
            .arg(if cfg.release { "/O2" } else { "/Od" });
        if cfg.include_dir.is_dir() {
            cmd.arg("/I").arg(cfg.include_dir);
        }
        cmd.arg(msvc_path_arg("/Fo:", &obj_path))
            .arg(msvc_path_arg("/Fe:", cfg.output_path))
            .arg(cfg.source_path)
            .arg("/link")
            .arg(msvc_path_arg("/IMPLIB:", &implib_path));
    } else {
        cmd.args(["-std=c99", "-Wall", "-Wextra", "-Werror"])
            .arg(if cfg.release { "-O2" } else { "-O0" })
            .arg("-shared");
        if cfg.include_dir.is_dir() {
            cmd.arg(format!("-I{}", cfg.include_dir.display()));
        }
        if !cfg!(target_os = "windows") {
            cmd.arg("-fPIC");
        }
        cmd.arg(cfg.source_path).arg("-o").arg(cfg.output_path);
    }
    cmd
}

/// Constructs a strict C++17 shared-library compilation [`Command`] from `cfg`.
#[must_use]
pub fn build_cpp17_mod_command(cfg: &NativeCompilerCommandConfig<'_>) -> Command {
    let mut cmd = msvc_command(cfg.compiler);
    cmd.current_dir(cfg.project_dir);
    if is_msvc_style_driver(cfg.compiler) {
        let obj_path = cfg.build_dir.join(format!("{}.cpp.obj", cfg.lib_stem));
        let implib_path = cfg.build_dir.join(format!("{}.cpp.lib", cfg.lib_stem));
        cmd.args([
            "/nologo",
            "/LD",
            "/TP",
            "/std:c++17",
            "/Zc:__cplusplus",
            "/EHsc",
            "/W4",
            "/WX",
        ])
        .arg(if cfg.release { "/O2" } else { "/Od" });
        if cfg.include_dir.is_dir() {
            cmd.arg("/I").arg(cfg.include_dir);
        }
        cmd.arg(msvc_path_arg("/Fo:", &obj_path))
            .arg(msvc_path_arg("/Fe:", cfg.output_path))
            .arg(cfg.source_path)
            .arg("/link")
            .arg(msvc_path_arg("/IMPLIB:", &implib_path));
    } else {
        cmd.args(["-std=c++17", "-Wall", "-Wextra", "-Wpedantic", "-Werror"])
            .arg(if cfg.release { "-O2" } else { "-O0" })
            .arg("-shared");
        if cfg.include_dir.is_dir() {
            cmd.arg(format!("-I{}", cfg.include_dir.display()));
        }
        if !cfg!(target_os = "windows") {
            cmd.args([
                "-fPIC",
                "-fvisibility=hidden",
                "-fvisibility-inlines-hidden",
            ]);
        }
        cmd.arg(cfg.source_path).arg("-o").arg(cfg.output_path);
    }
    cmd
}

fn resolve_confined_working_dir(
    project_dir: &Path,
    working_dir: Option<&str>,
) -> Result<PathBuf, BuildError> {
    let Some(rel) = working_dir else {
        return Ok(project_dir.to_path_buf());
    };
    let candidate = project_dir.join(rel);
    if let Ok(meta) = fs::symlink_metadata(&candidate)
        && meta.file_type().is_symlink()
    {
        return Err(BuildError::InvalidManifest(format!(
            "[build].working_dir must not be a symlink: {}",
            candidate.display()
        )));
    }
    if !candidate.is_dir() {
        return Err(BuildError::InvalidManifest(format!(
            "[build].working_dir does not exist: {}",
            candidate.display()
        )));
    }
    let canon_proj = fs::canonicalize(project_dir)?;
    let canon_work = fs::canonicalize(&candidate)?;
    if !canon_work.starts_with(&canon_proj) {
        return Err(BuildError::InvalidManifest(format!(
            "[build].working_dir '{}' escapes project root '{}'",
            canon_work.display(),
            canon_proj.display()
        )));
    }
    Ok(candidate)
}

fn resolve_confined_artifact_path(
    project_dir: &Path,
    rel_posix: &str,
    label: &str,
) -> Result<PathBuf, BuildError> {
    validate_manifest_entry_path(rel_posix).map_err(|reason| {
        BuildError::InvalidManifest(format!("invalid {label} '{rel_posix}': {reason}"))
    })?;
    let candidate = project_dir.join(rel_posix);
    if let Ok(meta) = fs::symlink_metadata(&candidate)
        && meta.file_type().is_symlink()
    {
        return Err(BuildError::InvalidManifest(format!(
            "{label} must not be a symlink: {}",
            candidate.display()
        )));
    }
    if !candidate.is_file() {
        return Err(BuildError::Command(format!(
            "expected built artifact for {label} not found at {}",
            candidate.display()
        )));
    }
    let canon_proj = fs::canonicalize(project_dir)?;
    let canon_art = fs::canonicalize(&candidate)?;
    if !canon_art.starts_with(&canon_proj) {
        return Err(BuildError::InvalidManifest(format!(
            "{label} '{}' escapes project root '{}'",
            canon_art.display(),
            canon_proj.display()
        )));
    }
    Ok(candidate)
}

fn execute_custom_build_command(
    project: &ResolvedProject,
    build_cfg: &ModBuildConfig,
    command_str: &str,
    release: bool,
    target: Option<&str>,
) -> Result<PathBuf, BuildError> {
    let work_dir =
        resolve_confined_working_dir(&project.project_dir, build_cfg.working_dir.as_deref())?;
    let active_target = match target {
        Some(t) => t,
        None => host_target_triple(),
    };
    let profile_str = if release { "release" } else { "debug" };

    let mut cmd = if !build_cfg.args.is_empty() {
        let mut c = Command::new(command_str);
        c.args(&build_cfg.args);
        c
    } else if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/D", "/S", "/C", command_str]);
        c
    } else {
        let mut c = Command::new("sh");
        c.args(["-c", command_str]);
        c
    };

    cmd.current_dir(&work_dir)
        .env("BAM_MOD_ID", &project.mod_id)
        .env("BAM_PROFILE", profile_str)
        .env("BAM_RELEASE", if release { "1" } else { "0" })
        .env("BAM_PROJECT_DIR", &project.project_dir)
        .env("BAM_TARGET_TRIPLE", active_target);
    for (k, v) in &build_cfg.env {
        cmd.env(k, v);
    }

    run_command(&mut cmd, &format!("[build].command `{command_str}`"))?;

    if let Some(ref output_rel) = build_cfg.output {
        return resolve_confined_artifact_path(&project.project_dir, output_rel, "[build].output");
    }
    if let Some(manifest) = &project.manifest {
        if let Some(target_entry) = manifest.targets.get(active_target) {
            return resolve_confined_artifact_path(
                &project.project_dir,
                &target_entry.entry,
                "[targets.<triple>].entry",
            );
        }
        if let Some(ref entry) = manifest.entry {
            return resolve_confined_artifact_path(&project.project_dir, entry, "[mod].entry");
        }
    }

    let (prefix, ext) = target
        .map(dylib_naming_for_target)
        .unwrap_or_else(dylib_naming);
    let expected_name = format!("{prefix}{}.{ext}", project.lib_stem);
    let candidates = [
        project
            .project_dir
            .join("target")
            .join(profile_str)
            .join(&expected_name),
        project
            .project_dir
            .join("zig-out")
            .join("lib")
            .join(&expected_name),
        project.project_dir.join(&expected_name),
    ];
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| {
            BuildError::Command(format!(
                "[build].command `{command_str}` succeeded, but no built shared library `{expected_name}` was found (set `[build].output` or `[mod].entry`)"
            ))
        })
}

/// Builds a guest mod project (Rust, C99, C++17, Zig, or `[build].command`), validates `mod.toml`
/// metadata if present, and optionally stages into `out_dir/<mod_id>/`.
pub fn build_mod(
    manifest_path: Option<&Path>,
    dir: Option<&Path>,
    release: bool,
    out_dir: Option<&Path>,
) -> Result<BuildOutput, BuildError> {
    build_mod_with_signing(
        manifest_path,
        dir,
        release,
        out_dir,
        None,
        DEFAULT_NAMESPACE,
    )
}

/// Builds, stages into `out_dir/<mod_id>/`, and optionally signs a guest mod artifact.
pub fn build_mod_with_signing(
    manifest_path: Option<&Path>,
    dir: Option<&Path>,
    release: bool,
    out_dir: Option<&Path>,
    sign_key: Option<&Path>,
    sign_namespace: &str,
) -> Result<BuildOutput, BuildError> {
    build_mod_with_options(&BuildOptions {
        manifest_path,
        dir,
        release,
        out_dir,
        sign_key,
        sign_namespace,
        target: None,
    })
}

/// Builds, optionally stages into `out_dir/<mod_id>/`, and optionally signs a guest mod artifact
/// using structured [`BuildOptions`].
pub fn build_mod_with_options(options: &BuildOptions<'_>) -> Result<BuildOutput, BuildError> {
    if options.sign_key.is_some() && options.sign_namespace.is_empty() {
        return Err(BuildError::InvalidArgument(
            "`--sign-namespace` must not be empty".to_owned(),
        ));
    }

    let project = resolve_project_info(options.manifest_path, options.dir)?;
    let project_dir = &project.project_dir;
    let language = project.language;
    let mod_id = &project.mod_id;
    let stem_from_mod = &project.lib_stem;
    let cargo_toml = project_dir.join("Cargo.toml");

    let custom_cmd = project
        .manifest
        .as_ref()
        .and_then(|m| m.build.as_ref())
        .and_then(|b| b.command.as_deref().map(|cmd| (b, cmd)));

    let built_artifact = if let Some((build_cfg, cmd_str)) = custom_cmd {
        execute_custom_build_command(
            &project,
            build_cfg,
            cmd_str,
            options.release,
            options.target,
        )?
    } else {
        let (prefix, ext) = options
            .target
            .map(dylib_naming_for_target)
            .unwrap_or_else(dylib_naming);
        match language {
            ModLanguage::Rust => {
                if !cargo_toml.is_file() {
                    return Err(BuildError::InvalidManifest(format!(
                        "expected Cargo.toml at {}",
                        cargo_toml.display()
                    )));
                }
                let crate_stem = detect_rust_crate_stem(&cargo_toml)?;
                let mut cmd = Command::new(cargo_bin());
                cmd.current_dir(project_dir)
                    .arg("build")
                    .arg("--manifest-path")
                    .arg(&cargo_toml);
                if let Some(triple) = options.target {
                    cmd.arg("--target").arg(triple);
                }
                if options.release {
                    cmd.arg("--release");
                }
                let profile_dir = if options.release { "release" } else { "debug" };
                run_command(&mut cmd, &format!("cargo build ({profile_dir})"))?;
                let target_root = env::var("CARGO_TARGET_DIR")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| project_dir.join("target"));
                let profile_base = match options.target {
                    Some(triple) => target_root.join(triple).join(profile_dir),
                    None => target_root.join(profile_dir),
                };
                let artifact = profile_base.join(format!("{prefix}{crate_stem}.{ext}"));
                if !artifact.is_file() {
                    return Err(BuildError::Command(format!(
                        "expected Rust cdylib artifact not found at {}",
                        artifact.display()
                    )));
                }
                artifact
            }
            ModLanguage::C99 => {
                let src =
                    find_first_existing(project_dir, &["src/mod.c", "mod.c"]).ok_or_else(|| {
                        BuildError::InvalidManifest(format!(
                            "expected C99 source `src/mod.c` or `mod.c` in {}",
                            project_dir.display()
                        ))
                    })?;
                let build_dir = project_dir.join("target").join(if options.release {
                    "release"
                } else {
                    "debug"
                });
                fs::create_dir_all(&build_dir)?;
                let out_path = build_dir.join(format!("{prefix}{stem_from_mod}.{ext}"));
                let include_dir = project_dir.join("include");
                let cc = c_compiler();
                let mut cmd = build_c_mod_command(&NativeCompilerCommandConfig {
                    compiler: &cc,
                    project_dir,
                    include_dir: &include_dir,
                    build_dir: &build_dir,
                    lib_stem: stem_from_mod,
                    source_path: &src,
                    output_path: &out_path,
                    release: options.release,
                });
                run_command(&mut cmd, &format!("{cc} C99/C11 build"))?;
                out_path
            }
            ModLanguage::Cpp17 => {
                let src = find_first_existing(project_dir, &["src/mod.cpp", "mod.cpp"])
                    .ok_or_else(|| {
                        BuildError::InvalidManifest(format!(
                            "expected C++17 source `src/mod.cpp` or `mod.cpp` in {}",
                            project_dir.display()
                        ))
                    })?;
                let build_dir = project_dir.join("target").join(if options.release {
                    "release"
                } else {
                    "debug"
                });
                fs::create_dir_all(&build_dir)?;
                let out_path = build_dir.join(format!("{prefix}{stem_from_mod}.{ext}"));
                let include_dir = project_dir.join("include");
                let cxx = cxx_compiler();
                let mut cmd = build_cpp17_mod_command(&NativeCompilerCommandConfig {
                    compiler: &cxx,
                    project_dir,
                    include_dir: &include_dir,
                    build_dir: &build_dir,
                    lib_stem: stem_from_mod,
                    source_path: &src,
                    output_path: &out_path,
                    release: options.release,
                });
                run_command(&mut cmd, &format!("{cxx} -std=c++17"))?;
                out_path
            }
            ModLanguage::Zig => {
                let mut cmd = Command::new("zig");
                cmd.current_dir(project_dir).arg("build");
                if options.release {
                    cmd.arg("-Doptimize=ReleaseFast");
                }
                run_command(&mut cmd, "zig build")?;
                let expected_name = format!("{prefix}{stem_from_mod}.{ext}");
                let candidates = [
                    project_dir.join("zig-out").join("lib").join(&expected_name),
                    project_dir.join("zig-out").join("bin").join(&expected_name),
                ];
                candidates
                    .into_iter()
                    .find(|p| p.is_file())
                    .ok_or_else(|| {
                        BuildError::Command(format!(
                            "expected Zig shared library `{expected_name}` under zig-out/"
                        ))
                    })?
            }
        }
    };

    if let Some(stage_root) = options.out_dir {
        let stage_dir = validated_stage_dir(stage_root, mod_id)?;
        let file_name = built_artifact
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                BuildError::Command("built artifact has no valid UTF-8 filename".to_owned())
            })?;
        let lib_bytes = read_file_bounded(
            &built_artifact,
            DEFAULT_MAX_MOD_BINARY_BYTES,
            "built shared library",
        )?;
        if lib_bytes.is_empty() {
            return Err(BuildError::Command(format!(
                "built shared library {} is empty",
                built_artifact.display()
            )));
        }

        let sig_pem = if let Some(key_path) = options.sign_key {
            let signing_key = signing::load_ed25519_private_key(key_path)?;
            Some(
                sign_mod_bytes_with_key(&signing_key, options.sign_namespace, &lib_bytes)
                    .map_err(|e| BuildError::Crypto(e.to_string()))?,
            )
        } else {
            None
        };

        // 1. Stage `mod.toml` atomically first.
        let staged_manifest = if let Some(ref mp) = project.mod_toml_path {
            let manifest_bytes = read_file_bounded(mp, MAX_MANIFEST_BYTES, "mod.toml")?;
            let dest_manifest = stage_dir.join("mod.toml");
            atomic_write_bytes(&dest_manifest, &manifest_bytes)?;
            Some(dest_manifest)
        } else {
            None
        };

        let staged_rel = options
            .target
            .and_then(|triple| {
                project
                    .manifest
                    .as_ref()
                    .and_then(|m| m.entry_for_target(triple))
            })
            .or_else(|| project.manifest.as_ref().and_then(|m| m.entry.as_deref()));

        let staged_lib = match staged_rel {
            Some(rel) => validated_staged_file_path(&stage_dir, rel)?,
            None => stage_dir.join(file_name),
        };

        // 2. Stage `.sig` atomically BEFORE the shared library so watchers observe a matching
        //    signature as soon as the new library appears.
        let signature_path = if let Some(pem) = sig_pem {
            let sig_dest = signing::default_sig_path(&staged_lib);
            atomic_write_bytes(&sig_dest, pem.as_bytes())?;
            Some(sig_dest)
        } else {
            None
        };

        // 3. Stage the shared library atomically LAST.
        atomic_write_bytes(&staged_lib, &lib_bytes)?;

        return Ok(BuildOutput {
            language,
            library_path: staged_lib,
            staged_manifest_path: staged_manifest,
            signature_path,
        });
    }

    let signature_path = if let Some(key_path) = options.sign_key {
        let signed =
            signing::sign_mod_file(key_path, &built_artifact, None, options.sign_namespace)?;
        Some(signed.signature_path)
    } else {
        None
    };

    Ok(BuildOutput {
        language,
        library_path: built_artifact,
        staged_manifest_path: None,
        signature_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn msvc_driver_classification_distinguishes_cl_clang_cl_and_gnu() {
        assert!(is_msvc_style_driver("cl"));
        assert!(is_msvc_style_driver("cl.exe"));
        assert!(is_msvc_style_driver("C:/MSVC/bin/Hostx64/x64/CL.EXE"));
        assert!(is_msvc_style_driver("clang-cl"));
        assert!(is_msvc_style_driver("clang-cl.exe"));
        assert!(!is_msvc_style_driver("clang"));
        assert!(!is_msvc_style_driver("clang++"));
        assert!(!is_msvc_style_driver("gcc"));
        assert!(!is_msvc_style_driver("x86_64-w64-mingw32-gcc"));

        assert!(is_plain_cl_driver("cl"));
        assert!(is_plain_cl_driver("cl.exe"));
        assert!(!is_plain_cl_driver("clang-cl"));
        assert!(!is_plain_cl_driver("clang"));

        let c_cands = c_candidates();
        assert!(c_cands.iter().any(|c| c == "clang"));
        assert!(c_cands.iter().any(|c| c == "gcc"));
        let cxx_cands = cxx_candidates();
        assert!(cxx_cands.iter().any(|c| c == "clang++"));
        assert!(cxx_cands.iter().any(|c| c == "g++"));
        #[cfg(target_os = "windows")]
        {
            let cl_pos = c_cands.iter().position(|c| c == "cl.exe").unwrap();
            let clang_pos = c_cands.iter().position(|c| c == "clang").unwrap();
            assert!(cl_pos < clang_pos);
            let cxx_cl_pos = cxx_cands.iter().position(|c| c == "cl.exe").unwrap();
            let cxx_clang_pos = cxx_cands.iter().position(|c| c == "clang++").unwrap();
            assert!(cxx_cl_pos < cxx_clang_pos);
        }
    }

    #[test]
    fn parse_vcvars_env_output_and_msvc_command_flags() {
        let sample = "\
=D:=D:\\a\\repo\r
Path=C:\\VS\\bin\\Hostx64\\x64;C:\\Windows\\System32\r
INCLUDE=C:\\VS\\include\r
LIB=C:\\VS\\lib\\x64\r
WindowsSdkDir=C:\\Windows Kits\\10\\\r
BAM_VCVARS_BAT=C:\\VS\\vcvars64.bat\r
";
        let vars = parse_vcvars_env_output(sample);
        assert!(vars.iter().any(|(k, _)| k == "PATH"));
        assert!(vars.iter().any(|(k, _)| k == "INCLUDE"));
        assert!(vars.iter().any(|(k, _)| k == "LIB"));
        assert!(vars.iter().any(|(k, _)| k == "WindowsSdkDir"));
        assert!(!vars.iter().any(|(k, _)| k == "BAM_VCVARS_BAT"));

        let bats = msvc_vcvars_bat_candidates(Path::new("C:/VS"), "x86_64");
        assert_eq!(
            bats[0].0,
            Path::new("C:/VS/VC/Auxiliary/Build/vcvars64.bat")
        );
        assert_eq!(bats[0].1, None);

        let proj = Path::new("/tmp/my mod");
        let inc = Path::new("/tmp/my mod/include");
        let bdir = Path::new("/tmp/my mod/target/release");
        let src_c = Path::new("/tmp/my mod/src/mod.c");
        let src_cpp = Path::new("/tmp/my mod/src/mod.cpp");
        let dll = Path::new("/tmp/my mod/target/release/my_mod.dll");

        let c_cmd = build_c_mod_command(&NativeCompilerCommandConfig {
            compiler: "cl.exe",
            project_dir: proj,
            include_dir: inc,
            build_dir: bdir,
            lib_stem: "my_mod",
            source_path: src_c,
            output_path: dll,
            release: true,
        });
        let c_args: Vec<String> = c_cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(c_args.contains(&"/nologo".to_owned()));
        assert!(c_args.contains(&"/LD".to_owned()));
        assert!(c_args.contains(&"/TC".to_owned()));
        assert!(c_args.contains(&"/std:c11".to_owned()));
        assert!(c_args.contains(&"/W4".to_owned()));
        assert!(c_args.contains(&"/WX".to_owned()));
        assert!(c_args.contains(&"/O2".to_owned()));
        assert!(c_args.contains(&format!("/Fo:{}", bdir.join("my_mod.c.obj").display())));
        assert!(c_args.contains(&format!("/Fe:{}", dll.display())));
        assert!(c_args.contains(&format!("/IMPLIB:{}", bdir.join("my_mod.c.lib").display())));

        let cpp_cmd = build_cpp17_mod_command(&NativeCompilerCommandConfig {
            compiler: "cl.exe",
            project_dir: proj,
            include_dir: inc,
            build_dir: bdir,
            lib_stem: "my_mod",
            source_path: src_cpp,
            output_path: dll,
            release: false,
        });
        let cpp_args: Vec<String> = cpp_cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(cpp_args.contains(&"/LD".to_owned()));
        assert!(cpp_args.contains(&"/TP".to_owned()));
        assert!(cpp_args.contains(&"/std:c++17".to_owned()));
        assert!(cpp_args.contains(&"/Zc:__cplusplus".to_owned()));
        assert!(cpp_args.contains(&"/EHsc".to_owned()));
        assert!(cpp_args.contains(&"/W4".to_owned()));
        assert!(cpp_args.contains(&"/WX".to_owned()));
        assert!(cpp_args.contains(&"/Od".to_owned()));
        assert!(cpp_args.contains(&format!("/Fo:{}", bdir.join("my_mod.cpp.obj").display())));
        assert!(cpp_args.contains(&format!("/Fe:{}", dll.display())));
    }

    #[test]
    fn build_mod_executes_custom_build_command_from_mod_toml() {
        let tmp = TempDir::new().unwrap();
        let proj = tmp.path().join("custom_cmd_mod");
        fs::create_dir_all(proj.join("out")).unwrap();

        let cmd_script = if cfg!(windows) {
            "echo fake-dll > out\\custom_cmd_mod.dll"
        } else {
            "printf 'fake-dylib' > out/libcustom_cmd_mod.so"
        };
        let out_entry = if cfg!(windows) {
            "out/custom_cmd_mod.dll"
        } else {
            "out/libcustom_cmd_mod.so"
        };

        let mod_toml = format!(
            r#"
[mod]
id = "custom_cmd_mod"
version = "0.1.0"
language = "c99"
entry = "{out_entry}"

[build]
command = "{cmd_script}"
output = "{out_entry}"
"#
        );
        fs::write(proj.join("mod.toml"), mod_toml).unwrap();

        let stage = tmp.path().join("stage");
        let built = build_mod(None, Some(&proj), false, Some(&stage)).unwrap();
        assert!(built.library_path.is_file());
        assert!(built.staged_manifest_path.as_ref().unwrap().is_file());
        assert_eq!(
            built.library_path,
            stage.join("custom_cmd_mod").join(out_entry)
        );
    }
}
