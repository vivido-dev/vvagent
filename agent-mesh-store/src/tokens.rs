//! Where an endpoint token lives on disk.
//!
//! A token authenticates a process as an endpoint, so it goes to a file only its owner can read
//! and never to argv, an environment value, or a log line — the environment carries the *path*
//! (`AGENT_MESH_TOKEN_FILE`), which is not itself a secret.
//!
//! This lives in the store rather than in `vvagent` because the CLI is no longer the only thing
//! that binds an endpoint: the Python bindings do too, and a second copy of these permissions is
//! how two of them end up with two notions of owner-only.

use std::io::Write;
use std::path::{Path, PathBuf};

use agent_mesh_core::{ErrorCode, MeshError, Opaque, Result};

fn io(err: std::io::Error) -> MeshError {
    MeshError::new(ErrorCode::Io, err.to_string())
}

/// The owner-only directory tokens live in, created if it is missing.
///
/// Runtime state, not durable state: a token is only good for the incarnation that minted it, so
/// it belongs beside the socket rather than beside the database.
pub fn directory() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("TMPDIR").map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("vivido").join("agent-mesh").join("tokens");
    #[cfg(windows)]
    crate::windows::reject_reparse_points(&dir)?;
    std::fs::create_dir_all(&dir).map_err(io)?;
    owner_only(&dir, 0o700)?;
    Ok(dir)
}

/// Where this incarnation's token file sits. Named by incarnation, so a replacement process never
/// reads its predecessor's secret.
pub fn path(endpoint: &Opaque, incarnation: &Opaque) -> Result<PathBuf> {
    Ok(directory()?.join(format!("{endpoint}.{incarnation}")))
}

/// Write a freshly minted token, failing rather than overwriting an existing file.
pub fn write(endpoint: &Opaque, incarnation: &Opaque, token: &str) -> Result<PathBuf> {
    let path = path(endpoint, incarnation)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(io)?;
    owner_only(&path, 0o600)?;
    file.write_all(token.as_bytes()).map_err(io)?;
    Ok(path)
}

/// Read a token back, checking on Windows that the file really is owner-only.
pub fn read(path: &Path) -> Result<String> {
    #[cfg(windows)]
    crate::windows::owner_only(path)?;
    let token = std::fs::read_to_string(path).map_err(|err| {
        MeshError::new(
            ErrorCode::NotAuthorized,
            format!("cannot read the endpoint token file: {err}"),
        )
    })?;
    Ok(token.trim().to_owned())
}

/// Remove a token file. A missing file is not an error: unbinding twice is normal.
pub fn remove(endpoint: &Opaque, incarnation: &Opaque) -> Result<()> {
    let _ = std::fs::remove_file(path(endpoint, incarnation)?);
    Ok(())
}

#[cfg(unix)]
fn owner_only(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(io)
}

#[cfg(windows)]
fn owner_only(path: &Path, _mode: u32) -> Result<()> {
    crate::windows::owner_only(path)
}
