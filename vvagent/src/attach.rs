//! Handing files to agents, including agents on other hosts (`docs/vvagent-inter-host-plan.md` §7).
//!
//! The mesh never carries file bytes. For a local recipient an attachment is a reference with a
//! length and a SHA-256. For a remote one the file first crosses by `file-drop-v1` — Vivido's
//! `drop-file` on the window whose `vvssh` session carries the peer's bridge — and the message
//! then refers to the verified copy on the recipient's host.
//!
//! Order matters. The file is hashed here first, so a copy that does not match what this process
//! read is caught. Each copy is recorded under the send's idempotency key before the message is
//! enqueued, so a retried send reuses it instead of dropping the file again. And if the enqueue
//! fails after files were copied, the error says where they went: nothing is left behind silently,
//! and `file-drop-v1` never deletes a committed file.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use agent_mesh_core::{
    DEFAULT_MAX_ATTACHMENT_BYTES, Endpoint, ErrorCode, MAX_ATTACHMENTS, MAX_INLINE_VERIFY_BYTES,
    MeshError, PrincipalKind, Ref, Result, RuntimeKind, looks_absolute_anywhere,
};
use agent_mesh_store::{Caller, LeaseAnchor, Peer, RecordedAttachment, Store};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// A local file, read and hashed once.
#[derive(Debug, Clone)]
pub struct Local {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
}

/// What attaching produced: the references to add, and the remote copies made along the way.
#[derive(Debug, Default)]
pub struct Attached {
    pub refs: Vec<Ref>,
    /// `(peer label, remote path)` for every copy that now exists on a peer.
    pub copied: Vec<(String, String)>,
}

impl Attached {
    /// Say where the copies went, on an error that happened after they were made.
    pub fn explain(&self, err: MeshError) -> MeshError {
        if self.copied.is_empty() {
            return err;
        }
        let places: Vec<String> = self
            .copied
            .iter()
            .map(|(peer, path)| format!("{path} on {peer}"))
            .collect();
        MeshError::new(
            err.code,
            format!(
                "{} (already copied: {}; retry with the same idempotency key to reuse them)",
                err.message,
                places.join(", ")
            ),
        )
    }
}

/// Attach `paths` to a message from `caller` to `target`.
pub fn attach(
    store: &mut Store,
    caller: &Caller,
    target: &Endpoint,
    key: &str,
    paths: &[String],
    max_bytes: Option<u64>,
) -> Result<Attached> {
    if paths.is_empty() {
        return Ok(Attached::default());
    }
    if paths.len() > MAX_ATTACHMENTS {
        return Err(invalid(format!(
            "a message carries at most {MAX_ATTACHMENTS} attachments"
        )));
    }
    if let Some(endpoint) = &caller.principal.endpoint_id
        && caller.principal.kind == PrincipalKind::Agent
        && !store.policy(endpoint)?.attach
    {
        return Err(MeshError::new(
            ErrorCode::NotAuthorized,
            "attachments are turned off for this agent (`vvagent policy attach allow`)",
        ));
    }
    let max_bytes = max_bytes.unwrap_or(DEFAULT_MAX_ATTACHMENT_BYTES);
    let local = paths
        .iter()
        .map(|path| read(Path::new(path), max_bytes))
        .collect::<Result<Vec<_>>>()?;

    if target.locator.kind != RuntimeKind::Peer {
        // Same host: nothing to copy. The reference is the file itself, with what it held.
        return Ok(Attached {
            refs: local
                .iter()
                .map(|file| file_ref(file.path.to_string_lossy().into_owned(), file, None))
                .collect(),
            copied: Vec::new(),
        });
    }

    let proxy = store.proxy(&target.endpoint_id)?;
    let peer = store.peer_by_id(&proxy.peer_id)?;
    let anchor = carrier(&peer, caller, store)?;
    let mut attached = Attached::default();
    for (position, file) in local.iter().enumerate() {
        let copy = match store.recorded_attachment(caller, key, position)? {
            Some(recorded)
                if recorded.peer_id == peer.peer_id
                    && recorded.sha256 == file.sha256
                    && recorded.bytes == file.bytes =>
            {
                recorded
            }
            _ => {
                let copy = drop_file(&anchor, &peer, file).map_err(|err| attached.explain(err))?;
                store.record_attachment(caller, key, position, &proxy.endpoint_id, &copy)?;
                copy
            }
        };
        attached
            .copied
            .push((peer.label.to_string(), copy.remote_path.clone()));
        attached
            .refs
            .push(file_ref(copy.remote_path, file, Some(peer.peer_id.clone())));
    }
    Ok(attached)
}

fn file_ref(path: String, file: &Local, host: Option<agent_mesh_core::Opaque>) -> Ref {
    Ref::File {
        path,
        sha256: Some(file.sha256.clone()),
        bytes: Some(file.bytes),
        host,
    }
}

/// Open a regular file — not a link — and hash it, within `max_bytes`.
pub fn read(path: &Path, max_bytes: u64) -> Result<Local> {
    let path = std::path::absolute(path)
        .map_err(|err| invalid(format!("cannot resolve {}: {err}", path.display())))?;
    let kind = std::fs::symlink_metadata(&path)
        .map_err(|err| invalid(format!("cannot attach {}: {err}", path.display())))?;
    if !kind.file_type().is_file() {
        return Err(invalid(format!(
            "{} is not a regular file; only a regular file can be attached, and a link is not \
             followed",
            path.display()
        )));
    }
    if kind.len() > max_bytes {
        return Err(invalid(format!(
            "{} is {} bytes, over the {max_bytes}-byte attachment limit (`--max-attach-bytes`)",
            path.display(),
            kind.len()
        )));
    }
    let (bytes, sha256) = hash(&path, max_bytes)?;
    if bytes != kind.len() {
        return Err(MeshError::new(
            ErrorCode::AttachmentMismatch,
            format!("{} changed while it was being read", path.display()),
        ));
    }
    Ok(Local {
        path,
        bytes,
        sha256,
    })
}

fn hash(path: &Path, limit: u64) -> Result<(u64, String)> {
    let mut file = std::fs::File::open(path)
        .map_err(|err| invalid(format!("cannot read {}: {err}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| MeshError::new(ErrorCode::Io, err.to_string()))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > limit {
            return Err(invalid(format!("{} grew past the limit", path.display())));
        }
        hasher.update(&buffer[..read]);
    }
    Ok((total, agent_mesh_core::hex(&hasher.finalize())))
}

/// The window whose `vvssh` session carries this peer's bridge — the only place a file can cross.
///
/// The caller must sit in that window's runtime instance: the drop is made through the automation
/// channel this process inherited, and a window id means nothing in another instance.
fn carrier(peer: &Peer, caller: &Caller, store: &Store) -> Result<LeaseAnchor> {
    let now = agent_mesh_core::time::now_ms();
    let anchor = peer
        .lease
        .as_ref()
        .filter(|lease| lease.is_live(now))
        .and_then(|lease| lease.anchor.clone())
        .ok_or_else(|| {
            MeshError::new(
                ErrorCode::FileDropUnavailable,
                format!(
                    "no vvssh window carries the bridge to `{}`, and a file can only cross \
                     through one; connect with vvssh, or send the message without --attach",
                    peer.label
                ),
            )
        })?;
    let here = caller
        .principal
        .endpoint_id
        .as_ref()
        .and_then(|id| store.endpoint(id).ok())
        .filter(|endpoint| {
            matches!(
                endpoint.locator.kind,
                RuntimeKind::Vivido | RuntimeKind::Vivida
            )
        })
        .map(|endpoint| (endpoint.locator.kind, endpoint.locator.instance_name))
        .or_else(|| {
            let kind = RuntimeKind::parse(&std::env::var("AGENT_MESH_RUNTIME").ok()?).ok()?;
            Some((kind, std::env::var("AGENT_MESH_INSTANCE").ok()))
        });
    let same = here.as_ref().is_some_and(|(kind, instance)| {
        *kind == anchor.runtime && instance.as_deref() == Some(anchor.instance.as_str())
    });
    if !same {
        return Err(MeshError::new(
            ErrorCode::FileDropUnavailable,
            format!(
                "the bridge to `{}` runs in {}:{} window {}; attach from a pane of that instance",
                peer.label,
                anchor.runtime.as_str(),
                anchor.instance,
                anchor.window
            ),
        ));
    }
    Ok(anchor)
}

/// Copy one file through the anchor window with `drop-file`, and check what arrived.
fn drop_file(anchor: &LeaseAnchor, peer: &Peer, file: &Local) -> Result<RecordedAttachment> {
    let program = std::env::var_os("AGENT_MESH_DROP_CLIENT").map_or_else(
        || match anchor.runtime {
            RuntimeKind::Vivida => Ok("vivida".into()),
            RuntimeKind::Vivido => Ok("vivido".into()),
            other => Err(MeshError::new(
                ErrorCode::FileDropUnavailable,
                format!("a {} window cannot drop files", other.as_str()),
            )),
        },
        Ok,
    )?;
    let output = Command::new(&program)
        .arg("msg")
        .arg("drop-file")
        .arg(&file.path)
        .args([
            "--window-id",
            &anchor.window.to_string(),
            "--timeout",
            "10m",
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|err| {
            MeshError::new(
                ErrorCode::FileDropUnavailable,
                format!("cannot run `{}`: {err}", Path::new(&program).display()),
            )
        })?;
    if !output.status.success() {
        return Err(drop_error(&String::from_utf8_lossy(&output.stderr), peer));
    }
    let reply: Value = serde_json::from_slice(&output.stdout).map_err(|err| {
        MeshError::new(ErrorCode::Io, format!("unreadable drop-file reply: {err}"))
    })?;
    let name = file
        .path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !matches!(
        reply["result"].as_str(),
        Some("committed" | "already_committed")
    ) {
        return Err(MeshError::new(
            ErrorCode::Io,
            format!("{} reported {name} {}", peer.label, reply["result"]),
        ));
    }
    let remote_path = reply["remote_path"]
        .as_str()
        .filter(|path| {
            path.len() <= agent_mesh_core::MAX_PATH_BYTES
                && looks_absolute_anywhere(path)
                && !path.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            MeshError::new(
                ErrorCode::FileDropUnavailable,
                format!(
                    "{name} reached `{}`, but its receiver did not say where; update vvreceive \
                     there so it reports the committed path",
                    peer.label
                ),
            )
        })?
        .to_owned();
    let bytes = reply["bytes"].as_u64();
    let sha256 = reply["sha256"].as_str();
    if bytes != Some(file.bytes) || sha256 != Some(file.sha256.as_str()) {
        return Err(MeshError::new(
            ErrorCode::AttachmentMismatch,
            format!(
                "{name} changed while it was being sent: this side read {} bytes, `{}` received \
                 {}; the copy at {remote_path} is not what was attached",
                file.bytes,
                peer.label,
                bytes.map_or_else(|| "an unknown length".to_owned(), |bytes| bytes.to_string())
            ),
        ));
    }
    Ok(RecordedAttachment {
        peer_id: peer.peer_id.clone(),
        sha256: file.sha256.clone(),
        bytes: file.bytes,
        remote_path,
    })
}

/// Turn a `drop-file` failure into a mesh error an agent can act on.
fn drop_error(stderr: &str, peer: &Peer) -> MeshError {
    // `vivido msg` reports `…error: "<code>: <message>" …`.
    let detail = stderr
        .split_once("error: \"")
        .map_or(stderr, |(_, rest)| {
            rest.rsplit_once('"').map_or(rest, |(inner, _)| inner)
        })
        .trim();
    let code = detail.split_once(':').map_or(detail, |(code, _)| code);
    match code {
        "no_file_drop_binding" => MeshError::new(
            ErrorCode::FileDropUnavailable,
            format!(
                "the vvssh window to `{}` has no file-drop receiver; install vvreceive there, or \
                 check the session was not started with --no-receive-drops",
                peer.label
            ),
        ),
        "busy" => MeshError::new(
            ErrorCode::RateLimited,
            "that window's receiver is busy with other drops; try again shortly",
        ),
        _ => MeshError::new(
            ErrorCode::Io,
            format!(
                "drop-file failed: {}",
                detail.chars().take(300).collect::<String>()
            ),
        ),
    }
}

/// Check every file reference that names this host and carries a digest.
///
/// A reference is a claim, and the path and digest in it are peer-supplied: the file is opened
/// without following a final link, must be regular, and must match in length and SHA-256. Anything
/// else is `verified: false` with a reason — never a silent pass. Above `inline_limit` the file is
/// not hashed and the answer is `verified: null`.
pub fn verify(refs: &[Ref], inline_limit: u64) -> Vec<Value> {
    refs.iter()
        .filter_map(|reference| match reference {
            Ref::File {
                path,
                sha256: Some(sha256),
                bytes,
                host: None,
            } => Some(verify_one(path, sha256, *bytes, inline_limit)),
            _ => None,
        })
        .collect()
}

pub fn verify_inline(refs: &[Ref]) -> Vec<Value> {
    verify(refs, MAX_INLINE_VERIFY_BYTES)
}

fn verify_one(path: &str, sha256: &str, bytes: Option<u64>, inline_limit: u64) -> Value {
    let verdict = |verified: Value, reason: Option<&str>| {
        json!({
            "path": path,
            "bytes": bytes,
            "sha256": sha256,
            "verified": verified,
            "reason": reason,
        })
    };
    let Ok(kind) = std::fs::symlink_metadata(path) else {
        return verdict(Value::Bool(false), Some("missing"));
    };
    if !kind.file_type().is_file() {
        return verdict(Value::Bool(false), Some("not a regular file"));
    }
    if bytes.is_some_and(|bytes| bytes != kind.len()) {
        return verdict(Value::Bool(false), Some("length differs"));
    }
    if kind.len() > inline_limit {
        return verdict(
            Value::Null,
            Some("too large to verify inline; run `vvagent ref verify`"),
        );
    }
    match hash(Path::new(path), inline_limit) {
        Ok((_, actual)) if actual == sha256 => verdict(Value::Bool(true), None),
        Ok(_) => verdict(Value::Bool(false), Some("sha256 differs")),
        Err(_) => verdict(Value::Bool(false), Some("unreadable")),
    }
}

fn invalid(message: impl Into<String>) -> MeshError {
    MeshError::new(ErrorCode::InvalidRequest, message)
}
