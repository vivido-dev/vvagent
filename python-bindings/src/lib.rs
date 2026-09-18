//! Private PyO3 extension for the public `vvagent` Python package.
//!
//! The mesh has had one client since it existed: the `vvagent` CLI. Every runtime that wanted to
//! send a message spawned a process and parsed its JSON. This binds the same store directly, so a
//! Python agent can bind, send, claim, reply and wait in-process.
//!
//! Two invariants the CLI holds are held here too, because they are what make the mesh safe:
//!
//! * A [`Caller`] is only ever produced by the store. Python cannot construct one, so it cannot
//!   assert an identity it does not hold.
//! * An endpoint token never crosses this boundary. `bind` writes it to an owner-only file and
//!   returns the *path*; nothing here returns, logs, or reprs the secret itself.

// These are Python keyword arguments, not a Rust signature anyone calls positionally. Splitting
// `send` into a config struct would only move the same eight names one line further away.
#![allow(clippy::too_many_arguments)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use agent_mesh_core::time::now_ms;
use agent_mesh_core::{
    Address, AgentState, Alias, Draft, Endpoint, ErrorCode, Kind, Locator, MediaBinding, MeshError,
    Opaque, Origin, Outcome, PaneRef, Ref, RuntimeKind, Selector, State, resolve,
};
use agent_mesh_store::{Binding, Caller, Message, Store, tokens};
use pyo3::create_exception;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule, PyString};

create_exception!(_native, MeshFailure, PyOSError);

const ENV_ENDPOINT: &str = "AGENT_MESH_ENDPOINT";
const ENV_TOKEN_FILE: &str = "AGENT_MESH_TOKEN_FILE";

/// An open mailbox.
///
/// One SQLite connection, guarded so two Python threads cannot enter it at once. The mesh has no
/// daemon: concurrency between *processes* is SQLite's job, and this mutex only covers the fact
/// that a `Connection` is not `Sync`.
#[pyclass(name = "Store", module = "vvagent._native")]
struct PyStore {
    inner: Mutex<Store>,
    path: PathBuf,
}

#[pymethods]
impl PyStore {
    #[getter]
    fn path(&self) -> String {
        self.path.display().to_string()
    }

    fn __repr__(&self) -> String {
        format!("<vvagent.Store path={:?}>", self.path.display())
    }
}

/// An authenticated identity.
///
/// Opaque on purpose: there is no constructor and no way to edit one. The only way to hold an
/// agent caller is to have presented a valid endpoint token.
#[pyclass(name = "Caller", module = "vvagent._native")]
struct PyCaller {
    inner: Caller,
}

#[pymethods]
impl PyCaller {
    #[getter]
    fn principal(&self) -> &'static str {
        self.inner.principal.kind.as_str()
    }

    #[getter]
    fn endpoint_id(&self) -> Option<String> {
        self.inner
            .principal
            .endpoint_id
            .as_ref()
            .map(|id| id.to_string())
    }

    #[getter]
    fn incarnation_id(&self) -> Option<String> {
        self.inner
            .principal
            .incarnation_id
            .as_ref()
            .map(|id| id.to_string())
    }

    #[getter]
    fn scope(&self) -> Option<String> {
        self.inner.scope.as_ref().map(|id| id.to_string())
    }

    /// No token, and no field that could carry one. An identity is safe to print; the secret that
    /// proved it is not, and never reached this object.
    fn __repr__(&self) -> String {
        format!(
            "<vvagent.Caller principal='{}' endpoint={}>",
            self.inner.principal.kind.as_str(),
            match &self.inner.principal.endpoint_id {
                Some(id) => format!("'{id}'"),
                None => "None".into(),
            }
        )
    }
}

// -------------------------------------------------------------------------------------------
// Opening and identity
// -------------------------------------------------------------------------------------------

#[pyfunction]
#[pyo3(signature = (path = None))]
fn open_store(py: Python<'_>, path: Option<PathBuf>) -> PyResult<PyStore> {
    let store = py.detach(|| match path {
        Some(path) => Store::open(path),
        None => Store::open_default(),
    });
    let store = store.map_err(|err| mesh_error(py, &err))?;
    let path = store.path().to_path_buf();
    Ok(PyStore {
        inner: Mutex::new(store),
        path,
    })
}

/// The identity of this process, from the inherited endpoint token.
///
/// With no token this is the local user: a real principal with a durable mailbox, so a reply has
/// somewhere to land, but one that cannot claim to be an agent. Passing `endpoint`/`token_file`
/// explicitly is for a supervisor that bound the endpoint itself and has not yet exec'd a child.
#[pyfunction]
#[pyo3(signature = (store, endpoint = None, token_file = None))]
fn authenticate(
    py: Python<'_>,
    store: &PyStore,
    endpoint: Option<String>,
    token_file: Option<PathBuf>,
) -> PyResult<PyCaller> {
    let endpoint = endpoint.or_else(|| std::env::var(ENV_ENDPOINT).ok());
    let token_file = token_file.or_else(|| std::env::var_os(ENV_TOKEN_FILE).map(PathBuf::from));
    let mut guard = lock(py, &store.inner)?;
    let caller = match (endpoint, token_file) {
        (Some(endpoint), Some(token_file)) => {
            let endpoint = Opaque::parse(&endpoint).map_err(|err| mesh_error(py, &err))?;
            let token = tokens::read(&token_file).map_err(|err| mesh_error(py, &err))?;
            guard.authenticate(&endpoint, &token)
        }
        _ => guard.ensure_local_user(),
    };
    Ok(PyCaller {
        inner: caller.map_err(|err| mesh_error(py, &err))?,
    })
}

/// Bind an agent endpoint and return the durable slot plus the path to its token file.
///
/// The token itself is deliberately not returned. Hand the child `AGENT_MESH_ENDPOINT` and
/// `AGENT_MESH_TOKEN_FILE`; a path in the environment is not a secret, and a token in argv is.
#[pyfunction]
#[pyo3(signature = (store, *, runtime, instance_id, alias = None, provider = None, instance_name = None, address = None))]
fn bind(
    py: Python<'_>,
    store: &PyStore,
    runtime: &str,
    instance_id: &str,
    alias: Option<&str>,
    provider: Option<String>,
    instance_name: Option<String>,
    address: Option<&str>,
) -> PyResult<Py<PyDict>> {
    let binding = Binding {
        alias: alias
            .map(Alias::parse)
            .transpose()
            .map_err(|err| mesh_error(py, &err))?,
        provider,
        locator: Locator {
            kind: RuntimeKind::parse(runtime).map_err(|err| mesh_error(py, &err))?,
            runtime_instance_id: Opaque::parse(instance_id).map_err(|err| mesh_error(py, &err))?,
            instance_name,
            address: address
                .map(Address::parse)
                .transpose()
                .map_err(|err| mesh_error(py, &err))?,
        },
    };
    let bound = {
        let mut guard = lock(py, &store.inner)?;
        guard.bind(&binding).map_err(|err| mesh_error(py, &err))?
    };
    let token_file = tokens::write(&bound.endpoint_id, &bound.incarnation_id, &bound.token)
        .map_err(|err| mesh_error(py, &err))?;

    let result = PyDict::new(py);
    result.set_item("endpoint_id", bound.endpoint_id.as_str())?;
    result.set_item("incarnation_id", bound.incarnation_id.as_str())?;
    result.set_item("rebound", bound.rebound)?;
    result.set_item("token_file", token_file.display().to_string())?;
    Ok(result.unbind())
}

#[pyfunction]
fn unbind(py: Python<'_>, store: &PyStore, endpoint: &str, incarnation: &str) -> PyResult<()> {
    let endpoint = Opaque::parse(endpoint).map_err(|err| mesh_error(py, &err))?;
    let incarnation = Opaque::parse(incarnation).map_err(|err| mesh_error(py, &err))?;
    lock(py, &store.inner)?
        .unbind(&endpoint, &incarnation)
        .map_err(|err| mesh_error(py, &err))?;
    tokens::remove(&endpoint, &incarnation).map_err(|err| mesh_error(py, &err))
}

#[pyfunction]
fn set_state(py: Python<'_>, store: &PyStore, endpoint: &str, state: &str) -> PyResult<i64> {
    let endpoint = Opaque::parse(endpoint).map_err(|err| mesh_error(py, &err))?;
    let state = parse_agent_state(py, state)?;
    lock(py, &store.inner)?
        .set_state(&endpoint, state)
        .map_err(|err| mesh_error(py, &err))
}

// -------------------------------------------------------------------------------------------
// Addressing
// -------------------------------------------------------------------------------------------

#[pyfunction]
fn list_endpoints(py: Python<'_>, store: &PyStore) -> PyResult<Py<PyList>> {
    let endpoints = lock(py, &store.inner)?
        .list_endpoints()
        .map_err(|err| mesh_error(py, &err))?;
    let rows = PyList::empty(py);
    for endpoint in &endpoints {
        rows.append(endpoint_dict(py, endpoint)?)?;
    }
    Ok(rows.unbind())
}

/// Turn what a caller typed into exactly one endpoint.
///
/// Ambiguity is an error, never a guess: two sessions may both hold an agent called `reviewer`,
/// and a bare `p2` is both a legal alias and a legal address. The caller's own neighbourhood is
/// preferred, and where that does not settle it the error carries the candidates to retype.
#[pyfunction]
fn resolve_selector(
    py: Python<'_>,
    store: &PyStore,
    caller: &PyCaller,
    selector: &str,
) -> PyResult<Py<PyDict>> {
    let selector = Selector::parse(selector).map_err(|err| mesh_error(py, &err))?;
    let guard = lock(py, &store.inner)?;
    let endpoints = guard.list_endpoints().map_err(|err| mesh_error(py, &err))?;
    let here = caller
        .inner
        .principal
        .endpoint_id
        .as_ref()
        .and_then(|id| guard.endpoint(id).ok())
        .and_then(|endpoint| endpoint.locator.address);
    let found = resolve(
        &selector,
        &endpoints,
        Origin {
            scope: caller.inner.scope.as_ref(),
            address: here.as_ref(),
            endpoint: caller.inner.principal.endpoint_id.as_ref(),
        },
    )
    .map_err(|err| mesh_error(py, &err))?;
    endpoint_dict(py, found)
}

// -------------------------------------------------------------------------------------------
// Sending and receiving
// -------------------------------------------------------------------------------------------

#[pyfunction]
#[pyo3(signature = (store, caller, *, to, kind, text, idempotency_key, subject = None, refs = None, reply_to = None, outcome = None, expires_in_ms = None))]
fn send(
    py: Python<'_>,
    store: &PyStore,
    caller: &PyCaller,
    to: &str,
    kind: &str,
    text: String,
    idempotency_key: String,
    subject: Option<String>,
    refs: Option<&Bound<'_, PyList>>,
    reply_to: Option<&str>,
    outcome: Option<&str>,
    expires_in_ms: Option<i64>,
) -> PyResult<Py<PyDict>> {
    let draft = Draft {
        to: Opaque::parse(to).map_err(|err| mesh_error(py, &err))?,
        kind: Kind::parse(kind).map_err(|err| mesh_error(py, &err))?,
        reply_to: reply_to
            .map(Opaque::parse)
            .transpose()
            .map_err(|err| mesh_error(py, &err))?,
        outcome: outcome
            .map(Outcome::parse)
            .transpose()
            .map_err(|err| mesh_error(py, &err))?,
        subject,
        text,
        refs: parse_refs(py, refs)?,
        idempotency_key,
        expires_in_ms,
    };
    let message = lock(py, &store.inner)?
        .send(&caller.inner, &draft)
        .map_err(|err| mesh_error(py, &err))?;
    message_dict(py, &message)
}

#[pyfunction]
#[pyo3(signature = (store, endpoint, states = None, limit = 64))]
fn inbox(
    py: Python<'_>,
    store: &PyStore,
    endpoint: &str,
    states: Option<Vec<String>>,
    limit: usize,
) -> PyResult<Py<PyList>> {
    let endpoint = Opaque::parse(endpoint).map_err(|err| mesh_error(py, &err))?;
    let states = states
        .unwrap_or_default()
        .iter()
        .map(|state| State::parse(state))
        .collect::<agent_mesh_core::Result<Vec<_>>>()
        .map_err(|err| mesh_error(py, &err))?;
    let messages = lock(py, &store.inner)?
        .inbox(&endpoint, &states, limit)
        .map_err(|err| mesh_error(py, &err))?;
    let rows = PyList::empty(py);
    for message in &messages {
        rows.append(message_dict(py, message)?)?;
    }
    Ok(rows.unbind())
}

#[pyfunction]
#[pyo3(signature = (store, caller, lease_ms = None))]
fn claim(
    py: Python<'_>,
    store: &PyStore,
    caller: &PyCaller,
    lease_ms: Option<i64>,
) -> PyResult<Option<Py<PyDict>>> {
    let claimed = lock(py, &store.inner)?
        .claim(&caller.inner, lease_ms)
        .map_err(|err| mesh_error(py, &err))?;
    claimed
        .as_ref()
        .map(|message| message_dict(py, message))
        .transpose()
}

#[pyfunction]
#[pyo3(signature = (store, caller, *, request, outcome, text, idempotency_key, refs = None))]
fn respond(
    py: Python<'_>,
    store: &PyStore,
    caller: &PyCaller,
    request: &str,
    outcome: &str,
    text: &str,
    idempotency_key: &str,
    refs: Option<&Bound<'_, PyList>>,
) -> PyResult<Py<PyDict>> {
    let request = Opaque::parse(request).map_err(|err| mesh_error(py, &err))?;
    let outcome = Outcome::parse(outcome).map_err(|err| mesh_error(py, &err))?;
    let refs = parse_refs(py, refs)?;
    let response = lock(py, &store.inner)?
        .respond(
            &caller.inner,
            &request,
            outcome,
            text,
            refs,
            idempotency_key,
        )
        .map_err(|err| mesh_error(py, &err))?;
    message_dict(py, &response)
}

#[pyfunction]
fn response_for(py: Python<'_>, store: &PyStore, request: &str) -> PyResult<Option<Py<PyDict>>> {
    let request = Opaque::parse(request).map_err(|err| mesh_error(py, &err))?;
    let found = lock(py, &store.inner)?
        .response_for(&request)
        .map_err(|err| mesh_error(py, &err))?;
    found
        .as_ref()
        .map(|message| message_dict(py, message))
        .transpose()
}

#[pyfunction]
fn cancel(py: Python<'_>, store: &PyStore, caller: &PyCaller, request: &str) -> PyResult<String> {
    let request = Opaque::parse(request).map_err(|err| mesh_error(py, &err))?;
    let state = lock(py, &store.inner)?
        .cancel(&caller.inner, &request)
        .map_err(|err| mesh_error(py, &err))?;
    Ok(state.as_str().to_owned())
}

#[pyfunction]
fn sweep(py: Python<'_>, store: &PyStore) -> PyResult<(usize, usize)> {
    lock(py, &store.inner)?
        .sweep(now_ms())
        .map_err(|err| mesh_error(py, &err))
}

/// Block until a request is answered, cancelled, expired, or the deadline passes.
///
/// The poll loop runs with the GIL released and takes the store lock only for the moment it needs
/// it, so another Python thread can keep sending while this one waits. A timeout here never
/// mutates the request: a client giving up is not the same as the work stopping.
#[pyfunction]
#[pyo3(signature = (store, request, *, timeout_ms, poll_ms = 100))]
fn wait(
    py: Python<'_>,
    store: &PyStore,
    request: &str,
    timeout_ms: i64,
    poll_ms: i64,
) -> PyResult<Py<PyDict>> {
    let request = Opaque::parse(request).map_err(|err| mesh_error(py, &err))?;
    let deadline = now_ms().saturating_add(timeout_ms);
    let poll = Duration::from_millis(poll_ms.clamp(10, 5_000) as u64);
    let inner = &store.inner;

    let target = request.clone();
    let outcome = py.detach(move || {
        loop {
            let step = {
                let mut guard = match inner.lock() {
                    Ok(guard) => guard,
                    Err(_) => {
                        return Err(MeshError::new(
                            ErrorCode::Io,
                            "the store lock was poisoned by a panic",
                        ));
                    }
                };
                // Any process may sweep; correctness never depends on a sweeper running.
                let _ = guard.sweep(now_ms());
                match guard.response_for(&target)? {
                    Some(response) => Some(Ok(response)),
                    None => {
                        let request = guard.message(&target)?;
                        let settled = matches!(
                            request.state,
                            State::Cancelled | State::Expired | State::Undeliverable
                        );
                        (settled || now_ms() >= deadline)
                            .then_some(Err((request.state, request.failure)))
                    }
                }
            };
            match step {
                Some(step) => return Ok(step),
                None => std::thread::sleep(poll),
            }
        }
    });

    let result = PyDict::new(py);
    result.set_item("request", request.as_str())?;
    match outcome.map_err(|err| mesh_error(py, &err))? {
        Ok(response) => {
            result.set_item("resolution", "response")?;
            result.set_item("message", message_dict(py, &response)?)?;
        }
        Err((state, failure)) => {
            result.set_item(
                "resolution",
                match state {
                    State::Cancelled => "cancelled",
                    State::Expired => "expired",
                    State::Undeliverable => "undeliverable",
                    _ => "timeout",
                },
            )?;
            result.set_item("state", state.as_str())?;
            if let Some(failure) = failure {
                result.set_item("failure", failure)?;
            }
        }
    }
    Ok(result.unbind())
}

// -------------------------------------------------------------------------------------------
// Conversion
// -------------------------------------------------------------------------------------------

fn message_dict(py: Python<'_>, message: &Message) -> PyResult<Py<PyDict>> {
    let from = PyDict::new(py);
    from.set_item("kind", message.from.kind.as_str())?;
    from.set_item(
        "endpoint_id",
        message.from.endpoint_id.as_ref().map(Opaque::as_str),
    )?;
    from.set_item(
        "incarnation_id",
        message.from.incarnation_id.as_ref().map(Opaque::as_str),
    )?;

    let refs = PyList::empty(py);
    for reference in &message.refs {
        refs.append(ref_dict(py, reference)?)?;
    }

    let entry = PyDict::new(py);
    entry.set_item("message_id", message.message_id.as_str())?;
    entry.set_item("to", message.to_endpoint.as_str())?;
    entry.set_item("from", from)?;
    entry.set_item("kind", message.kind.as_str())?;
    entry.set_item("conversation_id", message.conversation_id.as_str())?;
    entry.set_item("reply_to", message.reply_to.as_ref().map(Opaque::as_str))?;
    entry.set_item("outcome", message.outcome.map(Outcome::as_str))?;
    entry.set_item("recipient_sequence", message.recipient_sequence)?;
    entry.set_item("state", message.state.as_str())?;
    entry.set_item("subject", message.subject.as_deref())?;
    entry.set_item("text", &message.text)?;
    entry.set_item("refs", refs)?;
    entry.set_item("created_at_ms", message.created_at_ms)?;
    entry.set_item("expires_at_ms", message.expires_at_ms)?;
    Ok(entry.unbind())
}

fn endpoint_dict(py: Python<'_>, endpoint: &Endpoint) -> PyResult<Py<PyDict>> {
    let locator = PyDict::new(py);
    locator.set_item("runtime", endpoint.locator.kind.as_str())?;
    locator.set_item(
        "runtime_instance_id",
        endpoint.locator.runtime_instance_id.as_str(),
    )?;
    locator.set_item("instance_name", endpoint.locator.instance_name.as_deref())?;
    locator.set_item(
        "address",
        endpoint
            .locator
            .address
            .as_ref()
            .map(|address| address.to_string()),
    )?;

    let entry = PyDict::new(py);
    entry.set_item("endpoint_id", endpoint.endpoint_id.as_str())?;
    entry.set_item(
        "incarnation_id",
        endpoint.incarnation_id.as_ref().map(Opaque::as_str),
    )?;
    entry.set_item("alias", endpoint.alias.as_ref().map(Alias::as_str))?;
    entry.set_item("provider", endpoint.provider.as_deref())?;
    entry.set_item("locator", locator)?;
    entry.set_item("online", endpoint.online)?;
    entry.set_item("state", endpoint.state.as_str())?;
    entry.set_item("state_generation", endpoint.state_generation)?;
    entry.set_item("pending", endpoint.pending)?;
    Ok(entry.unbind())
}

fn ref_dict(py: Python<'_>, reference: &Ref) -> PyResult<Py<PyDict>> {
    let entry = PyDict::new(py);
    match reference {
        Ref::File {
            path,
            sha256,
            bytes,
            host,
        } => {
            entry.set_item("kind", "file")?;
            entry.set_item("path", path)?;
            entry.set_item("sha256", sha256.as_deref())?;
            entry.set_item("bytes", bytes)?;
            // The peer whose filesystem the path names; absent for this host.
            entry.set_item("host", host.as_ref().map(Opaque::as_str))?;
        }
        Ref::Pane {
            runtime_instance_id,
            locator,
        } => {
            entry.set_item("kind", "pane")?;
            entry.set_item("runtime_instance_id", runtime_instance_id.as_str())?;
            entry.set_item("runtime", locator.runtime.as_str())?;
            entry.set_item("workspace", locator.workspace.as_deref())?;
            entry.set_item("tab", locator.tab.as_deref())?;
            entry.set_item("pane_id", locator.pane_id)?;
        }
        Ref::Media {
            runtime_instance_id,
            resource_id,
            binding,
        } => {
            entry.set_item("kind", "media")?;
            entry.set_item("runtime_instance_id", runtime_instance_id.as_str())?;
            entry.set_item("resource_id", resource_id)?;
            entry.set_item("binding", binding.as_str())?;
        }
    }
    Ok(entry.unbind())
}

fn parse_refs(py: Python<'_>, refs: Option<&Bound<'_, PyList>>) -> PyResult<Vec<Ref>> {
    let Some(refs) = refs else {
        return Ok(Vec::new());
    };
    let mut parsed = Vec::with_capacity(refs.len());
    for item in refs.iter() {
        parsed.push(parse_ref(py, item.cast::<PyDict>()?)?);
    }
    Ok(parsed)
}

fn parse_ref(py: Python<'_>, item: &Bound<'_, PyDict>) -> PyResult<Ref> {
    let kind: String = required(item, "kind")?.extract()?;
    let reference = match kind.as_str() {
        "file" => Ref::File {
            path: required(item, "path")?.extract()?,
            sha256: optional(item, "sha256")?
                .map(|value| value.extract::<String>())
                .transpose()?,
            bytes: optional(item, "bytes")?
                .map(|value| value.extract::<u64>())
                .transpose()?,
            // Only a bridge says a file is on another host.
            host: None,
        },
        "pane" => Ref::Pane {
            runtime_instance_id: opaque(
                py,
                &required(item, "runtime_instance_id")?.extract::<String>()?,
            )?,
            locator: PaneRef {
                runtime: RuntimeKind::parse(&required(item, "runtime")?.extract::<String>()?)
                    .map_err(|err| mesh_error(py, &err))?,
                workspace: optional(item, "workspace")?
                    .map(|value| value.extract::<String>())
                    .transpose()?,
                tab: optional(item, "tab")?
                    .map(|value| value.extract::<String>())
                    .transpose()?,
                pane_id: optional(item, "pane_id")?
                    .map(|value| value.extract::<u64>())
                    .transpose()?,
            },
        },
        "media" => Ref::Media {
            runtime_instance_id: opaque(
                py,
                &required(item, "runtime_instance_id")?.extract::<String>()?,
            )?,
            resource_id: required(item, "resource_id")?.extract()?,
            binding: MediaBinding::parse(&required(item, "binding")?.extract::<String>()?)
                .map_err(|err| mesh_error(py, &err))?,
        },
        other => {
            return Err(mesh_error(
                py,
                &MeshError::new(
                    ErrorCode::InvalidRequest,
                    format!("a reference is `file`, `pane` or `media`, not {other:?}"),
                ),
            ));
        }
    };
    reference.validate().map_err(|err| mesh_error(py, &err))?;
    Ok(reference)
}

fn required<'py>(item: &Bound<'py, PyDict>, key: &str) -> PyResult<Bound<'py, PyAny>> {
    item.get_item(key)?.ok_or_else(|| {
        pyo3::exceptions::PyKeyError::new_err(format!("a reference needs a `{key}`"))
    })
}

/// A key that may be absent or explicitly `None`. Both mean "not supplied": a caller building a
/// reference from a dict of optional fields should not have to delete the empty ones.
fn optional<'py>(item: &Bound<'py, PyDict>, key: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
    Ok(item.get_item(key)?.filter(|value| !value.is_none()))
}

fn opaque(py: Python<'_>, value: &str) -> PyResult<Opaque> {
    Opaque::parse(value).map_err(|err| mesh_error(py, &err))
}

fn parse_agent_state(py: Python<'_>, state: &str) -> PyResult<AgentState> {
    match state {
        "unknown" => Ok(AgentState::Unknown),
        "idle" => Ok(AgentState::Idle),
        "working" => Ok(AgentState::Working),
        "blocked" => Ok(AgentState::Blocked),
        "offline" => Ok(AgentState::Offline),
        other => Err(mesh_error(
            py,
            &MeshError::new(
                ErrorCode::InvalidRequest,
                format!("unknown agent state `{other}`"),
            ),
        )),
    }
}

fn lock<'a>(py: Python<'_>, mutex: &'a Mutex<Store>) -> PyResult<MutexGuard<'a, Store>> {
    mutex.lock().map_err(|_| {
        mesh_error(
            py,
            &MeshError::new(ErrorCode::Io, "the store lock was poisoned by a panic"),
        )
    })
}

/// Carry the typed error code across the boundary.
///
/// The code is contract and the message is for humans, so both survive: `err.code` is what a
/// caller branches on, and it stays a string rather than becoming a Python enum nobody imports.
fn mesh_error(py: Python<'_>, error: &MeshError) -> PyErr {
    let raised = MeshFailure::new_err(error.to_string());
    let value = raised.value(py);
    let candidates = PyList::empty(py);
    for candidate in &error.candidates {
        let _ = candidates.append(PyString::new(py, candidate));
    }
    let _ = value.setattr("code", error.code.as_str());
    let _ = value.setattr("message", error.message.as_str());
    let _ = value.setattr("candidates", candidates);
    raised
}

#[pymodule]
fn _native(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("MeshFailure", py.get_type::<MeshFailure>())?;
    module.add_class::<PyStore>()?;
    module.add_class::<PyCaller>()?;
    module.add_function(wrap_pyfunction!(open_store, module)?)?;
    module.add_function(wrap_pyfunction!(authenticate, module)?)?;
    module.add_function(wrap_pyfunction!(bind, module)?)?;
    module.add_function(wrap_pyfunction!(unbind, module)?)?;
    module.add_function(wrap_pyfunction!(set_state, module)?)?;
    module.add_function(wrap_pyfunction!(list_endpoints, module)?)?;
    module.add_function(wrap_pyfunction!(resolve_selector, module)?)?;
    module.add_function(wrap_pyfunction!(send, module)?)?;
    module.add_function(wrap_pyfunction!(inbox, module)?)?;
    module.add_function(wrap_pyfunction!(claim, module)?)?;
    module.add_function(wrap_pyfunction!(respond, module)?)?;
    module.add_function(wrap_pyfunction!(response_for, module)?)?;
    module.add_function(wrap_pyfunction!(cancel, module)?)?;
    module.add_function(wrap_pyfunction!(sweep, module)?)?;
    module.add_function(wrap_pyfunction!(wait, module)?)?;
    Ok(())
}
