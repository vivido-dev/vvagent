//! The durable agent-mesh mailbox.
//!
//! One SQLite database in WAL mode with `synchronous=FULL`, opened directly by every `vvagent`
//! process. There is no broker: SQLite's own transactions are what make concurrent unrelated
//! writers safe, which the M0 spike proved and `docs/agent-mesh-m0-results.md` §3.1 records.
//!
//! Every mutating operation is one `IMMEDIATE` transaction covering its idempotency check, policy
//! gate, quota check, sequence allocation, insert, counter update, and audit row together. A
//! partially applied send is not a state this module can produce.
//!
//! See `docs/agent-mesh-plan-final.md` §6–§9.

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_mesh_core::bridge::{Deliver, MAX_SELECTOR_BYTES, RefHost, WireRef};
use agent_mesh_core::time::now_ms;
use agent_mesh_core::{
    Address, Admit, AgentState, Alias, Capabilities, DEFAULT_CLAIM_LEASE_MS, Decision,
    DeliveryMode, Draft, Endpoint, ErrorCode, Gate, Kind, Locator, MAX_ENDPOINTS,
    MAX_PENDING_BYTES, MAX_PENDING_COUNT, MAX_REQUEST_LIFETIME_MS, MeshError, Opaque, Outcome,
    PEER_MAX_AUTO_TURNS_PER_MINUTE, PEER_MAX_INBOUND_PER_MINUTE, PeerLabel, Policy, Principal,
    PrincipalKind, RESERVED_BYTES, RESERVED_COUNT, Ref, Result, Rule, RuntimeKind, State,
    TeamScope, hex,
};
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior};

pub mod tokens;
#[cfg(windows)]
pub mod windows;

pub const SCHEMA_VERSION: i64 = 7;

/// The reserved runtime-instance id for the local user's own mailbox.
///
/// A person running `vvagent send` from a shell is a real principal and needs somewhere for the
/// answer to land — otherwise `send` works and `wait` could never succeed. This scope is fixed and
/// distinct from every derived runtime instance, so the local user is never mistaken for a
/// teammate by the team grant.
pub const LOCAL_USER_INSTANCE: &str = "00000000000000000000000000000001";
const LOCAL_USER_ALIAS: &str = "local-user";

const BUSY_TIMEOUT: Duration = Duration::from_secs(10);

fn sql(err: rusqlite::Error) -> MeshError {
    MeshError::new(ErrorCode::Io, format!("sqlite: {err}"))
}

fn io(err: std::io::Error) -> MeshError {
    MeshError::new(ErrorCode::Io, err.to_string())
}

fn not_found(what: &str) -> MeshError {
    MeshError::new(ErrorCode::NotFound, format!("no such {what}"))
}

/// An authenticated caller. Produced only by [`Store::authenticate`]; never deserialized from a
/// client, which is what stops a caller asserting an identity it does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub principal: Principal,
    /// The runtime instance the caller belongs to, when it is an agent.
    pub scope: Option<Opaque>,
}

impl Caller {
    /// A shell with no endpoint token. It can send, but it cannot claim to be an agent.
    pub fn local_user() -> Self {
        Self {
            principal: Principal {
                kind: PrincipalKind::LocalUser,
                endpoint_id: None,
                incarnation_id: None,
            },
            scope: None,
        }
    }
}

/// What a runtime supplies when it binds an agent endpoint.
#[derive(Debug, Clone)]
pub struct Binding {
    pub alias: Option<Alias>,
    pub provider: Option<String>,
    pub locator: Locator,
}

/// The result of binding: the durable slot plus the secret its child processes authenticate with.
#[derive(Debug, Clone)]
pub struct Bound {
    pub endpoint_id: Opaque,
    pub incarnation_id: Opaque,
    /// Give this to the child through an owner-only file, never through argv (plan §6.4).
    pub token: String,
    /// True when an existing slot was rebound rather than a new one created.
    pub rebound: bool,
}

/// One audit row. Metadata only: never a message body, never a payload digest (plan §9.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub at_ms: i64,
    pub message_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub operation: String,
    pub from_state: Option<String>,
    pub to_state: Option<String>,
    pub rule: Option<String>,
    pub bytes: i64,
    pub result: String,
}

/// A stored message, with everything the CLI needs to render an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub message_id: Opaque,
    pub to_endpoint: Opaque,
    pub from: Principal,
    pub kind: Kind,
    pub conversation_id: Opaque,
    pub reply_to: Option<Opaque>,
    pub outcome: Option<Outcome>,
    pub recipient_sequence: i64,
    pub state: State,
    pub subject: Option<String>,
    pub text: String,
    pub refs: Vec<Ref>,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    /// Why an `undeliverable` message could not be handed to its peer: an error code.
    pub failure: Option<String>,
    /// For mail from a peer: the originating host's own id for it.
    pub origin_message_id: Option<Opaque>,
}

/// A peer host this store exchanges mail with (`vvagent-inter-host-plan.md` §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub peer_id: Opaque,
    pub label: PeerLabel,
    /// The other store's id, pinned the first time this label connected.
    pub host_id: Opaque,
    /// Whether remote-originated work from this peer passes gates that admit trust.
    pub trusted: bool,
    pub lease: Option<Lease>,
}

/// The one bridge currently allowed to act for a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub owner: Opaque,
    pub expires_at_ms: i64,
    pub anchor: Option<LeaseAnchor>,
}

impl Lease {
    pub fn is_live(&self, now: i64) -> bool {
        self.expires_at_ms > now
    }
}

/// The window a bridge was launched from, so a sender can reach that window's Vivid session.
///
/// Held only while the lease is: a window id is a stable id, not a position, and it is never stored
/// as anyone's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseAnchor {
    pub runtime: RuntimeKind,
    pub instance: String,
    pub window: u32,
}

/// A local stand-in for one agent on a peer host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub endpoint_id: Opaque,
    pub peer_id: Opaque,
    pub remote_endpoint_id: Opaque,
    /// What the peer last said this agent is called and where it sits. For people only.
    pub display: Option<String>,
}

/// What forgetting a peer did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetiredPeer {
    pub proxies: usize,
    /// Outbound mail still waiting for the peer.
    pub undeliverable: usize,
    /// Inbound mail from the peer that no local agent had claimed yet.
    pub withdrawn: usize,
}

/// One file already handed to a peer for a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedAttachment {
    pub peer_id: Opaque,
    pub sha256: String,
    pub bytes: u64,
    pub remote_path: String,
}

/// A peer's answer to "what does this selector name on your host".
pub type Resolution = std::result::Result<(Opaque, Option<String>), MeshError>;

/// How long a question for a peer is worth asking, and how long an answer is kept.
pub const RESOLUTION_TIMEOUT_MS: i64 = 10_000;
const RESOLUTION_RETENTION_MS: i64 = 60_000;
/// Unanswered questions one peer may have waiting.
const MAX_PENDING_RESOLUTIONS: i64 = 64;

/// Longest `display` a peer may give a proxy. It is shown, never parsed.
pub const MAX_PROXY_DISPLAY_BYTES: usize = agent_mesh_core::MAX_DISPLAY_BYTES;

/// A queued message whose recipient could be woken, with the decision already made.
#[derive(Debug, Clone)]
pub struct Activatable {
    pub message: Message,
    pub endpoint_id: Opaque,
    pub capabilities: Capabilities,
    pub mode: DeliveryMode,
    pub decision: Decision,
}

pub struct Store {
    conn: Connection,
    path: PathBuf,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("path", &self.path).finish()
    }
}

impl Store {
    /// The default store location: `$XDG_STATE_HOME/vivido/agent-mesh/mesh.sqlite`.
    pub fn default_path() -> Result<PathBuf> {
        if let Some(explicit) = std::env::var_os("AGENT_MESH_DB") {
            return Ok(PathBuf::from(explicit));
        }
        let base = if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
            PathBuf::from(state)
        } else if cfg!(windows) && std::env::var_os("LOCALAPPDATA").is_some() {
            PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default())
        } else if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(".local").join("state")
        } else {
            return Err(MeshError::new(
                ErrorCode::Io,
                "neither AGENT_MESH_DB, XDG_STATE_HOME nor HOME is set",
            ));
        };
        Ok(base.join("vivido").join("agent-mesh").join("mesh.sqlite"))
    }

    /// Open or create the store.
    ///
    /// A file that exists but is not a database of this schema version is refused by name. It is
    /// never deleted, truncated, recreated, or migrated over.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        #[cfg(windows)]
        windows::reject_reparse_points(&path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
            set_owner_only_dir(parent)?;
        }
        // Validate and protect pre-existing database sidecars before SQLite reads any of them.
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut object = path.clone().into_os_string();
            object.push(suffix);
            let object = PathBuf::from(object);
            #[cfg(windows)]
            windows::reject_reparse_points(&object)?;
            if object.exists() {
                set_owner_only_file(&object)?;
            }
        }
        let conn = Connection::open(&path).map_err(sql)?;
        conn.busy_timeout(BUSY_TIMEOUT).map_err(sql)?;

        // Switching a new database into WAL takes a lock SQLite's busy handler does not wait on,
        // so two processes creating the store at once — a watcher and a command starting together
        // on a fresh machine — would see "database is locked". Wait for it as for any other lock.
        let started = std::time::Instant::now();
        let mode: String = loop {
            match conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0)) {
                Ok(mode) => break mode,
                Err(err)
                    if matches!(
                        err.sqlite_error_code(),
                        Some(
                            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                        )
                    ) && started.elapsed() < BUSY_TIMEOUT =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => {
                    return Err(MeshError::new(
                        ErrorCode::StoreCorrupt,
                        format!("{}: cannot enter WAL mode: {err}", path.display()),
                    ));
                }
            }
        };
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(MeshError::new(
                ErrorCode::StoreCorrupt,
                format!("{}: journal mode is {mode}, not WAL", path.display()),
            ));
        }
        // Durability before a `send` is acknowledged (plan guarantee §5.2.1). `NORMAL` would be
        // faster and would risk recently committed transactions on power loss; the guarantee says
        // durable, so the default says FULL.
        let synchronous = std::env::var("AGENT_MESH_SYNCHRONOUS").unwrap_or_else(|_| "FULL".into());
        let synchronous = synchronous.to_ascii_uppercase();
        if !matches!(synchronous.as_str(), "FULL" | "NORMAL") {
            return Err(MeshError::new(
                ErrorCode::InvalidRequest,
                "AGENT_MESH_SYNCHRONOUS must be FULL or NORMAL",
            ));
        }
        conn.pragma_update(None, "synchronous", synchronous.as_str())
            .map_err(sql)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(sql)?;

        let mut store = Self { conn, path };
        store.migrate()?;
        store.set_owner_only_files()?;
        Ok(store)
    }

    pub fn open_default() -> Result<Self> {
        Self::open(Self::default_path()?)
    }

    fn migrate(&mut self) -> Result<()> {
        let path = self.path.display().to_string();
        let corrupt = |what: &str, err: rusqlite::Error| {
            MeshError::new(ErrorCode::StoreCorrupt, format!("{path}: {what}: {err}"))
        };
        // Read and act on the version inside one IMMEDIATE transaction, so two processes opening an
        // old store at once cannot both decide to migrate it.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|err| corrupt("cannot lock for migration", err))?;
        let found: i64 = tx
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|err| corrupt("unreadable header", err))?;
        match found {
            0 => {
                let existing: i64 = tx
                    .query_row(
                        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='message'",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|err| corrupt("unreadable catalog", err))?;
                if existing != 0 {
                    return Err(MeshError::new(
                        ErrorCode::StoreCorrupt,
                        format!(
                            "{path}: a message table exists with no schema version; refusing to \
                             migrate over another program's database"
                        ),
                    ));
                }
                tx.execute_batch(SCHEMA).map_err(sql)?;
                apply_v5(&tx)?;
                apply_v6(&tx)?;
                apply_v7(&tx)?;
            }
            // Additive, one step at a time, in one transaction. A failure part-way rolls back to
            // the store the previous build still opens, never a hybrid neither build understands.
            4 => {
                apply_v5(&tx)?;
                apply_v6(&tx)?;
                apply_v7(&tx)?;
            }
            5 => {
                apply_v6(&tx)?;
                apply_v7(&tx)?;
            }
            6 => apply_v7(&tx)?,
            SCHEMA_VERSION => return Ok(()),
            _ => {
                return Err(MeshError::new(
                    ErrorCode::SchemaMismatch,
                    format!("{path}: schema version {found}, this build speaks {SCHEMA_VERSION}"),
                ));
            }
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(())
    }

    fn set_owner_only_files(&self) -> Result<()> {
        for suffix in ["", "-wal", "-shm"] {
            let mut candidate = self.path.clone().into_os_string();
            candidate.push(suffix);
            let candidate = PathBuf::from(candidate);
            if candidate.exists() {
                set_owner_only_file(&candidate)?;
            }
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    // -----------------------------------------------------------------------------------------
    // Endpoint lifecycle
    // -----------------------------------------------------------------------------------------

    /// Bind an agent endpoint, reusing the durable slot when one already answers to this alias in
    /// this runtime instance.
    ///
    /// Reuse is what makes an endpoint id survive a restart: the same alias in the same instance
    /// is the same logical agent slot, so its mailbox and pending work come back with it. Every
    /// bind mints a *new* incarnation, so a replacement process can never inherit its
    /// predecessor's claims.
    pub fn bind(&mut self, binding: &Binding) -> Result<Bound> {
        if binding.locator.kind == RuntimeKind::Peer {
            return Err(MeshError::new(
                ErrorCode::InvalidRequest,
                "a peer endpoint is a proxy for a remote agent; no local process binds one",
            ));
        }
        let now = now_ms();
        let mut token_bytes = [0u8; 32];
        getrandom::fill(&mut token_bytes).map_err(|err| {
            MeshError::new(ErrorCode::Io, format!("no OS entropy for a token: {err}"))
        })?;
        let token = hex(&token_bytes);
        let incarnation = Opaque::generate();

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;

        let existing: Option<String> = match &binding.alias {
            Some(alias) => tx
                .query_row(
                    "SELECT endpoint_id FROM endpoint
                     WHERE alias = ?1 AND runtime_instance_id = ?2",
                    (alias.as_str(), binding.locator.runtime_instance_id.as_str()),
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql)?,
            None => None,
        };

        let (endpoint_id, rebound) = match existing {
            Some(id) => (Opaque::parse(&id)?, true),
            None => {
                let count: i64 = tx
                    .query_row("SELECT count(*) FROM endpoint", [], |row| row.get(0))
                    .map_err(sql)?;
                if count >= MAX_ENDPOINTS {
                    return Err(MeshError::new(
                        ErrorCode::EndpointLimit,
                        format!("{MAX_ENDPOINTS} endpoints already registered"),
                    ));
                }
                (Opaque::generate(), false)
            }
        };

        let token_hash = hex(&sha256(token.as_bytes()));
        if rebound {
            tx.execute(
                "UPDATE endpoint SET incarnation_id=?2, token_hash=?3, provider=?4, online=1,
                        state='unknown', state_generation=state_generation+1,
                        instance_name=?5, address=?6, updated_at=?7
                 WHERE endpoint_id=?1",
                rusqlite::params![
                    endpoint_id.as_str(),
                    incarnation.as_str(),
                    token_hash,
                    binding.provider,
                    binding.locator.instance_name,
                    binding.locator.address.as_ref().map(Address::to_string),
                    now,
                ],
            )
            .map_err(sql)?;
        } else {
            tx.execute(
                "INSERT INTO endpoint (endpoint_id, incarnation_id, token_hash, alias, provider,
                                       runtime_kind, runtime_instance_id, instance_name,
                                       address, online, state, state_generation, next_sequence,
                                       pending_count, pending_bytes, policy_json, created_at,
                                       updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, 'unknown',
                         1, 1, 0, 0, NULL, ?10, ?10)",
                rusqlite::params![
                    endpoint_id.as_str(),
                    incarnation.as_str(),
                    token_hash,
                    binding.alias.as_ref().map(Alias::as_str),
                    binding.provider,
                    binding.locator.kind.as_str(),
                    binding.locator.runtime_instance_id.as_str(),
                    binding.locator.instance_name,
                    binding.locator.address.as_ref().map(Address::to_string),
                    now,
                ],
            )
            .map_err(sql)?;
        }

        audit(
            &tx,
            now,
            None,
            Some(endpoint_id.as_str()),
            if rebound { "rebind" } else { "bind" },
            None,
            None,
            None,
            0,
            "ok",
        )?;
        tx.commit().map_err(sql)?;

        Ok(Bound {
            endpoint_id,
            incarnation_id: incarnation,
            token,
            rebound,
        })
    }

    /// Release a binding. The endpoint goes offline; its mailbox and pending work survive.
    ///
    /// Scoped by incarnation so a late unbind from a replaced process cannot take its successor
    /// offline.
    pub fn unbind(&mut self, endpoint_id: &Opaque, incarnation: &Opaque) -> Result<()> {
        let now = now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let changed = tx
            .execute(
                "UPDATE endpoint SET online=0, state='offline', incarnation_id=NULL,
                        token_hash=NULL, state_generation=state_generation+1, updated_at=?3
                 WHERE endpoint_id=?1 AND incarnation_id=?2",
                (endpoint_id.as_str(), incarnation.as_str(), now),
            )
            .map_err(sql)?;
        if changed == 0 {
            // Not an error: a superseded incarnation unbinding is normal on a fast restart.
            audit(
                &tx,
                now,
                None,
                Some(endpoint_id.as_str()),
                "unbind",
                None,
                None,
                None,
                0,
                "stale_incarnation",
            )?;
        } else {
            // Claims held by the departing incarnation go back on the queue immediately rather
            // than waiting for their lease to lapse.
            tx.execute(
                "UPDATE message SET state='queued', claim_owner=NULL, claim_expires_at=NULL
                 WHERE to_endpoint=?1 AND state='claimed' AND claim_owner=?2",
                (endpoint_id.as_str(), incarnation.as_str()),
            )
            .map_err(sql)?;
            audit(
                &tx,
                now,
                None,
                Some(endpoint_id.as_str()),
                "unbind",
                None,
                None,
                None,
                0,
                "ok",
            )?;
        }
        tx.commit().map_err(sql)?;
        Ok(())
    }

    /// The local user's own durable mailbox, created on first use.
    ///
    /// The principal stays `LocalUser`: having a mailbox does not let a shell claim to be an
    /// agent. It only means a reply has somewhere to go.
    pub fn ensure_local_user(&mut self) -> Result<Caller> {
        let scope = Opaque::parse(LOCAL_USER_INSTANCE)?;
        let now = now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let existing: Option<(String, Option<String>)> = tx
            .query_row(
                "SELECT endpoint_id, incarnation_id FROM endpoint
                 WHERE alias=?1 AND runtime_instance_id=?2",
                (LOCAL_USER_ALIAS, scope.as_str()),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql)?;

        let (endpoint_id, incarnation) = match existing {
            Some((id, Some(incarnation))) => (Opaque::parse(&id)?, Opaque::parse(&incarnation)?),
            Some((id, None)) => {
                // Its binding was released; the mailbox is the same one either way.
                tx.execute(
                    "UPDATE endpoint SET incarnation_id=?1, online=1, updated_at=?2
                     WHERE endpoint_id=?1",
                    (&id, now),
                )
                .map_err(sql)?;
                let id = Opaque::parse(&id)?;
                (id.clone(), id)
            }
            None => {
                let id = Opaque::generate();
                tx.execute(
                    "INSERT INTO endpoint (endpoint_id, incarnation_id, token_hash, alias,
                                           provider, runtime_kind, runtime_instance_id,
                                           instance_name, address, online, state,
                                           state_generation, next_sequence, pending_count,
                                           pending_bytes, created_at, updated_at)
                     VALUES (?1, ?1, NULL, ?2, NULL, 'wrapper', ?3, 'local', NULL, 1, 'unknown',
                             1, 1, 0, 0, ?4, ?4)",
                    (id.as_str(), LOCAL_USER_ALIAS, scope.as_str(), now),
                )
                .map_err(sql)?;
                (id.clone(), id)
            }
        };
        tx.commit().map_err(sql)?;

        Ok(Caller {
            principal: Principal {
                kind: PrincipalKind::LocalUser,
                endpoint_id: Some(endpoint_id),
                incarnation_id: Some(incarnation),
            },
            scope: Some(scope),
        })
    }

    /// Authenticate a caller from its endpoint id and token.
    ///
    /// Constant-time comparison of the stored hash. Note the honest limit recorded in the plan
    /// §6.4: this is attribution among cooperating processes, not a boundary against a hostile
    /// process running as the same user.
    pub fn authenticate(&self, endpoint_id: &Opaque, token: &str) -> Result<Caller> {
        let row: Option<(Option<String>, Option<String>, String)> = self
            .conn
            .query_row(
                "SELECT token_hash, incarnation_id, runtime_instance_id FROM endpoint
                 WHERE endpoint_id=?1",
                [endpoint_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sql)?;
        let Some((Some(stored), incarnation, scope)) = row else {
            return Err(MeshError::new(
                ErrorCode::NotAuthorized,
                "that endpoint has no live binding",
            ));
        };
        let presented = hex(&sha256(token.as_bytes()));
        if !constant_time_eq(stored.as_bytes(), presented.as_bytes()) {
            return Err(MeshError::new(
                ErrorCode::NotAuthorized,
                "endpoint token does not match",
            ));
        }
        Ok(Caller {
            principal: Principal {
                kind: PrincipalKind::Agent,
                endpoint_id: Some(endpoint_id.clone()),
                incarnation_id: incarnation.as_deref().map(Opaque::parse).transpose()?,
            },
            scope: Some(Opaque::parse(&scope)?),
        })
    }

    /// Refuse an operation from a process that is no longer this endpoint's live binding.
    ///
    /// Authentication already rejects a superseded *token*, but a `Caller` obtained before a
    /// rebind is still a value a program can hold. Invariant: a replacement process never
    /// inherits its predecessor's claims, acknowledgements, or state authority.
    fn require_current_incarnation(
        &self,
        endpoint_id: &Opaque,
        incarnation: &Opaque,
    ) -> Result<()> {
        let current: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT incarnation_id FROM endpoint WHERE endpoint_id=?1",
                [endpoint_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;
        match current.flatten() {
            Some(live) if live == incarnation.as_str() => Ok(()),
            Some(_) => Err(MeshError::new(
                ErrorCode::ClaimLost,
                "this endpoint has been rebound; a superseded incarnation cannot act for it",
            )),
            None => Err(MeshError::new(
                ErrorCode::NotAuthorized,
                "this endpoint has no live binding",
            )),
        }
    }

    pub fn set_state(&mut self, endpoint_id: &Opaque, state: AgentState) -> Result<i64> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        tx.execute(
            "UPDATE endpoint SET state=?2, state_generation=state_generation+1, updated_at=?3
             WHERE endpoint_id=?1",
            (endpoint_id.as_str(), state.as_str(), now_ms()),
        )
        .map_err(sql)?;
        let generation: i64 = tx
            .query_row(
                "SELECT state_generation FROM endpoint WHERE endpoint_id=?1",
                [endpoint_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(generation)
    }

    /// Every endpoint on this host. Proxies for remote agents are listed by [`Self::list_proxies`]
    /// instead, so no local alias or address resolution can land on one.
    pub fn list_endpoints(&self) -> Result<Vec<Endpoint>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT endpoint_id, incarnation_id, alias, provider, runtime_kind,
                        runtime_instance_id, instance_name, address,
                        online, state, state_generation, pending_count
                 FROM endpoint WHERE runtime_kind != 'peer' ORDER BY alias, endpoint_id",
            )
            .map_err(sql)?;
        let rows = stmt.query_map([], read_endpoint).map_err(sql)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(sql)??);
        }
        Ok(out)
    }

    pub fn endpoint(&self, endpoint_id: &Opaque) -> Result<Endpoint> {
        self.conn
            .query_row(
                "SELECT endpoint_id, incarnation_id, alias, provider, runtime_kind,
                        runtime_instance_id, instance_name, address,
                        online, state, state_generation, pending_count
                 FROM endpoint WHERE endpoint_id=?1",
                [endpoint_id.as_str()],
                read_endpoint,
            )
            .optional()
            .map_err(sql)?
            .ok_or_else(|| not_found("endpoint"))?
    }

    pub fn policy(&self, endpoint_id: &Opaque) -> Result<Policy> {
        let stored: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT policy_json FROM endpoint WHERE endpoint_id=?1",
                [endpoint_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;
        match stored.flatten() {
            Some(json) => serde_json::from_str(&json).map_err(|err| {
                MeshError::new(ErrorCode::InvalidRequest, format!("stored policy: {err}"))
            }),
            None => Ok(Policy::default()),
        }
    }

    /// What this endpoint's provider was *established* to be able to do.
    ///
    /// Absent means nothing was established, which is not the same as "it probably has MCP". An
    /// endpoint with no recorded capabilities cannot be activated.
    pub fn capabilities(&self, endpoint_id: &Opaque) -> Result<Capabilities> {
        let stored: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT capabilities_json FROM endpoint WHERE endpoint_id=?1",
                [endpoint_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;
        match stored.flatten() {
            Some(json) => serde_json::from_str(&json).map_err(|err| {
                MeshError::new(
                    ErrorCode::InvalidRequest,
                    format!("stored capabilities: {err}"),
                )
            }),
            None => Ok(Capabilities::default()),
        }
    }

    /// Record what an adapter proved this endpoint's provider can do, for its exact version.
    pub fn set_capabilities(
        &mut self,
        endpoint_id: &Opaque,
        capabilities: &Capabilities,
    ) -> Result<()> {
        let json = serde_json::to_string(capabilities)
            .map_err(|err| MeshError::new(ErrorCode::InvalidRequest, err.to_string()))?;
        let changed = self
            .conn
            .execute(
                "UPDATE endpoint SET capabilities_json=?2, updated_at=?3 WHERE endpoint_id=?1",
                (endpoint_id.as_str(), json, now_ms()),
            )
            .map_err(sql)?;
        if changed == 0 {
            return Err(not_found("endpoint"));
        }
        Ok(())
    }

    /// Move an endpoint to a new position.
    ///
    /// Only the address changes: the endpoint id, its mailbox, its pending work, and everything
    /// holding that id are untouched. That is the whole point of an address being a locator —
    /// a window can be dragged to another space without any message losing its way.
    pub fn set_address(&mut self, endpoint_id: &Opaque, address: Option<&Address>) -> Result<()> {
        let changed = self
            .conn
            .execute(
                "UPDATE endpoint SET address=?2, updated_at=?3 WHERE endpoint_id=?1",
                (
                    endpoint_id.as_str(),
                    address.map(Address::to_string),
                    now_ms(),
                ),
            )
            .map_err(sql)?;
        if changed == 0 {
            return Err(not_found("endpoint"));
        }
        Ok(())
    }

    pub fn set_policy(&mut self, endpoint_id: &Opaque, policy: &Policy) -> Result<()> {
        let json = serde_json::to_string(policy)
            .map_err(|err| MeshError::new(ErrorCode::InvalidRequest, err.to_string()))?;
        let changed = self
            .conn
            .execute(
                "UPDATE endpoint SET policy_json=?2, updated_at=?3 WHERE endpoint_id=?1",
                (endpoint_id.as_str(), json, now_ms()),
            )
            .map_err(sql)?;
        if changed == 0 {
            return Err(not_found("endpoint"));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Sending
    // -----------------------------------------------------------------------------------------

    /// Accept one message durably, or refuse it with a typed error.
    ///
    /// One transaction covers idempotency, the enqueue gate, quotas, sequence allocation, the
    /// insert, the counter update, and the audit row.
    pub fn send(&mut self, caller: &Caller, draft: &Draft) -> Result<Message> {
        self.send_as(caller, draft, None)
    }

    /// `send`, recording the originating host's id for mail a bridge inserts.
    fn send_as(
        &mut self,
        caller: &Caller,
        draft: &Draft,
        origin: Option<&Opaque>,
    ) -> Result<Message> {
        draft.validate()?;
        self.require_peer_authority(caller)?;
        let now = now_ms();
        let digest = draft.digest();
        let bytes = draft.charged_bytes();
        let sender_key = principal_key(&caller.principal);

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;

        // 1. Idempotency, before anything is charged or allocated.
        let prior: Option<(String, String)> = tx
            .query_row(
                "SELECT message_id, digest FROM idempotency WHERE sender=?1 AND key=?2",
                (&sender_key, &draft.idempotency_key),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql)?;
        if let Some((message_id, prior_digest)) = prior {
            if prior_digest != digest {
                audit(
                    &tx,
                    now,
                    None,
                    None,
                    "send",
                    None,
                    None,
                    None,
                    bytes,
                    "idempotency_conflict",
                )?;
                tx.commit().map_err(sql)?;
                return Err(MeshError::new(
                    ErrorCode::IdempotencyConflict,
                    "that idempotency key was used for a different message",
                ));
            }
            let message = load_message(&tx, &message_id)?;
            tx.commit().map_err(sql)?;
            return Ok(message);
        }

        // 2. Target must exist. Its mailbox works whether or not it is currently bound.
        let target: Option<(String, i64, i64, i64, Option<String>, String)> = tx
            .query_row(
                "SELECT runtime_instance_id, next_sequence, pending_count, pending_bytes,
                        policy_json, runtime_kind
                 FROM endpoint WHERE endpoint_id=?1",
                [draft.to.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(sql)?;
        let Some((
            target_scope,
            next_sequence,
            pending_count,
            pending_bytes,
            policy_json,
            target_kind,
        )) = target
        else {
            return Err(MeshError::new(
                ErrorCode::AgentNotFound,
                "no endpoint with that id",
            ));
        };
        let target_scope = Opaque::parse(&target_scope)?;
        if target_kind == RuntimeKind::Peer.as_str() {
            // No transitive routing: a peer relaying through this host would launder its sender
            // into this host's identity on the next hop.
            if caller.principal.kind == PrincipalKind::Peer {
                return Err(MeshError::new(
                    ErrorCode::NotAuthorized,
                    "a peer cannot route through this host to another peer",
                ));
            }
            let retired: i64 = tx
                .query_row(
                    "SELECT p.retired FROM proxy x JOIN peer p ON p.peer_id = x.peer_id
                     WHERE x.endpoint_id=?1",
                    [draft.to.as_str()],
                    |row| row.get(0),
                )
                .map_err(sql)?;
            if retired != 0 {
                return Err(MeshError::new(
                    ErrorCode::PeerRetired,
                    "that agent's peer host was forgotten",
                ));
            }
        }

        // 3. Is this a reply to something the target actually asked for? That is what lets a
        //    response through a policy that refuses unsolicited requests.
        let sender_address = caller
            .principal
            .endpoint_id
            .as_ref()
            .and_then(|id| self_endpoint_address(&tx, id.as_str()));
        let target_address = self_endpoint_address(&tx, draft.to.as_str());

        let is_reply = match &draft.reply_to {
            Some(request_id) => {
                let request = load_message(&tx, request_id.as_str())?;
                if request.kind != Kind::Request
                    || caller.principal.endpoint_id.as_ref() != Some(&request.to_endpoint)
                    || request.from.endpoint_id.as_ref() != Some(&draft.to)
                {
                    return Err(MeshError::new(
                        ErrorCode::NotAuthorized,
                        "a response must answer a request addressed to this endpoint",
                    ));
                }
                let origin: Option<Option<String>> = tx
                    .query_row(
                        "SELECT from_endpoint FROM message WHERE message_id=?1",
                        [request_id.as_str()],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sql)?;
                origin.flatten().as_deref() == Some(draft.to.as_str())
            }
            None => false,
        };

        // 4. The enqueue gate.
        let policy: Policy = match policy_json {
            Some(json) => serde_json::from_str(&json).map_err(|err| {
                MeshError::new(ErrorCode::InvalidRequest, format!("stored policy: {err}"))
            })?,
            None => Policy::default(),
        };
        let decision = policy.evaluate(
            Gate::Enqueue,
            &agent_mesh_core::Request {
                sender: &caller.principal,
                sender_scope: caller.scope.as_ref(),
                target_scope: &target_scope,
                is_reply_to_our_request: is_reply,
                sender_address: sender_address.as_ref(),
                target_address: target_address.as_ref(),
                peer_trusted: peer_trusted(&tx, &caller.principal)?,
            },
        );
        if !decision.allowed {
            audit(
                &tx,
                now,
                None,
                Some(draft.to.as_str()),
                "send",
                None,
                None,
                Some(decision.rule.as_str()),
                bytes,
                "policy_refused",
            )?;
            tx.commit().map_err(sql)?;
            return Err(MeshError::new(
                ErrorCode::PolicyRefused,
                "the target's enqueue policy does not admit this sender",
            ));
        }

        // 5. Rate. The gates decided who may write; this bounds how fast. Responses are exempt:
        //    a target that asked for something must be able to receive the answer, and the reply
        //    reserve already bounds how much of that there can be.
        if !draft.kind.may_use_reserve() {
            let accepted = {
                let count: i64 = tx
                    .query_row(
                        "SELECT count(*) FROM audit
                         WHERE endpoint_id=?1 AND operation='send' AND result='accepted'
                           AND at_ms > ?2",
                        rusqlite::params![draft.to.as_str(), now - 60_000],
                        |row| row.get(0),
                    )
                    .map_err(sql)?;
                u32::try_from(count).unwrap_or(u32::MAX)
            };
            if accepted >= policy.max_inbound_per_minute {
                audit(
                    &tx,
                    now,
                    None,
                    Some(draft.to.as_str()),
                    "send",
                    None,
                    None,
                    Some(decision.rule.as_str()),
                    bytes,
                    "rate_limited",
                )?;
                tx.commit().map_err(sql)?;
                return Err(MeshError::new(
                    ErrorCode::RateLimited,
                    format!(
                        "that endpoint accepts {} messages a minute and has had them",
                        policy.max_inbound_per_minute
                    ),
                ));
            }
        }

        // 6. Quotas. Requests get the ordinary ceiling; responses may reach into the reserve so a
        //    request flood cannot prevent completion traffic.
        let (count_cap, byte_cap) = if draft.kind.may_use_reserve() {
            (
                MAX_PENDING_COUNT + RESERVED_COUNT,
                MAX_PENDING_BYTES + RESERVED_BYTES,
            )
        } else {
            (MAX_PENDING_COUNT, MAX_PENDING_BYTES)
        };
        if pending_count + 1 > count_cap || pending_bytes + bytes > byte_cap {
            audit(
                &tx,
                now,
                None,
                Some(draft.to.as_str()),
                "send",
                None,
                None,
                Some(decision.rule.as_str()),
                bytes,
                "mailbox_full",
            )?;
            tx.commit().map_err(sql)?;
            return Err(MeshError::new(
                ErrorCode::MailboxFull,
                "the recipient's mailbox is full; accepted work is never evicted to make room",
            ));
        }

        // 7. Insert. Every identity field here is ours, not the caller's.
        let message_id = Opaque::generate();
        let conversation_id = match &draft.reply_to {
            Some(request_id) => {
                let existing: Option<String> = tx
                    .query_row(
                        "SELECT conversation_id FROM message WHERE message_id=?1",
                        [request_id.as_str()],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sql)?;
                existing
                    .map(|id| Opaque::parse(&id))
                    .transpose()?
                    .unwrap_or_else(Opaque::generate)
            }
            None => Opaque::generate(),
        };
        let expires_at = draft
            .expires_in_ms
            .or_else(|| (draft.kind == Kind::Notice).then_some(60 * 60 * 1000))
            .map(|lifetime| now.saturating_add(lifetime.min(MAX_REQUEST_LIFETIME_MS)));
        let refs_json = serde_json::to_string(&draft.refs)
            .map_err(|err| MeshError::new(ErrorCode::InvalidRequest, err.to_string()))?;

        tx.execute(
            "INSERT INTO message (message_id, to_endpoint, from_kind, from_endpoint,
                                  from_incarnation, kind, conversation_id, reply_to, outcome,
                                  recipient_sequence, state, subject, text, refs_json, bytes,
                                  created_at, expires_at, origin_message_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'queued', ?11, ?12, ?13, ?14,
                     ?15, ?16, ?17)",
            rusqlite::params![
                message_id.as_str(),
                draft.to.as_str(),
                caller.principal.kind.as_str(),
                caller.principal.endpoint_id.as_ref().map(Opaque::as_str),
                caller.principal.incarnation_id.as_ref().map(Opaque::as_str),
                draft.kind.as_str(),
                conversation_id.as_str(),
                draft.reply_to.as_ref().map(Opaque::as_str),
                draft.outcome.map(Outcome::as_str),
                next_sequence,
                draft.subject,
                draft.text,
                refs_json,
                bytes,
                now,
                expires_at,
                origin.map(Opaque::as_str),
            ],
        )
        .map_err(sql)?;
        tx.execute(
            "UPDATE endpoint SET next_sequence=next_sequence+1, pending_count=pending_count+1,
                    pending_bytes=pending_bytes+?2
             WHERE endpoint_id=?1",
            (draft.to.as_str(), bytes),
        )
        .map_err(sql)?;
        tx.execute(
            "INSERT INTO idempotency (sender, key, digest, message_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                &sender_key,
                &draft.idempotency_key,
                &digest,
                message_id.as_str(),
                now,
            ),
        )
        .map_err(sql)?;
        audit(
            &tx,
            now,
            Some(message_id.as_str()),
            Some(draft.to.as_str()),
            "send",
            None,
            Some("queued"),
            Some(decision.rule.as_str()),
            bytes,
            "accepted",
        )?;

        let message = load_message(&tx, message_id.as_str())?;
        tx.commit().map_err(sql)?;
        Ok(message)
    }

    // -----------------------------------------------------------------------------------------
    // Receiving
    // -----------------------------------------------------------------------------------------

    pub fn inbox(
        &self,
        endpoint_id: &Opaque,
        states: &[State],
        limit: usize,
    ) -> Result<Vec<Message>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT * FROM message WHERE to_endpoint=?1 ORDER BY recipient_sequence LIMIT ?2",
            )
            .map_err(sql)?;
        let rows = stmt
            .query_map(
                rusqlite::params![
                    endpoint_id.as_str(),
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                read_message,
            )
            .map_err(sql)?;
        let mut out = Vec::new();
        for row in rows {
            let message = row.map_err(sql)??;
            if (states.is_empty() || states.contains(&message.state))
                && message_decision(&self.conn, &message, Gate::MakeVisible)?.allowed
            {
                out.push(message);
            }
        }
        Ok(out)
    }

    pub fn message(&self, message_id: &Opaque) -> Result<Message> {
        load_message(&self.conn, message_id.as_str())
    }

    /// Capture the exact owner of delivered work before asking a provider to stop it.
    /// A session-wide abort is unsafe when another request is also in flight.
    pub fn interrupt_target(&self, request_id: &Opaque) -> Result<Option<Opaque>> {
        let message = self.message(request_id)?;
        if message.kind != Kind::Request
            || message.state != State::CancellationRequested
            || !message_decision(&self.conn, &message, Gate::Interrupt)?.allowed
        {
            return Ok(None);
        }
        let incarnation: Option<String> = self.conn.query_row(
            "SELECT e.incarnation_id FROM endpoint e JOIN message m ON m.to_endpoint=e.endpoint_id
             WHERE m.message_id=?1 AND e.online=1 AND m.claim_owner=e.incarnation_id
               AND NOT EXISTS (SELECT 1 FROM message other WHERE other.to_endpoint=e.endpoint_id
                 AND other.message_id!=m.message_id AND other.state IN ('claimed','delivered','cancellation_requested'))",
            [request_id.as_str()], |row| row.get(0),
        ).optional().map_err(sql)?.flatten();
        incarnation.as_deref().map(Opaque::parse).transpose()
    }

    /// Commit only a confirmed stop of the captured incarnation. A replacement owner,
    /// racing reply, or expiry cannot be overwritten by a delayed acknowledgement.
    pub fn confirm_interrupt(
        &mut self,
        request_id: &Opaque,
        incarnation: &Opaque,
    ) -> Result<State> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let message = load_message(&tx, request_id.as_str())?;
        let changed = tx.execute(
            "UPDATE message SET state='cancelled', outcome='cancelled', claim_owner=NULL, claim_expires_at=NULL
             WHERE message_id=?1 AND state='cancellation_requested' AND claim_owner=?2
               AND EXISTS (SELECT 1 FROM endpoint e WHERE e.endpoint_id=message.to_endpoint AND e.incarnation_id=?2 AND e.online=1)",
            (request_id.as_str(), incarnation.as_str()),
        ).map_err(sql)?;
        if changed > 0 {
            recount(&tx, message.to_endpoint.as_str())?;
            audit(
                &tx,
                now_ms(),
                Some(request_id.as_str()),
                Some(message.to_endpoint.as_str()),
                "interrupt",
                Some("cancellation_requested"),
                Some("cancelled"),
                Some("anyone"),
                0,
                "confirmed",
            )?;
        }
        let state = load_message(&tx, request_id.as_str())?.state;
        tx.commit().map_err(sql)?;
        Ok(state)
    }

    /// Take the oldest queued message under a bounded lease.
    ///
    /// The lease is held by the caller's incarnation, so a replacement process cannot acknowledge
    /// work its predecessor claimed.
    pub fn claim(&mut self, caller: &Caller, lease_ms: Option<i64>) -> Result<Option<Message>> {
        self.claim_as(caller, lease_ms, true)
    }

    /// Take the oldest queued message on a proxy's outbox, for a bridge to forward.
    ///
    /// Unlike [`Self::claim`], a notice is not consumed on claim: it has not reached its recipient
    /// until the peer commits it, and a dropped connection must leave it to be sent again.
    pub fn claim_outbound(&mut self, caller: &Caller) -> Result<Option<Message>> {
        if caller.principal.kind != PrincipalKind::Peer {
            return Err(MeshError::new(
                ErrorCode::NotAuthorized,
                "only a peer's bridge takes mail off a proxy's outbox",
            ));
        }
        self.claim_as(caller, None, false)
    }

    fn claim_as(
        &mut self,
        caller: &Caller,
        lease_ms: Option<i64>,
        consume_notices: bool,
    ) -> Result<Option<Message>> {
        let (endpoint_id, incarnation) = agent_identity(caller)?;
        self.require_current_incarnation(&endpoint_id, &incarnation)?;
        self.require_peer_authority(caller)?;
        let now = now_ms();
        let lease = lease_ms.unwrap_or(DEFAULT_CLAIM_LEASE_MS).max(1);

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        // Reclaim anything whose lease lapsed before looking for work; any process may sweep.
        tx.execute(
            "UPDATE message SET state='queued', claim_owner=NULL, claim_expires_at=NULL
             WHERE state='claimed' AND claim_expires_at <= ?1",
            [now],
        )
        .map_err(sql)?;

        let candidates: Vec<String> = tx
            .prepare(
                "SELECT message_id FROM message
                 WHERE to_endpoint=?1 AND state='queued'
                   AND (expires_at IS NULL OR expires_at > ?2)
                 ORDER BY recipient_sequence",
            )
            .map_err(sql)?
            .query_map((endpoint_id.as_str(), now), |row| row.get(0))
            .map_err(sql)?
            .collect::<std::result::Result<_, _>>()
            .map_err(sql)?;
        let mut candidate = None;
        for id in candidates {
            let message = load_message(&tx, &id)?;
            let decision = message_decision(&tx, &message, Gate::MakeVisible)?;
            if decision.allowed {
                candidate = Some((id, message.kind, decision.rule));
                break;
            }
        }
        let Some((message_id, kind, rule)) = candidate else {
            tx.commit().map_err(sql)?;
            return Ok(None);
        };
        tx.execute(
            "UPDATE message SET state='claimed', claim_owner=?2, claim_expires_at=?3
             WHERE message_id=?1",
            (&message_id, incarnation.as_str(), now.saturating_add(lease)),
        )
        .map_err(sql)?;
        // Notices have no response path. Deliver once and release their mailbox charge.
        let consumed = consume_notices && kind == Kind::Notice;
        if consumed {
            tx.execute("UPDATE message SET state='consumed', claim_owner=NULL, claim_expires_at=NULL WHERE message_id=?1", [&message_id]).map_err(sql)?;
            recount(&tx, endpoint_id.as_str())?;
        }
        audit(
            &tx,
            now,
            Some(&message_id),
            Some(endpoint_id.as_str()),
            "claim",
            Some("queued"),
            Some(if consumed { "consumed" } else { "claimed" }),
            Some(rule.as_str()),
            0,
            "ok",
        )?;
        let message = load_message(&tx, &message_id)?;
        tx.commit().map_err(sql)?;
        Ok(Some(message))
    }

    /// Answer a claimed or delivered request.
    ///
    /// One transaction: the response lands in the requester's mailbox and the request leaves the
    /// responder's, so there is no window in which a request is answered but still pending.
    pub fn respond(
        &mut self,
        caller: &Caller,
        request_id: &Opaque,
        outcome: Outcome,
        text: &str,
        refs: Vec<Ref>,
        idempotency_key: &str,
    ) -> Result<Message> {
        let (endpoint_id, incarnation) = agent_identity(caller)?;
        self.require_current_incarnation(&endpoint_id, &incarnation)?;
        self.require_peer_authority(caller)?;
        let request = self.message(request_id)?;
        if request.kind != Kind::Request {
            return Err(MeshError::new(
                ErrorCode::InvalidRequest,
                "only a request can be answered",
            ));
        }
        if request.to_endpoint != endpoint_id {
            return Err(MeshError::new(
                ErrorCode::NotAuthorized,
                "that request was not addressed to this endpoint",
            ));
        }
        let Some(requester) = request.from.endpoint_id.clone() else {
            return Err(MeshError::new(
                ErrorCode::InvalidRequest,
                "that request came from the local user and has no mailbox to answer",
            ));
        };
        if matches!(
            request.state,
            State::Consumed | State::Cancelled | State::Expired | State::Undeliverable
        ) {
            return Err(MeshError::new(
                ErrorCode::AlreadyResponded,
                format!("that request is already {}", request.state.as_str()),
            ));
        }

        let draft = Draft {
            to: requester,
            kind: Kind::Response,
            reply_to: Some(request_id.clone()),
            outcome: Some(outcome),
            subject: request.subject.clone(),
            text: text.to_owned(),
            refs,
            idempotency_key: idempotency_key.to_owned(),
            expires_in_ms: None,
        };
        // `send` performs its own transaction; the request is retired in a second one below. A
        // crash between them leaves the response delivered and the request still pending, which is
        // recoverable (a duplicate response is refused) — the reverse would lose the answer.
        let response = self.send(caller, &draft)?;

        let now = now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let changed = tx
            .execute(
                "UPDATE message SET state='consumed', claim_owner=NULL, claim_expires_at=NULL
                 WHERE message_id=?1 AND state IN ('queued','claimed','delivered',
                                                   'cancellation_requested')",
                [request_id.as_str()],
            )
            .map_err(sql)?;
        if changed > 0 {
            tx.execute(
                "UPDATE endpoint SET pending_count=pending_count-1, pending_bytes=pending_bytes-?2
                 WHERE endpoint_id=?1",
                (endpoint_id.as_str(), request.text.len() as i64),
            )
            .map_err(sql)?;
            // Recompute rather than trusting an arithmetic guess about the original charge.
            tx.execute(
                "UPDATE endpoint SET
                     pending_count = (SELECT count(*) FROM message
                                      WHERE to_endpoint=?1 AND state IN
                                        ('queued','claimed','delivered','cancellation_requested')),
                     pending_bytes = (SELECT coalesce(sum(bytes),0) FROM message
                                      WHERE to_endpoint=?1 AND state IN
                                        ('queued','claimed','delivered','cancellation_requested'))
                 WHERE endpoint_id=?1",
                [endpoint_id.as_str()],
            )
            .map_err(sql)?;
        }
        audit(
            &tx,
            now,
            Some(request_id.as_str()),
            Some(endpoint_id.as_str()),
            "respond",
            None,
            Some("consumed"),
            None,
            0,
            outcome.as_str(),
        )?;
        tx.commit().map_err(sql)?;
        Ok(response)
    }

    /// The response to a request, if one has arrived.
    pub fn response_for(&self, request_id: &Opaque) -> Result<Option<Message>> {
        let found: Option<String> = self
            .conn
            .query_row(
                "SELECT message_id FROM message WHERE reply_to=?1 AND kind='response'
                 ORDER BY recipient_sequence LIMIT 1",
                [request_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;
        let message = found.map(|id| load_message(&self.conn, &id)).transpose()?;
        match message {
            Some(message) if message_decision(&self.conn, &message, Gate::MakeVisible)?.allowed => {
                Ok(Some(message))
            }
            _ => Ok(None),
        }
    }

    /// Cancel a request.
    ///
    /// Queued work is removed atomically. Work already claimed or delivered can only be *asked* to
    /// stop: the store records `cancellation_requested` and never manufactures a `cancelled`
    /// outcome an adapter has not confirmed (plan §7.2 rule 7).
    pub fn cancel(&mut self, caller: &Caller, request_id: &Opaque) -> Result<State> {
        if matches!(
            caller.principal.kind,
            PrincipalKind::Agent | PrincipalKind::Peer
        ) {
            let (endpoint, incarnation) = agent_identity(caller)?;
            self.require_current_incarnation(&endpoint, &incarnation)?;
            self.require_peer_authority(caller)?;
        }
        let request = self.message(request_id)?;
        if request.from.endpoint_id != caller.principal.endpoint_id {
            return Err(MeshError::new(
                ErrorCode::NotAuthorized,
                "only the sender may cancel a request",
            ));
        }
        let now = now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let queued = tx
            .execute(
                "UPDATE message SET state='cancelled' WHERE message_id=?1 AND state='queued'",
                [request_id.as_str()],
            )
            .map_err(sql)?;
        let new_state = if queued > 0 {
            recount(&tx, request.to_endpoint.as_str())?;
            State::Cancelled
        } else {
            let asked = tx
                .execute(
                    "UPDATE message SET state='cancellation_requested'
                     WHERE message_id=?1 AND state IN ('claimed','delivered')",
                    [request_id.as_str()],
                )
                .map_err(sql)?;
            if asked > 0 {
                State::CancellationRequested
            } else {
                request.state
            }
        };
        audit(
            &tx,
            now,
            Some(request_id.as_str()),
            Some(request.to_endpoint.as_str()),
            "cancel",
            Some(request.state.as_str()),
            Some(new_state.as_str()),
            None,
            0,
            "ok",
        )?;
        tx.commit().map_err(sql)?;
        Ok(new_state)
    }

    /// Return lapsed claims to the queue and retire messages past their deadline.
    ///
    /// Any process may call this on any operation; correctness never depends on a sweeper running.
    pub fn sweep(&mut self, now: i64) -> Result<(usize, usize)> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let reclaimed = tx
            .execute(
                "UPDATE message SET state='queued', claim_owner=NULL, claim_expires_at=NULL
                 WHERE state='claimed' AND claim_expires_at <= ?1",
                [now],
            )
            .map_err(sql)?;
        let expired = tx
            .execute(
                "UPDATE message SET state='expired'
                 WHERE expires_at IS NOT NULL AND expires_at <= ?1
                   AND state IN ('queued','claimed')",
                [now],
            )
            .map_err(sql)?;
        if expired > 0 {
            let mut stmt = tx
                .prepare("SELECT DISTINCT to_endpoint FROM message WHERE state='expired'")
                .map_err(sql)?;
            let endpoints: Vec<String> = stmt
                .query_map([], |row| row.get(0))
                .map_err(sql)?
                .collect::<std::result::Result<_, _>>()
                .map_err(sql)?;
            drop(stmt);
            for endpoint in endpoints {
                recount(&tx, &endpoint)?;
            }
        }
        tx.commit().map_err(sql)?;
        Ok((reclaimed, expired))
    }

    /// Messages that are waiting and whose recipient could be woken.
    ///
    /// Returns only what passes the `activate` gate, so a watcher never has to re-derive policy.
    /// `backoff_ms` and `max_attempts` bound re-activation: an agent that ignored a wake-up is not
    /// woken again immediately, and never more than a few times, because each attempt costs the
    /// user a turn.
    pub fn activatable(
        &self,
        scope: &Opaque,
        now: i64,
        backoff_ms: i64,
        max_attempts: i64,
    ) -> Result<Vec<Activatable>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT m.message_id, m.to_endpoint
                 FROM message m JOIN endpoint e ON e.endpoint_id = m.to_endpoint
                 WHERE e.runtime_instance_id = ?1
                   AND e.online = 1
                   AND m.state = \'queued\'
                   AND (m.expires_at IS NULL OR m.expires_at > ?2)
                   AND m.activations < ?3
                   AND (m.last_activated_at IS NULL OR m.last_activated_at <= ?4)
                 ORDER BY m.recipient_sequence",
            )
            .map_err(sql)?;
        let rows: Vec<(String, String)> = stmt
            .query_map(
                rusqlite::params![scope.as_str(), now, max_attempts, now - backoff_ms],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sql)?
            .collect::<std::result::Result<_, _>>()
            .map_err(sql)?;
        drop(stmt);

        let mut out = Vec::new();
        for (message_id, endpoint_id) in rows {
            let endpoint_id = Opaque::parse(&endpoint_id)?;
            let endpoint = self.endpoint(&endpoint_id)?;
            let message = load_message(&self.conn, &message_id)?;
            let capabilities = self.capabilities(&endpoint_id)?;
            let mode = capabilities.delivery_mode();
            if !mode.activates() {
                continue;
            }
            let policy = self.policy(&endpoint_id)?;
            let sender_scope = match &message.from.endpoint_id {
                Some(id) => self
                    .endpoint(id)
                    .ok()
                    .map(|e| e.locator.runtime_instance_id),
                None => None,
            };
            let is_reply = match &message.reply_to {
                Some(request) => {
                    self.message(request)
                        .ok()
                        .and_then(|r| r.from.endpoint_id)
                        .as_ref()
                        == Some(&endpoint_id)
                }
                None => false,
            };
            let sender_address = message
                .from
                .endpoint_id
                .as_ref()
                .and_then(|id| self.endpoint(id).ok())
                .and_then(|endpoint| endpoint.locator.address);
            let target_address = endpoint.locator.address.clone();
            let decision = policy.evaluate(
                Gate::Activate,
                &agent_mesh_core::Request {
                    sender: &message.from,
                    sender_scope: sender_scope.as_ref(),
                    target_scope: scope,
                    is_reply_to_our_request: is_reply,
                    sender_address: sender_address.as_ref(),
                    target_address: target_address.as_ref(),
                    peer_trusted: peer_trusted(&self.conn, &message.from)?,
                },
            );
            let visibility = message_decision(&self.conn, &message, Gate::MakeVisible)?;
            let decision = if visibility.allowed {
                decision
            } else {
                visibility
            };
            out.push(Activatable {
                message,
                endpoint_id,
                capabilities,
                mode,
                decision,
            });
        }
        Ok(out)
    }

    /// Note that an activation was attempted, whatever its outcome.
    ///
    /// The message stays `queued`: waking an agent is not delivery, and the agent still has to
    /// claim the message itself. Recording the attempt is what stops a watcher waking the same
    /// agent every poll.
    pub fn record_activation(
        &mut self,
        message_id: &Opaque,
        endpoint_id: &Opaque,
        mode: DeliveryMode,
        rule: Rule,
        result: &str,
    ) -> Result<()> {
        let now = now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        tx.execute(
            "UPDATE message SET activations = activations + 1, last_activated_at = ?2
             WHERE message_id = ?1",
            (message_id.as_str(), now),
        )
        .map_err(sql)?;
        audit(
            &tx,
            now,
            Some(message_id.as_str()),
            Some(endpoint_id.as_str()),
            "activate",
            Some(mode.as_str()),
            None,
            Some(rule.as_str()),
            0,
            result,
        )?;
        tx.commit().map_err(sql)?;
        Ok(())
    }

    /// How many times an operation was recorded for an endpoint in the last minute.
    ///
    /// Counted from the audit trail rather than a separate counter: it is written in the same
    /// transaction as the thing it records, so the two cannot disagree, and a restart does not
    /// reset a budget the way an in-memory tally would.
    fn recent(&self, endpoint_id: &str, operation: &str, result: &str, now: i64) -> Result<u32> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM audit
                 WHERE endpoint_id=?1 AND operation=?2 AND result=?3 AND at_ms > ?4",
                rusqlite::params![endpoint_id, operation, result, now - 60_000],
                |row| row.get(0),
            )
            .map_err(sql)?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    /// Whether this endpoint has room for another wake-up this minute.
    pub fn activation_budget_left(&self, endpoint_id: &Opaque, now: i64) -> Result<bool> {
        let policy = self.policy(endpoint_id)?;
        Ok(
            self.recent(endpoint_id.as_str(), "activate", "started", now)?
                < policy.max_auto_turns_per_minute,
        )
    }

    // ---------------------------------------------------------------------------------------
    // Groups
    // ---------------------------------------------------------------------------------------

    /// Create a group, or replace its membership.
    ///
    /// Members are stored as endpoint ids. A group holding aliases would follow those names to
    /// whatever answered to them next, which is the same trap `policy trust` avoids.
    pub fn set_group(&mut self, name: &Alias, members: &[Opaque]) -> Result<()> {
        let now = now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        tx.execute(
            "INSERT INTO mesh_group (name, created_at) VALUES (?1, ?2)
             ON CONFLICT(name) DO NOTHING",
            (name.as_str(), now),
        )
        .map_err(sql)?;
        tx.execute("DELETE FROM group_member WHERE name=?1", [name.as_str()])
            .map_err(sql)?;
        for member in members {
            tx.execute(
                "INSERT INTO group_member (name, endpoint_id) VALUES (?1, ?2)",
                (name.as_str(), member.as_str()),
            )
            .map_err(sql)?;
        }
        tx.commit().map_err(sql)?;
        Ok(())
    }

    pub fn delete_group(&mut self, name: &Alias) -> Result<bool> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        tx.execute("DELETE FROM group_member WHERE name=?1", [name.as_str()])
            .map_err(sql)?;
        let removed = tx
            .execute("DELETE FROM mesh_group WHERE name=?1", [name.as_str()])
            .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(removed > 0)
    }

    /// A group's current membership, in a stable order.
    pub fn group_members(&self, name: &Alias) -> Result<Vec<Opaque>> {
        let exists: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM mesh_group WHERE name=?1",
                [name.as_str()],
                |row| row.get(0),
            )
            .map_err(sql)?;
        if exists == 0 {
            return Err(not_found("group"));
        }
        let mut stmt = self
            .conn
            .prepare("SELECT endpoint_id FROM group_member WHERE name=?1 ORDER BY endpoint_id")
            .map_err(sql)?;
        let rows = stmt
            .query_map([name.as_str()], |row| row.get::<_, String>(0))
            .map_err(sql)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(Opaque::parse(&row.map_err(sql)?)?);
        }
        Ok(out)
    }

    pub fn list_groups(&self) -> Result<Vec<(Alias, Vec<Opaque>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name FROM mesh_group ORDER BY name")
            .map_err(sql)?;
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .map_err(sql)?
            .collect::<std::result::Result<_, _>>()
            .map_err(sql)?;
        drop(stmt);
        let mut out = Vec::new();
        for name in names {
            let name = Alias::parse(&name)?;
            let members = self.group_members(&name)?;
            out.push((name, members));
        }
        Ok(out)
    }

    /// Record a fan-out and the membership it was sent to.
    ///
    /// The snapshot is what makes a later quorum meaningful: it counts answers against who was
    /// actually asked, not against whoever happens to be in the group when the count is taken.
    pub fn open_group_send(
        &mut self,
        name: &Alias,
        sender: &Caller,
        members: &[Opaque],
    ) -> Result<Opaque> {
        let id = Opaque::generate();
        let snapshot = members
            .iter()
            .map(Opaque::as_str)
            .collect::<Vec<_>>()
            .join(",");
        self.conn
            .execute(
                "INSERT INTO group_send (group_send_id, name, sender, members, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    id.as_str(),
                    name.as_str(),
                    principal_key(&sender.principal),
                    snapshot,
                    now_ms(),
                ),
            )
            .map_err(sql)?;
        Ok(id)
    }

    /// Tie a message to the fan-out it belongs to.
    pub fn attach_to_group_send(&mut self, message_id: &Opaque, send: &Opaque) -> Result<()> {
        self.conn
            .execute(
                "UPDATE message SET group_send_id=?2 WHERE message_id=?1",
                (message_id.as_str(), send.as_str()),
            )
            .map_err(sql)?;
        Ok(())
    }

    /// The membership a fan-out was sent to, as recorded when it was sent.
    pub fn group_send_members(&self, send: &Opaque) -> Result<Vec<Opaque>> {
        let snapshot: String = self
            .conn
            .query_row(
                "SELECT members FROM group_send WHERE group_send_id=?1",
                [send.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?
            .ok_or_else(|| not_found("group send"))?;
        snapshot
            .split(',')
            .filter(|value| !value.is_empty())
            .map(Opaque::parse)
            .collect()
    }

    /// Every request that a fan-out actually placed, with its recipient.
    pub fn group_send_requests(&self, send: &Opaque) -> Result<Vec<Message>> {
        let mut stmt = self
            .conn
            .prepare("SELECT message_id FROM message WHERE group_send_id=?1 ORDER BY created_at")
            .map_err(sql)?;
        let ids: Vec<String> = stmt
            .query_map([send.as_str()], |row| row.get(0))
            .map_err(sql)?
            .collect::<std::result::Result<_, _>>()
            .map_err(sql)?;
        drop(stmt);
        ids.iter().map(|id| load_message(&self.conn, id)).collect()
    }

    // ---------------------------------------------------------------------------------------
    // Peers (vvagent-inter-host-plan.md §4)
    // ---------------------------------------------------------------------------------------

    /// This store's own id, minted once when the store was created. Not a secret.
    pub fn host_id(&self) -> Result<Opaque> {
        let id: String = self
            .conn
            .query_row(
                "SELECT host_id FROM store_identity WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(sql)?;
        Opaque::parse(&id)
    }

    /// Record a peer under `label`, or confirm the one already there.
    ///
    /// The first connection pins the label to the store that answered, as `known_hosts` pins an SSH
    /// key. A different store behind the same label is refused until the user forgets the old one,
    /// so a reinstalled or substituted host never inherits the old one's trust or queued mail.
    pub fn pin_peer(&mut self, label: &PeerLabel, host_id: &Opaque) -> Result<Peer> {
        if *host_id == self.host_id()? {
            return Err(MeshError::new(
                ErrorCode::InvalidRequest,
                "that is this store; a host cannot be its own peer",
            ));
        }
        let now = now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let by_label: Option<Peer> = tx
            .query_row(
                "SELECT * FROM peer WHERE label=?1 AND retired=0",
                [label.as_str()],
                read_peer,
            )
            .optional()
            .map_err(sql)?
            .transpose()?;
        if let Some(peer) = by_label {
            if peer.host_id != *host_id {
                return Err(MeshError::new(
                    ErrorCode::PeerMismatch,
                    format!(
                        "`{label}` is pinned to store {} but store {host_id} answered; if the host \
                         was reinstalled, run `vvagent peer forget {label}` and connect again",
                        peer.host_id
                    ),
                ));
            }
            return Ok(peer);
        }
        let other: Option<String> = tx
            .query_row(
                "SELECT label FROM peer WHERE host_id=?1 AND retired=0",
                [host_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;
        if let Some(other) = other {
            // Two labels for one store would give each remote agent two proxies and two mailboxes.
            return Err(MeshError::new(
                ErrorCode::PeerMismatch,
                format!("that store is already the peer `{other}`; connect with that label"),
            ));
        }
        let peer_id = Opaque::generate();
        tx.execute(
            "INSERT INTO peer (peer_id, label, host_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)",
            (peer_id.as_str(), label.as_str(), host_id.as_str(), now),
        )
        .map_err(sql)?;
        audit(&tx, now, None, None, "peer_pin", None, None, None, 0, "ok")?;
        let peer = tx
            .query_row(
                "SELECT * FROM peer WHERE peer_id=?1",
                [peer_id.as_str()],
                read_peer,
            )
            .map_err(sql)??;
        tx.commit().map_err(sql)?;
        Ok(peer)
    }

    pub fn peer(&self, label: &PeerLabel) -> Result<Peer> {
        self.conn
            .query_row(
                "SELECT * FROM peer WHERE label=?1 AND retired=0",
                [label.as_str()],
                read_peer,
            )
            .optional()
            .map_err(sql)?
            .ok_or_else(|| not_found("peer"))?
    }

    pub fn peer_by_id(&self, peer_id: &Opaque) -> Result<Peer> {
        self.conn
            .query_row(
                "SELECT * FROM peer WHERE peer_id=?1 AND retired=0",
                [peer_id.as_str()],
                read_peer,
            )
            .optional()
            .map_err(sql)?
            .ok_or_else(|| not_found("peer"))?
    }

    pub fn list_peers(&self) -> Result<Vec<Peer>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM peer WHERE retired=0 ORDER BY label")
            .map_err(sql)?;
        let rows = stmt.query_map([], read_peer).map_err(sql)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(sql)??);
        }
        Ok(out)
    }

    /// Trust, or stop trusting, remote-originated work from a whole peer.
    pub fn set_peer_trust(&mut self, label: &PeerLabel, trusted: bool) -> Result<()> {
        let changed = self
            .conn
            .execute(
                "UPDATE peer SET trusted=?2, updated_at=?3 WHERE label=?1 AND retired=0",
                (label.as_str(), i64::from(trusted), now_ms()),
            )
            .map_err(sql)?;
        if changed == 0 {
            return Err(not_found("peer"));
        }
        Ok(())
    }

    /// Take or renew the one lease that lets a bridge act for this peer.
    ///
    /// Returns `false`, changing nothing, while another owner holds a live lease: that is how a
    /// second window connected to the same host stands aside. Taking over a lapsed lease returns
    /// the previous owner's in-flight claims to the queue, and moves every proxy's incarnation to
    /// the new owner so nothing the old bridge still holds can be acknowledged.
    pub fn acquire_peer_lease(
        &mut self,
        peer_id: &Opaque,
        owner: &Opaque,
        anchor: Option<&LeaseAnchor>,
        ttl_ms: i64,
        now: i64,
    ) -> Result<bool> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let current: Option<(Option<String>, Option<i64>)> = tx
            .query_row(
                "SELECT lease_owner, lease_expires_at FROM peer WHERE peer_id=?1 AND retired=0",
                [peer_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql)?;
        let Some((holder, expires)) = current else {
            return Err(not_found("peer"));
        };
        let held_by_other = holder
            .as_deref()
            .is_some_and(|holder| holder != owner.as_str());
        if held_by_other && expires.is_some_and(|expires| expires > now) {
            return Ok(false);
        }
        if let Some(previous) = holder.as_deref().filter(|_| held_by_other) {
            requeue_proxy_claims(&tx, peer_id.as_str(), previous)?;
        }
        tx.execute(
            "UPDATE peer SET lease_owner=?2, lease_expires_at=?3, lease_anchor=?4, updated_at=?5
             WHERE peer_id=?1",
            rusqlite::params![
                peer_id.as_str(),
                owner.as_str(),
                now.saturating_add(ttl_ms.max(1)),
                anchor.map(anchor_json),
                now,
            ],
        )
        .map_err(sql)?;
        tx.execute(
            "UPDATE endpoint SET incarnation_id=?2, online=1, updated_at=?3
             WHERE endpoint_id IN (SELECT endpoint_id FROM proxy WHERE peer_id=?1)",
            (peer_id.as_str(), owner.as_str(), now),
        )
        .map_err(sql)?;
        if holder.as_deref() != Some(owner.as_str()) {
            audit(
                &tx,
                now,
                None,
                None,
                "peer_lease",
                None,
                None,
                None,
                0,
                "acquired",
            )?;
        }
        tx.commit().map_err(sql)?;
        Ok(true)
    }

    /// Give a lease up. Only its owner can; anyone else's call changes nothing.
    pub fn release_peer_lease(&mut self, peer_id: &Opaque, owner: &Opaque) -> Result<()> {
        let now = now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let changed = tx
            .execute(
                "UPDATE peer SET lease_owner=NULL, lease_expires_at=NULL, lease_anchor=NULL,
                        updated_at=?3
                 WHERE peer_id=?1 AND lease_owner=?2",
                (peer_id.as_str(), owner.as_str(), now),
            )
            .map_err(sql)?;
        if changed > 0 {
            requeue_proxy_claims(&tx, peer_id.as_str(), owner.as_str())?;
            tx.execute(
                "UPDATE endpoint SET incarnation_id=NULL, online=0, updated_at=?2
                 WHERE endpoint_id IN (SELECT endpoint_id FROM proxy WHERE peer_id=?1)",
                (peer_id.as_str(), now),
            )
            .map_err(sql)?;
            audit(
                &tx,
                now,
                None,
                None,
                "peer_lease",
                None,
                None,
                None,
                0,
                "released",
            )?;
        }
        tx.commit().map_err(sql)?;
        Ok(())
    }

    /// The proxy standing for `remote_endpoint_id` on this peer, created on first use.
    ///
    /// Creating one needs no lease: an exact remote id may be addressed while the bridge is down,
    /// and the mail queues. Proxies count against the endpoint limit like any endpoint.
    pub fn ensure_proxy(
        &mut self,
        peer_id: &Opaque,
        remote_endpoint_id: &Opaque,
        display: Option<&str>,
    ) -> Result<Opaque> {
        // Peer-supplied, shown to people: bounded and free of control characters, or dropped.
        let display = display.filter(|value| {
            value.len() <= MAX_PROXY_DISPLAY_BYTES && !value.chars().any(char::is_control)
        });
        let now = now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let lease: Option<(Option<String>, Option<i64>)> = tx
            .query_row(
                "SELECT lease_owner, lease_expires_at FROM peer WHERE peer_id=?1 AND retired=0",
                [peer_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql)?;
        let Some((owner, expires)) = lease else {
            return Err(not_found("peer"));
        };
        let existing: Option<String> = tx
            .query_row(
                "SELECT endpoint_id FROM proxy WHERE peer_id=?1 AND remote_endpoint_id=?2",
                (peer_id.as_str(), remote_endpoint_id.as_str()),
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;
        if let Some(id) = existing {
            if let Some(display) = display {
                tx.execute(
                    "UPDATE proxy SET display=?2 WHERE endpoint_id=?1",
                    (&id, display),
                )
                .map_err(sql)?;
            }
            tx.commit().map_err(sql)?;
            return Opaque::parse(&id);
        }
        let count: i64 = tx
            .query_row("SELECT count(*) FROM endpoint", [], |row| row.get(0))
            .map_err(sql)?;
        if count >= MAX_ENDPOINTS {
            return Err(MeshError::new(
                ErrorCode::EndpointLimit,
                format!("{MAX_ENDPOINTS} endpoints already registered"),
            ));
        }
        let live_owner = owner.filter(|_| expires.is_some_and(|expires| expires > now));
        let endpoint_id = Opaque::generate();
        let policy = serde_json::to_string(&proxy_policy())
            .map_err(|err| MeshError::new(ErrorCode::InvalidRequest, err.to_string()))?;
        tx.execute(
            "INSERT INTO endpoint (endpoint_id, incarnation_id, token_hash, alias, provider,
                                   runtime_kind, runtime_instance_id, instance_name, address,
                                   online, state, state_generation, next_sequence, pending_count,
                                   pending_bytes, policy_json, created_at, updated_at)
             VALUES (?1, ?2, NULL, NULL, NULL, 'peer', ?3, NULL, NULL, ?4, 'unknown', 1, 1, 0, 0,
                     ?5, ?6, ?6)",
            rusqlite::params![
                endpoint_id.as_str(),
                live_owner,
                peer_id.as_str(),
                i64::from(live_owner.is_some()),
                policy,
                now,
            ],
        )
        .map_err(sql)?;
        tx.execute(
            "INSERT INTO proxy (endpoint_id, peer_id, remote_endpoint_id, display)
             VALUES (?1, ?2, ?3, ?4)",
            (
                endpoint_id.as_str(),
                peer_id.as_str(),
                remote_endpoint_id.as_str(),
                display,
            ),
        )
        .map_err(sql)?;
        audit(
            &tx,
            now,
            None,
            Some(endpoint_id.as_str()),
            "proxy",
            None,
            None,
            None,
            0,
            "created",
        )?;
        tx.commit().map_err(sql)?;
        Ok(endpoint_id)
    }

    pub fn proxy(&self, endpoint_id: &Opaque) -> Result<Proxy> {
        self.conn
            .query_row(
                "SELECT endpoint_id, peer_id, remote_endpoint_id, display FROM proxy
                 WHERE endpoint_id=?1",
                [endpoint_id.as_str()],
                read_proxy,
            )
            .optional()
            .map_err(sql)?
            .ok_or_else(|| not_found("proxy"))?
    }

    /// Every proxy of one peer, oldest first.
    pub fn list_proxies(&self, peer_id: &Opaque) -> Result<Vec<Proxy>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT x.endpoint_id, x.peer_id, x.remote_endpoint_id, x.display
                 FROM proxy x JOIN endpoint e ON e.endpoint_id = x.endpoint_id
                 WHERE x.peer_id=?1 ORDER BY e.created_at, x.endpoint_id",
            )
            .map_err(sql)?;
        let rows = stmt
            .query_map([peer_id.as_str()], read_proxy)
            .map_err(sql)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(sql)??);
        }
        Ok(out)
    }

    /// Act as a proxy. Only the live holder of its peer's lease may.
    ///
    /// A proxy has no token, so no local process can authenticate as one; this is the only way to
    /// obtain a `peer` caller, and it is what a bridge uses to claim outbound mail and to insert
    /// what its peer sent.
    pub fn proxy_caller(&self, proxy: &Opaque, owner: &Opaque) -> Result<Caller> {
        let proxy = self.proxy(proxy)?;
        self.require_live_lease(&proxy.peer_id, owner)?;
        Ok(Caller {
            principal: Principal {
                kind: PrincipalKind::Peer,
                endpoint_id: Some(proxy.endpoint_id),
                incarnation_id: Some(owner.clone()),
            },
            scope: Some(proxy.peer_id),
        })
    }

    fn require_live_lease(&self, peer_id: &Opaque, owner: &Opaque) -> Result<()> {
        let peer = self.peer_by_id(peer_id).map_err(|err| match err.code {
            ErrorCode::NotFound => {
                MeshError::new(ErrorCode::PeerRetired, "that peer was forgotten")
            }
            _ => err,
        })?;
        match peer.lease {
            Some(lease) if lease.owner == *owner && lease.is_live(now_ms()) => Ok(()),
            _ => Err(MeshError::new(
                ErrorCode::ClaimLost,
                "this bridge no longer holds the peer's lease",
            )),
        }
    }

    /// A `peer` caller must still be its peer's live bridge. Anything else passes untouched.
    fn require_peer_authority(&self, caller: &Caller) -> Result<()> {
        if caller.principal.kind != PrincipalKind::Peer {
            return Ok(());
        }
        let (endpoint, owner) = agent_identity(caller)?;
        let proxy = self.proxy(&endpoint)?;
        self.require_live_lease(&proxy.peer_id, &owner)
    }

    /// Forget a peer: retire its proxies and make everything still waiting on it undeliverable.
    ///
    /// One transaction, and an explicit user decision rather than capacity pressure, so it is not
    /// eviction. Outbound mail still waiting for the peer fails with `peer_retired`. Inbound mail
    /// from it that no local agent has claimed is withdrawn the same way: its peer can never be
    /// trusted again, so it could only sit invisible and hold capacity. Work an agent has already
    /// claimed stays with that agent; only answering it becomes impossible. The label is freed, so
    /// a different store may later be pinned under it as a new peer with new proxies — the old ones
    /// are never reused.
    pub fn retire_peer(&mut self, label: &PeerLabel) -> Result<RetiredPeer> {
        let now = now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let peer_id: String = tx
            .query_row(
                "SELECT peer_id FROM peer WHERE label=?1 AND retired=0",
                [label.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?
            .ok_or_else(|| not_found("peer"))?;
        let proxies: Vec<String> = tx
            .prepare("SELECT endpoint_id FROM proxy WHERE peer_id=?1")
            .map_err(sql)?
            .query_map([&peer_id], |row| row.get(0))
            .map_err(sql)?
            .collect::<std::result::Result<_, _>>()
            .map_err(sql)?;
        let mut undeliverable = 0;
        let mut withdrawn = 0;
        for proxy in &proxies {
            let unclaimed: Vec<(String, String)> = tx
                .prepare(
                    "SELECT message_id, to_endpoint FROM message
                     WHERE from_endpoint=?1 AND state='queued'",
                )
                .map_err(sql)?
                .query_map([proxy], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(sql)?
                .collect::<std::result::Result<_, _>>()
                .map_err(sql)?;
            for (message_id, recipient) in &unclaimed {
                tx.execute(
                    "UPDATE message SET state='undeliverable', failure=?2 WHERE message_id=?1",
                    (message_id, ErrorCode::PeerRetired.as_str()),
                )
                .map_err(sql)?;
                recount(&tx, recipient)?;
                audit(
                    &tx,
                    now,
                    Some(message_id),
                    Some(recipient),
                    "peer_retire",
                    Some("queued"),
                    Some("undeliverable"),
                    None,
                    0,
                    ErrorCode::PeerRetired.as_str(),
                )?;
            }
            withdrawn += unclaimed.len();

            let waiting: Vec<(String, String)> = tx
                .prepare(
                    "SELECT message_id, state FROM message
                     WHERE to_endpoint=?1
                       AND state IN ('queued','claimed','delivered','cancellation_requested')",
                )
                .map_err(sql)?
                .query_map([proxy], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(sql)?
                .collect::<std::result::Result<_, _>>()
                .map_err(sql)?;
            for (message_id, state) in &waiting {
                tx.execute(
                    "UPDATE message SET state='undeliverable', failure=?2, claim_owner=NULL,
                            claim_expires_at=NULL
                     WHERE message_id=?1",
                    (message_id, ErrorCode::PeerRetired.as_str()),
                )
                .map_err(sql)?;
                audit(
                    &tx,
                    now,
                    Some(message_id),
                    Some(proxy),
                    "peer_retire",
                    Some(state),
                    Some("undeliverable"),
                    None,
                    0,
                    ErrorCode::PeerRetired.as_str(),
                )?;
            }
            undeliverable += waiting.len();
            recount(&tx, proxy)?;
            tx.execute(
                "UPDATE endpoint SET incarnation_id=NULL, online=0, state='offline',
                        state_generation=state_generation+1, updated_at=?2
                 WHERE endpoint_id=?1",
                (proxy, now),
            )
            .map_err(sql)?;
        }
        tx.execute(
            "UPDATE peer SET retired=1, label=NULL, trusted=0, lease_owner=NULL,
                    lease_expires_at=NULL, lease_anchor=NULL, updated_at=?2
             WHERE peer_id=?1",
            (&peer_id, now),
        )
        .map_err(sql)?;
        audit(
            &tx,
            now,
            None,
            None,
            "peer_retire",
            None,
            None,
            None,
            0,
            "ok",
        )?;
        tx.commit().map_err(sql)?;
        Ok(RetiredPeer {
            proxies: proxies.len(),
            undeliverable,
            withdrawn,
        })
    }

    // ---------------------------------------------------------------------------------------
    // What a bridge does (vvagent-inter-host-plan.md §6.2)
    // ---------------------------------------------------------------------------------------

    /// The peer whose store presented `host_id`, if it is one this store knows.
    pub fn peer_by_host(&self, host_id: &Opaque) -> Result<Option<Peer>> {
        self.conn
            .query_row(
                "SELECT * FROM peer WHERE host_id=?1 AND retired=0",
                [host_id.as_str()],
                read_peer,
            )
            .optional()
            .map_err(sql)?
            .transpose()
    }

    /// Commit one message a peer delivered.
    ///
    /// The sender is authored here, as the proxy for `(this peer, origin_endpoint_id)` — never
    /// taken from the frame. The origin message id is the idempotency key, so a redelivery after a
    /// lost `accepted` commits nothing new and is accepted again. Then every local gate, quota and
    /// budget applies as it would to local mail, plus the per-peer inbound budget.
    pub fn ingest(
        &mut self,
        peer_id: &Opaque,
        owner: &Opaque,
        deliver: &Deliver,
    ) -> Result<Message> {
        deliver.validate()?;
        self.require_live_lease(peer_id, owner)?;
        let proxy = self.ensure_proxy(peer_id, &deliver.origin_endpoint_id, None)?;
        let caller = self.proxy_caller(&proxy, owner)?;
        let origin = &deliver.origin_message_id;

        let prior: Option<String> = self
            .conn
            .query_row(
                "SELECT message_id FROM idempotency WHERE sender=?1 AND key=?2",
                (principal_key(&caller.principal), origin.as_str()),
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;
        // A response's request is already answered by the time it is replayed, so answering it
        // again would be refused; the prior commit is the answer.
        if let (Some(prior), Kind::Response) = (&prior, deliver.kind) {
            return load_message(&self.conn, prior);
        }

        let refs: Vec<Ref> = deliver
            .refs
            .iter()
            .map(|wire| localize_ref(wire, peer_id))
            .collect();
        if deliver.kind == Kind::Response {
            let request = deliver
                .reply_to_origin
                .as_ref()
                .expect("a validated response names its request");
            let outcome = deliver
                .outcome
                .expect("a validated response carries an outcome");
            return self.respond(
                &caller,
                request,
                outcome,
                &deliver.text,
                refs,
                origin.as_str(),
            );
        }

        if prior.is_none() && !self.peer_inbound_budget_left(peer_id, now_ms())? {
            return Err(MeshError::new(
                ErrorCode::RateLimited,
                format!(
                    "this host accepts {PEER_MAX_INBOUND_PER_MINUTE} messages a minute from one \
                     peer and has had them"
                ),
            ));
        }
        let draft = Draft {
            to: deliver.to_endpoint_id.clone(),
            kind: deliver.kind,
            reply_to: None,
            outcome: None,
            subject: deliver.subject.clone(),
            text: deliver.text.clone(),
            refs,
            idempotency_key: origin.as_str().to_owned(),
            expires_in_ms: deliver.remaining_lifetime_ms,
        };
        self.send_as(&caller, &draft, Some(origin))
    }

    fn peer_inbound_budget_left(&self, peer_id: &Opaque, now: i64) -> Result<bool> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM message m JOIN proxy x ON x.endpoint_id = m.from_endpoint
                 WHERE x.peer_id=?1 AND m.kind != 'response' AND m.created_at > ?2",
                (peer_id.as_str(), now - 60_000),
                |row| row.get(0),
            )
            .map_err(sql)?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX) < PEER_MAX_INBOUND_PER_MINUTE)
    }

    /// Whether mail from this sender may start another turn this minute, counted across every
    /// local agent its peer host has reached. Anything that is not a peer has no such budget.
    pub fn peer_activation_budget_left(&self, sender: &Principal, now: i64) -> Result<bool> {
        let Some(proxy) = sender
            .endpoint_id
            .as_ref()
            .filter(|_| sender.kind == PrincipalKind::Peer)
        else {
            return Ok(true);
        };
        let count: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM audit a
                   JOIN message m ON m.message_id = a.message_id
                   JOIN proxy x ON x.endpoint_id = m.from_endpoint
                 WHERE x.peer_id = (SELECT peer_id FROM proxy WHERE endpoint_id=?1)
                   AND a.operation='activate' AND a.result='started' AND a.at_ms > ?2",
                (proxy.as_str(), now - 60_000),
                |row| row.get(0),
            )
            .map_err(sql)?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX) < PEER_MAX_AUTO_TURNS_PER_MINUTE)
    }

    /// The `deliver` frame for a message on a proxy's outbox.
    ///
    /// Refused — for the bridge to record as the message's failure — when the message cannot be
    /// expressed to the peer: no sending endpoint to answer, a reference naming a third host, a
    /// response to something the peer never asked, or a lifetime already spent.
    pub fn outbound(&self, proxy: &Proxy, message: &Message, now: i64) -> Result<Deliver> {
        let origin_endpoint_id = message.from.endpoint_id.clone().ok_or_else(|| {
            MeshError::new(
                ErrorCode::InvalidRequest,
                "the sender has no mailbox for the peer to answer",
            )
        })?;
        let mut refs = Vec::with_capacity(message.refs.len());
        for reference in &message.refs {
            refs.push(match reference {
                Ref::File { host: None, .. } => WireRef {
                    on: RefHost::Sender,
                    reference: reference.clone(),
                },
                Ref::File {
                    path,
                    sha256,
                    bytes,
                    host: Some(host),
                } if *host == proxy.peer_id => WireRef {
                    on: RefHost::Recipient,
                    reference: Ref::File {
                        path: path.clone(),
                        sha256: sha256.clone(),
                        bytes: *bytes,
                        host: None,
                    },
                },
                Ref::File { .. } => {
                    return Err(MeshError::new(
                        ErrorCode::InvalidRequest,
                        "a reference names a file on a third host, which this peer cannot reach",
                    ));
                }
                other => WireRef {
                    on: RefHost::Sender,
                    reference: other.clone(),
                },
            });
        }
        let reply_to_origin = match message.kind {
            Kind::Response => {
                let request = message
                    .reply_to
                    .as_ref()
                    .ok_or_else(|| MeshError::new(ErrorCode::StoreCorrupt, "an orphan response"))?;
                let origin = self.message(request)?.origin_message_id.ok_or_else(|| {
                    MeshError::new(
                        ErrorCode::InvalidRequest,
                        "that response answers a request the peer did not send",
                    )
                })?;
                Some(origin)
            }
            Kind::Request | Kind::Notice => None,
        };
        let remaining_lifetime_ms = match message.expires_at_ms {
            Some(expires) if expires <= now => {
                return Err(MeshError::new(
                    ErrorCode::Expired,
                    "the message expired before it reached the peer",
                ));
            }
            Some(expires) => Some((expires - now).min(MAX_REQUEST_LIFETIME_MS)),
            None => None,
        };
        let deliver = Deliver {
            origin_message_id: message.message_id.clone(),
            origin_endpoint_id,
            to_endpoint_id: proxy.remote_endpoint_id.clone(),
            kind: message.kind,
            reply_to_origin,
            outcome: message.outcome,
            subject: message.subject.clone(),
            text: message.text.clone(),
            refs,
            remaining_lifetime_ms,
        };
        deliver.validate()?;
        Ok(deliver)
    }

    /// The peer committed a message the bridge forwarded.
    ///
    /// A request is now `delivered` — it still waits for its answer and still holds the outbox's
    /// capacity, which is what bounds how much one local agent may have outstanding with a remote
    /// one. A notice or a response has nothing left to wait for and is consumed. Returns `false`,
    /// changing nothing, if this bridge no longer holds the claim.
    pub fn forwarded(&mut self, caller: &Caller, message_id: &Opaque) -> Result<bool> {
        self.settle_outbound(caller, message_id, None)
    }

    /// The peer refused a message, or it could not be expressed to the peer. It becomes
    /// `undeliverable` with the reason, so the sender's `wait` ends instead of hanging.
    pub fn forward_failed(
        &mut self,
        caller: &Caller,
        message_id: &Opaque,
        code: ErrorCode,
    ) -> Result<bool> {
        self.settle_outbound(caller, message_id, Some(code))
    }

    fn settle_outbound(
        &mut self,
        caller: &Caller,
        message_id: &Opaque,
        failure: Option<ErrorCode>,
    ) -> Result<bool> {
        let (proxy, owner) = agent_identity(caller)?;
        self.require_peer_authority(caller)?;
        let now = now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let changed = tx
            .execute(
                "UPDATE message SET
                     state = CASE WHEN ?4 IS NOT NULL THEN 'undeliverable'
                                  WHEN kind = 'request' THEN 'delivered'
                                  ELSE 'consumed' END,
                     failure = ?4, claim_owner = NULL, claim_expires_at = NULL
                 WHERE message_id=?1 AND to_endpoint=?2 AND state='claimed' AND claim_owner=?3",
                rusqlite::params![
                    message_id.as_str(),
                    proxy.as_str(),
                    owner.as_str(),
                    failure.map(ErrorCode::as_str),
                ],
            )
            .map_err(sql)?;
        if changed > 0 {
            recount(&tx, proxy.as_str())?;
            let state = load_message(&tx, message_id.as_str())?.state;
            audit(
                &tx,
                now,
                Some(message_id.as_str()),
                Some(proxy.as_str()),
                "forward",
                Some("claimed"),
                Some(state.as_str()),
                None,
                0,
                failure.map_or("accepted", ErrorCode::as_str),
            )?;
        }
        tx.commit().map_err(sql)?;
        Ok(changed > 0)
    }

    /// Mail this peer sent, by the peer's own id for it.
    pub fn message_by_origin(&self, peer_id: &Opaque, origin: &Opaque) -> Result<Option<Message>> {
        let id: Option<String> = self
            .conn
            .query_row(
                "SELECT m.message_id FROM message m JOIN proxy x ON x.endpoint_id = m.from_endpoint
                 WHERE x.peer_id=?1 AND m.origin_message_id=?2",
                (peer_id.as_str(), origin.as_str()),
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;
        id.map(|id| load_message(&self.conn, &id)).transpose()
    }

    /// Requests to this peer whose senders asked for them to stop, for the bridge to pass on.
    pub fn cancellations_to_forward(&self, peer_id: &Opaque) -> Result<Vec<(Opaque, Opaque)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT m.message_id, m.to_endpoint FROM message m
                   JOIN proxy x ON x.endpoint_id = m.to_endpoint
                 WHERE x.peer_id=?1 AND m.state='cancellation_requested'
                 ORDER BY m.created_at",
            )
            .map_err(sql)?;
        let rows: Vec<(String, String)> = stmt
            .query_map([peer_id.as_str()], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(sql)?
            .collect::<std::result::Result<_, _>>()
            .map_err(sql)?;
        rows.iter()
            .map(|(message, proxy)| Ok((Opaque::parse(message)?, Opaque::parse(proxy)?)))
            .collect()
    }

    /// The peer reports where a cancellation got to. Only a confirmed `cancelled` changes anything
    /// here: the store still never manufactures an outcome nobody confirmed.
    pub fn confirm_remote_cancel(
        &mut self,
        caller: &Caller,
        message_id: &Opaque,
        state: State,
    ) -> Result<State> {
        let (proxy, _) = agent_identity(caller)?;
        self.require_peer_authority(caller)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        if state == State::Cancelled {
            let changed = tx
                .execute(
                    "UPDATE message SET state='cancelled', claim_owner=NULL, claim_expires_at=NULL
                     WHERE message_id=?1 AND to_endpoint=?2
                       AND state IN ('claimed','delivered','cancellation_requested')",
                    (message_id.as_str(), proxy.as_str()),
                )
                .map_err(sql)?;
            if changed > 0 {
                recount(&tx, proxy.as_str())?;
                audit(
                    &tx,
                    now_ms(),
                    Some(message_id.as_str()),
                    Some(proxy.as_str()),
                    "cancel",
                    None,
                    Some("cancelled"),
                    None,
                    0,
                    "confirmed_by_peer",
                )?;
            }
        }
        let now = load_message(&tx, message_id.as_str())?.state;
        tx.commit().map_err(sql)?;
        Ok(now)
    }

    /// Ask a peer to resolve `selector` in its own tree. The bridge holding the connection asks
    /// and records the answer; poll [`Self::take_resolution`] for it.
    ///
    /// Refused as `peer_unreachable` unless a bridge holds the peer's lease now: an alias or
    /// address means whatever is in that place on that host *now*, and nothing else can say.
    pub fn request_resolution(&mut self, peer_id: &Opaque, selector: &str) -> Result<i64> {
        if selector.is_empty()
            || selector.len() > MAX_SELECTOR_BYTES
            || selector.chars().any(char::is_control)
        {
            return Err(MeshError::new(
                ErrorCode::InvalidRequest,
                format!("a selector is 1..={MAX_SELECTOR_BYTES} bytes with no control characters"),
            ));
        }
        let now = now_ms();
        let peer = self.peer_by_id(peer_id)?;
        if !peer.lease.as_ref().is_some_and(|lease| lease.is_live(now)) {
            return Err(MeshError::new(
                ErrorCode::PeerUnreachable,
                format!(
                    "no bridge to `{}` is connected, and only it can say what that names; \
                     connect first, or address an exact id, which queues while it is away",
                    peer.label
                ),
            ));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        tx.execute(
            "DELETE FROM resolution WHERE created_at <= ?1",
            [now - RESOLUTION_RETENTION_MS],
        )
        .map_err(sql)?;
        let waiting: i64 = tx
            .query_row(
                "SELECT count(*) FROM resolution
                 WHERE peer_id=?1 AND answered_at IS NULL AND created_at > ?2",
                (peer_id.as_str(), now - RESOLUTION_TIMEOUT_MS),
                |row| row.get(0),
            )
            .map_err(sql)?;
        if waiting >= MAX_PENDING_RESOLUTIONS {
            return Err(MeshError::new(
                ErrorCode::RateLimited,
                "too many questions are already waiting for that peer",
            ));
        }
        tx.execute(
            "INSERT INTO resolution (peer_id, selector, created_at) VALUES (?1, ?2, ?3)",
            (peer_id.as_str(), selector, now),
        )
        .map_err(sql)?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(sql)?;
        Ok(id)
    }

    /// Questions for this peer that are still worth asking.
    pub fn pending_resolutions(&self, peer_id: &Opaque) -> Result<Vec<(i64, String)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT request_id, selector FROM resolution
                 WHERE peer_id=?1 AND answered_at IS NULL AND created_at > ?2
                 ORDER BY request_id",
            )
            .map_err(sql)?;
        let rows = stmt
            .query_map(
                (peer_id.as_str(), now_ms() - RESOLUTION_TIMEOUT_MS),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sql)?
            .collect::<std::result::Result<_, _>>()
            .map_err(sql)?;
        Ok(rows)
    }

    /// Record the peer's answer. Only the peer that was asked can answer, and only once.
    pub fn answer_resolution(
        &mut self,
        peer_id: &Opaque,
        request_id: i64,
        answer: Resolution,
    ) -> Result<bool> {
        let (endpoint, display, code, message, candidates) =
            match answer {
                Ok((endpoint, display)) => (Some(endpoint), display, None, None, None),
                Err(err) => (
                    None,
                    None,
                    Some(err.code.as_str()),
                    Some(err.message),
                    Some(serde_json::to_string(&err.candidates).map_err(|err| {
                        MeshError::new(ErrorCode::InvalidRequest, err.to_string())
                    })?),
                ),
            };
        let changed = self
            .conn
            .execute(
                "UPDATE resolution SET answered_at=?3, endpoint_id=?4, display=?5, error_code=?6,
                        error_message=?7, candidates_json=?8
                 WHERE request_id=?1 AND peer_id=?2 AND answered_at IS NULL",
                rusqlite::params![
                    request_id,
                    peer_id.as_str(),
                    now_ms(),
                    endpoint.as_ref().map(Opaque::as_str),
                    display,
                    code,
                    message,
                    candidates,
                ],
            )
            .map_err(sql)?;
        Ok(changed > 0)
    }

    /// The answer to a question, once there is one. Reading it removes it.
    pub fn take_resolution(&mut self, request_id: i64) -> Result<Option<Resolution>> {
        type Answer = (
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let row: Option<Answer> = self
            .conn
            .query_row(
                "SELECT answered_at, endpoint_id, display, error_code, error_message,
                        candidates_json
                 FROM resolution WHERE request_id=?1",
                [request_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(sql)?;
        let Some((Some(_), endpoint, display, code, message, candidates)) = row else {
            return Ok(None);
        };
        self.conn
            .execute("DELETE FROM resolution WHERE request_id=?1", [request_id])
            .map_err(sql)?;
        let answer = match (endpoint, code) {
            (Some(endpoint), _) => Ok((Opaque::parse(&endpoint)?, display)),
            (None, Some(code)) => {
                let code = serde_json::from_value(serde_json::Value::String(code))
                    .unwrap_or(ErrorCode::AgentNotFound);
                let candidates: Vec<String> = candidates
                    .as_deref()
                    .and_then(|json| serde_json::from_str(json).ok())
                    .unwrap_or_default();
                Err(MeshError::new(code, message.unwrap_or_default()).with_candidates(candidates))
            }
            (None, None) => {
                return Err(MeshError::new(
                    ErrorCode::StoreCorrupt,
                    "an answered resolution with no answer",
                ));
            }
        };
        Ok(Some(answer))
    }

    /// The copy of attachment `position` a send with this key already handed to a peer, if any.
    pub fn recorded_attachment(
        &self,
        caller: &Caller,
        key: &str,
        position: usize,
    ) -> Result<Option<RecordedAttachment>> {
        type Row = (String, String, i64, String);
        let row: Option<Row> = self
            .conn
            .query_row(
                "SELECT peer_id, sha256, bytes, remote_path FROM attachment
                 WHERE sender=?1 AND key=?2 AND position=?3",
                rusqlite::params![
                    principal_key(&caller.principal),
                    key,
                    i64::try_from(position).unwrap_or(i64::MAX),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sql)?;
        row.map(|(peer_id, sha256, bytes, remote_path)| {
            Ok(RecordedAttachment {
                peer_id: Opaque::parse(&peer_id)?,
                sha256,
                bytes: u64::try_from(bytes).unwrap_or_default(),
                remote_path,
            })
        })
        .transpose()
    }

    /// Record that attachment `position` of a send with this key now exists on a peer.
    ///
    /// Recorded before the message is enqueued, so a send that fails after its files were copied
    /// can be retried without copying them again. The audit row says how many bytes went to which
    /// proxy — never the file's name, path, or digest (plan-final §9.4).
    pub fn record_attachment(
        &mut self,
        caller: &Caller,
        key: &str,
        position: usize,
        proxy: &Opaque,
        attachment: &RecordedAttachment,
    ) -> Result<()> {
        let now = now_ms();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        // A record is useful only while a retry of its send could still be accepted.
        tx.execute(
            "DELETE FROM attachment WHERE created_at <= ?1",
            [now - MAX_REQUEST_LIFETIME_MS],
        )
        .map_err(sql)?;
        let bytes = i64::try_from(attachment.bytes).map_err(|_| {
            MeshError::new(ErrorCode::InvalidRequest, "an attachment larger than i64")
        })?;
        tx.execute(
            "INSERT OR REPLACE INTO attachment
                 (sender, key, position, peer_id, sha256, bytes, remote_path, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                principal_key(&caller.principal),
                key,
                i64::try_from(position).unwrap_or(i64::MAX),
                attachment.peer_id.as_str(),
                attachment.sha256,
                bytes,
                attachment.remote_path,
                now,
            ],
        )
        .map_err(sql)?;
        audit(
            &tx,
            now,
            None,
            Some(proxy.as_str()),
            "attach",
            None,
            None,
            None,
            bytes,
            "copied",
        )?;
        tx.commit().map_err(sql)?;
        Ok(())
    }

    /// How to name an endpoint to a person, in a form they can retype. A proxy is named by its
    /// peer and the remote id, `agent://buildbox/<id>`, never as if it were local.
    pub fn name_of(&self, endpoint: &Endpoint) -> String {
        if endpoint.locator.kind != RuntimeKind::Peer {
            return agent_mesh_core::qualified_name(endpoint);
        }
        let named = self.proxy(&endpoint.endpoint_id).ok().and_then(|proxy| {
            let peer = self.peer_by_id(&proxy.peer_id).ok()?;
            Some(format!(
                "agent://{}/{}",
                peer.label, proxy.remote_endpoint_id
            ))
        });
        named.unwrap_or_else(|| format!("agent://peer/{}", endpoint.endpoint_id))
    }

    /// The audit trail for one message: metadata only, never its body.
    pub fn audit_for(&self, message_id: &Opaque) -> Result<Vec<AuditRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT at_ms, message_id, endpoint_id, operation, from_state, to_state, rule,
                        bytes, result
                 FROM audit WHERE message_id=?1 ORDER BY id",
            )
            .map_err(sql)?;
        let rows = stmt
            .query_map([message_id.as_str()], |row| {
                Ok(AuditRow {
                    at_ms: row.get(0)?,
                    message_id: row.get(1)?,
                    endpoint_id: row.get(2)?,
                    operation: row.get(3)?,
                    from_state: row.get(4)?,
                    to_state: row.get(5)?,
                    rule: row.get(6)?,
                    bytes: row.get(7)?,
                    result: row.get(8)?,
                })
            })
            .map_err(sql)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(sql)?);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn agent_identity(caller: &Caller) -> Result<(Opaque, Opaque)> {
    match (
        caller.principal.endpoint_id.clone(),
        caller.principal.incarnation_id.clone(),
    ) {
        (Some(endpoint), Some(incarnation)) => Ok((endpoint, incarnation)),
        _ => Err(MeshError::new(
            ErrorCode::NotAuthorized,
            "this operation needs a bound endpoint; the local user has no mailbox",
        )),
    }
}

/// The idempotency namespace for a sender. Scoped to the endpoint, so two agents may use the same
/// key without colliding.
fn principal_key(principal: &Principal) -> String {
    match &principal.endpoint_id {
        Some(id) => format!("agent:{id}"),
        None => "local_user".to_owned(),
    }
}

/// One endpoint's address, read inside a transaction. `None` when it has none or is unknown.
fn self_endpoint_address(tx: &rusqlite::Transaction<'_>, endpoint_id: &str) -> Option<Address> {
    tx.query_row(
        "SELECT address FROM endpoint WHERE endpoint_id=?1",
        [endpoint_id],
        |row| row.get::<_, Option<String>>(0),
    )
    .optional()
    .ok()
    .flatten()
    .flatten()
    .and_then(|value| Address::parse(&value).ok())
}

fn recount(tx: &rusqlite::Transaction<'_>, endpoint_id: &str) -> Result<()> {
    tx.execute(
        "UPDATE endpoint SET
             pending_count = (SELECT count(*) FROM message WHERE to_endpoint=?1
                              AND state IN ('queued','claimed','delivered',
                                            'cancellation_requested')),
             pending_bytes = (SELECT coalesce(sum(bytes),0) FROM message WHERE to_endpoint=?1
                              AND state IN ('queued','claimed','delivered',
                                            'cancellation_requested'))
         WHERE endpoint_id=?1",
        [endpoint_id],
    )
    .map_err(sql)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn audit(
    tx: &rusqlite::Transaction<'_>,
    at_ms: i64,
    message_id: Option<&str>,
    endpoint_id: Option<&str>,
    operation: &str,
    from_state: Option<&str>,
    to_state: Option<&str>,
    rule: Option<&str>,
    bytes: i64,
    result: &str,
) -> Result<()> {
    tx.execute(
        "INSERT INTO audit (at_ms, message_id, endpoint_id, operation, from_state, to_state,
                            rule, bytes, result)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            at_ms,
            message_id,
            endpoint_id,
            operation,
            from_state,
            to_state,
            rule,
            bytes,
            result
        ],
    )
    .map_err(sql)?;
    Ok(())
}

trait Queryable {
    fn one<T, F>(&self, sql: &str, id: &str, f: F) -> rusqlite::Result<Option<T>>
    where
        F: FnOnce(&Row<'_>) -> rusqlite::Result<T>;
}

impl Queryable for Connection {
    fn one<T, F>(&self, query: &str, id: &str, f: F) -> rusqlite::Result<Option<T>>
    where
        F: FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    {
        self.query_row(query, [id], f).optional()
    }
}

impl Queryable for rusqlite::Transaction<'_> {
    fn one<T, F>(&self, query: &str, id: &str, f: F) -> rusqlite::Result<Option<T>>
    where
        F: FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    {
        self.query_row(query, [id], f).optional()
    }
}

fn load_message(conn: &impl Queryable, message_id: &str) -> Result<Message> {
    conn.one(
        "SELECT * FROM message WHERE message_id=?1",
        message_id,
        read_message,
    )
    .map_err(sql)?
    .ok_or_else(|| not_found("message"))?
}

fn read_message(row: &Row<'_>) -> rusqlite::Result<Result<Message>> {
    Ok(build_message(row))
}

fn build_message(row: &Row<'_>) -> Result<Message> {
    let get =
        |name: &str| -> Result<Option<String>> { row.get::<_, Option<String>>(name).map_err(sql) };
    let refs_json: String = row.get("refs_json").map_err(sql)?;
    Ok(Message {
        message_id: Opaque::parse(&row.get::<_, String>("message_id").map_err(sql)?)?,
        to_endpoint: Opaque::parse(&row.get::<_, String>("to_endpoint").map_err(sql)?)?,
        from: Principal {
            kind: PrincipalKind::parse(&row.get::<_, String>("from_kind").map_err(sql)?)?,
            endpoint_id: get("from_endpoint")?
                .as_deref()
                .map(Opaque::parse)
                .transpose()?,
            incarnation_id: get("from_incarnation")?
                .as_deref()
                .map(Opaque::parse)
                .transpose()?,
        },
        kind: Kind::parse(&row.get::<_, String>("kind").map_err(sql)?)?,
        conversation_id: Opaque::parse(&row.get::<_, String>("conversation_id").map_err(sql)?)?,
        reply_to: get("reply_to")?.as_deref().map(Opaque::parse).transpose()?,
        outcome: get("outcome")?.as_deref().map(Outcome::parse).transpose()?,
        recipient_sequence: row.get("recipient_sequence").map_err(sql)?,
        state: State::parse(&row.get::<_, String>("state").map_err(sql)?)?,
        subject: get("subject")?,
        text: row.get("text").map_err(sql)?,
        refs: serde_json::from_str(&refs_json)
            .map_err(|err| MeshError::new(ErrorCode::StoreCorrupt, err.to_string()))?,
        created_at_ms: row.get("created_at").map_err(sql)?,
        expires_at_ms: row.get("expires_at").map_err(sql)?,
        failure: get("failure")?,
        origin_message_id: get("origin_message_id")?
            .as_deref()
            .map(Opaque::parse)
            .transpose()?,
    })
}

fn read_endpoint(row: &Row<'_>) -> rusqlite::Result<Result<Endpoint>> {
    Ok(build_endpoint(row))
}

fn build_endpoint(row: &Row<'_>) -> Result<Endpoint> {
    Ok(Endpoint {
        endpoint_id: Opaque::parse(&row.get::<_, String>(0).map_err(sql)?)?,
        incarnation_id: row
            .get::<_, Option<String>>(1)
            .map_err(sql)?
            .as_deref()
            .map(Opaque::parse)
            .transpose()?,
        alias: row
            .get::<_, Option<String>>(2)
            .map_err(sql)?
            .as_deref()
            .map(Alias::parse)
            .transpose()?,
        provider: row.get(3).map_err(sql)?,
        locator: Locator {
            kind: RuntimeKind::parse(&row.get::<_, String>(4).map_err(sql)?)?,
            runtime_instance_id: Opaque::parse(&row.get::<_, String>(5).map_err(sql)?)?,
            instance_name: row.get(6).map_err(sql)?,
            address: row
                .get::<_, Option<String>>(7)
                .map_err(sql)?
                .as_deref()
                .map(Address::parse)
                .transpose()?,
        },
        online: row.get::<_, i64>(8).map_err(sql)? != 0,
        state: AgentState::parse(&row.get::<_, String>(9).map_err(sql)?)?,
        state_generation: row.get(10).map_err(sql)?,
        pending: row.get(11).map_err(sql)?,
    })
}

/// Evaluate visibility against the same database snapshot as the claim. A refused head
/// message stays queued without hiding later authorized mail.
fn message_decision(conn: &Connection, message: &Message, gate: Gate) -> Result<Decision> {
    let (json, scope, address): (Option<String>, String, Option<String>) = conn
        .query_row(
            "SELECT policy_json, runtime_instance_id, address FROM endpoint WHERE endpoint_id=?1",
            [message.to_endpoint.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sql)?;
    let policy: Policy = json
        .map(|json| {
            serde_json::from_str(&json)
                .map_err(|error| MeshError::new(ErrorCode::InvalidRequest, error.to_string()))
        })
        .transpose()?
        .unwrap_or_default();
    let sender: Option<(String, Option<String>)> = match &message.from.endpoint_id {
        Some(id) => conn
            .query_row(
                "SELECT runtime_instance_id, address FROM endpoint WHERE endpoint_id=?1",
                [id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql)?,
        None => None,
    };
    let sender_scope = sender
        .as_ref()
        .map(|(scope, _)| Opaque::parse(scope))
        .transpose()?;
    let sender_address = sender
        .as_ref()
        .and_then(|(_, address)| address.as_deref())
        .map(Address::parse)
        .transpose()?;
    let target_address = address.as_deref().map(Address::parse).transpose()?;
    let is_reply = message.kind == Kind::Response
        && message.reply_to.as_ref().is_some_and(|id| {
            load_message(conn, id.as_str()).is_ok_and(|request| {
                request.from.endpoint_id.as_ref() == Some(&message.to_endpoint)
            })
        });
    Ok(policy.evaluate(
        gate,
        &agent_mesh_core::Request {
            sender: &message.from,
            sender_scope: sender_scope.as_ref(),
            target_scope: &Opaque::parse(&scope)?,
            is_reply_to_our_request: is_reply,
            sender_address: sender_address.as_ref(),
            target_address: target_address.as_ref(),
            peer_trusted: peer_trusted(conn, &message.from)?,
        },
    ))
}

fn apply_v7(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    tx.execute_batch(SCHEMA_V7).map_err(sql)
}

fn apply_v6(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    tx.execute_batch(SCHEMA_V6).map_err(sql)
}

fn apply_v5(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    tx.execute_batch(SCHEMA_V5).map_err(sql)?;
    tx.execute(
        "INSERT INTO store_identity (singleton, host_id, created_at) VALUES (1, ?1, ?2)",
        (Opaque::generate().as_str(), now_ms()),
    )
    .map_err(sql)?;
    Ok(())
}

/// Whether a `peer` sender's whole host is trusted. Anything else is not a peer and gets `false`.
fn peer_trusted(conn: &Connection, sender: &Principal) -> Result<bool> {
    let Some(id) = sender.endpoint_id.as_ref() else {
        return Ok(false);
    };
    if sender.kind != PrincipalKind::Peer {
        return Ok(false);
    }
    let trusted: Option<i64> = conn
        .query_row(
            "SELECT p.trusted FROM proxy x JOIN peer p ON p.peer_id = x.peer_id
             WHERE x.endpoint_id = ?1 AND p.retired = 0",
            [id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    Ok(trusted == Some(1))
}

/// A proxy's own gates: it is an outbox for local senders, and is never woken.
///
/// The real policy is the remote agent's, applied on its host when the message arrives there.
fn proxy_policy() -> Policy {
    Policy {
        enqueue: Admit::Anyone,
        make_visible: Admit::Anyone,
        activate: Admit::Nobody,
        team: TeamScope::Off,
        ..Policy::default()
    }
}

fn read_peer(row: &Row<'_>) -> rusqlite::Result<Result<Peer>> {
    Ok(build_peer(row))
}

fn build_peer(row: &Row<'_>) -> Result<Peer> {
    let label: String = row.get("label").map_err(sql)?;
    let owner: Option<String> = row.get("lease_owner").map_err(sql)?;
    let expires: Option<i64> = row.get("lease_expires_at").map_err(sql)?;
    let anchor: Option<String> = row.get("lease_anchor").map_err(sql)?;
    let lease = match (owner, expires) {
        (Some(owner), Some(expires_at_ms)) => Some(Lease {
            owner: Opaque::parse(&owner)?,
            expires_at_ms,
            anchor: anchor.as_deref().map(parse_anchor).transpose()?,
        }),
        _ => None,
    };
    Ok(Peer {
        peer_id: Opaque::parse(&row.get::<_, String>("peer_id").map_err(sql)?)?,
        label: PeerLabel::parse(&label)?,
        host_id: Opaque::parse(&row.get::<_, String>("host_id").map_err(sql)?)?,
        trusted: row.get::<_, i64>("trusted").map_err(sql)? != 0,
        lease,
    })
}

/// A reference as this store holds it. `on: sender` means the peer's filesystem.
fn localize_ref(wire: &WireRef, peer_id: &Opaque) -> Ref {
    match (&wire.on, &wire.reference) {
        (
            RefHost::Sender,
            Ref::File {
                path,
                sha256,
                bytes,
                ..
            },
        ) => Ref::File {
            path: path.clone(),
            sha256: sha256.clone(),
            bytes: *bytes,
            host: Some(peer_id.clone()),
        },
        (_, reference) => reference.clone(),
    }
}

fn read_proxy(row: &Row<'_>) -> rusqlite::Result<Result<Proxy>> {
    Ok(build_proxy(row))
}

fn build_proxy(row: &Row<'_>) -> Result<Proxy> {
    Ok(Proxy {
        endpoint_id: Opaque::parse(&row.get::<_, String>(0).map_err(sql)?)?,
        peer_id: Opaque::parse(&row.get::<_, String>(1).map_err(sql)?)?,
        remote_endpoint_id: Opaque::parse(&row.get::<_, String>(2).map_err(sql)?)?,
        display: row.get(3).map_err(sql)?,
    })
}

fn anchor_json(anchor: &LeaseAnchor) -> String {
    serde_json::json!({
        "runtime": anchor.runtime.as_str(),
        "instance": anchor.instance,
        "window": anchor.window,
    })
    .to_string()
}

fn parse_anchor(json: &str) -> Result<LeaseAnchor> {
    let corrupt = || MeshError::new(ErrorCode::StoreCorrupt, "unreadable lease anchor");
    let value: serde_json::Value = serde_json::from_str(json).map_err(|_| corrupt())?;
    Ok(LeaseAnchor {
        runtime: RuntimeKind::parse(value["runtime"].as_str().ok_or_else(corrupt)?)?,
        instance: value["instance"].as_str().ok_or_else(corrupt)?.to_owned(),
        window: value["window"]
            .as_u64()
            .and_then(|window| u32::try_from(window).ok())
            .ok_or_else(corrupt)?,
    })
}

/// Return a departing bridge's in-flight proxy claims to the queue, so its successor resends them.
/// The peer's idempotency on the origin message id makes that resend harmless.
fn requeue_proxy_claims(tx: &rusqlite::Transaction<'_>, peer_id: &str, owner: &str) -> Result<()> {
    tx.execute(
        "UPDATE message SET state='queued', claim_owner=NULL, claim_expires_at=NULL
         WHERE state='claimed' AND claim_owner=?2
           AND to_endpoint IN (SELECT endpoint_id FROM proxy WHERE peer_id=?1)",
        (peer_id, owner),
    )
    .map_err(sql)?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Compare without an early return on the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(unix)]
fn set_owner_only_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(io)
}

#[cfg(unix)]
fn set_owner_only_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io)
}

#[cfg(windows)]
fn set_owner_only_dir(path: &Path) -> Result<()> {
    windows::owner_only(path)
}

#[cfg(windows)]
fn set_owner_only_file(path: &Path) -> Result<()> {
    windows::owner_only(path)
}

/// Version 5: peer hosts, their proxies, and why forwarded mail could not be delivered.
///
/// A proxy is an ordinary `endpoint` row — so ids, quotas, idempotency, audit and `wait` all work
/// unchanged — plus a `proxy` row naming the peer and the remote endpoint it stands for. It keeps no
/// alias and no address in `endpoint`, so no local selector can ever resolve to one; `display` is a
/// label for people and is never resolved against (`vvagent-inter-host-plan.md` §4.2).
const SCHEMA_V5: &str = r"
CREATE TABLE store_identity (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    host_id    TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE peer (
    peer_id          TEXT PRIMARY KEY,
    -- NULL once retired, which frees the name for a different store.
    label            TEXT,
    -- The other store's id as first presented under this label; a different one is refused.
    host_id          TEXT NOT NULL,
    trusted          INTEGER NOT NULL DEFAULT 0,
    retired          INTEGER NOT NULL DEFAULT 0,
    -- The one bridge allowed to act for this peer, and until when. Live state, never identity.
    lease_owner      TEXT,
    lease_expires_at INTEGER,
    lease_anchor     TEXT,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX peer_label ON peer (label) WHERE label IS NOT NULL;

CREATE TABLE proxy (
    endpoint_id        TEXT PRIMARY KEY REFERENCES endpoint(endpoint_id),
    peer_id            TEXT NOT NULL REFERENCES peer(peer_id),
    remote_endpoint_id TEXT NOT NULL,
    display            TEXT,
    UNIQUE (peer_id, remote_endpoint_id)
) STRICT;

ALTER TABLE message ADD COLUMN failure TEXT;
-- For mail a bridge inserted: the originating host's own id for it, which is also the idempotency
-- key the insert used. It is how a local reply names the request on the host that asked.
ALTER TABLE message ADD COLUMN origin_message_id TEXT;
CREATE INDEX message_origin ON message (from_endpoint, origin_message_id)
    WHERE origin_message_id IS NOT NULL;
";

/// Version 6: questions for a peer that only it can answer (`vvagent-inter-host-plan.md` §5.2).
///
/// The store is the rendezvous between a `vvagent send` and the bridge process holding the
/// connection, as it is for everything else: the sender records the question, the bridge asks, and
/// writes the answer back. Rows are short-lived and bounded; nothing here is identity.
const SCHEMA_V6: &str = r"
CREATE TABLE resolution (
    request_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id         TEXT NOT NULL REFERENCES peer(peer_id),
    selector        TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    answered_at     INTEGER,
    endpoint_id     TEXT,
    display         TEXT,
    error_code      TEXT,
    error_message   TEXT,
    candidates_json TEXT
) STRICT;

CREATE INDEX resolution_peer ON resolution (peer_id, answered_at);
";

/// Version 7: files already handed to a peer for a send, by that send's idempotency key
/// (`vvagent-inter-host-plan.md` §7.5). A retried send finds its copies here instead of dropping
/// the same file a second time and leaving `name (1).ext` behind.
const SCHEMA_V7: &str = r"
CREATE TABLE attachment (
    sender      TEXT NOT NULL,
    key         TEXT NOT NULL,
    position    INTEGER NOT NULL,
    peer_id     TEXT NOT NULL REFERENCES peer(peer_id),
    sha256      TEXT NOT NULL,
    bytes       INTEGER NOT NULL,
    remote_path TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (sender, key, position)
) STRICT;
";

const SCHEMA: &str = r"
CREATE TABLE endpoint (
    endpoint_id         TEXT PRIMARY KEY,
    incarnation_id      TEXT,
    token_hash          TEXT,
    alias               TEXT,
    provider            TEXT,
    runtime_kind        TEXT NOT NULL,
    runtime_instance_id TEXT NOT NULL,
    instance_name       TEXT,
    -- One canonical address (§6.3), not four independent columns that could disagree.
    address             TEXT,
    online              INTEGER NOT NULL DEFAULT 0,
    state               TEXT NOT NULL DEFAULT 'unknown',
    state_generation    INTEGER NOT NULL DEFAULT 1,
    next_sequence       INTEGER NOT NULL DEFAULT 1,
    pending_count       INTEGER NOT NULL DEFAULT 0,
    pending_bytes       INTEGER NOT NULL DEFAULT 0,
    policy_json         TEXT,
    capabilities_json   TEXT,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
) STRICT;

-- One alias per runtime instance: that pairing is what makes a rebind find its own slot.
CREATE UNIQUE INDEX endpoint_alias_scope
    ON endpoint (alias, runtime_instance_id) WHERE alias IS NOT NULL;

CREATE TABLE message (
    message_id         TEXT PRIMARY KEY,
    to_endpoint        TEXT NOT NULL REFERENCES endpoint(endpoint_id),
    from_kind          TEXT NOT NULL,
    from_endpoint      TEXT,
    from_incarnation   TEXT,
    kind               TEXT NOT NULL,
    conversation_id    TEXT NOT NULL,
    reply_to           TEXT,
    outcome            TEXT,
    recipient_sequence INTEGER NOT NULL,
    state              TEXT NOT NULL,
    subject            TEXT,
    text               TEXT NOT NULL,
    refs_json          TEXT NOT NULL,
    bytes              INTEGER NOT NULL,
    created_at         INTEGER NOT NULL,
    expires_at         INTEGER,
    claim_owner        TEXT,
    claim_expires_at   INTEGER,
    activations        INTEGER NOT NULL DEFAULT 0,
    last_activated_at  INTEGER,
    group_send_id      TEXT,
    UNIQUE (to_endpoint, recipient_sequence)
) STRICT;

CREATE INDEX message_queue ON message (to_endpoint, state, recipient_sequence);
CREATE INDEX message_reply ON message (reply_to);

CREATE TABLE idempotency (
    sender     TEXT NOT NULL,
    key        TEXT NOT NULL,
    digest     TEXT NOT NULL,
    message_id TEXT NOT NULL REFERENCES message(message_id),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (sender, key)
) STRICT;

-- Metadata only. The mailbox already holds the body for its retention window; duplicating it here
-- would create a second secret-bearing surface (plan §9.4).
CREATE TABLE audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms       INTEGER NOT NULL,
    message_id  TEXT,
    endpoint_id TEXT,
    operation   TEXT NOT NULL,
    from_state  TEXT,
    to_state    TEXT,
    rule        TEXT,
    bytes       INTEGER NOT NULL DEFAULT 0,
    result      TEXT NOT NULL
) STRICT;

CREATE INDEX audit_message ON audit (message_id);

-- A group is a name for a set of endpoints. Membership is stored as ids for the same reason a
-- trust rule is: a list of aliases would follow those names to whatever answered to them next.
CREATE TABLE mesh_group (
    name       TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE group_member (
    name        TEXT NOT NULL REFERENCES mesh_group(name) ON DELETE CASCADE,
    endpoint_id TEXT NOT NULL REFERENCES endpoint(endpoint_id),
    PRIMARY KEY (name, endpoint_id)
) STRICT;

-- One fan-out. `members` is the membership *at the time of sending*, so later changes to the group
-- cannot change what a send meant, and a quorum is counted against who was actually asked.
CREATE TABLE group_send (
    group_send_id TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    sender        TEXT NOT NULL,
    members       TEXT NOT NULL,
    created_at    INTEGER NOT NULL
) STRICT;

CREATE INDEX message_group ON message (group_send_id);
";

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "agent-mesh-migrate-{name}-{}-{}",
                std::process::id(),
                now_ms()
            ))
            .join("mesh.sqlite")
    }

    /// Put a store back into the exact version-4 shape: the v4 schema, no v5 objects.
    fn downgrade_to_v4(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "DROP TABLE attachment;
             DROP TABLE resolution;
             DROP TABLE proxy; DROP TABLE peer; DROP TABLE store_identity;
             DROP INDEX message_origin;
             ALTER TABLE message DROP COLUMN failure;
             ALTER TABLE message DROP COLUMN origin_message_id;
             PRAGMA user_version = 4;",
        )
        .unwrap();
    }

    #[test]
    fn a_version_4_store_migrates_in_place_and_keeps_its_mail() {
        let path = scratch("v4");
        let (endpoint, message) = {
            let mut store = Store::open(&path).unwrap();
            let bound = store
                .bind(&Binding {
                    alias: Some(Alias::parse("keeper").unwrap()),
                    provider: None,
                    locator: Locator {
                        kind: RuntimeKind::Wrapper,
                        runtime_instance_id: Opaque::generate(),
                        instance_name: None,
                        address: None,
                    },
                })
                .unwrap();
            let user = store.ensure_local_user().unwrap();
            let sent = store
                .send(
                    &user,
                    &Draft {
                        to: bound.endpoint_id.clone(),
                        kind: Kind::Request,
                        reply_to: None,
                        outcome: None,
                        subject: None,
                        text: "survive the upgrade".into(),
                        refs: Vec::new(),
                        idempotency_key: "k".into(),
                        expires_in_ms: None,
                    },
                )
                .unwrap();
            (bound.endpoint_id, sent.message_id)
        };
        downgrade_to_v4(&path);

        let store = Store::open(&path).unwrap();
        let version: i64 = store
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let kept = store.message(&message).unwrap();
        assert_eq!(kept.text, "survive the upgrade");
        assert_eq!(kept.to_endpoint, endpoint);
        assert_eq!(kept.failure, None);
        let host = store.host_id().unwrap();
        drop(store);
        assert_eq!(
            Store::open(&path).unwrap().host_id().unwrap(),
            host,
            "migrating once mints the host id once"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn many_processes_creating_one_store_at_once_all_succeed() {
        // Found by the IH5 lane test: a watcher and a command opening a brand-new store together
        // failed with "cannot enter WAL mode: database is locked".
        for round in 0..20 {
            let path = scratch(&format!("race{round}"));
            let openers: Vec<_> = (0..8)
                .map(|_| {
                    let path = path.clone();
                    std::thread::spawn(move || Store::open(&path).map(|store| store.host_id()))
                })
                .collect();
            let ids: Vec<Opaque> = openers
                .into_iter()
                .map(|opener| opener.join().unwrap().unwrap().unwrap())
                .collect();
            assert!(
                ids.windows(2).all(|pair| pair[0] == pair[1]),
                "one store, one id"
            );
            let _ = std::fs::remove_dir_all(path.parent().unwrap());
        }
    }

    #[test]
    fn an_older_or_newer_store_is_refused_rather_than_guessed_at() {
        for version in [3, SCHEMA_VERSION + 1] {
            let path = scratch(&format!("v{version}"));
            drop(Store::open(&path).unwrap());
            Connection::open(&path)
                .unwrap()
                .pragma_update(None, "user_version", version)
                .unwrap();
            let refused = Store::open(&path).unwrap_err();
            assert_eq!(refused.code, ErrorCode::SchemaMismatch, "version {version}");
            let _ = std::fs::remove_dir_all(path.parent().unwrap());
        }
    }
}
