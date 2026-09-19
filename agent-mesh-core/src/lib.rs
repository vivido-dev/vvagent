//! Types, bounds, and pure logic for the agent mesh.
//!
//! No I/O. Everything here is either a wire type, a bound, or a decision that can be tested
//! without a database: identity, selector resolution, policy gates, and validation.
//!
//! See `docs/agent-mesh-plan-final.md` §6–§9.

use std::fmt;

use serde::{Deserialize, Serialize};

pub mod address;
pub mod bridge;
pub mod capability;
pub mod time;

pub use address::{Address, Level, Segment};

pub use capability::{ACTUATING, Capabilities, Capability, DeliveryMode, activation_text};

// ---------------------------------------------------------------------------------------------
// Bounds (plan §6.5). Every one of these is checked before allocation or mutation.
// ---------------------------------------------------------------------------------------------

pub const MAX_TEXT_BYTES: usize = 32 * 1024;
pub const MAX_SUBJECT_BYTES: usize = 256;
pub const MAX_REFS: usize = 16;
pub const MAX_PENDING_COUNT: i64 = 256;
pub const MAX_PENDING_BYTES: i64 = 4 * 1024 * 1024;
/// Headroom above the ordinary ceiling, reachable only by responses and cancellation state, so a
/// request flood cannot starve completion traffic.
pub const RESERVED_COUNT: i64 = 16;
pub const RESERVED_BYTES: i64 = 1024 * 1024;
pub const MAX_ENDPOINTS: i64 = 1024;
pub const MAX_ALIAS_BYTES: usize = 32;
pub const MAX_PEER_LABEL_BYTES: usize = 64;
/// Longest name a peer may give one of its agents. It is shown to people, never parsed.
pub const MAX_DISPLAY_BYTES: usize = 256;
/// Requests and notices one peer host may place on this host per minute, across every local agent.
///
/// Per-endpoint limits alone would let one peer spend the full allowance of every local agent at
/// once (`vvagent-inter-host-plan.md` §6.3).
pub const PEER_MAX_INBOUND_PER_MINUTE: u32 = 60;
/// Turns one peer host's mail may start per minute, across every local agent.
pub const PEER_MAX_AUTO_TURNS_PER_MINUTE: u32 = 4;
/// Files one message may carry to a peer (`vvagent-inter-host-plan.md` §7.6).
pub const MAX_ATTACHMENTS: usize = 8;
/// The default ceiling on one attachment. Configurable per send, never above the receiver's own.
pub const DEFAULT_MAX_ATTACHMENT_BYTES: u64 = 1024 * 1024 * 1024;
/// Above this, a recipient reports an attachment unverified rather than hashing it inline.
pub const MAX_INLINE_VERIFY_BYTES: u64 = 256 * 1024 * 1024;
/// Longest workspace or tab label a pane reference may carry.
pub const MAX_PANE_FIELD_BYTES: usize = 64;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
pub const MAX_PATH_BYTES: usize = 4096;
/// A media resource id is opaque, so it is bounded rather than parsed.
pub const MAX_RESOURCE_ID_BYTES: usize = 128;
/// Default and ceiling for a claim lease.
pub const DEFAULT_CLAIM_LEASE_MS: i64 = 5 * 60 * 1000;
/// The longest a request may live before it expires (plan §6.5).
pub const MAX_REQUEST_LIFETIME_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Bounded candidate list returned with `agent_ambiguous`, so an error cannot enumerate the host.
pub const MAX_AMBIGUOUS_CANDIDATES: usize = 8;

/// The envelope schema version. Bumped when the wire shape changes.
pub const ENVELOPE_SCHEMA: u32 = 1;

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// A stable, typed error. The `code` is contract; the message is for humans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshError {
    pub code: ErrorCode,
    pub message: String,
    /// Bounded, sanitized candidates for `AgentAmbiguous`. Never a full host enumeration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
}

impl MeshError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            candidates: Vec::new(),
        }
    }

    pub fn with_candidates(mut self, candidates: Vec<String>) -> Self {
        candidates
            .into_iter()
            .take(MAX_AMBIGUOUS_CANDIDATES)
            .for_each(|candidate| self.candidates.push(candidate));
        self
    }
}

impl fmt::Display for MeshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)?;
        if !self.candidates.is_empty() {
            write!(f, " [{}]", self.candidates.join(", "))?;
        }
        Ok(())
    }
}

impl std::error::Error for MeshError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    AgentNotFound,
    AgentAmbiguous,
    IdempotencyConflict,
    MailboxFull,
    ClaimLost,
    NotAuthorized,
    InvalidRequest,
    EndpointLimit,
    NotFound,
    AlreadyResponded,
    Expired,
    SchemaMismatch,
    StoreCorrupt,
    PolicyRefused,
    RateLimited,
    /// A peer label is pinned to a different store than the one now answering to it.
    PeerMismatch,
    /// The peer was forgotten; nothing more will be delivered to or from it.
    PeerRetired,
    /// Only a connected peer can answer this, and no bridge to it is connected.
    PeerUnreachable,
    /// A file cannot be handed to that peer: no `vvssh` window with a file-drop receiver carries
    /// its bridge.
    FileDropUnavailable,
    /// An attachment's length or SHA-256 did not match what was sent or recorded.
    AttachmentMismatch,
    Io,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentNotFound => "agent_not_found",
            Self::AgentAmbiguous => "agent_ambiguous",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::MailboxFull => "mailbox_full",
            Self::ClaimLost => "claim_lost",
            Self::NotAuthorized => "not_authorized",
            Self::InvalidRequest => "invalid_request",
            Self::EndpointLimit => "endpoint_limit",
            Self::NotFound => "not_found",
            Self::AlreadyResponded => "already_responded",
            Self::Expired => "expired",
            Self::SchemaMismatch => "schema_mismatch",
            Self::StoreCorrupt => "store_corrupt",
            Self::PolicyRefused => "policy_refused",
            Self::RateLimited => "rate_limited",
            Self::PeerMismatch => "peer_mismatch",
            Self::PeerRetired => "peer_retired",
            Self::PeerUnreachable => "peer_unreachable",
            Self::FileDropUnavailable => "file_drop_unavailable",
            Self::AttachmentMismatch => "attachment_mismatch",
            Self::Io => "io",
        }
    }
}

pub type Result<T> = std::result::Result<T, MeshError>;

fn invalid(message: impl Into<String>) -> MeshError {
    MeshError::new(ErrorCode::InvalidRequest, message)
}

// ---------------------------------------------------------------------------------------------
// Identity (plan §6.1)
// ---------------------------------------------------------------------------------------------

/// A 128-bit opaque identifier rendered as lowercase hex.
///
/// Deliberately not derived from a name, path, pid, or pane number: those are all reusable, and
/// the whole point of `EndpointId` is that it is not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Opaque(String);

/// Deserializing checks the same rule as [`Opaque::parse`]. An id that arrives in JSON — from a
/// bridge frame, a stored policy, an MCP call — is held to the format every other id is.
impl<'de> Deserialize<'de> for Opaque {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(|err| serde::de::Error::custom(err.message))
    }
}

impl Opaque {
    /// Mint a fresh identifier from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("OS entropy is available");
        Self(hex(&bytes))
    }

    pub fn parse(value: &str) -> Result<Self> {
        let ok = value.len() == 32
            && value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        ok.then(|| Self(value.to_owned()))
            .ok_or_else(|| invalid("an identifier is exactly 32 lowercase hex characters"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Opaque {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A human-chosen name for an endpoint.
///
/// Spelling matches `vvmux`'s `valid_target_name` exactly, so a name means the same thing on both
/// sides and a user never has to remember which surface tolerates an uppercase letter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Alias(String);

impl Alias {
    pub fn parse(value: &str) -> Result<Self> {
        let mut bytes = value.bytes();
        let ok = !value.is_empty()
            && value.len() <= MAX_ALIAS_BYTES
            && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
            && bytes
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'));
        ok.then(|| Self(value.to_owned())).ok_or_else(|| {
            invalid(
                "an alias starts with a lowercase letter and contains only lowercase letters, \
                 digits, '-' or '_' (1..=32 bytes)",
            )
        })
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Alias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The local name for a peer host — normally the host part of the SSH destination the user dials.
///
/// A display and selector name, never authority: a peer is identified by the `host_id` its store
/// presents, and a label is only pinned to one (`vvagent-inter-host-plan.md` §4.1). The spelling
/// excludes `@`, `:` and `/` so that `@label:selector` can never be read two ways.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerLabel(String);

impl PeerLabel {
    pub fn parse(value: &str) -> Result<Self> {
        let mut bytes = value.bytes();
        let ok = !value.is_empty()
            && value.len() <= MAX_PEER_LABEL_BYTES
            && bytes
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && bytes.all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
            });
        ok.then(|| Self(value.to_owned())).ok_or_else(|| {
            invalid(format!(
                "a peer label starts with a lowercase letter or digit and contains only lowercase \
                 letters, digits, '-', '_' or '.' (1..={MAX_PEER_LABEL_BYTES} bytes)"
            ))
        })
    }

    /// The label an SSH destination implies: its host, lowercased, without user or port.
    ///
    /// `user@Build.Example.com`, `ssh://user@buildbox:2222` and `buildbox` give `build.example.com`,
    /// `buildbox` and `buildbox`. A destination whose host does not fit the grammar — an IPv6
    /// literal, say — is refused, and the caller names the peer explicitly instead.
    pub fn from_destination(destination: &str) -> Result<Self> {
        let rest = destination.strip_prefix("ssh://").unwrap_or(destination);
        let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
        let host = match destination.starts_with("ssh://") {
            true => host.split_once(':').map_or(host, |(host, _)| host),
            false => host,
        };
        Self::parse(&host.to_ascii_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PeerLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which product owns the pane an endpoint lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Vvmux,
    Vivido,
    Vivida,
    /// An endpoint bound by `vvagent run` with no terminal runtime around it.
    Wrapper,
    /// A proxy for an agent on a peer host. Never bound by a process on this host.
    Peer,
}

impl RuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vvmux => "vvmux",
            Self::Vivido => "vivido",
            Self::Vivida => "vivida",
            Self::Wrapper => "wrapper",
            Self::Peer => "peer",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "vvmux" => Ok(Self::Vvmux),
            "vivido" => Ok(Self::Vivido),
            "vivida" => Ok(Self::Vivida),
            "wrapper" => Ok(Self::Wrapper),
            "peer" => Ok(Self::Peer),
            other => Err(invalid(format!("unknown runtime `{other}`"))),
        }
    }
}

/// Where an endpoint sits inside its runtime. Local numeric IDs are only ever meaningful together
/// with `runtime_instance_id`, which is why they never travel alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locator {
    pub kind: RuntimeKind,
    pub runtime_instance_id: Opaque,
    /// The instance's human name, for the runtime-qualified selector form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_name: Option<String>,
    /// Where this endpoint sits, as one canonical path (§6.3). One field, not four: a position is
    /// only meaningful as a whole path, and four independent columns invited them to disagree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
}

/// A live endpoint record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub endpoint_id: Opaque,
    /// `None` once the binding is released; the mailbox survives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incarnation_id: Option<Opaque>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<Alias>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub locator: Locator,
    pub online: bool,
    /// Monotonic, so a stale snapshot can be recognised rather than trusted (plan §2 row 9).
    pub state_generation: i64,
    pub state: AgentState,
    pub pending: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    Unknown,
    Idle,
    Working,
    Blocked,
    Offline,
}

impl AgentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Idle => "idle",
            Self::Working => "working",
            Self::Blocked => "blocked",
            Self::Offline => "offline",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "unknown" => Ok(Self::Unknown),
            "idle" => Ok(Self::Idle),
            "working" => Ok(Self::Working),
            "blocked" => Ok(Self::Blocked),
            "offline" => Ok(Self::Offline),
            other => Err(invalid(format!("unknown agent state `{other}`"))),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Selectors (plan §6.2)
// ---------------------------------------------------------------------------------------------

/// A human-typed way of naming an endpoint.
/// What a caller typed. A bare token may be a legal alias, a legal address, or both — `p2` is
/// both — so a selector records every reading rather than choosing one silently.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Selector {
    /// An exact endpoint id short-circuits everything else.
    pub endpoint: Option<Opaque>,
    /// `vvmux:dev/...` restricts the search to one runtime instance.
    pub scope: Option<QualifiedScope>,
    pub alias: Option<Alias>,
    pub address: Option<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedScope {
    pub kind: RuntimeKind,
    pub instance_name: String,
}

impl Selector {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.strip_prefix("agent://local/").unwrap_or(value);
        if let Ok(id) = Opaque::parse(value) {
            return Ok(Self {
                endpoint: Some(id),
                ..Self::default()
            });
        }
        let (scope, target) = match value.split_once(':') {
            Some((runtime, rest)) => {
                let kind = RuntimeKind::parse(runtime)?;
                let (instance_name, target) = rest.split_once('/').ok_or_else(|| {
                    invalid("a qualified selector is `<runtime>:<instance>/<alias-or-address>`")
                })?;
                if instance_name.is_empty() {
                    return Err(invalid("a qualified selector needs an instance name"));
                }
                (
                    Some(QualifiedScope {
                        kind,
                        instance_name: instance_name.to_owned(),
                    }),
                    target,
                )
            }
            None => (None, value),
        };

        // Both readings are kept. Choosing one here is how a caller ends up silently addressing an
        // agent named `p2` when they meant pane 2, or the reverse.
        let alias = Alias::parse(target).ok();
        let address = Address::parse(target).ok();
        if alias.is_none() && address.is_none() {
            return Err(invalid(format!(
                "`{target}` is neither a valid alias nor a valid address"
            )));
        }
        Ok(Self {
            endpoint: None,
            scope,
            alias,
            address,
        })
    }
}

/// A selector naming an agent on a peer host (`vvagent-inter-host-plan.md` §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSelector {
    /// `agent://<peer>/<id>` or `@<peer>:<id>`: one exact remote endpoint. Needs no live bridge, so
    /// mail to it queues while the peer is away.
    Exact {
        peer: PeerLabel,
        endpoint_id: Opaque,
    },
    /// `@<peer>:<selector>`: an alias or address in the peer's own tree, which only the peer can
    /// resolve, so it needs a connected bridge.
    Named { peer: PeerLabel, selector: String },
    /// `s1t2w12f1p2`: whatever is at `f1p2` on the host that window 12's bridge is connected to.
    /// The window is a stable id, so the space and tab before it are not consulted.
    Through { window: u32, rest: Address },
}

impl RemoteSelector {
    /// Read a selector as a remote one, or `None` when it names nothing remote.
    ///
    /// A positional form is only a *candidate*: `w12f1p2` is also a legal alias, so the caller
    /// falls back to local resolution when no bridge is anchored on that window.
    pub fn parse(value: &str) -> Result<Option<Self>> {
        if let Some(rest) = value.strip_prefix("agent://") {
            let Some((peer, id)) = rest.split_once('/') else {
                return Ok(None);
            };
            if peer == "local" {
                return Ok(None);
            }
            return Ok(Some(Self::Exact {
                peer: PeerLabel::parse(peer)?,
                endpoint_id: Opaque::parse(id)?,
            }));
        }
        if let Some(rest) = value.strip_prefix('@') {
            let (peer, selector) = rest
                .split_once(':')
                .ok_or_else(|| invalid("a remote selector is `@<peer>:<selector>`"))?;
            let peer = PeerLabel::parse(peer)?;
            let selector = selector.strip_prefix("agent://local/").unwrap_or(selector);
            if let Ok(endpoint_id) = Opaque::parse(selector) {
                return Ok(Some(Self::Exact { peer, endpoint_id }));
            }
            if selector.is_empty()
                || selector.len() > bridge::MAX_SELECTOR_BYTES
                || selector.chars().any(char::is_control)
            {
                return Err(invalid(format!(
                    "the selector after `@{peer}:` is 1..={} bytes with no control characters",
                    bridge::MAX_SELECTOR_BYTES
                )));
            }
            if selector.starts_with('@')
                || selector.starts_with("agent://")
                || selector.starts_with("peer:")
            {
                return Err(invalid(
                    "a peer resolves only its own agents; mail is never routed through it",
                ));
            }
            return Ok(Some(Self::Named {
                peer,
                selector: selector.to_owned(),
            }));
        }
        if let Some(rest) = value.strip_prefix("peer:") {
            let (peer, selector) = rest.split_once([':', '/']).ok_or_else(|| {
                invalid("a peer selector is `peer:<peer>:<selector>` or `peer:<peer>/<selector>`")
            })?;
            let peer = PeerLabel::parse(peer)?;
            let selector = selector.strip_prefix("agent://local/").unwrap_or(selector);
            if let Ok(endpoint_id) = Opaque::parse(selector) {
                return Ok(Some(Self::Exact { peer, endpoint_id }));
            }
            if selector.is_empty()
                || selector.len() > bridge::MAX_SELECTOR_BYTES
                || selector.chars().any(char::is_control)
            {
                return Err(invalid(format!(
                    "the selector after `peer:{peer}:` is 1..={} bytes with no control characters",
                    bridge::MAX_SELECTOR_BYTES
                )));
            }
            if selector.starts_with('@')
                || selector.starts_with("agent://")
                || selector.starts_with("peer:")
            {
                return Err(invalid(
                    "a peer resolves only its own agents; mail is never routed through it",
                ));
            }
            return Ok(Some(Self::Named {
                peer,
                selector: selector.to_owned(),
            }));
        }
        let Ok(address) = Address::parse(value) else {
            return Ok(None);
        };
        let Some(window) = address.get(Level::Window) else {
            return Ok(None);
        };
        let rest: Vec<Segment> = address
            .segments()
            .iter()
            .copied()
            .filter(|segment| segment.level > Level::Window)
            .collect();
        if rest.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self::Through {
            window,
            rest: Address::new(rest)?,
        }))
    }
}

/// Where the caller is, for the "own scope wins" step of resolution.
#[derive(Debug, Clone, Copy, Default)]
pub struct Origin<'a> {
    pub scope: Option<&'a Opaque>,
    pub address: Option<&'a Address>,
    /// The caller itself, so an address naming the region it sits in does not resolve to it.
    pub endpoint: Option<&'a Opaque>,
}

/// Resolve a selector against a candidate set (plan §6.3).
///
/// The rule that governs every step: **more than one match is never silently narrowed to one.**
/// Two sessions may both name an agent `reviewer`, and a bare `p2` may be both an alias and an
/// address. The caller's own neighbourhood is preferred; where that does not settle it, the caller
/// is told what to retype rather than guessed at.
pub fn resolve<'a>(
    selector: &Selector,
    candidates: &'a [Endpoint],
    origin: Origin<'_>,
) -> Result<&'a Endpoint> {
    // 1. An exact endpoint id is unambiguous by construction and works while the target is offline.
    if let Some(id) = &selector.endpoint {
        return candidates
            .iter()
            .find(|endpoint| &endpoint.endpoint_id == id)
            .ok_or_else(|| MeshError::new(ErrorCode::AgentNotFound, "no endpoint with that id"));
    }

    // 2. A qualified selector restricts the field to one runtime instance before anything else.
    let in_scope_of_selector = |endpoint: &Endpoint| match &selector.scope {
        Some(scope) => {
            endpoint.locator.kind == scope.kind
                && endpoint.locator.instance_name.as_deref() == Some(scope.instance_name.as_str())
        }
        None => true,
    };

    // 3. Match on either reading of the token. An address pattern's omitted levels are wildcards.
    let mut matches: Vec<&Endpoint> = candidates
        .iter()
        .filter(|endpoint| in_scope_of_selector(endpoint))
        .filter(|endpoint| {
            let by_alias = selector
                .alias
                .as_ref()
                .is_some_and(|alias| endpoint.alias.as_ref() == Some(alias));
            let by_address = match (&selector.address, &endpoint.locator.address) {
                (Some(pattern), Some(address)) => address.satisfies(pattern),
                _ => false,
            };
            by_alias || by_address
        })
        .collect();

    // 4. An address naming a region the caller sits in means somebody *else* in that region.
    //    Without this, `t2` asked from inside tab 2 resolves to the asker — it has the longest
    //    shared prefix with itself — and every container-level address means "me". Self survives
    //    only when nothing else matches, so an exact self-address still works.
    if matches.len() > 1
        && let Some(me) = origin.endpoint
    {
        let others: Vec<&Endpoint> = matches
            .iter()
            .copied()
            .filter(|endpoint| &endpoint.endpoint_id != me)
            .collect();
        if !others.is_empty() {
            matches = others;
        }
    }

    // 5. The caller's own runtime instance wins outright when it holds any match.
    if matches.len() > 1
        && let Some(scope) = origin.scope
    {
        let mine: Vec<&Endpoint> = matches
            .iter()
            .copied()
            .filter(|endpoint| &endpoint.locator.runtime_instance_id == scope)
            .collect();
        if !mine.is_empty() {
            matches = mine;
        }
    }

    // 6. Otherwise prefer the caller's own neighbourhood — the space or tab it is sitting in. This
    //    is what lets a bare `t2` mean "the tab beside me" without making it mean that everywhere.
    if matches.len() > 1
        && let Some(here) = origin.address
    {
        let best = matches
            .iter()
            .filter_map(|endpoint| endpoint.locator.address.as_ref())
            .map(|address| address.shared_prefix(here))
            .max()
            .unwrap_or(0);
        if best > 0 {
            matches.retain(|endpoint| {
                endpoint
                    .locator
                    .address
                    .as_ref()
                    .is_some_and(|address| address.shared_prefix(here) == best)
            });
        }
    }

    match matches.len() {
        0 => Err(MeshError::new(
            ErrorCode::AgentNotFound,
            "no endpoint matches that selector",
        )),
        1 => Ok(matches[0]),
        _ => Err(MeshError::new(
            ErrorCode::AgentAmbiguous,
            "several endpoints match; use a fuller address, the runtime-qualified form, or an \
             endpoint id",
        )
        .with_candidates(
            matches
                .iter()
                .map(|endpoint| qualified_name(endpoint))
                .collect(),
        )),
    }
}

/// The selector a user should retype to disambiguate. Carries no secret and no body.
pub fn qualified_name(endpoint: &Endpoint) -> String {
    let Some(instance) = &endpoint.locator.instance_name else {
        return format!("agent://local/{}", endpoint.endpoint_id);
    };
    let runtime = endpoint.locator.kind.as_str();
    // An alias reads better, but an address is what disambiguates two agents sharing a name — so
    // when a candidate list is being offered to disambiguate, the address is the useful half.
    match (&endpoint.alias, &endpoint.locator.address) {
        (Some(alias), _) => format!("{runtime}:{instance}/{alias}"),
        (None, Some(address)) => format!("{runtime}:{instance}/{address}"),
        (None, None) => format!("agent://local/{}", endpoint.endpoint_id),
    }
}

/// The address form of a candidate, for an ambiguity a name cannot settle.
pub fn qualified_address(endpoint: &Endpoint) -> Option<String> {
    let instance = endpoint.locator.instance_name.as_ref()?;
    let address = endpoint.locator.address.as_ref()?;
    Some(format!(
        "{}:{instance}/{address}",
        endpoint.locator.kind.as_str()
    ))
}

// ---------------------------------------------------------------------------------------------
// Envelope (plan §7.1)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Request,
    Response,
    Notice,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Notice => "notice",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "request" => Ok(Self::Request),
            "response" => Ok(Self::Response),
            "notice" => Ok(Self::Notice),
            other => Err(invalid(format!("unknown message kind `{other}`"))),
        }
    }

    /// Responses and cancellation state may reach into the reserve; requests may not.
    pub fn may_use_reserve(self) -> bool {
        matches!(self, Self::Response)
    }
}

/// One terminal outcome. `deferred` is deliberately absent: it is a delivery state, not an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The responder claims the requested work finished.
    Completed,
    /// An adapter captured a final answer but cannot claim task completion.
    Answered,
    Refused,
    Failed,
    Cancelled,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Answered => "answered",
            Self::Refused => "refused",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "completed" => Ok(Self::Completed),
            "answered" => Ok(Self::Answered),
            "refused" => Ok(Self::Refused),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(invalid(format!("unknown outcome `{other}`"))),
        }
    }
}

/// The state a message occupies in the store (plan §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Queued,
    Claimed,
    Delivered,
    Consumed,
    CancellationRequested,
    Cancelled,
    Expired,
    /// The mesh could not hand a message to its peer host. The stored failure code says why; for a
    /// message that was already in flight it may still have reached the peer.
    Undeliverable,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Claimed => "claimed",
            Self::Delivered => "delivered",
            Self::Consumed => "consumed",
            Self::CancellationRequested => "cancellation_requested",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Undeliverable => "undeliverable",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "queued" => Ok(Self::Queued),
            "claimed" => Ok(Self::Claimed),
            "delivered" => Ok(Self::Delivered),
            "consumed" => Ok(Self::Consumed),
            "cancellation_requested" => Ok(Self::CancellationRequested),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            "undeliverable" => Ok(Self::Undeliverable),
            other => Err(invalid(format!("unknown state `{other}`"))),
        }
    }

    /// Whether the message still occupies mailbox capacity.
    pub fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Claimed | Self::Delivered | Self::CancellationRequested
        )
    }
}

/// Who sent a message. Always filled in by the store from the authenticated caller — never
/// accepted from a client (plan §6.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub kind: PrincipalKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<Opaque>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incarnation_id: Option<Opaque>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A process holding a valid endpoint token.
    Agent,
    /// A shell with no token. It cannot assert that it is an agent.
    LocalUser,
    /// An agent on a peer host, as attributed by that peer. Authority is per peer (plan §3 of
    /// `vvagent-inter-host-plan.md`); the store never lets a local process act as one.
    Peer,
}

impl PrincipalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::LocalUser => "local_user",
            Self::Peer => "peer",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "agent" => Ok(Self::Agent),
            "local_user" => Ok(Self::LocalUser),
            "peer" => Ok(Self::Peer),
            other => Err(invalid(format!("unknown principal `{other}`"))),
        }
    }
}

/// A bounded claim about something outside the mesh. It grants no access (plan §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Ref {
    File {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bytes: Option<u64>,
        /// The peer whose filesystem `path` names, as this store's `peer_id`; absent for this
        /// host. Set only by a bridge, from which end of a frame the reference was about.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<Opaque>,
    },
    Pane {
        runtime_instance_id: Opaque,
        #[serde(flatten)]
        locator: PaneRef,
    },
    /// Media a runtime is holding, named by an id that runtime minted (plan §10.1).
    ///
    /// Like every other reference this grants no access and carries no payload: the receiver
    /// resolves it by asking that runtime, which answers with the owner tuple and the revisions it
    /// currently sees, or refuses.
    ///
    /// `binding` is not decoration. "Look at what I was showing when I asked" and "look at what is
    /// on that surface now" are different requests, and an envelope that did not say which it held
    /// would leave a reader to guess — where the wrong guess is sometimes a wrong picture rather
    /// than an error.
    ///
    /// A resource is scoped to one runtime instance and does not survive a gateway hop, because
    /// re-origination creates independent ids and revisions on the far side. Correlating the two
    /// would need a content digest the audit design refuses.
    Media {
        runtime_instance_id: Opaque,
        resource_id: String,
        binding: MediaBinding,
    },
}

/// Which question a media reference answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaBinding {
    /// The content as it was when the reference was minted. Resolution fails once any revision,
    /// generation, or media epoch has moved, and never returns what replaced it.
    Pinned,
    /// Whatever is on that surface now. Stale only when the surface or its owner is gone.
    Live,
}

impl MediaBinding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pinned => "pinned",
            Self::Live => "live",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "pinned" => Ok(Self::Pinned),
            "live" => Ok(Self::Live),
            other => Err(invalid(format!(
                "a media binding is `pinned` or `live`, not {other:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaneRef {
    pub runtime: RuntimeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tab: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pane_id: Option<u64>,
}

impl Ref {
    pub fn validate(&self) -> Result<()> {
        self.check(matches!(self, Self::File { host: Some(_), .. }))
    }

    /// Validate a reference about another machine before it has been assigned to a peer: a bridge
    /// checking what arrived about the sender's host.
    pub fn validate_elsewhere(&self) -> Result<()> {
        self.check(true)
    }

    fn check(&self, elsewhere: bool) -> Result<()> {
        match self {
            Self::File { path, sha256, .. } => {
                if path.is_empty() || path.len() > MAX_PATH_BYTES {
                    return Err(invalid("a file reference path is 1..=4096 bytes"));
                }
                if path.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
                    return Err(invalid(
                        "a file reference path may not contain NUL or control bytes",
                    ));
                }
                // A path on this host is judged by this host's rules. One on a peer may be on
                // another platform, so it need only be absolute on *some* platform.
                let absolute = if elsewhere {
                    looks_absolute_anywhere(path)
                } else {
                    std::path::Path::new(path).is_absolute()
                };
                if !absolute {
                    return Err(invalid("a file reference path must be absolute"));
                }
                if let Some(digest) = sha256
                    && (digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err(invalid("a sha256 is 64 hex characters"));
                }
                Ok(())
            }
            Self::Pane { locator, .. } => {
                for field in [&locator.workspace, &locator.tab].into_iter().flatten() {
                    if field.len() > MAX_PANE_FIELD_BYTES
                        || field.bytes().any(|b| b < 0x20 || b == 0x7f)
                    {
                        return Err(invalid(format!(
                            "a pane reference's workspace and tab are at most \
                             {MAX_PANE_FIELD_BYTES} bytes with no control bytes"
                        )));
                    }
                }
                Ok(())
            }
            Self::Media { resource_id, .. } => {
                // Opaque to everyone but the runtime that minted it, so the only rules are that it
                // is bounded and cannot smuggle control bytes through a log or a terminal.
                if resource_id.is_empty() || resource_id.len() > MAX_RESOURCE_ID_BYTES {
                    return Err(invalid("a media resource id is 1..=128 bytes"));
                }
                if resource_id
                    .bytes()
                    .any(|byte| byte == 0 || byte < 0x20 || byte == 0x7f)
                {
                    return Err(invalid(
                        "a media resource id may not contain NUL or control bytes",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// `/…` on Unix, `C:\…`, `C:/…` or `\\server\…` on Windows: absolute on some platform.
pub fn looks_absolute_anywhere(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with('/')
        || path.starts_with("\\\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
}

/// A message as it appears on the wire and in `vvagent inbox`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub schema: u32,
    pub message_id: Opaque,
    pub recipient_sequence: i64,
    pub from: Principal,
    pub to: Opaque,
    pub kind: Kind,
    pub conversation_id: Opaque,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Opaque>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    pub state: State,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<Ref>,
}

/// What a caller submits. The store fills in everything a caller must not control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    pub to: Opaque,
    pub kind: Kind,
    pub reply_to: Option<Opaque>,
    pub outcome: Option<Outcome>,
    pub subject: Option<String>,
    pub text: String,
    pub refs: Vec<Ref>,
    pub idempotency_key: String,
    pub expires_in_ms: Option<i64>,
}

impl Draft {
    /// Reject anything out of bounds before a byte is allocated or charged.
    pub fn validate(&self) -> Result<()> {
        if self.text.len() > MAX_TEXT_BYTES {
            return Err(invalid(format!(
                "message text is {} bytes, over the {MAX_TEXT_BYTES}-byte limit",
                self.text.len()
            )));
        }
        if let Some(subject) = &self.subject
            && subject.len() > MAX_SUBJECT_BYTES
        {
            return Err(invalid(format!(
                "subject is {} bytes, over the {MAX_SUBJECT_BYTES}-byte limit",
                subject.len()
            )));
        }
        if self.refs.len() > MAX_REFS {
            return Err(invalid(format!(
                "{} references, over the limit of {MAX_REFS}",
                self.refs.len()
            )));
        }
        for reference in &self.refs {
            reference.validate()?;
        }
        if self.idempotency_key.is_empty() || self.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        {
            return Err(invalid("an idempotency key is 1..=128 bytes"));
        }
        if let Some(lifetime) = self.expires_in_ms
            && !(1..=MAX_REQUEST_LIFETIME_MS).contains(&lifetime)
        {
            return Err(invalid(format!(
                "a request lifetime is 1..={MAX_REQUEST_LIFETIME_MS} ms"
            )));
        }
        match self.kind {
            Kind::Response => {
                if self.reply_to.is_none() {
                    return Err(invalid("a response must name the request it answers"));
                }
                if self.outcome.is_none() {
                    return Err(invalid("a response must carry an outcome"));
                }
            }
            Kind::Request | Kind::Notice => {
                if self.outcome.is_some() {
                    return Err(invalid("only a response carries an outcome"));
                }
            }
        }
        Ok(())
    }

    /// The content digest that decides whether an idempotency-key retry is a replay or a conflict.
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut field = |bytes: &[u8]| {
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        };
        field(self.to.as_str().as_bytes());
        field(self.kind.as_str().as_bytes());
        field(
            self.reply_to
                .as_ref()
                .map(Opaque::as_str)
                .unwrap_or_default()
                .as_bytes(),
        );
        field(
            self.outcome
                .map(Outcome::as_str)
                .unwrap_or_default()
                .as_bytes(),
        );
        field(self.subject.as_deref().unwrap_or_default().as_bytes());
        field(self.text.as_bytes());
        field(
            serde_json::to_string(&self.refs)
                .unwrap_or_default()
                .as_bytes(),
        );
        hex(&hasher.finalize())
    }

    /// What this message charges against the recipient's mailbox.
    pub fn charged_bytes(&self) -> i64 {
        let refs = serde_json::to_string(&self.refs)
            .map(|s| s.len())
            .unwrap_or(0);
        i64::try_from(self.text.len() + self.subject.as_deref().unwrap_or_default().len() + refs)
            .unwrap_or(i64::MAX)
    }
}

// ---------------------------------------------------------------------------------------------
// Policy (plan §9)
// ---------------------------------------------------------------------------------------------

/// How far a peer's message may go. Each gate is a separate decision on purpose: permission to
/// queue a message is not permission to spend the target's tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Gate {
    Enqueue,
    MakeVisible,
    Activate,
    PtyNudge,
    Interrupt,
}

/// Who a rule admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Admit {
    /// Nobody.
    Nobody,
    /// Only responses to a request this endpoint originated.
    RepliesOnly,
    /// Replies, plus any endpoint bound into the same runtime instance (plan §9.2 team grant).
    RepliesAndTeam,
    /// Replies, team, and explicitly trusted endpoint ids.
    RepliesAndTrusted,
    /// Any registered endpoint or the local user.
    Anyone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub enqueue: Admit,
    pub make_visible: Admit,
    pub activate: Admit,
    pub pty_nudge: bool,
    pub interrupt: bool,
    /// Endpoint ids admitted by `RepliesAndTrusted`. Aliases are resolved to ids when saved.
    #[serde(default)]
    pub trusted: Vec<Opaque>,
    /// How far "teammate" reaches.
    #[serde(default)]
    pub team: TeamScope,
    /// Messages this endpoint will accept per minute, whoever sends them.
    ///
    /// The gates decide *who* may write; this bounds *how fast*. Without it an admitted peer can
    /// still fill a mailbox as quickly as it can call, and `mailbox_full` would arrive as the
    /// first sign of it.
    #[serde(default = "default_inbound_per_minute")]
    pub max_inbound_per_minute: u32,
    /// Turns this endpoint may be woken for per minute.
    ///
    /// Distinct from the inbound limit because each activation spends the user's tokens. A peer
    /// that is allowed to write is not thereby allowed to keep a model busy.
    #[serde(default = "default_auto_turns_per_minute")]
    pub max_auto_turns_per_minute: u32,
    /// Whether this endpoint may send files to other hosts with `--attach`. On by default: the far
    /// side is the same user's SSH account, and an agent with a shell could copy a file anyway.
    /// The gate is for agents given deliberately narrow tools, so the mesh is not their way out.
    #[serde(default = "default_attach")]
    pub attach: bool,
}

/// How far the team grant reaches (plan §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamScope {
    /// Nobody is a teammate; only replies and explicitly trusted peers get through.
    Off,
    /// Everything bound into the same runtime instance — one vvmux session, one Vivida window set.
    #[default]
    RuntimeInstance,
    /// Everything in the same space, which spans instances a person thinks of as one workspace.
    Space,
}

impl TeamScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::RuntimeInstance => "runtime_instance",
            Self::Space => "space",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "off" => Ok(Self::Off),
            "runtime_instance" => Ok(Self::RuntimeInstance),
            "space" => Ok(Self::Space),
            other => Err(invalid(format!(
                "unknown team scope `{other}`; use off, runtime_instance or space"
            ))),
        }
    }
}

const fn default_inbound_per_minute() -> u32 {
    60
}

const fn default_auto_turns_per_minute() -> u32 {
    4
}

const fn default_attach() -> bool {
    true
}

impl Default for Policy {
    /// The plan's recommended defaults: queueing is open within the account, activation is limited
    /// to replies and same-instance teammates, and nothing touches a PTY or interrupts a turn.
    fn default() -> Self {
        Self {
            enqueue: Admit::Anyone,
            make_visible: Admit::RepliesAndTrusted,
            activate: Admit::RepliesAndTeam,
            pty_nudge: false,
            interrupt: false,
            team: TeamScope::RuntimeInstance,
            max_inbound_per_minute: default_inbound_per_minute(),
            max_auto_turns_per_minute: default_auto_turns_per_minute(),
            attach: default_attach(),
            trusted: Vec::new(),
        }
    }
}

/// Everything a gate decision depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub sender: &'a Principal,
    /// The sending endpoint's runtime instance, when it has one.
    pub sender_scope: Option<&'a Opaque>,
    pub target_scope: &'a Opaque,
    /// True when this answers a request the target originated.
    pub is_reply_to_our_request: bool,
    /// The two endpoints' addresses, for a team grant that reaches beyond one instance.
    pub sender_address: Option<&'a Address>,
    pub target_address: Option<&'a Address>,
    /// For a `peer` sender, whether the user trusted that whole peer host.
    pub peer_trusted: bool,
}

/// Why a gate decided what it decided. Recorded in the audit log so `explain` has an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub allowed: bool,
    pub rule: Rule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    Anyone,
    Reply,
    Team,
    Trusted,
    NotAdmitted,
    Disabled,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anyone => "anyone",
            Self::Reply => "reply",
            Self::Team => "team",
            Self::Trusted => "trusted",
            Self::NotAdmitted => "not_admitted",
            Self::Disabled => "disabled",
        }
    }
}

impl Policy {
    pub fn evaluate(&self, gate: Gate, request: &Request<'_>) -> Decision {
        let admit = match gate {
            Gate::Enqueue => self.enqueue,
            Gate::MakeVisible => self.make_visible,
            Gate::Activate => self.activate,
            Gate::PtyNudge => {
                return Decision {
                    allowed: self.pty_nudge,
                    rule: if self.pty_nudge {
                        Rule::Anyone
                    } else {
                        Rule::Disabled
                    },
                };
            }
            Gate::Interrupt => {
                return Decision {
                    allowed: self.interrupt,
                    rule: if self.interrupt {
                        Rule::Anyone
                    } else {
                        Rule::Disabled
                    },
                };
            }
        };

        // A peer host is a narrower principal than anything local. No team grant reaches it and
        // `anyone` means anyone on this host: only a correlated reply or explicit trust — of the
        // whole peer, or of this one proxy — admits it, and only where the rule admits trust.
        if request.sender.kind == PrincipalKind::Peer {
            if admit == Admit::Nobody {
                return Decision {
                    allowed: false,
                    rule: Rule::NotAdmitted,
                };
            }
            if request.is_reply_to_our_request {
                return Decision {
                    allowed: true,
                    rule: Rule::Reply,
                };
            }
            let trusted = request.peer_trusted
                || request
                    .sender
                    .endpoint_id
                    .as_ref()
                    .is_some_and(|id| self.trusted.contains(id));
            let admits_trust = matches!(admit, Admit::Anyone | Admit::RepliesAndTrusted);
            return if trusted && admits_trust {
                Decision {
                    allowed: true,
                    rule: Rule::Trusted,
                }
            } else {
                Decision {
                    allowed: false,
                    rule: Rule::NotAdmitted,
                }
            };
        }

        // The account operator is not an untrusted peer. Explicit `Nobody` still closes
        // a gate, and interruption/nudging remain independently disabled above.
        if request.sender.kind == PrincipalKind::LocalUser
            && gate == Gate::MakeVisible
            && admit == Admit::RepliesAndTrusted
        {
            return Decision {
                allowed: true,
                rule: Rule::Anyone,
            };
        }
        // A reply to our own request is admitted by every rule above `Nobody`: we asked for it.
        if request.is_reply_to_our_request && admit != Admit::Nobody {
            return Decision {
                allowed: true,
                rule: Rule::Reply,
            };
        }

        let same_instance = match self.team {
            TeamScope::Off => false,
            TeamScope::RuntimeInstance => request.sender_scope == Some(request.target_scope),
            // A person who arranges several instances into one space thinks of them as one place.
            // Membership is then sharing that space, which is the outermost address segment.
            TeamScope::Space => match (request.sender_address, request.target_address) {
                (Some(theirs), Some(ours)) => {
                    let space = ours.get(Level::Space);
                    space.is_some() && theirs.get(Level::Space) == space
                }
                _ => request.sender_scope == Some(request.target_scope),
            },
        };
        let trusted = request
            .sender
            .endpoint_id
            .as_ref()
            .is_some_and(|id| self.trusted.contains(id));

        match admit {
            Admit::Anyone => Decision {
                allowed: true,
                rule: Rule::Anyone,
            },
            Admit::RepliesAndTrusted if trusted => Decision {
                allowed: true,
                rule: Rule::Trusted,
            },
            Admit::RepliesAndTrusted if same_instance => Decision {
                allowed: true,
                rule: Rule::Team,
            },
            Admit::RepliesAndTeam if same_instance => Decision {
                allowed: true,
                rule: Rule::Team,
            },
            _ => Decision {
                allowed: false,
                rule: Rule::NotAdmitted,
            },
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_media_reference_says_which_question_it_answers() {
        // The discriminant is the design. Serialising one without it would leave a reader to guess
        // between "what I was showing" and "what is there now".
        let pinned = Ref::Media {
            runtime_instance_id: Opaque::parse(&"a".repeat(32)).unwrap(),
            resource_id: "abc-1".into(),
            binding: MediaBinding::Pinned,
        };
        pinned.validate().expect("valid");

        let json = serde_json::to_string(&pinned).expect("encode");
        assert!(json.contains(r#""kind":"media""#), "{json}");
        assert!(json.contains(r#""binding":"pinned""#), "{json}");

        let decoded: Ref = serde_json::from_str(&json).expect("decode");
        assert_eq!(
            decoded, pinned,
            "a reference survives the envelope unchanged"
        );
    }

    #[test]
    fn a_media_resource_id_is_bounded_and_free_of_control_bytes() {
        let reference = |id: &str| Ref::Media {
            runtime_instance_id: Opaque::parse(&"b".repeat(32)).unwrap(),
            resource_id: id.into(),
            binding: MediaBinding::Live,
        };

        assert!(
            reference("").validate().is_err(),
            "an empty id names nothing"
        );
        assert!(
            reference(&"x".repeat(MAX_RESOURCE_ID_BYTES))
                .validate()
                .is_ok()
        );
        assert!(
            reference(&"x".repeat(MAX_RESOURCE_ID_BYTES + 1))
                .validate()
                .is_err()
        );
        // An id reaches logs and terminals; it does not get to carry an escape sequence there.
        assert!(reference("abc\u{1b}[2J").validate().is_err());
        assert!(reference("abc\0def").validate().is_err());
    }

    #[test]
    fn a_binding_round_trips_through_its_own_spelling() {
        for binding in [MediaBinding::Pinned, MediaBinding::Live] {
            assert_eq!(MediaBinding::parse(binding.as_str()).unwrap(), binding);
        }
        assert!(
            MediaBinding::parse("latest").is_err(),
            "there are exactly two kinds"
        );
    }
    use super::*;

    fn endpoint(alias: &str, instance: &str, name: &str) -> Endpoint {
        located(Some(alias), instance, name, None)
    }

    fn located(alias: Option<&str>, instance: &str, name: &str, address: Option<&str>) -> Endpoint {
        Endpoint {
            endpoint_id: Opaque::generate(),
            incarnation_id: Some(Opaque::generate()),
            alias: alias.map(|value| Alias::parse(value).unwrap()),
            provider: None,
            locator: Locator {
                kind: RuntimeKind::Vvmux,
                runtime_instance_id: Opaque::parse(instance).unwrap(),
                instance_name: Some(name.to_owned()),
                address: address.map(|value| Address::parse(value).unwrap()),
            },
            online: true,
            state_generation: 1,
            state: AgentState::Idle,
            pending: 0,
        }
    }

    fn from_instance(instance: &str) -> Opaque {
        Opaque::parse(instance).unwrap()
    }

    const A: &str = "11111111111111111111111111111111";
    const B: &str = "22222222222222222222222222222222";

    #[test]
    fn alias_spelling_matches_the_vvmux_rule() {
        assert!(Alias::parse("reviewer").is_ok());
        assert!(Alias::parse("code-reviewer_2").is_ok());
        assert!(Alias::parse("Reviewer").is_err(), "no uppercase");
        assert!(
            Alias::parse("2reviewer").is_err(),
            "must start with a letter"
        );
        assert!(Alias::parse("").is_err());
        assert!(Alias::parse(&"a".repeat(33)).is_err());
    }

    #[test]
    fn selectors_parse_every_form() {
        let id = Opaque::generate();
        assert_eq!(
            Selector::parse(&format!("agent://local/{id}"))
                .unwrap()
                .endpoint,
            Some(id.clone())
        );
        assert_eq!(Selector::parse(id.as_str()).unwrap().endpoint, Some(id));

        let qualified = Selector::parse("vvmux:dev/reviewer").unwrap();
        assert_eq!(qualified.scope.unwrap().instance_name, "dev");
        assert_eq!(qualified.alias.unwrap().as_str(), "reviewer");

        let by_address = Selector::parse("vvmux:dev/f1p2").unwrap();
        assert_eq!(by_address.address.unwrap(), Address::parse("f1p2").unwrap());

        assert!(Selector::parse("reviewer").unwrap().alias.is_some());
        assert!(Selector::parse("vvmux:dev").is_err(), "needs a target");
        assert!(
            Selector::parse("Reviewer").is_err(),
            "neither a valid alias nor a valid address"
        );
    }

    #[test]
    fn a_token_that_reads_as_both_an_alias_and_an_address_keeps_both() {
        // `p2` is a legal alias and a legal address. Choosing one here is how a caller silently
        // addresses an agent named p2 when they meant pane 2, or the reverse.
        let selector = Selector::parse("p2").unwrap();
        assert!(selector.alias.is_some());
        assert!(selector.address.is_some());
    }

    #[test]
    fn an_alias_and_an_address_that_collide_are_ambiguous_not_guessed() {
        let named = located(Some("p2"), A, "dev", Some("f1p9"));
        let positioned = located(None, A, "dev", Some("f1p2"));
        let all = vec![named, positioned];

        let err = resolve(
            &Selector::parse("p2").unwrap(),
            &all,
            Origin {
                scope: Some(&from_instance(A)),
                address: None,
                endpoint: None,
            },
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::AgentAmbiguous);
        assert_eq!(err.candidates.len(), 2);
    }

    #[test]
    fn a_colliding_alias_prefers_the_callers_own_scope() {
        let mine = endpoint("reviewer", A, "dev");
        let theirs = endpoint("reviewer", B, "other");
        let all = vec![mine.clone(), theirs];
        let scope = Opaque::parse(A).unwrap();

        let found = resolve(
            &Selector::parse("reviewer").unwrap(),
            &all,
            Origin {
                scope: Some(&scope),
                address: None,
                endpoint: None,
            },
        )
        .unwrap();
        assert_eq!(found.endpoint_id, mine.endpoint_id);
    }

    #[test]
    fn a_colliding_alias_with_no_scope_is_ambiguous_not_guessed() {
        let all = vec![
            endpoint("reviewer", A, "dev"),
            endpoint("reviewer", B, "other"),
        ];
        let err = resolve(
            &Selector::parse("reviewer").unwrap(),
            &all,
            Origin::default(),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::AgentAmbiguous);
        assert_eq!(err.candidates.len(), 2, "the user is told what to retype");
        assert!(err.candidates.iter().any(|c| c == "vvmux:dev/reviewer"));
    }

    #[test]
    fn the_qualified_form_disambiguates() {
        let all = vec![
            endpoint("reviewer", A, "dev"),
            endpoint("reviewer", B, "other"),
        ];
        let found = resolve(
            &Selector::parse("vvmux:other/reviewer").unwrap(),
            &all,
            Origin::default(),
        )
        .unwrap();
        assert_eq!(found.locator.instance_name.as_deref(), Some("other"));
    }

    #[test]
    fn an_unknown_selector_is_not_found() {
        let all = vec![endpoint("reviewer", A, "dev")];
        let err =
            resolve(&Selector::parse("nobody").unwrap(), &all, Origin::default()).unwrap_err();
        assert_eq!(err.code, ErrorCode::AgentNotFound);
    }

    #[test]
    fn ambiguity_candidates_are_bounded() {
        let all: Vec<Endpoint> = (0..40)
            .map(|i| endpoint("reviewer", &format!("{i:032x}"), &format!("inst{i}")))
            .collect();
        let err = resolve(
            &Selector::parse("reviewer").unwrap(),
            &all,
            Origin::default(),
        )
        .unwrap_err();
        assert_eq!(err.candidates.len(), MAX_AMBIGUOUS_CANDIDATES);
    }

    // --- partial addresses (plan §6.3) ---------------------------------------------------------

    #[test]
    fn a_bare_pane_crosses_frames() {
        // The M2.5 exit criterion. An implementation that completed `p2` from the caller's own
        // address would look in frame 1 and miss this entirely.
        let caller_address = Address::parse("s2t2w3f1p7").unwrap();
        let all = vec![
            located(None, A, "dev", Some("s2t2w3f1p7")),
            located(None, A, "dev", Some("s2t2w3f2p2")),
        ];
        let found = resolve(
            &Selector::parse("p2").unwrap(),
            &all,
            Origin {
                scope: Some(&from_instance(A)),
                address: Some(&caller_address),
                endpoint: None,
            },
        )
        .unwrap();
        assert_eq!(
            found.locator.address.as_ref().unwrap().to_string(),
            "s2t2w3f2p2"
        );
    }

    #[test]
    fn an_address_naming_the_callers_own_region_means_someone_else() {
        // Found by running it: without this, `t2` asked from inside tab 2 resolves to the asker,
        // which has the longest shared prefix with itself, and every container-level address
        // becomes a way to name yourself.
        let me = located(Some("builder"), A, "dev", Some("s2t2w3f1p7"));
        let neighbour = located(Some("reviewer"), A, "dev", Some("s2t2w3f2p2"));
        let my_id = me.endpoint_id.clone();
        let my_address = me.locator.address.clone().unwrap();
        let all = vec![me, neighbour.clone()];

        let found = resolve(
            &Selector::parse("t2").unwrap(),
            &all,
            Origin {
                scope: Some(&from_instance(A)),
                address: Some(&my_address),
                endpoint: Some(&my_id),
            },
        )
        .unwrap();
        assert_eq!(found.endpoint_id, neighbour.endpoint_id);
    }

    #[test]
    fn an_exact_self_address_still_resolves_to_the_caller() {
        // Self is dropped only when something else matches, so naming yourself exactly still works.
        let me = located(Some("builder"), A, "dev", Some("s2t2w3f1p7"));
        let my_id = me.endpoint_id.clone();
        let my_address = me.locator.address.clone().unwrap();
        let all = vec![me, located(Some("reviewer"), A, "dev", Some("s2t2w3f2p2"))];

        let found = resolve(
            &Selector::parse("p7").unwrap(),
            &all,
            Origin {
                scope: Some(&from_instance(A)),
                address: Some(&my_address),
                endpoint: Some(&my_id),
            },
        )
        .unwrap();
        assert_eq!(found.endpoint_id, my_id);
    }

    #[test]
    fn a_bare_window_crosses_spaces_and_tabs() {
        let caller_address = Address::parse("s1t1w1").unwrap();
        let all = vec![
            located(None, A, "main", Some("s1t1w1")),
            located(None, A, "main", Some("s3t7w5")),
        ];
        let found = resolve(
            &Selector::parse("w5").unwrap(),
            &all,
            Origin {
                scope: Some(&from_instance(A)),
                address: Some(&caller_address),
                endpoint: None,
            },
        )
        .unwrap();
        assert_eq!(
            found.locator.address.as_ref().unwrap().to_string(),
            "s3t7w5"
        );
    }

    #[test]
    fn a_bare_tab_prefers_the_callers_own_space() {
        // A tab position repeats in every space, so this is the one level that needs help. The
        // caller's own space provides it.
        let caller_address = Address::parse("s2t1w1").unwrap();
        let all = vec![
            located(None, A, "main", Some("s1t2w9")),
            located(None, A, "main", Some("s2t2w8")),
            located(None, A, "main", Some("s3t2w7")),
        ];
        let found = resolve(
            &Selector::parse("t2").unwrap(),
            &all,
            Origin {
                scope: Some(&from_instance(A)),
                address: Some(&caller_address),
                endpoint: None,
            },
        )
        .unwrap();
        assert_eq!(
            found.locator.address.as_ref().unwrap().to_string(),
            "s2t2w8"
        );
    }

    #[test]
    fn a_bare_tab_without_a_space_is_ambiguous() {
        let all = vec![
            located(None, A, "main", Some("s1t2w9")),
            located(None, A, "main", Some("s2t2w8")),
        ];
        let err = resolve(
            &Selector::parse("t2").unwrap(),
            &all,
            Origin {
                scope: Some(&from_instance(A)),
                address: None,
                endpoint: None,
            },
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::AgentAmbiguous);
        assert!(
            err.candidates.iter().any(|c| c.contains("s1t2w9")),
            "candidates name full addresses so the caller has something exact to retype: {:?}",
            err.candidates
        );
    }

    #[test]
    fn a_caller_with_no_address_falls_back_to_needing_a_unique_match() {
        // A shell. Nothing about it says which pane it meant, so it gets uniqueness or nothing.
        let all = vec![
            located(None, A, "dev", Some("f1p2")),
            located(None, B, "other", Some("f1p2")),
        ];
        let err = resolve(&Selector::parse("p2").unwrap(), &all, Origin::default()).unwrap_err();
        assert_eq!(err.code, ErrorCode::AgentAmbiguous);

        let unique = vec![located(None, A, "dev", Some("f1p2"))];
        assert!(resolve(&Selector::parse("p2").unwrap(), &unique, Origin::default()).is_ok());
    }

    #[test]
    fn a_qualified_address_pins_the_instance() {
        let all = vec![
            located(None, A, "dev", Some("f1p2")),
            located(None, B, "other", Some("f1p2")),
        ];
        let found = resolve(
            &Selector::parse("vvmux:other/p2").unwrap(),
            &all,
            Origin::default(),
        )
        .unwrap();
        assert_eq!(found.locator.instance_name.as_deref(), Some("other"));
    }

    #[test]
    fn an_address_naming_a_container_of_several_agents_is_ambiguous() {
        let all = vec![
            located(None, A, "dev", Some("s2t2w3f1p1")),
            located(None, A, "dev", Some("s2t2w3f1p2")),
        ];
        let err = resolve(
            &Selector::parse("w3").unwrap(),
            &all,
            Origin {
                scope: Some(&from_instance(A)),
                address: None,
                endpoint: None,
            },
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::AgentAmbiguous);
        assert_eq!(err.candidates.len(), 2, "both agents inside are listed");
    }

    #[test]
    fn a_reply_is_admitted_even_when_unsolicited_requests_are_not() {
        let policy = Policy {
            activate: Admit::RepliesOnly,
            ..Policy::default()
        };
        let sender = Principal {
            kind: PrincipalKind::Agent,
            endpoint_id: Some(Opaque::generate()),
            incarnation_id: None,
        };
        let their_scope = Opaque::parse(B).unwrap();
        let our_scope = Opaque::parse(A).unwrap();

        let reply = policy.evaluate(
            Gate::Activate,
            &Request {
                sender: &sender,
                sender_scope: Some(&their_scope),
                target_scope: &our_scope,
                is_reply_to_our_request: true,
                sender_address: None,
                target_address: None,
                peer_trusted: false,
            },
        );
        assert!(reply.allowed);
        assert_eq!(reply.rule, Rule::Reply);

        let unsolicited = policy.evaluate(
            Gate::Activate,
            &Request {
                sender: &sender,
                sender_scope: Some(&their_scope),
                target_scope: &our_scope,
                is_reply_to_our_request: false,
                sender_address: None,
                target_address: None,
                peer_trusted: false,
            },
        );
        assert!(!unsolicited.allowed);
        assert_eq!(unsolicited.rule, Rule::NotAdmitted);
    }

    #[test]
    fn the_team_grant_admits_the_same_runtime_instance_only() {
        let policy = Policy::default();
        let sender = Principal {
            kind: PrincipalKind::Agent,
            endpoint_id: Some(Opaque::generate()),
            incarnation_id: None,
        };
        let ours = Opaque::parse(A).unwrap();
        let theirs = Opaque::parse(B).unwrap();

        let teammate = policy.evaluate(
            Gate::Activate,
            &Request {
                sender: &sender,
                sender_scope: Some(&ours),
                target_scope: &ours,
                is_reply_to_our_request: false,
                sender_address: None,
                target_address: None,
                peer_trusted: false,
            },
        );
        assert!(teammate.allowed);
        assert_eq!(teammate.rule, Rule::Team);

        let stranger = policy.evaluate(
            Gate::Activate,
            &Request {
                sender: &sender,
                sender_scope: Some(&theirs),
                target_scope: &ours,
                is_reply_to_our_request: false,
                sender_address: None,
                target_address: None,
                peer_trusted: false,
            },
        );
        assert!(!stranger.allowed, "the team grant does not cross instances");
    }

    #[test]
    fn a_peer_is_admitted_only_by_a_reply_or_explicit_trust_and_never_as_a_teammate() {
        let proxy = Opaque::generate();
        let peer = Principal {
            kind: PrincipalKind::Peer,
            endpoint_id: Some(proxy.clone()),
            incarnation_id: None,
        };
        // Even a proxy that shares the target's scope and space is not a teammate: the check is on
        // the principal, not on whatever scope or address a row happens to carry.
        let scope = Opaque::parse(A).unwrap();
        let space = Address::parse("s1t1w1").unwrap();
        let ask = |policy: &Policy, gate, reply, peer_trusted| {
            policy.evaluate(
                gate,
                &Request {
                    sender: &peer,
                    sender_scope: Some(&scope),
                    target_scope: &scope,
                    is_reply_to_our_request: reply,
                    sender_address: Some(&space),
                    target_address: Some(&space),
                    peer_trusted,
                },
            )
        };
        let open = Policy {
            team: TeamScope::Space,
            ..Policy::default()
        };

        // `anyone` means anyone on this host.
        assert!(!ask(&open, Gate::Enqueue, false, false).allowed);
        assert!(!ask(&open, Gate::Activate, false, false).allowed);
        // A reply to our own request always gets through, short of `nobody`.
        assert_eq!(ask(&open, Gate::Activate, true, false).rule, Rule::Reply);
        let closed = Policy {
            enqueue: Admit::Nobody,
            ..open.clone()
        };
        assert!(!ask(&closed, Gate::Enqueue, true, false).allowed);

        // Trusting the peer admits it where the rule admits trust, and nowhere else.
        assert_eq!(ask(&open, Gate::Enqueue, false, true).rule, Rule::Trusted);
        assert_eq!(
            ask(&open, Gate::MakeVisible, false, true).rule,
            Rule::Trusted
        );
        assert!(
            !ask(&open, Gate::Activate, false, true).allowed,
            "replies-and-team admits no peer, trusted or not"
        );
        let proxy_trusted = Policy {
            trusted: vec![proxy.clone()],
            ..open.clone()
        };
        assert!(ask(&proxy_trusted, Gate::Enqueue, false, false).allowed);
    }

    #[test]
    fn remote_selectors_are_read_in_three_forms_and_only_those() {
        let id = "0123456789abcdef0123456789abcdef";
        let exact = RemoteSelector::Exact {
            peer: PeerLabel::parse("buildbox").unwrap(),
            endpoint_id: Opaque::parse(id).unwrap(),
        };
        for form in [
            format!("agent://buildbox/{id}"),
            format!("@buildbox:{id}"),
            format!("@buildbox:agent://local/{id}"),
            format!("peer:buildbox:{id}"),
            format!("peer:buildbox/{id}"),
            format!("peer:buildbox:agent://local/{id}"),
        ] {
            assert_eq!(
                RemoteSelector::parse(&form).unwrap(),
                Some(exact.clone()),
                "{form}"
            );
        }
        assert_eq!(
            RemoteSelector::parse("@build.example.com:vvmux:dev/f1p2").unwrap(),
            Some(RemoteSelector::Named {
                peer: PeerLabel::parse("build.example.com").unwrap(),
                selector: "vvmux:dev/f1p2".into(),
            })
        );
        assert_eq!(
            RemoteSelector::parse("peer:build.example.com:vvmux:dev/f1p2").unwrap(),
            Some(RemoteSelector::Named {
                peer: PeerLabel::parse("build.example.com").unwrap(),
                selector: "vvmux:dev/f1p2".into(),
            })
        );
        assert_eq!(
            RemoteSelector::parse("peer:build.example.com/vvmux:dev/f1p2").unwrap(),
            Some(RemoteSelector::Named {
                peer: PeerLabel::parse("build.example.com").unwrap(),
                selector: "vvmux:dev/f1p2".into(),
            })
        );
        assert_eq!(
            RemoteSelector::parse("s1t2w12f1p2").unwrap(),
            Some(RemoteSelector::Through {
                window: 12,
                rest: Address::parse("f1p2").unwrap(),
            }),
            "the space and tab before a window are not consulted"
        );
        assert_eq!(
            RemoteSelector::parse("w3p9").unwrap(),
            Some(RemoteSelector::Through {
                window: 3,
                rest: Address::parse("p9").unwrap(),
            })
        );

        // Nothing remote: local forms pass through untouched.
        for local in [
            format!("agent://local/{id}"),
            id.to_owned(),
            "builder".into(),
            "p2".into(),
            "s1t2w12".into(),
            "vvmux:dev/f1p2".into(),
        ] {
            assert_eq!(RemoteSelector::parse(&local).unwrap(), None, "{local}");
        }

        // A peer resolves only its own agents: no second hop, and nothing empty or unbounded.
        for bad in [
            "@buildbox".to_owned(),
            "@buildbox:".into(),
            "@Buildbox:builder".into(),
            "@buildbox:@other:builder".into(),
            "@buildbox:peer:other:builder".into(),
            "@buildbox:agent://other/0123456789abcdef0123456789abcdef".into(),
            format!("@buildbox:{}", "p".repeat(bridge::MAX_SELECTOR_BYTES + 1)),
            "agent://buildbox/not-an-id".into(),
            "peer:buildbox".into(),
            "peer:buildbox:".into(),
            "peer:buildbox:@other:builder".into(),
            "peer:buildbox:peer:other:builder".into(),
            format!(
                "peer:buildbox:{}",
                "p".repeat(bridge::MAX_SELECTOR_BYTES + 1)
            ),
        ] {
            assert!(RemoteSelector::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_peer_label_is_a_host_name_and_cannot_be_read_two_ways() {
        for (destination, label) in [
            ("buildbox", "buildbox"),
            ("user@Build.Example.com", "build.example.com"),
            ("ssh://user@buildbox:2222", "buildbox"),
            ("10.0.0.7", "10.0.0.7"),
        ] {
            assert_eq!(
                PeerLabel::from_destination(destination).unwrap().as_str(),
                label
            );
        }
        for bad in [
            "",
            "-x",
            "a:b",
            "a/b",
            "a@b",
            "Upper",
            "[::1]",
            &"a".repeat(65),
        ] {
            assert!(PeerLabel::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn nudge_and_interrupt_are_off_by_default() {
        let policy = Policy::default();
        let sender = Principal {
            kind: PrincipalKind::Agent,
            endpoint_id: None,
            incarnation_id: None,
        };
        let scope = Opaque::parse(A).unwrap();
        let request = Request {
            sender: &sender,
            sender_scope: Some(&scope),
            target_scope: &scope,
            is_reply_to_our_request: true,
            sender_address: None,
            target_address: None,
            peer_trusted: false,
        };
        assert!(!policy.evaluate(Gate::PtyNudge, &request).allowed);
        assert!(!policy.evaluate(Gate::Interrupt, &request).allowed);
    }

    #[test]
    fn drafts_reject_out_of_bounds_content() {
        let base = Draft {
            to: Opaque::generate(),
            kind: Kind::Request,
            reply_to: None,
            outcome: None,
            subject: None,
            text: "hello".into(),
            refs: Vec::new(),
            idempotency_key: "k1".into(),
            expires_in_ms: None,
        };
        base.validate().unwrap();

        let oversize = Draft {
            text: "x".repeat(MAX_TEXT_BYTES + 1),
            ..base.clone()
        };
        assert_eq!(
            oversize.validate().unwrap_err().code,
            ErrorCode::InvalidRequest
        );

        let too_many_refs = Draft {
            refs: (0..MAX_REFS + 1)
                .map(|i| Ref::File {
                    path: format!("/tmp/{i}"),
                    sha256: None,
                    bytes: None,
                    host: None,
                })
                .collect(),
            ..base.clone()
        };
        assert!(too_many_refs.validate().is_err());

        let response_without_target = Draft {
            kind: Kind::Response,
            outcome: Some(Outcome::Completed),
            ..base.clone()
        };
        assert!(response_without_target.validate().is_err());

        let request_with_outcome = Draft {
            outcome: Some(Outcome::Completed),
            ..base
        };
        assert!(request_with_outcome.validate().is_err());
    }

    #[test]
    fn file_references_reject_control_bytes_and_relative_paths() {
        assert!(
            Ref::File {
                path: std::env::temp_dir()
                    .join("ok.patch")
                    .to_string_lossy()
                    .into_owned(),
                sha256: None,
                bytes: None,
                host: None,
            }
            .validate()
            .is_ok()
        );
        assert!(
            Ref::File {
                path: "relative.patch".into(),
                host: None,
                sha256: None,
                bytes: None
            }
            .validate()
            .is_err()
        );
        assert!(
            Ref::File {
                path: "/tmp/bad\u{0}name".into(),
                host: None,
                sha256: None,
                bytes: None
            }
            .validate()
            .is_err()
        );
        assert!(
            Ref::File {
                path: "/tmp/esc\u{1b}[2J".into(),
                host: None,
                sha256: None,
                bytes: None
            }
            .validate()
            .is_err(),
            "terminal escapes must not ride in a reference"
        );
    }

    #[test]
    fn the_digest_separates_fields_so_content_cannot_be_shifted_between_them() {
        let base = Draft {
            to: Opaque::parse(A).unwrap(),
            kind: Kind::Request,
            reply_to: None,
            outcome: None,
            subject: Some("ab".into()),
            text: "c".into(),
            refs: Vec::new(),
            idempotency_key: "k".into(),
            expires_in_ms: None,
        };
        let shifted = Draft {
            subject: Some("a".into()),
            text: "bc".into(),
            ..base.clone()
        };
        assert_ne!(base.digest(), shifted.digest());
    }
}
