//! `VVAM-BRIDGE/1`: what two peer hosts' bridges say to each other (`vvagent-inter-host-plan.md` §6).
//!
//! Pure types and a codec, with no I/O, like the rest of this crate. The carrier is any reliable,
//! ordered byte stream — the stdio of an SSH exec channel in v1:
//!
//! ```text
//! hello (once per direction):  "VVAB" | u16 BE version | u32 BE length | JSON
//! frame (thereafter):          u32 BE length | JSON
//! ```
//!
//! Three properties carry the design:
//!
//! - **Bounds before allocation.** A length is checked the moment its header is complete, before a
//!   byte of body is buffered, and [`Decoder`] never holds more than one maximal frame.
//! - **Nothing a frame says is identity.** There is no `from`, principal, sender address, host id
//!   after `hello`, or absolute time. The receiving bridge attributes a frame to the connection it
//!   arrived on; an unknown field — such as a smuggled `from` — is refused, not ignored.
//! - **Strict v1.** An unknown frame type or field is a protocol violation that closes the
//!   connection. `Hello::understands` is how a later version adds frame types without a v1 peer
//!   ever receiving one.

use serde::{Deserialize, Serialize};

use crate::{
    ErrorCode, Kind, MAX_AMBIGUOUS_CANDIDATES, MAX_DISPLAY_BYTES, MAX_REFS,
    MAX_REQUEST_LIFETIME_MS, MAX_SUBJECT_BYTES, MAX_TEXT_BYTES, MeshError, Opaque, Outcome,
    PeerLabel, Ref, Result, State, invalid,
};

pub const MAGIC: [u8; 4] = *b"VVAB";
pub const VERSION: u16 = 1;

/// The largest frame body, sized from the largest legal message *as JSON*, not as raw bytes.
///
/// JSON escapes a control character as six bytes and a backslash as two, and both are legal where
/// they can occur, so the worst case is 32 KiB of control characters (192 KiB), a 256-byte subject
/// of them (1.5 KiB), and sixteen 4 KiB Windows paths of backslashes (128 KiB), plus envelope —
/// about 330 KiB. `the_largest_legal_delivery_fits_a_frame` builds exactly that.
pub const MAX_FRAME_BYTES: usize = 384 * 1024;
pub const MAX_HELLO_BYTES: usize = 4 * 1024;
pub const HELLO_HEADER_BYTES: usize = 10;
pub const FRAME_HEADER_BYTES: usize = 4;

pub const MAX_SELECTOR_BYTES: usize = 256;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 512;
/// How many frame-type names a `hello` may list, and how long each may be.
pub const MAX_UNDERSTOOD: usize = 32;
pub const MAX_FRAME_TYPE_BYTES: usize = 32;
/// Deliveries a bridge may have sent and not yet seen `accepted` or `refused` for (plan §6.2).
pub const MAX_IN_FLIGHT: usize = 32;

/// Which end of the carrier a bridge is. Exactly one of each per connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Started the carrier: `vvagent bridge --dial`.
    Dial,
    /// Started by it: `vvagent bridge --serve` under sshd.
    Serve,
}

/// The first thing each side sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// The sender's store id, which the dialer pins against its label (plan §4.1).
    pub host_id: Opaque,
    pub role: Role,
    /// Frame types this side can receive. Names it does not recognise are ignored, so a later
    /// version can list more; a v1 peer missing any v1 type is refused.
    pub understands: Vec<String>,
    /// What the sender suggests the other side call it, normally its host name. A suggestion for
    /// display, never identity: the other side pins the `host_id` and may pick another label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Hello {
    /// A v1 hello that understands every v1 frame type.
    pub fn new(host_id: Opaque, role: Role) -> Self {
        Self {
            host_id,
            role,
            understands: FRAME_TYPES.iter().map(|name| (*name).to_owned()).collect(),
            name: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.understands.len() > MAX_UNDERSTOOD {
            return Err(invalid(format!(
                "a hello lists at most {MAX_UNDERSTOOD} frame types"
            )));
        }
        for name in &self.understands {
            if name.is_empty()
                || name.len() > MAX_FRAME_TYPE_BYTES
                || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            {
                return Err(invalid(
                    "a frame type name is 1..=32 lowercase letters or '_'",
                ));
            }
        }
        if let Some(name) = &self.name {
            PeerLabel::parse(name)?;
        }
        Ok(())
    }

    /// Whether `theirs` is an acceptable other end for this side.
    pub fn accept_peer(&self, theirs: &Hello) -> Result<()> {
        if theirs.role == self.role {
            return Err(invalid(format!(
                "both ends of the bridge claim to {}",
                match self.role {
                    Role::Dial => "dial",
                    Role::Serve => "serve",
                }
            )));
        }
        if theirs.host_id == self.host_id {
            return Err(invalid(
                "the bridge reached this same store; a host cannot be its own peer",
            ));
        }
        if let Some(missing) = FRAME_TYPES
            .iter()
            .find(|name| !theirs.understands.iter().any(|theirs| theirs == *name))
        {
            return Err(invalid(format!(
                "the peer does not understand `{missing}`, which VVAM-BRIDGE/1 requires"
            )));
        }
        Ok(())
    }
}

/// Every v1 frame type, as it appears in the `type` field.
pub const FRAME_TYPES: [&str; 10] = [
    "resolve",
    "resolved",
    "unresolved",
    "deliver",
    "accepted",
    "refused",
    "cancel",
    "cancel_state",
    "ping",
    "pong",
];

/// One frame after `hello`.
///
/// "Origin" always means the host that originated the message a frame is about, and an
/// `origin_message_id` is that host's own id for it: the sender of `deliver` names its message, and
/// `accepted`, `refused`, `cancel` and `cancel_state` repeat that same id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frame {
    /// Resolve a selector in the receiver's own tree (plan §5.2). Only that host can.
    Resolve {
        request_id: u64,
        selector: String,
    },
    Resolved {
        request_id: u64,
        endpoint_id: Opaque,
        /// What the receiver calls that agent and where it sits, for people.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display: Option<String>,
    },
    Unresolved {
        request_id: u64,
        error: WireError,
    },
    Deliver(Deliver),
    /// Committed on the receiving host. Sent only after the commit.
    Accepted {
        origin_message_id: Opaque,
    },
    /// Refused by the receiving host, for a reason the sender records as the message's failure.
    Refused {
        origin_message_id: Opaque,
        error: WireError,
    },
    /// The originator asks for a request it delivered to be cancelled. A request, never a verdict.
    Cancel {
        origin_message_id: Opaque,
    },
    /// Where a cancelled request got to on the receiving host. Sent in answer to `cancel`, and
    /// again if a provider later confirms a stop.
    CancelState {
        origin_message_id: Opaque,
        state: State,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

/// One message crossing to the peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deliver {
    /// The sender's id for this message, and the receiver's idempotency key for it.
    pub origin_message_id: Opaque,
    /// Which of the sender's agents sent it. The peer's claim, attributed per peer (plan §3).
    pub origin_endpoint_id: Opaque,
    /// The recipient, as an endpoint id on the receiving host.
    pub to_endpoint_id: Opaque,
    pub kind: Kind,
    /// For a response: the receiving host's own id for the request this answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_origin: Option<Opaque>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<WireRef>,
    /// What is left of the sender's lifetime. Relative, because two hosts' clocks need not agree;
    /// the receiver sets its own deadline from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_lifetime_ms: Option<i64>,
}

/// A reference, and which end of the frame it is about.
///
/// Relative to the frame rather than naming a host, because the two stores call each other by
/// different names. The receiving bridge turns `sender` into "that peer" and `recipient` into
/// "this host" (plan §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRef {
    pub on: RefHost,
    #[serde(rename = "ref")]
    pub reference: Ref,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefHost {
    Sender,
    Recipient,
}

/// Why the far side said no.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireError {
    pub code: ErrorCode,
    pub message: String,
    /// For `agent_ambiguous`: how the peer names each match, so the asker can retype one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
}

impl WireError {
    /// A wire error from a local one, with the message cut to the wire bound on a char boundary.
    pub fn from_mesh(error: &MeshError) -> Self {
        let mut message: String = error.message.chars().filter(|c| !c.is_control()).collect();
        if message.len() > MAX_ERROR_MESSAGE_BYTES {
            let mut end = MAX_ERROR_MESSAGE_BYTES;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        let candidates = error
            .candidates
            .iter()
            .take(MAX_AMBIGUOUS_CANDIDATES)
            .filter(|name| bounded_text(name, MAX_DISPLAY_BYTES, "a candidate").is_ok())
            .cloned()
            .collect();
        Self {
            code: error.code,
            message,
            candidates,
        }
    }

    pub fn validate(&self) -> Result<()> {
        bounded_text(&self.message, MAX_ERROR_MESSAGE_BYTES, "an error message")?;
        if self.candidates.len() > MAX_AMBIGUOUS_CANDIDATES {
            return Err(invalid(format!(
                "at most {MAX_AMBIGUOUS_CANDIDATES} candidates"
            )));
        }
        for candidate in &self.candidates {
            bounded_text(candidate, MAX_DISPLAY_BYTES, "a candidate")?;
        }
        Ok(())
    }

    /// The error as this host reports it.
    pub fn into_mesh(self) -> MeshError {
        MeshError::new(self.code, self.message).with_candidates(self.candidates)
    }
}

impl Frame {
    /// Semantic bounds. [`encode_frame`] and [`decode_frame`] both apply them, so a bridge neither
    /// sends nor accepts a frame its peer would have to refuse.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Resolve { selector, .. } => {
                if selector.is_empty() {
                    return Err(invalid("a selector is not empty"));
                }
                bounded_text(selector, MAX_SELECTOR_BYTES, "a selector")
            }
            Self::Resolved { display, .. } => match display {
                Some(display) => bounded_text(display, MAX_DISPLAY_BYTES, "a display name"),
                None => Ok(()),
            },
            Self::Unresolved { error, .. } | Self::Refused { error, .. } => error.validate(),
            Self::Deliver(deliver) => deliver.validate(),
            Self::Accepted { .. }
            | Self::Cancel { .. }
            | Self::CancelState { .. }
            | Self::Ping { .. }
            | Self::Pong { .. } => Ok(()),
        }
    }
}

impl Deliver {
    pub fn validate(&self) -> Result<()> {
        if self.text.len() > MAX_TEXT_BYTES {
            return Err(invalid(format!(
                "message text is over the {MAX_TEXT_BYTES}-byte limit"
            )));
        }
        if let Some(subject) = &self.subject
            && subject.len() > MAX_SUBJECT_BYTES
        {
            return Err(invalid(format!(
                "subject is over the {MAX_SUBJECT_BYTES}-byte limit"
            )));
        }
        if self.refs.len() > MAX_REFS {
            return Err(invalid(format!("more than {MAX_REFS} references")));
        }
        for reference in &self.refs {
            reference.validate()?;
        }
        if let Some(lifetime) = self.remaining_lifetime_ms
            && !(1..=MAX_REQUEST_LIFETIME_MS).contains(&lifetime)
        {
            return Err(invalid(format!(
                "a remaining lifetime is 1..={MAX_REQUEST_LIFETIME_MS} ms"
            )));
        }
        match self.kind {
            Kind::Response => {
                if self.reply_to_origin.is_none() || self.outcome.is_none() {
                    return Err(invalid(
                        "a delivered response names the request it answers and carries an outcome",
                    ));
                }
            }
            Kind::Request | Kind::Notice => {
                if self.reply_to_origin.is_some() || self.outcome.is_some() {
                    return Err(invalid(
                        "only a delivered response answers a request or carries an outcome",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl WireRef {
    /// On the wire, a path is always judged by portable rules — bounded, no control bytes,
    /// absolute on *some* platform — because whichever side is checking, the path may belong to
    /// the other machine, whose platform may differ. The host a path *is* on applies its own rules
    /// when the message lands: the receiving store validates the references it inserts, and the
    /// sending store validated its own when they were sent.
    ///
    /// Which host a reference is about travels as `on`, never as a store's own `host` field.
    pub fn validate(&self) -> Result<()> {
        if matches!(self.reference, Ref::File { host: Some(_), .. }) {
            return Err(invalid(
                "a reference on the wire says which end it is about with `on`, not `host`",
            ));
        }
        self.reference.validate_elsewhere()
    }
}

fn bounded_text(value: &str, max: usize, what: &str) -> Result<()> {
    if value.len() > max {
        return Err(invalid(format!("{what} is at most {max} bytes")));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{what} may not contain control characters"
        )));
    }
    Ok(())
}

fn violation(message: impl Into<String>) -> MeshError {
    MeshError::new(ErrorCode::InvalidRequest, message)
}

// ---------------------------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------------------------

pub fn encode_hello(hello: &Hello) -> Result<Vec<u8>> {
    hello.validate()?;
    let body = serde_json::to_vec(hello).map_err(|err| violation(err.to_string()))?;
    if body.len() > MAX_HELLO_BYTES {
        return Err(violation("a hello is over its size limit"));
    }
    let mut out = Vec::with_capacity(HELLO_HEADER_BYTES + body.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&length_prefix(body.len()));
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>> {
    frame.validate()?;
    let body = serde_json::to_vec(frame).map_err(|err| violation(err.to_string()))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(violation(format!(
            "a frame is over the {MAX_FRAME_BYTES}-byte limit"
        )));
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_BYTES + body.len());
    out.extend_from_slice(&length_prefix(body.len()));
    out.extend_from_slice(&body);
    Ok(out)
}

fn length_prefix(length: usize) -> [u8; 4] {
    // Both callers have already bounded `length` far below u32::MAX.
    u32::try_from(length)
        .expect("a bounded body fits a u32 length")
        .to_be_bytes()
}

/// The body length a hello header announces, refused before any body is read.
pub fn hello_len(header: &[u8; HELLO_HEADER_BYTES]) -> Result<usize> {
    if header[..4] != MAGIC {
        return Err(violation("not a VVAM-BRIDGE stream"));
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != VERSION {
        return Err(violation(format!(
            "the peer speaks VVAM-BRIDGE/{version}; this bridge speaks /{VERSION}"
        )));
    }
    let length = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if length == 0 || length > MAX_HELLO_BYTES {
        return Err(violation(format!(
            "a hello announces {length} bytes; the limit is 1..={MAX_HELLO_BYTES}"
        )));
    }
    Ok(length)
}

/// The body length a frame header announces, refused before any body is read.
pub fn frame_len(header: &[u8; FRAME_HEADER_BYTES]) -> Result<usize> {
    let length = u32::from_be_bytes(*header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(violation(format!(
            "a frame announces {length} bytes; the limit is 1..={MAX_FRAME_BYTES}"
        )));
    }
    Ok(length)
}

pub fn decode_hello(body: &[u8]) -> Result<Hello> {
    if body.len() > MAX_HELLO_BYTES {
        return Err(violation("a hello is over its size limit"));
    }
    let hello: Hello =
        serde_json::from_slice(body).map_err(|err| violation(format!("bad hello: {err}")))?;
    hello.validate()?;
    Ok(hello)
}

pub fn decode_frame(body: &[u8]) -> Result<Frame> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(violation("a frame is over its size limit"));
    }
    let frame: Frame =
        serde_json::from_slice(body).map_err(|err| violation(format!("bad frame: {err}")))?;
    frame.validate()?;
    Ok(frame)
}

/// Reassembles a byte stream into a hello and then frames, holding at most one maximal frame.
///
/// [`Decoder::push`] takes only as many bytes as fit and says how many; the caller drains complete
/// items with [`Decoder::next_hello`] / [`Decoder::next_frame`] and pushes the rest. An announced
/// length is refused as soon as its header is complete. After any violation the decoder refuses
/// everything, because the stream it was reading is no longer trustworthy.
#[derive(Debug, Default)]
pub struct Decoder {
    buffer: Vec<u8>,
    hello_done: bool,
    failed: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// The most this decoder will ever buffer.
    pub const CAPACITY: usize = FRAME_HEADER_BYTES + MAX_FRAME_BYTES;

    /// Buffer as much of `bytes` as fits and return how many were taken.
    pub fn push(&mut self, bytes: &[u8]) -> usize {
        if self.failed {
            return 0;
        }
        let room = Self::CAPACITY - self.buffer.len();
        let take = room.min(bytes.len());
        self.buffer.extend_from_slice(&bytes[..take]);
        take
    }

    pub fn next_hello(&mut self) -> Result<Option<Hello>> {
        self.guard(|this| {
            if this.hello_done {
                return Err(violation("the hello was already received"));
            }
            let Some(header) = this.buffer.first_chunk::<HELLO_HEADER_BYTES>() else {
                return Ok(None);
            };
            let length = hello_len(header)?;
            let Some(body) = this
                .buffer
                .get(HELLO_HEADER_BYTES..HELLO_HEADER_BYTES + length)
            else {
                return Ok(None);
            };
            let hello = decode_hello(body)?;
            this.buffer.drain(..HELLO_HEADER_BYTES + length);
            this.hello_done = true;
            Ok(Some(hello))
        })
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>> {
        self.guard(|this| {
            if !this.hello_done {
                return Err(violation("a frame arrived before the hello"));
            }
            let Some(header) = this.buffer.first_chunk::<FRAME_HEADER_BYTES>() else {
                return Ok(None);
            };
            let length = frame_len(header)?;
            let Some(body) = this
                .buffer
                .get(FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + length)
            else {
                return Ok(None);
            };
            let frame = decode_frame(body)?;
            this.buffer.drain(..FRAME_HEADER_BYTES + length);
            Ok(Some(frame))
        })
    }

    /// Call at end of stream: a partial hello or frame left over means the stream was truncated.
    pub fn finish(&self) -> Result<()> {
        if self.failed {
            return Err(violation("the stream already failed"));
        }
        if self.buffer.is_empty() {
            Ok(())
        } else {
            Err(violation(format!(
                "the stream ended {} bytes into an incomplete {}",
                self.buffer.len(),
                if self.hello_done { "frame" } else { "hello" }
            )))
        }
    }

    /// Bytes buffered and not yet decoded.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    fn guard<T>(&mut self, step: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        if self.failed {
            return Err(violation("the stream already failed"));
        }
        let result = step(self);
        if result.is_err() {
            self.failed = true;
            self.buffer = Vec::new();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAX_PATH_BYTES, MediaBinding, PaneRef, RuntimeKind};

    /// A small deterministic generator, so a failing case reproduces from its seed.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }

        fn chance(&mut self) -> bool {
            self.next() & 1 == 1
        }

        fn id(&mut self) -> Opaque {
            Opaque::parse(&format!("{:016x}{:016x}", self.next(), self.next())).unwrap()
        }

        /// Text that stresses JSON escaping: quotes, backslashes, newlines, multi-byte characters.
        fn text(&mut self, max_chars: u64, controls: bool) -> String {
            const ALPHABET: &[char] = &[
                'a', 'Z', '0', ' ', '"', '\\', '/', 'é', '中', '🦀', '\u{2028}',
            ];
            let length = self.below(max_chars + 1);
            (0..length)
                .map(|_| {
                    if controls && self.below(8) == 0 {
                        '\n'
                    } else {
                        ALPHABET[self.below(ALPHABET.len() as u64) as usize]
                    }
                })
                .collect()
        }

        fn reference(&mut self) -> WireRef {
            let on = if self.chance() {
                RefHost::Sender
            } else {
                RefHost::Recipient
            };
            let reference = match self.below(3) {
                0 => Ref::File {
                    path: match (on, self.chance()) {
                        (RefHost::Sender, true) => format!("C:\\build\\{}", self.below(1000)),
                        _ => format!("/tmp/{}", self.below(1000)),
                    },
                    sha256: self.chance().then(|| "ab".repeat(32)),
                    bytes: self.chance().then(|| self.next() >> 1),
                    host: None,
                },
                1 => Ref::Pane {
                    runtime_instance_id: self.id(),
                    locator: PaneRef {
                        runtime: RuntimeKind::Vvmux,
                        workspace: self.chance().then(|| "dev".into()),
                        tab: None,
                        pane_id: Some(self.below(64)),
                    },
                },
                _ => Ref::Media {
                    runtime_instance_id: self.id(),
                    resource_id: format!("r{}", self.below(1 << 20)),
                    binding: if self.chance() {
                        MediaBinding::Pinned
                    } else {
                        MediaBinding::Live
                    },
                },
            };
            WireRef { on, reference }
        }

        fn deliver(&mut self) -> Deliver {
            let kind = [Kind::Request, Kind::Response, Kind::Notice][self.below(3) as usize];
            let response = kind == Kind::Response;
            Deliver {
                origin_message_id: self.id(),
                origin_endpoint_id: self.id(),
                to_endpoint_id: self.id(),
                kind,
                reply_to_origin: response.then(|| self.id()),
                outcome: response.then_some(Outcome::Completed),
                subject: self.chance().then(|| self.text(40, false)),
                text: self.text(400, true),
                refs: (0..self.below(MAX_REFS as u64 + 1))
                    .map(|_| self.reference())
                    .collect(),
                remaining_lifetime_ms: self
                    .chance()
                    .then(|| 1 + self.below(MAX_REQUEST_LIFETIME_MS as u64) as i64),
            }
        }

        fn error(&mut self) -> WireError {
            WireError {
                code: [
                    ErrorCode::MailboxFull,
                    ErrorCode::PolicyRefused,
                    ErrorCode::AgentNotFound,
                ][self.below(3) as usize],
                message: self.text(80, false),
                candidates: Vec::new(),
            }
        }

        fn frame(&mut self) -> Frame {
            match self.below(10) {
                0 => Frame::Resolve {
                    request_id: self.next(),
                    selector: format!("vvmux:dev/p{}", 1 + self.below(9)),
                },
                1 => Frame::Resolved {
                    request_id: self.next(),
                    endpoint_id: self.id(),
                    display: self.chance().then(|| self.text(60, false)),
                },
                2 => Frame::Unresolved {
                    request_id: self.next(),
                    error: self.error(),
                },
                3 => Frame::Deliver(self.deliver()),
                4 => Frame::Accepted {
                    origin_message_id: self.id(),
                },
                5 => Frame::Refused {
                    origin_message_id: self.id(),
                    error: self.error(),
                },
                6 => Frame::Cancel {
                    origin_message_id: self.id(),
                },
                7 => Frame::CancelState {
                    origin_message_id: self.id(),
                    state: [State::Cancelled, State::CancellationRequested][self.below(2) as usize],
                },
                8 => Frame::Ping { nonce: self.next() },
                _ => Frame::Pong { nonce: self.next() },
            }
        }
    }

    fn hello(role: Role) -> Hello {
        Hello::new(Opaque::generate(), role)
    }

    fn raw_frame(json: &str) -> Vec<u8> {
        let mut out = (json.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(json.as_bytes());
        out
    }

    fn opened() -> Decoder {
        let mut decoder = Decoder::new();
        let bytes = encode_hello(&hello(Role::Dial)).unwrap();
        assert_eq!(decoder.push(&bytes), bytes.len());
        assert!(decoder.next_hello().unwrap().is_some());
        decoder
    }

    #[test]
    fn every_frame_type_round_trips_under_random_content() {
        let mut seen = std::collections::BTreeSet::new();
        for seed in 1..=2_000u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let frame = rng.frame();
            let bytes = encode_frame(&frame).unwrap_or_else(|err| panic!("seed {seed}: {err}"));
            let header: [u8; 4] = bytes[..4].try_into().unwrap();
            assert_eq!(frame_len(&header).unwrap(), bytes.len() - 4, "seed {seed}");
            assert_eq!(decode_frame(&bytes[4..]).unwrap(), frame, "seed {seed}");
            let json: serde_json::Value = serde_json::from_slice(&bytes[4..]).unwrap();
            seen.insert(json["type"].as_str().unwrap().to_owned());
        }
        let all: std::collections::BTreeSet<_> =
            FRAME_TYPES.iter().map(|name| (*name).to_owned()).collect();
        assert_eq!(seen, all, "the generator reaches every v1 frame type");
    }

    #[test]
    fn the_decoder_reassembles_a_stream_split_at_every_byte() {
        let mut rng = Rng(7);
        let frames: Vec<Frame> = (0..6).map(|_| rng.frame()).collect();
        let first = hello(Role::Serve);
        let mut stream = encode_hello(&first).unwrap();
        for frame in &frames {
            stream.extend(encode_frame(frame).unwrap());
        }

        for split in 0..=stream.len() {
            let mut decoder = Decoder::new();
            let mut hello_out = None;
            let mut out = Vec::new();
            for chunk in [&stream[..split], &stream[split..]] {
                let mut rest = chunk;
                while !rest.is_empty() {
                    let taken = decoder.push(rest);
                    rest = &rest[taken..];
                    if hello_out.is_none() {
                        hello_out = decoder.next_hello().unwrap();
                    }
                    if hello_out.is_some() {
                        while let Some(frame) = decoder.next_frame().unwrap() {
                            out.push(frame);
                        }
                    }
                }
            }
            assert_eq!(hello_out.as_ref(), Some(&first), "split at {split}");
            assert_eq!(out, frames, "split at {split}");
            decoder.finish().unwrap();
        }
    }

    #[test]
    fn a_random_chunking_of_many_frames_decodes_to_the_same_frames() {
        let mut rng = Rng(0xdead_beef);
        for round in 0..50 {
            let frames: Vec<Frame> = (0..(1 + rng.below(40))).map(|_| rng.frame()).collect();
            let mut stream = encode_hello(&hello(Role::Dial)).unwrap();
            for frame in &frames {
                stream.extend(encode_frame(frame).unwrap());
            }
            let mut decoder = Decoder::new();
            let mut out = Vec::new();
            let mut rest = &stream[..];
            let mut greeted = false;
            while !rest.is_empty() {
                let chunk = 1 + rng.below(4096) as usize;
                let taken = decoder.push(&rest[..chunk.min(rest.len())]);
                rest = &rest[taken..];
                if !greeted {
                    greeted = decoder.next_hello().unwrap().is_some();
                }
                while greeted && let Some(frame) = decoder.next_frame().unwrap() {
                    out.push(frame);
                }
            }
            assert_eq!(out, frames, "round {round}");
            decoder.finish().unwrap();
        }
    }

    #[test]
    fn an_oversized_length_is_refused_from_its_header_alone() {
        let mut decoder = opened();
        let announced = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
        assert_eq!(decoder.push(&announced), 4);
        assert!(decoder.next_frame().is_err());
        assert_eq!(decoder.buffered(), 0, "nothing of the body was held");
        // A failed stream stays failed.
        assert_eq!(decoder.push(b"more"), 0);
        assert!(decoder.next_frame().is_err());
        assert!(decoder.finish().is_err());

        assert!(
            frame_len(&0u32.to_be_bytes()).is_err(),
            "an empty frame is refused"
        );
        assert!(frame_len(&u32::MAX.to_be_bytes()).is_err());

        let mut header = [0u8; HELLO_HEADER_BYTES];
        header[..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&VERSION.to_be_bytes());
        header[6..].copy_from_slice(&(MAX_HELLO_BYTES as u32 + 1).to_be_bytes());
        assert!(hello_len(&header).is_err());
    }

    #[test]
    fn the_decoder_never_buffers_more_than_one_maximal_frame() {
        let mut decoder = opened();
        let flood = vec![0u8; 3 * Decoder::CAPACITY];
        assert_eq!(decoder.push(&flood), Decoder::CAPACITY);
        assert_eq!(decoder.push(&flood), 0);
    }

    #[test]
    fn a_truncated_stream_is_reported_at_its_end() {
        let frame = Frame::Ping { nonce: 9 };
        let bytes = encode_frame(&frame).unwrap();
        let mut decoder = opened();
        decoder.push(&bytes[..bytes.len() - 1]);
        assert_eq!(decoder.next_frame().unwrap(), None);
        assert!(decoder.finish().is_err());

        let mut fresh = Decoder::new();
        fresh.push(&encode_hello(&hello(Role::Dial)).unwrap()[..7]);
        assert_eq!(fresh.next_hello().unwrap(), None);
        assert!(fresh.finish().is_err());
    }

    #[test]
    fn a_wrong_magic_version_or_order_is_refused() {
        let good = encode_hello(&hello(Role::Dial)).unwrap();

        let mut magic = good.clone();
        magic[0] = b'X';
        let mut decoder = Decoder::new();
        decoder.push(&magic);
        assert!(decoder.next_hello().is_err());

        let mut version = good.clone();
        version[4..6].copy_from_slice(&2u16.to_be_bytes());
        let mut decoder = Decoder::new();
        decoder.push(&version);
        let refused = decoder.next_hello().unwrap_err();
        assert!(
            refused.message.contains("VVAM-BRIDGE/2"),
            "{}",
            refused.message
        );

        let mut early = Decoder::new();
        early.push(&encode_frame(&Frame::Ping { nonce: 1 }).unwrap());
        assert!(early.next_frame().is_err(), "a frame before the hello");

        let mut twice = opened();
        twice.push(&good);
        assert!(twice.next_hello().is_err(), "a second hello");
    }

    #[test]
    fn unknown_frame_types_and_fields_are_refused_not_ignored() {
        let id = Opaque::generate();
        for json in [
            r#"{"type":"teleport","nonce":1}"#.to_owned(),
            r#"{"nonce":1}"#.to_owned(),
            r#"{"type":"ping","nonce":1,"extra":true}"#.to_owned(),
            // A sender identity smuggled into a delivery is refused, not quietly dropped.
            format!(
                r#"{{"type":"deliver","origin_message_id":"{id}","origin_endpoint_id":"{id}",
                   "to_endpoint_id":"{id}","kind":"request","text":"hi","from":"{id}"}}"#
            ),
            format!(
                r#"{{"type":"deliver","origin_message_id":"{id}","origin_endpoint_id":"{id}",
                   "to_endpoint_id":"{id}","kind":"request","text":"hi",
                   "refs":[{{"on":"sender","ref":{{"kind":"file","path":"/x"}},"host":"h"}}]}}"#
            ),
            r#"{"type":"accepted","origin_message_id":"not-an-id"}"#.to_owned(),
            r#"{"type":"accepted","origin_message_id":"ABCDEF0123456789ABCDEF0123456789"}"#
                .to_owned(),
            "not json".to_owned(),
        ] {
            let mut decoder = opened();
            decoder.push(&raw_frame(&json));
            assert!(decoder.next_frame().is_err(), "accepted: {json}");
        }
        let smuggled =
            format!(r#"{{"host_id":"{id}","role":"dial","understands":[],"token":"x"}}"#);
        assert!(decode_hello(smuggled.as_bytes()).is_err());
    }

    #[test]
    fn semantic_bounds_hold_on_both_encode_and_decode() {
        let mut rng = Rng(3);
        let base = rng.deliver();
        let request = Deliver {
            kind: Kind::Request,
            reply_to_origin: None,
            outcome: None,
            ..base
        };
        let bad = [
            Deliver {
                text: "x".repeat(MAX_TEXT_BYTES + 1),
                ..request.clone()
            },
            Deliver {
                subject: Some("s".repeat(MAX_SUBJECT_BYTES + 1)),
                ..request.clone()
            },
            Deliver {
                refs: vec![request.refs.first().cloned().unwrap_or(rng.reference()); MAX_REFS + 1],
                ..request.clone()
            },
            Deliver {
                remaining_lifetime_ms: Some(0),
                ..request.clone()
            },
            Deliver {
                remaining_lifetime_ms: Some(MAX_REQUEST_LIFETIME_MS + 1),
                ..request.clone()
            },
            // A request that claims to answer something, and a response that does not.
            Deliver {
                reply_to_origin: Some(Opaque::generate()),
                ..request.clone()
            },
            Deliver {
                kind: Kind::Response,
                outcome: Some(Outcome::Completed),
                ..request.clone()
            },
            Deliver {
                refs: vec![WireRef {
                    on: RefHost::Sender,
                    reference: Ref::File {
                        path: "relative/path".into(),
                        sha256: None,
                        bytes: None,
                        host: None,
                    },
                }],
                ..request.clone()
            },
        ];
        for deliver in bad {
            let frame = Frame::Deliver(deliver);
            assert!(encode_frame(&frame).is_err(), "encoded {frame:?}");
            let json = serde_json::to_vec(&frame).unwrap();
            assert!(decode_frame(&json).is_err(), "decoded {frame:?}");
        }

        for frame in [
            Frame::Resolve {
                request_id: 1,
                selector: String::new(),
            },
            Frame::Resolve {
                request_id: 1,
                selector: "p".repeat(MAX_SELECTOR_BYTES + 1),
            },
            Frame::Resolved {
                request_id: 1,
                endpoint_id: Opaque::generate(),
                display: Some("line\nbreak".into()),
            },
            Frame::Refused {
                origin_message_id: Opaque::generate(),
                error: WireError {
                    code: ErrorCode::MailboxFull,
                    message: "e".repeat(MAX_ERROR_MESSAGE_BYTES + 1),
                    candidates: Vec::new(),
                },
            },
        ] {
            assert!(encode_frame(&frame).is_err(), "encoded {frame:?}");
            assert!(decode_frame(&serde_json::to_vec(&frame).unwrap()).is_err());
        }
    }

    #[test]
    fn the_largest_legal_delivery_fits_a_frame() {
        // Every field at its limit, filled with whatever JSON inflates most: control characters in
        // text and subject (six bytes each) and backslashes in paths on the sender's Windows host
        // (two bytes each).
        let id = Opaque::generate();
        let windows_path = format!("C:\\{}", "\\".repeat(MAX_PATH_BYTES - 3));
        assert_eq!(windows_path.len(), MAX_PATH_BYTES);
        let worst = Frame::Deliver(Deliver {
            origin_message_id: id.clone(),
            origin_endpoint_id: id.clone(),
            to_endpoint_id: id.clone(),
            kind: Kind::Response,
            reply_to_origin: Some(id.clone()),
            outcome: Some(Outcome::Completed),
            subject: Some("\u{1}".repeat(MAX_SUBJECT_BYTES)),
            text: "\u{1}".repeat(MAX_TEXT_BYTES),
            refs: vec![
                WireRef {
                    on: RefHost::Sender,
                    reference: Ref::File {
                        path: windows_path,
                        sha256: Some("ab".repeat(32)),
                        bytes: Some(u64::MAX),
                        host: None,
                    },
                };
                MAX_REFS
            ],
            remaining_lifetime_ms: Some(MAX_REQUEST_LIFETIME_MS),
        });
        let bytes = encode_frame(&worst).unwrap();
        assert!(
            bytes.len() - FRAME_HEADER_BYTES > 300 * 1024,
            "the case really is the inflated worst case: {} bytes",
            bytes.len()
        );
        assert!(bytes.len() <= FRAME_HEADER_BYTES + MAX_FRAME_BYTES);
        assert_eq!(decode_frame(&bytes[4..]).unwrap(), worst);
    }

    #[test]
    fn a_file_on_the_senders_host_is_judged_by_portable_rules() {
        for path in [
            "/home/u/x.bin",
            "C:\\Users\\u\\x.bin",
            "D:/x.bin",
            "\\\\server\\share\\x",
        ] {
            let reference = WireRef {
                on: RefHost::Sender,
                reference: Ref::File {
                    path: path.into(),
                    sha256: None,
                    bytes: None,
                    host: None,
                },
            };
            assert!(reference.validate().is_ok(), "{path}");
        }
        for path in ["x.bin", "C:x.bin", "", "/a\u{0}b"] {
            let reference = WireRef {
                on: RefHost::Sender,
                reference: Ref::File {
                    path: path.into(),
                    sha256: None,
                    bytes: None,
                    host: None,
                },
            };
            assert!(reference.validate().is_err(), "{path:?}");
        }
        let bad_digest = WireRef {
            on: RefHost::Sender,
            reference: Ref::File {
                path: "/x".into(),
                sha256: Some("zz".into()),
                bytes: None,
                host: None,
            },
        };
        assert!(bad_digest.validate().is_err());
    }

    #[test]
    fn a_pane_reference_is_bounded() {
        let pane = |workspace: &str| Ref::Pane {
            runtime_instance_id: Opaque::generate(),
            locator: PaneRef {
                runtime: RuntimeKind::Vivida,
                workspace: Some(workspace.into()),
                tab: None,
                pane_id: None,
            },
        };
        assert!(pane("main").validate().is_ok());
        assert!(
            pane(&"w".repeat(crate::MAX_PANE_FIELD_BYTES + 1))
                .validate()
                .is_err()
        );
        assert!(pane("a\u{1b}[2J").validate().is_err());
    }

    #[test]
    fn a_hello_is_accepted_only_from_the_other_role_on_another_store() {
        let dialer = hello(Role::Dial);
        let server = hello(Role::Serve);
        dialer.accept_peer(&server).unwrap();
        server.accept_peer(&dialer).unwrap();

        assert!(
            dialer.accept_peer(&hello(Role::Dial)).is_err(),
            "two dialers"
        );
        let mirror = Hello {
            role: Role::Serve,
            ..dialer.clone()
        };
        assert!(dialer.accept_peer(&mirror).is_err(), "the same store");

        let mut partial = server.clone();
        partial.understands.retain(|name| name != "cancel_state");
        let refused = dialer.accept_peer(&partial).unwrap_err();
        assert!(refused.message.contains("cancel_state"));

        // A later version may list frame types this one has never heard of.
        let mut newer = server.clone();
        newer.understands.push("attach_offer".into());
        dialer.accept_peer(&newer).unwrap();
        assert_eq!(
            decode_hello(&encode_hello(&newer).unwrap()[HELLO_HEADER_BYTES..]).unwrap(),
            newer
        );

        let mut crowded = server.clone();
        crowded.understands = vec!["x".into(); MAX_UNDERSTOOD + 1];
        assert!(encode_hello(&crowded).is_err());
        let mut odd = server;
        odd.understands.push("Deliver!".into());
        assert!(encode_hello(&odd).is_err());
    }

    #[test]
    fn a_local_error_is_cut_to_the_wire_bound_on_a_character_boundary() {
        let long = MeshError::new(ErrorCode::MailboxFull, format!("é{}\n", "中".repeat(400)));
        let wire = WireError::from_mesh(&long);
        wire.validate().unwrap();
        assert!(wire.message.len() <= MAX_ERROR_MESSAGE_BYTES);
        assert_eq!(wire.code, ErrorCode::MailboxFull);
    }
}
