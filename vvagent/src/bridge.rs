//! `vvagent bridge`: carry mail between this host's store and one peer host's
//! (`docs/vvagent-inter-host-plan.md` §6, §8).
//!
//! One process per connection, on each end: `--dial` starts the carrier (an SSH exec channel in
//! practice) and `--serve` is what that channel runs on the far side. Both speak
//! `VVAM-BRIDGE/1` over any reliable byte stream, which is why [`run`] takes a reader and a writer
//! rather than a socket — the tests drive it over in-memory pipes.
//!
//! The shape keeps the store single-threaded: a reader thread only decodes, into a bounded
//! channel, and one loop owns the store and the writer. Nothing durable lives here. A bridge holds
//! a lease on its peer, the claims it takes are ordinary store claims, and when it goes — cleanly
//! or not — its successor finds everything it had in flight back on the queue and sends it again,
//! which the peer's idempotency on the origin id makes harmless. That is also why this is not a
//! daemon: it lives exactly as long as its connection (plan §8.2).

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::time::{Duration, Instant};

use agent_mesh_core::bridge::{
    self as wire, Decoder, Frame, Hello, MAX_IN_FLIGHT, Role, WireError,
};
use agent_mesh_core::time::now_ms;
use agent_mesh_core::{
    ErrorCode, MAX_DISPLAY_BYTES, MeshError, Opaque, Origin, PeerLabel, Result, Selector, State,
    qualified_name, resolve,
};
use agent_mesh_store::{LeaseAnchor, Peer, Store};

pub struct Config {
    pub role: Role,
    /// Dialling: the label the user dialled, pinned to whichever store answers. Serving: a name
    /// to use for the dialler instead of the one it suggests.
    pub label: Option<PeerLabel>,
    /// What to suggest the other end call this host.
    pub name: Option<String>,
    /// The window this bridge was launched from, recorded in the lease (plan §5.3, §7.5).
    pub anchor: Option<LeaseAnchor>,
    /// Stop when this process is gone, as the watcher does.
    pub parent_pid: Option<u32>,
    /// Stop, cleanly, when this is set: how a supervisor such as `vvssh` ends a bridge so that
    /// both ends release their leases instead of leaving them to lapse.
    pub stop: Option<Arc<AtomicBool>>,
    pub poll: Duration,
    pub lease_ttl_ms: i64,
    pub heartbeat: Duration,
    pub idle_timeout: Duration,
    pub handshake_timeout: Duration,
}

impl Config {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            label: None,
            name: None,
            anchor: None,
            parent_pid: None,
            stop: None,
            poll: Duration::from_millis(200),
            lease_ttl_ms: 30_000,
            heartbeat: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(45),
            handshake_timeout: Duration::from_secs(30),
        }
    }
}

/// How a bridge ended without an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The carrier closed. The peer's label, for the caller's report.
    Closed(PeerLabel),
    /// Another bridge already holds this peer's lease, so this one stood aside.
    Standby(PeerLabel),
}

enum Incoming {
    Hello(Hello),
    Frame(Frame),
    Closed,
    Failed(MeshError),
}

/// Bridge `reader`/`writer` to whichever peer answers, until the carrier closes.
pub fn run<R, W>(store: &mut Store, config: &Config, reader: R, mut writer: W) -> Result<Ended>
where
    R: Read + Send + 'static,
    W: Write,
{
    let incoming = spawn_reader(reader);
    let mut own = Hello::new(store.host_id()?, config.role);
    own.name = config.name.clone();
    write_bytes(&mut writer, &wire::encode_hello(&own)?)?;
    flush(&mut writer)?;

    let theirs = match incoming.recv_timeout(config.handshake_timeout) {
        Ok(Incoming::Hello(hello)) => hello,
        Ok(Incoming::Failed(err)) => return Err(err),
        // Nothing answered: no SSH connection, no `vvagent` on the far side, or authentication
        // that needed a person. Distinct from a refusal, because trying again later can help.
        Ok(Incoming::Closed) | Err(RecvTimeoutError::Disconnected) => {
            return Err(MeshError::new(
                ErrorCode::PeerUnreachable,
                "the carrier closed before the peer said hello",
            ));
        }
        Ok(Incoming::Frame(_)) => return Err(protocol("a frame arrived before the hello")),
        Err(RecvTimeoutError::Timeout) => {
            return Err(MeshError::new(
                ErrorCode::PeerUnreachable,
                "the peer did not say hello in time",
            ));
        }
    };
    own.accept_peer(&theirs)?;
    let peer = identify(store, config, &theirs)?;

    let owner = Opaque::generate();
    let now = now_ms();
    if !store.acquire_peer_lease(
        &peer.peer_id,
        &owner,
        config.anchor.as_ref(),
        config.lease_ttl_ms,
        now,
    )? {
        return Ok(Ended::Standby(peer.label));
    }

    let mut session = Session {
        store,
        peer: peer.peer_id.clone(),
        owner: owner.clone(),
        writer,
        in_flight: HashMap::new(),
        cancels_sent: HashSet::new(),
        resolutions_asked: HashSet::new(),
    };
    let result = session.pump(&incoming, config);
    // Hand in-flight claims back to the queue now rather than when the lease lapses, so a
    // reconnect resends at once. Best effort: a crash leaves the same outcome, only slower.
    let _ = session.store.release_peer_lease(&peer.peer_id, &owner);
    result.map(|()| Ended::Closed(peer.label))
}

/// Which peer the other end is.
///
/// Dialling pins the label the user dialled to the store that answered, strictly (plan §4.1).
/// Serving has no label of its own for the dialler, so it finds the dialler by the `host_id` it
/// already knows, and otherwise takes the name it suggested — falling back to a name derived from
/// its id when that is taken by another store.
fn identify(store: &mut Store, config: &Config, theirs: &Hello) -> Result<Peer> {
    match config.role {
        Role::Dial => {
            let label = config.label.as_ref().ok_or_else(|| {
                MeshError::new(
                    ErrorCode::InvalidRequest,
                    "dialling needs the label of the peer",
                )
            })?;
            store.pin_peer(label, &theirs.host_id)
        }
        Role::Serve => {
            if let Some(known) = store.peer_by_host(&theirs.host_id)? {
                return Ok(known);
            }
            let short = &theirs.host_id.as_str()[..8];
            let label = match (&config.label, theirs.name.as_deref()) {
                (Some(label), _) => label.clone(),
                (None, Some(name)) => PeerLabel::parse(name)?,
                (None, None) => PeerLabel::parse(&format!("peer-{short}"))?,
            };
            match store.pin_peer(&label, &theirs.host_id) {
                Err(err) if err.code == ErrorCode::PeerMismatch => {
                    let base = &label.as_str()[..label.as_str().len().min(55)];
                    store.pin_peer(
                        &PeerLabel::parse(&format!("{base}-{short}"))?,
                        &theirs.host_id,
                    )
                }
                other => other,
            }
        }
    }
}

struct Session<'a, W: Write> {
    store: &'a mut Store,
    peer: Opaque,
    owner: Opaque,
    writer: W,
    /// Deliveries awaiting `accepted` or `refused`: local message id → the proxy it left through.
    in_flight: HashMap<Opaque, Opaque>,
    /// Cancellations already passed on over this connection.
    cancels_sent: HashSet<Opaque>,
    /// Questions asked of the peer over this connection and not yet answered. Only these may be
    /// answered, so a peer cannot write answers to questions nobody asked it.
    resolutions_asked: HashSet<i64>,
}

impl<W: Write> Session<'_, W> {
    fn pump(&mut self, incoming: &Receiver<Incoming>, config: &Config) -> Result<()> {
        let mut last_heard = Instant::now();
        let mut last_ping = Instant::now();
        let mut last_renewal = Instant::now();
        let renew_every = Duration::from_millis((config.lease_ttl_ms / 3).max(1) as u64);
        let mut nonce = 0u64;
        loop {
            let first = match incoming.recv_timeout(config.poll) {
                Ok(item) => Some(item),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            };
            let mut next = first;
            while let Some(item) = next.take() {
                match item {
                    Incoming::Frame(frame) => {
                        last_heard = Instant::now();
                        self.handle(frame)?;
                    }
                    Incoming::Closed => return Ok(()),
                    Incoming::Failed(err) => return Err(err),
                    Incoming::Hello(_) => return Err(protocol("a second hello")),
                }
                next = match incoming.try_recv() {
                    Ok(item) => Some(item),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => return Ok(()),
                };
            }

            if config
                .parent_pid
                .is_some_and(|pid| !crate::watch::process_is_alive(pid))
                || config
                    .stop
                    .as_ref()
                    .is_some_and(|stop| stop.load(Ordering::SeqCst))
            {
                return Ok(());
            }
            if last_renewal.elapsed() >= renew_every {
                if !self.store.acquire_peer_lease(
                    &self.peer,
                    &self.owner,
                    config.anchor.as_ref(),
                    config.lease_ttl_ms,
                    now_ms(),
                )? {
                    return Err(MeshError::new(
                        ErrorCode::ClaimLost,
                        "another bridge took over this peer",
                    ));
                }
                last_renewal = Instant::now();
            }
            self.forward_outbound()?;
            self.forward_cancellations()?;
            self.forward_resolutions()?;
            if last_heard.elapsed() >= config.idle_timeout {
                return Err(MeshError::new(ErrorCode::Io, "the peer stopped answering"));
            }
            if last_ping.elapsed() >= config.heartbeat {
                nonce = nonce.wrapping_add(1);
                self.send(&Frame::Ping { nonce })?;
                last_ping = Instant::now();
            }
            flush(&mut self.writer)?;
        }
    }

    fn handle(&mut self, frame: Frame) -> Result<()> {
        match frame {
            Frame::Deliver(deliver) => {
                let origin_message_id = deliver.origin_message_id.clone();
                match self.store.ingest(&self.peer, &self.owner, &deliver) {
                    Ok(_) => self.send(&Frame::Accepted { origin_message_id }),
                    // Nothing was decided about the message; the sender keeps it and resends.
                    Err(err) if fatal(&err) => Err(err),
                    Err(err) => self.send(&Frame::Refused {
                        origin_message_id,
                        error: WireError::from_mesh(&err),
                    }),
                }
            }
            // Only a delivery this bridge sent can be settled: a peer cannot mark anything else.
            Frame::Accepted { origin_message_id } => {
                if let Some(proxy) = self.in_flight.remove(&origin_message_id) {
                    let caller = self.store.proxy_caller(&proxy, &self.owner)?;
                    self.store.forwarded(&caller, &origin_message_id)?;
                }
                Ok(())
            }
            Frame::Refused {
                origin_message_id,
                error,
            } => {
                if let Some(proxy) = self.in_flight.remove(&origin_message_id) {
                    let caller = self.store.proxy_caller(&proxy, &self.owner)?;
                    self.store
                        .forward_failed(&caller, &origin_message_id, error.code)?;
                }
                Ok(())
            }
            Frame::Cancel { origin_message_id } => {
                let state = match self
                    .store
                    .message_by_origin(&self.peer, &origin_message_id)?
                {
                    Some(message) => {
                        let proxy = message
                            .from
                            .endpoint_id
                            .clone()
                            .expect("mail from a peer has a proxy sender");
                        let caller = self.store.proxy_caller(&proxy, &self.owner)?;
                        match self.store.cancel(&caller, &message.message_id) {
                            Ok(state) => state,
                            Err(err) if fatal(&err) => return Err(err),
                            Err(_) => message.state,
                        }
                    }
                    // Never received. The sender only asks after its copy stopped being resent, so
                    // nothing of it can still arrive: it is as cancelled as it will ever be.
                    None => State::Cancelled,
                };
                self.send(&Frame::CancelState {
                    origin_message_id,
                    state,
                })
            }
            Frame::CancelState {
                origin_message_id,
                state,
            } => {
                let Ok(message) = self.store.message(&origin_message_id) else {
                    return Ok(());
                };
                // Only mail that left through one of this peer's proxies.
                match self.store.proxy(&message.to_endpoint) {
                    Ok(proxy) if proxy.peer_id == self.peer => {
                        let caller = self.store.proxy_caller(&proxy.endpoint_id, &self.owner)?;
                        self.store
                            .confirm_remote_cancel(&caller, &origin_message_id, state)?;
                    }
                    _ => {}
                }
                Ok(())
            }
            Frame::Resolve {
                request_id,
                selector,
            } => {
                let endpoints = self.store.list_endpoints()?;
                let answer = Selector::parse(&selector).and_then(|selector| {
                    resolve(&selector, &endpoints, Origin::default()).cloned()
                });
                let frame = match answer {
                    Ok(endpoint) => Frame::Resolved {
                        request_id,
                        display: Some(display(&qualified_name(&endpoint))),
                        endpoint_id: endpoint.endpoint_id,
                    },
                    Err(err) => Frame::Unresolved {
                        request_id,
                        error: WireError::from_mesh(&err),
                    },
                };
                self.send(&frame)
            }
            Frame::Resolved {
                request_id,
                endpoint_id,
                display,
            } => self.answer(request_id, Ok((endpoint_id, display))),
            Frame::Unresolved { request_id, error } => {
                self.answer(request_id, Err(error.into_mesh()))
            }
            Frame::Ping { nonce } => self.send(&Frame::Pong { nonce }),
            Frame::Pong { .. } => Ok(()),
        }
    }

    /// Take mail off every proxy's outbox, round-robin, while fewer than [`MAX_IN_FLIGHT`]
    /// deliveries await an answer.
    fn forward_outbound(&mut self) -> Result<()> {
        let proxies = self.store.list_proxies(&self.peer)?;
        let mut progressed = true;
        while progressed && self.in_flight.len() < MAX_IN_FLIGHT {
            progressed = false;
            for proxy in &proxies {
                if self.in_flight.len() >= MAX_IN_FLIGHT {
                    break;
                }
                let caller = self.store.proxy_caller(&proxy.endpoint_id, &self.owner)?;
                let Some(message) = self.store.claim_outbound(&caller)? else {
                    continue;
                };
                progressed = true;
                match self.store.outbound(proxy, &message, now_ms()) {
                    Ok(deliver) => {
                        self.send(&Frame::Deliver(deliver))?;
                        self.in_flight
                            .insert(message.message_id, proxy.endpoint_id.clone());
                    }
                    Err(err) if fatal(&err) => return Err(err),
                    Err(err) => {
                        self.store
                            .forward_failed(&caller, &message.message_id, err.code)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn forward_cancellations(&mut self) -> Result<()> {
        for (message_id, _) in self.store.cancellations_to_forward(&self.peer)? {
            if self.cancels_sent.insert(message_id.clone()) {
                self.send(&Frame::Cancel {
                    origin_message_id: message_id,
                })?;
            }
        }
        Ok(())
    }

    fn forward_resolutions(&mut self) -> Result<()> {
        for (request_id, selector) in self.store.pending_resolutions(&self.peer)? {
            if self.resolutions_asked.insert(request_id) {
                let request_id = u64::try_from(request_id).map_err(|_| {
                    MeshError::new(ErrorCode::StoreCorrupt, "a negative request id")
                })?;
                self.send(&Frame::Resolve {
                    request_id,
                    selector,
                })?;
            }
        }
        Ok(())
    }

    fn answer(
        &mut self,
        request_id: u64,
        answer: std::result::Result<(Opaque, Option<String>), MeshError>,
    ) -> Result<()> {
        let Ok(request_id) = i64::try_from(request_id) else {
            return Ok(());
        };
        if self.resolutions_asked.remove(&request_id) {
            self.store
                .answer_resolution(&self.peer, request_id, answer)?;
        }
        Ok(())
    }

    fn send(&mut self, frame: &Frame) -> Result<()> {
        write_bytes(&mut self.writer, &wire::encode_frame(frame)?)
    }
}

/// Errors that mean this bridge must stop rather than tell the peer "no": the store could not
/// decide, or this bridge no longer speaks for the peer. Whatever was in flight is resent later.
fn fatal(err: &MeshError) -> bool {
    matches!(
        err.code,
        ErrorCode::Io
            | ErrorCode::StoreCorrupt
            | ErrorCode::SchemaMismatch
            | ErrorCode::ClaimLost
            | ErrorCode::PeerRetired
    )
}

/// A display name the wire will accept: no control characters, within the bound.
fn display(name: &str) -> String {
    let mut clean: String = name.chars().filter(|c| !c.is_control()).collect();
    if clean.len() > MAX_DISPLAY_BYTES {
        let mut end = MAX_DISPLAY_BYTES;
        while !clean.is_char_boundary(end) {
            end -= 1;
        }
        clean.truncate(end);
    }
    clean
}

fn spawn_reader<R: Read + Send + 'static>(mut reader: R) -> Receiver<Incoming> {
    // Bounded, so a peer that floods frames is held back by its own carrier rather than by this
    // process's memory.
    let (sender, receiver) = mpsc::sync_channel(64);
    std::thread::spawn(move || {
        let mut decoder = Decoder::new();
        let mut buffer = vec![0u8; 16 * 1024];
        let mut greeted = false;
        loop {
            let read = match reader.read(&mut buffer) {
                Ok(0) => {
                    let end = match decoder.finish() {
                        Ok(()) => Incoming::Closed,
                        Err(err) => Incoming::Failed(err),
                    };
                    let _ = sender.send(end);
                    return;
                }
                Ok(read) => read,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    let _ = sender.send(Incoming::Failed(io(err)));
                    return;
                }
            };
            let mut rest = &buffer[..read];
            while !rest.is_empty() {
                let taken = decoder.push(rest);
                rest = &rest[taken..];
                loop {
                    let item = if greeted {
                        decoder.next_frame().map(|frame| frame.map(Incoming::Frame))
                    } else {
                        decoder.next_hello().map(|hello| hello.map(Incoming::Hello))
                    };
                    match item {
                        Ok(Some(item)) => {
                            greeted = true;
                            if sender.send(item).is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(err) => {
                            let _ = sender.send(Incoming::Failed(err));
                            return;
                        }
                    }
                }
                if taken == 0 && !rest.is_empty() {
                    // The decoder holds one maximal frame and could not complete it, which a
                    // well-formed stream cannot cause.
                    let _ = sender.send(Incoming::Failed(protocol("the stream stalled")));
                    return;
                }
            }
        }
    });
    receiver
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> Result<()> {
    writer.write_all(bytes).map_err(io)
}

fn flush(writer: &mut impl Write) -> Result<()> {
    writer.flush().map_err(io)
}

fn io(err: std::io::Error) -> MeshError {
    MeshError::new(ErrorCode::Io, format!("bridge carrier: {err}"))
}

fn protocol(message: &str) -> MeshError {
    MeshError::new(ErrorCode::InvalidRequest, message)
}

#[cfg(test)]
mod tests {
    use std::io::{PipeReader, PipeWriter};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::JoinHandle;

    use agent_mesh_core::{Alias, Draft, Kind, Locator, Outcome, Policy, RuntimeKind};
    use agent_mesh_store::{Binding, Bound, Caller};

    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let base = std::env::temp_dir().join(format!(
                "vvagent-bridge-{name}-{}-{}",
                std::process::id(),
                now_ms()
            ));
            std::fs::create_dir_all(&base).unwrap();
            Self(base)
        }

        fn db(&self, host: &str) -> PathBuf {
            self.0.join(host).join("mesh.sqlite")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A writer the test can cut, and that can be told to break the link instead of writing one
    /// kind of frame — which is how "the peer committed but its answer was lost" is staged.
    struct Wire {
        inner: PipeWriter,
        cut: Arc<AtomicBool>,
        break_on: Option<&'static [u8]>,
    }

    impl Write for Wire {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let tripped = self
                .break_on
                .is_some_and(|needle| buf.windows(needle.len()).any(|w| w == needle));
            if tripped {
                self.cut.store(true, Ordering::SeqCst);
            }
            if self.cut.load(Ordering::SeqCst) {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            self.inner.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    fn fast(role: Role) -> Config {
        Config {
            poll: Duration::from_millis(10),
            lease_ttl_ms: 3_000,
            heartbeat: Duration::from_millis(200),
            idle_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
            ..Config::new(role)
        }
    }

    /// One connection: a dialler on `laptop` calling it `buildbox`, a server on `buildbox` calling
    /// the dialler `laptop`.
    struct Link {
        cut: Arc<AtomicBool>,
        dial: JoinHandle<Result<Ended>>,
        serve: JoinHandle<Result<Ended>>,
    }

    impl Link {
        fn open(scratch: &Scratch, break_serve_on: Option<&'static [u8]>) -> Self {
            let (to_serve, from_dial) = std::io::pipe().unwrap();
            let (to_dial, from_serve) = std::io::pipe().unwrap();
            let cut = Arc::new(AtomicBool::new(false));
            let dial_db = scratch.db("laptop");
            let serve_db = scratch.db("buildbox");
            let dial_wire = Wire {
                inner: from_dial,
                cut: cut.clone(),
                break_on: None,
            };
            let serve_wire = Wire {
                inner: from_serve,
                cut: cut.clone(),
                break_on: break_serve_on,
            };
            let dial = spawn_end(dial_db, dial_config(), to_dial, dial_wire);
            let serve = spawn_end(serve_db, serve_config(), to_serve, serve_wire);
            Self { cut, dial, serve }
        }

        fn close(self) -> (Result<Ended>, Result<Ended>) {
            self.cut.store(true, Ordering::SeqCst);
            (self.dial.join().unwrap(), self.serve.join().unwrap())
        }
    }

    fn dial_config() -> Config {
        Config {
            label: Some(PeerLabel::parse("buildbox").unwrap()),
            name: Some("laptop".into()),
            ..fast(Role::Dial)
        }
    }

    fn serve_config() -> Config {
        fast(Role::Serve)
    }

    fn spawn_end(
        db: PathBuf,
        config: Config,
        reader: PipeReader,
        writer: Wire,
    ) -> JoinHandle<Result<Ended>> {
        std::thread::spawn(move || {
            let mut store = Store::open(db)?;
            run(&mut store, &config, reader, writer)
        })
    }

    fn until(what: &str, mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn bind(store: &mut Store, alias: &str) -> Bound {
        store
            .bind(&Binding {
                alias: Some(Alias::parse(alias).unwrap()),
                provider: None,
                locator: Locator {
                    kind: RuntimeKind::Wrapper,
                    runtime_instance_id: Opaque::generate(),
                    instance_name: Some(alias.into()),
                    address: None,
                },
            })
            .unwrap()
    }

    fn caller(store: &Store, bound: &Bound) -> Caller {
        store
            .authenticate(&bound.endpoint_id, &bound.token)
            .unwrap()
    }

    fn request(to: &Opaque, text: &str, key: &str) -> Draft {
        Draft {
            to: to.clone(),
            kind: Kind::Request,
            reply_to: None,
            outcome: None,
            subject: Some("build".into()),
            text: text.into(),
            refs: Vec::new(),
            idempotency_key: key.into(),
            expires_in_ms: Some(600_000),
        }
    }

    /// Both hosts, with an asker on the laptop and a builder on buildbox.
    struct Hosts {
        laptop: Store,
        buildbox: Store,
        asker: Bound,
        builder: Bound,
    }

    impl Hosts {
        fn new(scratch: &Scratch) -> Self {
            let mut laptop = Store::open(scratch.db("laptop")).unwrap();
            let mut buildbox = Store::open(scratch.db("buildbox")).unwrap();
            let asker = bind(&mut laptop, "asker");
            let builder = bind(&mut buildbox, "builder");
            Self {
                laptop,
                buildbox,
                asker,
                builder,
            }
        }

        /// Wait for the first handshake to pin both ends, then return the laptop's proxy for the
        /// builder.
        fn connected(&mut self) -> Opaque {
            until("both ends to pin each other", || {
                !self.laptop.list_peers().unwrap().is_empty()
                    && !self.buildbox.list_peers().unwrap().is_empty()
            });
            let peer = self
                .laptop
                .peer(&PeerLabel::parse("buildbox").unwrap())
                .unwrap();
            self.laptop
                .ensure_proxy(&peer.peer_id, &self.builder.endpoint_id, None)
                .unwrap()
        }

        fn trust_laptop(&mut self) {
            self.buildbox
                .set_peer_trust(&PeerLabel::parse("laptop").unwrap(), true)
                .unwrap();
        }

        fn ask(&mut self, proxy: &Opaque, key: &str) -> Opaque {
            let asker = caller(&self.laptop, &self.asker);
            self.laptop
                .send(&asker, &request(proxy, "run the kernel build test", key))
                .unwrap()
                .message_id
        }

        fn state(&self, message: &Opaque) -> State {
            self.laptop.message(message).unwrap().state
        }

        fn builder_mail(&self) -> Vec<agent_mesh_store::Message> {
            self.buildbox
                .inbox(&self.builder.endpoint_id, &[], 500)
                .unwrap()
        }
    }

    #[test]
    fn a_request_and_its_correlated_reply_cross_the_bridge() {
        let scratch = Scratch::new("round-trip");
        let mut hosts = Hosts::new(&scratch);
        let link = Link::open(&scratch, None);
        let proxy = hosts.connected();
        hosts.trust_laptop();
        let asked = hosts.ask(&proxy, "q1");

        let builder = caller(&hosts.buildbox, &hosts.builder);
        let mut arrived = None;
        until("the request to reach the builder", || {
            arrived = hosts.buildbox.claim(&builder, None).unwrap();
            arrived.is_some()
        });
        let arrived = arrived.unwrap();
        assert_eq!(arrived.text, "run the kernel build test");
        assert_eq!(arrived.from.kind, agent_mesh_core::PrincipalKind::Peer);
        assert_eq!(arrived.origin_message_id.as_ref(), Some(&asked));
        let sender = hosts
            .buildbox
            .endpoint(arrived.from.endpoint_id.as_ref().unwrap())
            .unwrap();
        assert_eq!(
            hosts.buildbox.name_of(&sender),
            format!("agent://laptop/{}", hosts.asker.endpoint_id),
            "the builder sees who asked, by a selector it could answer with"
        );
        until("the laptop to hear it was accepted", || {
            hosts.state(&asked) == State::Delivered
        });

        hosts
            .buildbox
            .respond(
                &builder,
                &arrived.message_id,
                Outcome::Completed,
                "passed",
                vec![],
                "r1",
            )
            .unwrap();
        let mut answer = None;
        until("the reply to reach the asker", || {
            answer = hosts.laptop.response_for(&asked).unwrap();
            answer.is_some()
        });
        let answer = answer.unwrap();
        assert_eq!(answer.text, "passed");
        assert_eq!(answer.outcome, Some(Outcome::Completed));
        assert_eq!(answer.from.endpoint_id.as_ref(), Some(&proxy));
        // `respond` commits the answer, then retires the request in a second transaction.
        until("the request to be retired", || {
            hosts.state(&asked) == State::Consumed
        });

        let (dial, serve) = link.close();
        assert!(dial.is_err() || matches!(dial, Ok(Ended::Closed(_))));
        assert!(serve.is_err() || matches!(serve, Ok(Ended::Closed(_))));
    }

    #[test]
    fn a_delivery_whose_acceptance_was_lost_lands_exactly_once() {
        let scratch = Scratch::new("exactly-once");
        let mut hosts = Hosts::new(&scratch);

        // The server commits, then the link breaks as it answers `accepted`.
        let link = Link::open(&scratch, Some(br#""type":"accepted""#));
        let proxy = hosts.connected();
        hosts.trust_laptop();
        let asked = hosts.ask(&proxy, "q1");
        until("the server to commit and then lose its answer", || {
            hosts.builder_mail().len() == 1 && link.cut.load(Ordering::SeqCst)
        });
        let (_, serve) = link.close();
        assert!(serve.is_err(), "the server's link broke on `accepted`");
        assert_eq!(hosts.builder_mail().len(), 1, "committed once");
        assert_eq!(
            hosts.state(&asked),
            State::Queued,
            "the laptop never heard, so the message went back on its outbox"
        );

        // Reconnect: it is sent again, recognised, and accepted without a second copy.
        let link = Link::open(&scratch, None);
        until("the resend to be accepted", || {
            hosts.state(&asked) == State::Delivered
        });
        assert_eq!(hosts.builder_mail().len(), 1, "and still exactly once");
        let _ = link.close();
    }

    #[test]
    fn a_refusal_becomes_a_terminal_failure_on_the_sender() {
        let scratch = Scratch::new("refusals");
        let mut hosts = Hosts::new(&scratch);
        let link = Link::open(&scratch, None);
        let proxy = hosts.connected();

        // Nobody on buildbox trusts the laptop yet.
        let denied = hosts.ask(&proxy, "q1");
        until("the refusal", || {
            hosts.state(&denied) == State::Undeliverable
        });
        assert_eq!(
            hosts.laptop.message(&denied).unwrap().failure.as_deref(),
            Some("policy_refused")
        );

        // Trusted now, but the builder's mailbox is full of local work.
        hosts.trust_laptop();
        let policy = Policy {
            max_inbound_per_minute: u32::MAX,
            ..hosts.buildbox.policy(&hosts.builder.endpoint_id).unwrap()
        };
        hosts
            .buildbox
            .set_policy(&hosts.builder.endpoint_id, &policy)
            .unwrap();
        let local = hosts.buildbox.ensure_local_user().unwrap();
        for index in 0..agent_mesh_core::MAX_PENDING_COUNT {
            hosts
                .buildbox
                .send(
                    &local,
                    &request(&hosts.builder.endpoint_id, "local", &format!("l{index}")),
                )
                .unwrap();
        }
        let full = hosts.ask(&proxy, "q2");
        until("the second refusal", || {
            hosts.state(&full) == State::Undeliverable
        });
        assert_eq!(
            hosts.laptop.message(&full).unwrap().failure.as_deref(),
            Some("mailbox_full")
        );
        let _ = link.close();
    }

    #[test]
    fn a_cancelled_request_is_cancelled_on_both_hosts() {
        let scratch = Scratch::new("cancel");
        let mut hosts = Hosts::new(&scratch);
        let link = Link::open(&scratch, None);
        let proxy = hosts.connected();
        hosts.trust_laptop();
        let asked = hosts.ask(&proxy, "q1");
        until("delivery", || hosts.state(&asked) == State::Delivered);

        let asker = caller(&hosts.laptop, &hosts.asker);
        assert_eq!(
            hosts.laptop.cancel(&asker, &asked).unwrap(),
            State::CancellationRequested,
            "delivered work is only asked to stop"
        );
        until("the peer's confirmation", || {
            hosts.state(&asked) == State::Cancelled
        });
        assert_eq!(hosts.builder_mail()[0].state, State::Cancelled);
        let _ = link.close();
    }

    #[test]
    fn after_an_unclean_drop_a_reconnect_works_once_the_far_lease_lapses() {
        // What `vvssh`'s retry is for. A far side that died without releasing leaves its lease
        // live; until it lapses, the next connection's server stands aside and the dialler sees a
        // plain close. Once it lapses, the next attempt works.
        let scratch = Scratch::new("stale-lease");
        let mut hosts = Hosts::new(&scratch);
        let link = Link::open(&scratch, None);
        let proxy = hosts.connected();
        hosts.trust_laptop();
        let _ = link.close();

        let laptop = PeerLabel::parse("laptop").unwrap();
        let peer = hosts.buildbox.peer(&laptop).unwrap().peer_id;
        let dead = Opaque::generate();
        let lapses_in = 800;
        assert!(
            hosts
                .buildbox
                .acquire_peer_lease(&peer, &dead, None, lapses_in, now_ms())
                .unwrap()
        );

        let early = Link::open(&scratch, None);
        let dial = early.dial.join().unwrap();
        let serve = early.serve.join().unwrap();
        assert!(matches!(serve, Ok(Ended::Standby(_))), "{serve:?}");
        assert!(matches!(dial, Ok(Ended::Closed(_))), "{dial:?}");

        std::thread::sleep(Duration::from_millis(lapses_in as u64 + 100));
        let link = Link::open(&scratch, None);
        let asked = hosts.ask(&proxy, "after-lapse");
        until("delivery once the stale lease lapsed", || {
            hosts.state(&asked) == State::Delivered
        });
        let _ = link.close();
    }

    #[test]
    fn a_second_bridge_to_the_same_peer_stands_aside() {
        let scratch = Scratch::new("single-flight");
        let mut hosts = Hosts::new(&scratch);
        let first = Link::open(&scratch, None);
        hosts.connected();

        let second = Link::open(&scratch, None);
        let dial = second.dial.join().unwrap().unwrap();
        let serve = second.serve.join().unwrap().unwrap();
        assert!(matches!(dial, Ended::Standby(ref peer) if peer.as_str() == "buildbox"));
        assert!(matches!(serve, Ended::Standby(ref peer) if peer.as_str() == "laptop"));
        let _ = first.close();
    }

    /// A hostile or broken peer, driven frame by frame.
    struct Scripted {
        to_bridge: PipeWriter,
        decoder: Decoder,
        from_bridge: PipeReader,
        bridge: JoinHandle<Result<Ended>>,
    }

    impl Scripted {
        fn connect(db: PathBuf, host_id: Opaque) -> Self {
            let (from_bridge, bridge_out) = std::io::pipe().unwrap();
            let (bridge_in, mut to_bridge) = std::io::pipe().unwrap();
            let config = Config {
                label: Some(PeerLabel::parse("buildbox").unwrap()),
                ..fast(Role::Dial)
            };
            let bridge = spawn_end(
                db,
                config,
                bridge_in,
                Wire {
                    inner: bridge_out,
                    cut: Arc::new(AtomicBool::new(false)),
                    break_on: None,
                },
            );
            let hello = wire::encode_hello(&Hello::new(host_id, Role::Serve)).unwrap();
            to_bridge.write_all(&hello).unwrap();
            let mut scripted = Self {
                to_bridge,
                decoder: Decoder::new(),
                from_bridge,
                bridge,
            };
            scripted.read(|decoder| decoder.next_hello().unwrap().map(|_| ()));
            scripted
        }

        fn send(&mut self, frame: &Frame) {
            self.to_bridge
                .write_all(&wire::encode_frame(frame).unwrap())
                .unwrap();
        }

        fn read<T>(&mut self, mut next: impl FnMut(&mut Decoder) -> Option<T>) -> T {
            let mut buffer = [0u8; 4096];
            loop {
                if let Some(item) = next(&mut self.decoder) {
                    return item;
                }
                let read = self.from_bridge.read(&mut buffer).unwrap();
                assert!(read > 0, "the bridge hung up");
                assert_eq!(self.decoder.push(&buffer[..read]), read);
            }
        }

        /// The next frame that is not a heartbeat.
        fn expect(&mut self) -> Frame {
            loop {
                match self.read(|decoder| decoder.next_frame().unwrap()) {
                    Frame::Ping { .. } | Frame::Pong { .. } => continue,
                    frame => return frame,
                }
            }
        }
    }

    #[test]
    fn a_peer_cannot_settle_or_cancel_mail_it_was_never_sent() {
        let scratch = Scratch::new("hostile");
        let mut laptop = Store::open(scratch.db("laptop")).unwrap();
        let asker = bind(&mut laptop, "asker");
        let bystander = bind(&mut laptop, "bystander");
        let asker_caller = caller(&laptop, &asker);
        // Local mail between two local agents: nothing to do with any peer.
        let local = laptop
            .send(
                &asker_caller,
                &request(&bystander.endpoint_id, "local only", "l1"),
            )
            .unwrap()
            .message_id;

        let buildbox = Opaque::generate();
        let mut peer = Scripted::connect(scratch.db("laptop"), buildbox);
        until("the peer to be pinned", || {
            !laptop.list_peers().unwrap().is_empty()
        });

        // Claims about mail this peer never received are ignored.
        peer.send(&Frame::Accepted {
            origin_message_id: local.clone(),
        });
        peer.send(&Frame::Refused {
            origin_message_id: local.clone(),
            error: WireError {
                code: ErrorCode::MailboxFull,
                message: "no".into(),
                candidates: Vec::new(),
            },
        });
        peer.send(&Frame::CancelState {
            origin_message_id: local.clone(),
            state: State::Cancelled,
        });
        // Delivering to one of this host's proxies would route through it; delivering as if from
        // a local agent is impossible, because the sender is the proxy whatever the frame says.
        let label = PeerLabel::parse("buildbox").unwrap();
        let peer_id = laptop.peer(&label).unwrap().peer_id;
        let proxy = laptop
            .ensure_proxy(&peer_id, &Opaque::generate(), None)
            .unwrap();
        laptop.set_peer_trust(&label, true).unwrap();
        let transit = Opaque::generate();
        peer.send(&Frame::Deliver(wire::Deliver {
            origin_message_id: transit.clone(),
            origin_endpoint_id: asker.endpoint_id.clone(),
            to_endpoint_id: proxy,
            kind: Kind::Request,
            reply_to_origin: None,
            outcome: None,
            subject: None,
            text: "relay this".into(),
            refs: Vec::new(),
            remaining_lifetime_ms: None,
        }));
        match peer.expect() {
            Frame::Refused {
                origin_message_id,
                error,
            } => {
                assert_eq!(origin_message_id, transit);
                assert_eq!(error.code, ErrorCode::NotAuthorized);
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        let spoofed = Opaque::generate();
        peer.send(&Frame::Deliver(wire::Deliver {
            origin_message_id: spoofed.clone(),
            origin_endpoint_id: asker.endpoint_id.clone(),
            to_endpoint_id: bystander.endpoint_id.clone(),
            kind: Kind::Request,
            reply_to_origin: None,
            outcome: None,
            subject: None,
            text: "pretending to be the asker".into(),
            refs: Vec::new(),
            remaining_lifetime_ms: None,
        }));
        assert!(matches!(peer.expect(), Frame::Accepted { .. }));

        let message = laptop.message(&local).unwrap();
        assert_eq!(message.state, State::Queued, "local mail untouched");
        assert!(message.failure.is_none());
        let landed = laptop
            .inbox(&bystander.endpoint_id, &[], 10)
            .unwrap()
            .into_iter()
            .find(|message| message.origin_message_id.as_ref() == Some(&spoofed))
            .unwrap();
        assert_eq!(landed.from.kind, agent_mesh_core::PrincipalKind::Peer);
        assert_ne!(
            landed.from.endpoint_id.as_ref(),
            Some(&asker.endpoint_id),
            "a remote agent claiming a local id is still a proxy on this host"
        );

        drop(peer.to_bridge);
        assert!(matches!(peer.bridge.join().unwrap(), Ok(Ended::Closed(_))));
    }
}
