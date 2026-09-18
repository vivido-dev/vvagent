//! Provider adapters: the only place that knows how to wake a particular agent.
//!
//! M0 established what each provider can actually do
//! (`docs/agent-mesh-m0-results.md` §2). Codex leads M2 because it is the only provider with both
//! a machine-readable control protocol *and* a non-experimental CLI over the same socket. Nothing
//! here infers a capability from a provider's name: an adapter declares what it was tested for,
//! and a version it has not been tested against loses the capability rather than assuming it
//! carried forward.
//!
//! Deliberately absent from M2: `pty_pointer_nudge`. The exit criterion is that no payload reaches
//! a PTY, and a fallback that types into a terminal has no place in proving it.

use std::fmt;
use std::process::{Command, Stdio};
use std::time::Duration;

use agent_mesh_core::{Capabilities, Capability, ErrorCode, MeshError, Result};

/// How long a provider control call may take before it is abandoned. An adapter that hangs must
/// not stall the watcher for every other endpoint.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(20);

/// What an adapter did, or could not do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activation {
    /// A turn was started in the provider's own session.
    Started,
    /// The provider was reachable but declined — busy, no such thread, not idle.
    Declined(String),
    /// The provider could not be reached at all.
    Unavailable(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Interruption {
    Confirmed,
    Unconfirmed,
}

impl Activation {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Started => "started",
            Self::Declined(_) => "declined",
            Self::Unavailable(_) => "unavailable",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Started => None,
            Self::Declined(reason) | Self::Unavailable(reason) => Some(reason),
        }
    }
}

/// One provider's control surface.
pub trait Adapter {
    /// Whether this adapter's activation text reaches the provider through argv.
    ///
    /// `codex queue --message` does; an HTTP body does not. It matters because argv is readable by
    /// every process this user runs, so an adapter that can only take argv must never be handed a
    /// message body — only the bounded pointer of `activate_and_pull`.
    fn carries_payload_in_argv(&self) -> bool {
        true
    }

    /// What this adapter can do for the given native session, established rather than assumed.
    fn capabilities(&self, native_session: Option<&str>) -> Capabilities;

    /// Start a user-level turn carrying `text`. Never a system or developer role: a peer must not
    /// reach a role that outranks the operator.
    fn activate(&self, native_session: &str, text: &str) -> Result<Activation>;

    /// Unsupported providers never manufacture confirmation from an idle-looking screen.
    fn interrupt(&self, _native_session: &str) -> Result<Interruption> {
        Ok(Interruption::Unconfirmed)
    }
}

/// Resolve a provider name to its adapter.
///
/// An unknown provider is not an error — it is an agent with no control surface, whose messages
/// wait until something else starts a turn.
pub fn for_provider(provider: &str) -> Option<Box<dyn Adapter>> {
    match provider {
        CODEX => Some(Box::new(CodexAdapter::detect())),
        CLAUDE => Some(Box::new(ClaudeAdapter::detect())),
        OPENCODE => Some(Box::new(OpenCodeAdapter::detect())),
        HERMES => Some(Box::new(HermesAdapter::detect())),
        "fake" => Some(Box::new(FakeAdapter::from_env())),
        _ => None,
    }
}

/// Every provider with an adapter, for the conformance suite and for `vvagent list`.
pub const PROVIDERS: &[&str] = &[CODEX, CLAUDE, OPENCODE, HERMES, "fake"];

pub const CODEX: &str = "codex";
pub const CLAUDE: &str = "claude";
pub const OPENCODE: &str = "opencode";
pub const HERMES: &str = "hermes";

/// Tested floors, from `docs/agent-mesh-m0-results.md` §2. A build below one of these loses its
/// actuating capabilities rather than being driven on the assumption that nothing changed.
const CODEX_MIN: Version = Version(0, 151, 0);
const CLAUDE_MIN: Version = Version(2, 1, 259);
const OPENCODE_MIN: Version = Version(0, 1, 0);
const HERMES_MIN: Version = Version(0, 19, 1);

/// Read a provider's version by running it, or `None` when it is not installed.
fn detect_version(binary: &str, args: &[&str]) -> Option<String> {
    Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            let text = String::from_utf8_lossy(&output.stdout);
            let line = text.lines().next().unwrap_or_default().trim().to_owned();
            if line.is_empty() {
                String::from_utf8_lossy(&output.stderr).trim().to_owned()
            } else {
                line
            }
        })
        .filter(|version| !version.is_empty())
}

fn binary_for(env: &str, default: &str) -> String {
    std::env::var(env).unwrap_or_else(|_| default.into())
}

// ---------------------------------------------------------------------------------------------
// Version gating
// ---------------------------------------------------------------------------------------------

/// A provider version, as three numbers pulled out of whatever the binary prints.
///
/// Providers announce themselves differently — `codex-cli 0.151.0`, `2.1.259 (Claude Code)`,
/// `Hermes Agent v0.19.1 (2026.7.30)` — so the rule is simply "the first dotted number", which is
/// the version in all three and easy to be wrong about loudly rather than quietly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32, pub u32, pub u32);

impl Version {
    pub fn parse(reported: &str) -> Option<Self> {
        let bytes = reported.as_bytes();
        let mut at = 0;
        while at < bytes.len() {
            if !bytes[at].is_ascii_digit() {
                at += 1;
                continue;
            }
            let start = at;
            let mut parts: Vec<u32> = Vec::new();
            let mut current = 0u32;
            let mut digits = 0;
            while at < bytes.len() {
                match bytes[at] {
                    b'0'..=b'9' => {
                        current = current
                            .saturating_mul(10)
                            .saturating_add(u32::from(bytes[at] - b'0'));
                        digits += 1;
                        at += 1;
                    }
                    b'.' if digits > 0
                        && at + 1 < bytes.len()
                        && bytes[at + 1].is_ascii_digit() =>
                    {
                        parts.push(current);
                        current = 0;
                        digits = 0;
                        at += 1;
                    }
                    _ => break,
                }
            }
            if digits > 0 {
                parts.push(current);
            }
            if parts.len() >= 2 {
                return Some(Self(parts[0], parts[1], parts.get(2).copied().unwrap_or(0)));
            }
            // A bare integer is not a version; keep looking past it.
            at = at.max(start + 1);
        }
        None
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// Apply an adapter's tested-version floor.
///
/// A version below the floor, or one that cannot be read at all, withdraws every actuating
/// capability and says so. The alternative — assuming a capability carried forward to a build
/// nobody tested — is exactly what M0 was run to stop.
pub fn gate(capabilities: &mut Capabilities, provider: &str, min_tested: Version) {
    let Some(reported) = capabilities.version.as_deref() else {
        capabilities.withdraw_actuating(format!(
            "{provider} is not installed or did not report a version"
        ));
        return;
    };
    let Some(found) = Version::parse(reported) else {
        capabilities.withdraw_actuating(format!(
            "cannot read a version from `{}`; {provider} is tested from {min_tested}",
            truncate(reported, 60)
        ));
        return;
    };
    if found < min_tested {
        capabilities.withdraw_actuating(format!(
            "{provider} {found} is below the tested floor {min_tested}"
        ));
    }
}

// ---------------------------------------------------------------------------------------------
// Codex
// ---------------------------------------------------------------------------------------------

/// Codex CLI, driven through `codex queue`.
///
/// M0 found the richer path — the app-server's `turn/start`, `turn/interrupt` and `turn/steer` —
/// but the CLI labels `app-server` and `remote-control` experimental, while `codex queue` is not
/// so labelled and speaks to the same control socket. So the stable CLI is the integration point
/// and direct JSON-RPC stays an optimisation for later, which is also M0 risk 1.
pub struct CodexAdapter {
    binary: String,
    version: Option<String>,
}

impl CodexAdapter {
    pub fn detect() -> Self {
        let binary = std::env::var("AGENT_MESH_CODEX_BIN").unwrap_or_else(|_| "codex".into());
        let version = Command::new(&binary)
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
            .filter(|version| !version.is_empty());
        Self { binary, version }
    }
}

impl Adapter for CodexAdapter {
    fn capabilities(&self, native_session: Option<&str>) -> Capabilities {
        let mut capabilities = Capabilities {
            provider: Some(CODEX.into()),
            version: self.version.clone(),
            native_session: native_session.map(str::to_owned),
            // The mailbox tools are this binary's own MCP server, so they do not depend on the
            // provider build; `codex queue --thread` does.
            granted: vec![Capability::StructuredPull, Capability::ExternalTurnStart],
            notes: Vec::new(),
        };
        gate(&mut capabilities, CODEX, CODEX_MIN);
        if native_session.is_none() {
            capabilities.withdraw_actuating(
                "no Codex thread to queue into; give --native-session a thread id or name",
            );
        }
        capabilities.note("Codex interruption and final-answer capture require an exact request-to-turn binding; neither is established by the queue adapter");
        capabilities
    }

    fn activate(&self, native_session: &str, text: &str) -> Result<Activation> {
        let result = run_control(
            &self.binary,
            &["queue", "--thread", native_session, "--message", text],
        )?;
        Ok(match result {
            Activation::Started => Activation::Started,
            other => Activation::Unavailable(format!(
                "{}; set up the local Codex daemon explicitly with `codex app-server daemon bootstrap`, then verify the thread is loaded; the mesh never starts the daemon",
                other.detail().unwrap_or("Codex activation failed")
            )),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Claude Code
// ---------------------------------------------------------------------------------------------

/// Claude Code: mailbox tools, and deliberately nothing that starts a turn.
///
/// M0 found that an interactive session listens on an owner-only socket at
/// `$XDG_RUNTIME_DIR/cc-socks/<pid>.sock`, and that peer messaging exists behind it. It is recorded
/// as a *mechanism*, not an interface: no CLI subcommand messages a running session, and stale
/// sockets are left behind when a process dies. Building activation on an undocumented, pid-named
/// socket would be building on something free to change between patch releases, so this adapter
/// does not — and says why, rather than leaving the absence unexplained.
pub struct ClaudeAdapter {
    version: Option<String>,
}

impl ClaudeAdapter {
    pub fn detect() -> Self {
        Self {
            version: detect_version(
                &binary_for("AGENT_MESH_CLAUDE_BIN", "claude"),
                &["--version"],
            ),
        }
    }
}

impl Adapter for ClaudeAdapter {
    fn capabilities(&self, native_session: Option<&str>) -> Capabilities {
        let mut capabilities = Capabilities {
            provider: Some(CLAUDE.into()),
            version: self.version.clone(),
            native_session: native_session.map(str::to_owned),
            granted: vec![Capability::StructuredPull],
            notes: Vec::new(),
        };
        gate(&mut capabilities, CLAUDE, CLAUDE_MIN);
        capabilities.note(
            "no supported way to start a turn in a running Claude Code session; mail waits for \
             its next turn",
        );
        capabilities
    }

    fn activate(&self, _native_session: &str, _text: &str) -> Result<Activation> {
        // Not "not implemented yet" — refused. The delivery ladder never reaches here because the
        // capability is absent, and this is the second lock on that door.
        Ok(Activation::Unavailable(
            "Claude Code exposes no supported external turn-start".into(),
        ))
    }
}

// ---------------------------------------------------------------------------------------------
// OpenCode
// ---------------------------------------------------------------------------------------------

/// OpenCode, driven through the HTTP server `opencode serve` exposes.
///
/// M0 read `POST /session/{id}/prompt_async` and `/session/{id}/abort` out of the installed SDK's
/// typings but could not exercise them, because the CLI was not installed. So the capability is
/// granted only when a server actually answers: the adapter probes `GET /session` and withdraws
/// activation when nothing is listening. That keeps a documented-but-unverified surface from
/// becoming an assumed one.
pub struct OpenCodeAdapter {
    version: Option<String>,
    server: Option<String>,
}

impl OpenCodeAdapter {
    pub fn detect() -> Self {
        let server = std::env::var("OPENCODE_SERVER")
            .ok()
            .filter(|value| !value.is_empty());
        Self {
            version: detect_version(
                &binary_for("AGENT_MESH_OPENCODE_BIN", "opencode"),
                &["--version"],
            ),
            server,
        }
    }

    fn reachable(&self) -> bool {
        self.server.as_deref().is_some_and(|server| {
            http::get(server, "/session").is_ok_and(|status| (200..300).contains(&status))
        })
    }
}

impl Adapter for OpenCodeAdapter {
    fn interrupt(&self, native_session: &str) -> Result<Interruption> {
        if !self
            .capabilities(Some(native_session))
            .has(Capability::ExternalInterrupt)
            || native_session.is_empty()
            || !native_session
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Ok(Interruption::Unconfirmed);
        }
        let Some(server) = &self.server else {
            return Ok(Interruption::Unconfirmed);
        };
        Ok(
            if http::post_confirmed(server, &format!("/session/{native_session}/abort")) {
                Interruption::Confirmed
            } else {
                Interruption::Unconfirmed
            },
        )
    }
    fn carries_payload_in_argv(&self) -> bool {
        // The prompt travels as an HTTP request body.
        false
    }

    fn capabilities(&self, native_session: Option<&str>) -> Capabilities {
        let mut capabilities = Capabilities {
            provider: Some(OPENCODE.into()),
            version: self.version.clone(),
            native_session: native_session.map(str::to_owned),
            granted: vec![
                Capability::StructuredPull,
                Capability::ExternalTurnStart,
                Capability::ExternalInterrupt,
            ],
            notes: Vec::new(),
        };
        gate(&mut capabilities, OPENCODE, OPENCODE_MIN);
        if self.server.is_none() {
            capabilities.withdraw_actuating(
                "no OpenCode server; set OPENCODE_SERVER to a running `opencode serve` origin",
            );
        } else if native_session.is_none() {
            capabilities
                .withdraw_actuating("no OpenCode session id to prompt; give --native-session");
        } else if !self.reachable() {
            capabilities.withdraw_actuating(format!(
                "the OpenCode server at {} did not answer",
                self.server.as_deref().unwrap_or("?")
            ));
        }
        capabilities
    }

    fn activate(&self, native_session: &str, text: &str) -> Result<Activation> {
        let Some(server) = self.server.as_deref() else {
            return Ok(Activation::Unavailable("OPENCODE_SERVER is unset".into()));
        };
        let body = serde_json::json!({ "parts": [{ "type": "text", "text": text }] });
        match http::post_json(
            server,
            &format!("/session/{native_session}/prompt_async"),
            &body,
        ) {
            Ok(status) if (200..300).contains(&status) => Ok(Activation::Started),
            Ok(status) => Ok(Activation::Declined(format!("HTTP {status}"))),
            Err(err) => Ok(Activation::Unavailable(truncate(&err, 200))),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Hermes
// ---------------------------------------------------------------------------------------------

/// Hermes: mailbox tools only, for now.
///
/// `hermes serve` is a JSON-RPC/WebSocket gateway for the desktop app and `hermes acp` speaks Agent
/// Client Protocol, but whether either can start a turn in an *already-running interactive TUI* —
/// a different topology from the desktop backend — was not established in M0 and is not assumed
/// here. Its shell hooks are gated by a first-use consent allowlist, which the mesh respects rather
/// than works around.
pub struct HermesAdapter {
    version: Option<String>,
}

impl HermesAdapter {
    pub fn detect() -> Self {
        Self {
            version: detect_version(
                &binary_for("AGENT_MESH_HERMES_BIN", "hermes"),
                &["--version"],
            ),
        }
    }
}

impl Adapter for HermesAdapter {
    fn capabilities(&self, native_session: Option<&str>) -> Capabilities {
        let mut capabilities = Capabilities {
            provider: Some(HERMES.into()),
            version: self.version.clone(),
            native_session: native_session.map(str::to_owned),
            granted: vec![Capability::StructuredPull],
            notes: Vec::new(),
        };
        gate(&mut capabilities, HERMES, HERMES_MIN);
        capabilities.note(
            "starting a turn in a running Hermes TUI is unproven; its shell hooks are consent-gated \
             and the mesh does not bypass that",
        );
        capabilities
    }

    fn activate(&self, _native_session: &str, _text: &str) -> Result<Activation> {
        Ok(Activation::Unavailable(
            "Hermes external turn-start is not established".into(),
        ))
    }
}

// ---------------------------------------------------------------------------------------------
// Just enough HTTP for a loopback control API
// ---------------------------------------------------------------------------------------------

/// A minimal HTTP/1.1 client for talking to a local `opencode serve`.
///
/// Hand-rolled rather than pulling an HTTP stack into a binary agents run: the whole requirement is
/// one GET and one POST to loopback, with a deadline.
mod http {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(10);
    /// A control API's reply is a status line and a short body; anything larger is not read.
    const MAX_RESPONSE: usize = 64 * 1024;

    /// The `host:port` an origin names. Deliberately no I/O: deriving this used to open a
    /// connection that was then thrown away, so every request cost two.
    fn authority_of(origin: &str) -> Result<&str, String> {
        let rest = origin
            .strip_prefix("http://")
            .ok_or_else(|| format!("`{origin}` is not an http:// origin"))?;
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        let address = loopback_address(authority)?;
        if !address.ip().is_loopback() {
            return Err("OpenCode control must use loopback".into());
        }
        Ok(authority)
    }

    fn loopback_address(authority: &str) -> Result<std::net::SocketAddr, String> {
        let address = authority
            .strip_prefix("localhost:")
            .map(|port| format!("127.0.0.1:{port}"));
        address
            .as_deref()
            .unwrap_or(authority)
            .parse::<std::net::SocketAddr>()
            .map_err(|_| "OpenCode control requires a loopback host and port".into())
    }

    fn exchange(origin: &str, request: &str, body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        let authority = authority_of(origin)?;
        let mut stream = TcpStream::connect_timeout(&loopback_address(authority)?, TIMEOUT)
            .map_err(|err| err.to_string())?;
        stream.set_read_timeout(Some(TIMEOUT)).ok();
        stream.set_write_timeout(Some(TIMEOUT)).ok();
        // One buffer, not two: a header write followed by a body write can reach the peer as
        // separate reads, which is a needless thing to make the other side handle.
        let mut wire = Vec::with_capacity(request.len() + body.len());
        wire.extend_from_slice(request.as_bytes());
        wire.extend_from_slice(body);
        stream
            .write_all(&wire)
            .and_then(|()| stream.flush())
            .map_err(|err| err.to_string())?;

        let mut response = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    response.extend_from_slice(&chunk[..read]);
                    if response.len() > MAX_RESPONSE {
                        return Err("HTTP response exceeded its bound".into());
                    }
                }
                Err(err) => return Err(err.to_string()),
            }
        }
        let head = String::from_utf8_lossy(&response);
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| "no HTTP status line".to_owned())?;
        let split = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| "incomplete HTTP response".to_owned())?;
        // An abort acknowledgement must be an unambiguous, complete boolean. Unsupported
        // transfer encodings remain unconfirmed rather than guessing at their framing.
        if head[..split]
            .to_ascii_lowercase()
            .contains("transfer-encoding:")
        {
            return Err("unsupported HTTP transfer encoding".into());
        }
        let lengths = head[..split]
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then_some(value.trim())
            })
            .collect::<Vec<_>>();
        if lengths.len() > 1
            || lengths.first().is_some_and(|value| {
                value.parse::<usize>().ok() != Some(response.len() - split - 4)
            })
        {
            return Err("incomplete or ambiguous HTTP body".into());
        }
        Ok((status, response[split + 4..].to_vec()))
    }

    fn send(origin: &str, request: &str, body: &[u8]) -> Result<u16, String> {
        exchange(origin, request, body).map(|(status, _)| status)
    }

    pub fn post_confirmed(origin: &str, path: &str) -> bool {
        let Ok(authority) = authority_of(origin) else {
            return false;
        };
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
        exchange(origin, &request, b"").is_ok_and(|(status, body)| {
            (200..300).contains(&status)
                && matches!(serde_json::from_slice::<bool>(&body), Ok(true))
        })
    }

    pub fn get(origin: &str, path: &str) -> Result<u16, String> {
        let authority = authority_of(origin)?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
        );
        send(origin, &request, b"")
    }

    pub fn post_json(origin: &str, path: &str, body: &serde_json::Value) -> Result<u16, String> {
        let authority = authority_of(origin)?;
        let payload = body.to_string();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            payload.len()
        );
        send(origin, &request, payload.as_bytes())
    }
}

// ---------------------------------------------------------------------------------------------
// A test double
// ---------------------------------------------------------------------------------------------

/// A provider stand-in driven entirely by the environment, so the watcher and the delivery ladder
/// can be tested without installing four agents.
///
/// `AGENT_MESH_FAKE_ACTIVATE` names a program run with the activation text on stdin. Its exit
/// status decides the outcome, which is exactly the contract a real adapter has.
pub struct FakeAdapter {
    program: Option<String>,
    capabilities: Vec<Capability>,
}

impl FakeAdapter {
    pub fn from_env() -> Self {
        let capabilities = std::env::var("AGENT_MESH_FAKE_CAPABILITIES")
            .unwrap_or_else(|_| "structured_pull,external_turn_start".into())
            .split(',')
            .filter(|name| !name.trim().is_empty())
            .filter_map(|name| Capability::parse(name.trim()).ok())
            .collect();
        Self {
            program: std::env::var("AGENT_MESH_FAKE_ACTIVATE").ok(),
            capabilities,
        }
    }
}

impl Adapter for FakeAdapter {
    fn capabilities(&self, native_session: Option<&str>) -> Capabilities {
        let mut capabilities = Capabilities {
            provider: Some("fake".into()),
            version: Some("9.9.9".into()),
            native_session: native_session.map(str::to_owned),
            granted: self.capabilities.clone(),
            notes: Vec::new(),
        };
        if native_session.is_none() {
            // Same rule as every real adapter: with no session there is nothing to start a turn
            // in. A double that could claim otherwise would let a test pass against a state the
            // world cannot produce.
            capabilities.withdraw_actuating("the fake provider was given no session");
        }
        capabilities
    }

    fn activate(&self, native_session: &str, text: &str) -> Result<Activation> {
        let Some(program) = &self.program else {
            return Ok(Activation::Unavailable(
                "AGENT_MESH_FAKE_ACTIVATE is unset".into(),
            ));
        };
        #[cfg(windows)]
        if program.ends_with(".ps1") {
            return run_control(
                "powershell.exe",
                &["-NoProfile", "-File", program, native_session, text],
            );
        }
        run_control(program, &[native_session, text])
    }
}

// ---------------------------------------------------------------------------------------------

/// Run a provider control command with a bounded deadline.
///
/// The activation text goes in argv here because that is the interface `codex queue` offers. It is
/// a bounded, labelled pointer in the mode M2 uses (`activate_and_pull`), never a credential and
/// never the message body — see `Capabilities::delivery_mode`.
fn run_control(program: &str, args: &[&str]) -> Result<Activation> {
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => return Ok(Activation::Unavailable(format!("{program}: {err}"))),
    };

    let deadline = std::time::Instant::now() + CONTROL_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|err| MeshError::new(ErrorCode::Io, format!("{program}: {err}")))?;
                return Ok(if status.success() {
                    Activation::Started
                } else {
                    let detail = String::from_utf8_lossy(&output.stderr)
                        .lines()
                        .next()
                        .unwrap_or("no detail")
                        .trim()
                        .to_owned();
                    Activation::Declined(truncate(&detail, 200))
                });
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(Activation::Unavailable(format!(
                        "{program} did not answer within {}s",
                        CONTROL_TIMEOUT.as_secs()
                    )));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Ok(Activation::Unavailable(format!("{program}: {err}"))),
        }
    }
}

fn truncate(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let mut end = limit;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    use agent_mesh_core::DeliveryMode;

    use agent_mesh_core::ACTUATING;

    #[test]
    fn versions_are_read_out_of_whatever_each_provider_prints() {
        // The three real shapes, from `docs/agent-mesh-m0-results.md` §2.
        assert_eq!(
            Version::parse("codex-cli 0.151.0"),
            Some(Version(0, 151, 0))
        );
        assert_eq!(
            Version::parse("2.1.259 (Claude Code)"),
            Some(Version(2, 1, 259))
        );
        assert_eq!(
            Version::parse("Hermes Agent v0.19.1 (2026.7.30)"),
            Some(Version(0, 19, 1)),
            "the first dotted number wins, not a later date"
        );
        assert_eq!(Version::parse("1.2"), Some(Version(1, 2, 0)));
        // Nothing version-shaped: better to report none than to invent one.
        assert_eq!(Version::parse(""), None);
        assert_eq!(Version::parse("nightly"), None);
        assert_eq!(
            Version::parse("build 4471"),
            None,
            "a bare integer is not a version"
        );
    }

    #[test]
    fn a_version_below_the_tested_floor_withdraws_actuating_capabilities() {
        let mut capabilities = Capabilities {
            provider: Some(CODEX.into()),
            version: Some("codex-cli 0.9.0".into()),
            native_session: Some("t1".into()),
            granted: vec![Capability::StructuredPull, Capability::ExternalTurnStart],
            notes: Vec::new(),
        };
        gate(&mut capabilities, CODEX, CODEX_MIN);

        assert!(!capabilities.has(Capability::ExternalTurnStart));
        assert!(
            capabilities.has(Capability::StructuredPull),
            "the mailbox tools are ours, not the provider's, so a stale build cannot misuse them"
        );
        let note = capabilities.notes.join(" ");
        assert!(
            note.contains("0.9.0"),
            "the diagnostic names what was found: {note}"
        );
        assert!(note.contains("0.151.0"), "and what was required: {note}");
        assert!(
            note.contains("external_turn_start"),
            "and what it cost: {note}"
        );
    }

    #[test]
    fn an_unreadable_version_is_treated_as_untested() {
        let mut capabilities = Capabilities {
            provider: Some(CODEX.into()),
            version: Some("nightly build from a branch".into()),
            native_session: Some("t1".into()),
            granted: vec![Capability::ExternalTurnStart],
            notes: Vec::new(),
        };
        gate(&mut capabilities, CODEX, CODEX_MIN);
        assert!(!capabilities.has(Capability::ExternalTurnStart));
        assert!(
            capabilities
                .notes
                .join(" ")
                .contains("cannot read a version")
        );
    }

    #[test]
    fn a_version_at_or_above_the_floor_keeps_its_capabilities() {
        for reported in ["codex-cli 0.151.0", "codex-cli 0.152.3", "codex-cli 1.0.0"] {
            let mut capabilities = Capabilities {
                provider: Some(CODEX.into()),
                version: Some(reported.into()),
                native_session: Some("t1".into()),
                granted: vec![Capability::ExternalTurnStart],
                notes: Vec::new(),
            };
            gate(&mut capabilities, CODEX, CODEX_MIN);
            assert!(
                capabilities.has(Capability::ExternalTurnStart),
                "{reported} should pass the floor"
            );
        }
    }

    #[test]
    fn withdrawal_only_ever_removes() {
        // Negotiation may remove a capability and never invents one.
        let mut capabilities = Capabilities {
            granted: vec![Capability::StructuredPull],
            ..Capabilities::default()
        };
        capabilities.withdraw_actuating("nothing to withdraw");
        assert_eq!(capabilities.granted, vec![Capability::StructuredPull]);
        assert_eq!(capabilities.notes.len(), 1, "the reason is still recorded");
        for capability in ACTUATING {
            assert!(!capabilities.has(capability));
        }
    }

    #[test]
    fn claude_refuses_turn_start_rather_than_using_an_undocumented_socket() {
        let adapter = ClaudeAdapter {
            version: Some("2.1.259 (Claude Code)".into()),
        };
        let capabilities = adapter.capabilities(Some("some-session"));
        assert!(capabilities.has(Capability::StructuredPull));
        assert!(!capabilities.has(Capability::ExternalTurnStart));
        assert!(capabilities.notes.join(" ").contains("no supported way"));
        // And the door is locked twice: even called directly, it declines.
        assert!(matches!(
            adapter.activate("s", "t").unwrap(),
            Activation::Unavailable(_)
        ));
    }

    #[test]
    fn hermes_refuses_turn_start_and_respects_its_consent_gate() {
        let adapter = HermesAdapter {
            version: Some("Hermes Agent v0.19.1 (2026.7.30)".into()),
        };
        let capabilities = adapter.capabilities(Some("session"));
        assert!(!capabilities.has(Capability::ExternalTurnStart));
        assert!(capabilities.notes.join(" ").contains("consent-gated"));
    }

    #[test]
    fn opencode_needs_a_server_that_actually_answers() {
        // Without an origin there is nothing to talk to.
        let adapter = OpenCodeAdapter {
            version: Some("0.5.0".into()),
            server: None,
        };
        let capabilities = adapter.capabilities(Some("session-1"));
        assert!(!capabilities.has(Capability::ExternalTurnStart));
        assert!(capabilities.notes.join(" ").contains("OPENCODE_SERVER"));

        // With an origin nothing is listening on, the capability is still withheld — M0 read this
        // surface out of typings and could not exercise it, so it is proved per machine, not
        // assumed from documentation.
        let adapter = OpenCodeAdapter {
            version: Some("0.5.0".into()),
            server: Some("http://127.0.0.1:1".into()),
        };
        let capabilities = adapter.capabilities(Some("session-1"));
        assert!(!capabilities.has(Capability::ExternalTurnStart));
        assert!(capabilities.notes.join(" ").contains("did not answer"));
    }

    #[test]
    fn opencode_activates_against_a_server_that_does_answer() {
        // A stub `opencode serve`: enough HTTP to prove the adapter speaks it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorder = std::sync::Arc::clone(&received);

        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                // Read until the whole request has arrived. A single `read` is not guaranteed to
                // return the body, which made this test pass alone and fail under load.
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                while let Ok(read) = stream.read(&mut chunk) {
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&request);
                    let Some(head_end) = text.find("\r\n\r\n") else {
                        continue;
                    };
                    let declared = text
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("Content-Length: ")?
                                .trim()
                                .parse::<usize>()
                                .ok()
                        })
                        .unwrap_or(0);
                    if request.len() >= head_end + 4 + declared {
                        break;
                    }
                }
                recorder
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request).into_owned());
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
            }
        });

        let adapter = OpenCodeAdapter {
            version: Some("0.5.0".into()),
            server: Some(origin),
        };
        let capabilities = adapter.capabilities(Some("session-1"));
        assert!(
            capabilities.has(Capability::ExternalTurnStart),
            "a reachable server earns the capability: {:?}",
            capabilities.notes
        );
        assert_eq!(capabilities.delivery_mode(), DeliveryMode::ActivateAndPull);

        assert_eq!(
            adapter
                .activate("session-1", "[agent-mesh] pointer")
                .unwrap(),
            Activation::Started
        );
        server.join().unwrap();

        let requests = received.lock().unwrap();
        assert!(
            requests[0].starts_with("GET /session "),
            "the probe: {:?}",
            requests[0]
        );
        let post = &requests[1];
        assert!(
            post.starts_with("POST /session/session-1/prompt_async "),
            "{post}"
        );
        assert!(
            post.contains("[agent-mesh] pointer"),
            "the pointer is the body: {post}"
        );
    }

    #[test]
    fn an_unknown_provider_has_no_control_surface() {
        assert!(for_provider("hermes-2029").is_none());
    }

    #[test]
    fn opencode_cancellation_requires_a_positive_provider_acknowledgement() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        for (status, body, expected) in [
            (200, "true", true),
            (200, "false", false),
            (500, "true", false),
            (204, "", false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut chunk = [0; 512];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let count = socket.read(&mut chunk).unwrap();
                    assert_ne!(count, 0);
                    request.extend_from_slice(&chunk[..count]);
                }
                assert!(request.starts_with(b"POST /session/test/abort HTTP/1.1\r\n"));
                write!(socket, "HTTP/1.1 {status} result\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            });
            assert_eq!(
                http::post_confirmed(&origin, "/session/test/abort"),
                expected
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn codex_without_a_thread_cannot_be_woken() {
        // There is nothing to queue into, so the capability is absent rather than merely unused.
        let adapter = CodexAdapter {
            binary: "codex".into(),
            version: Some("codex-cli 0.151.0".into()),
        };
        let capabilities = adapter.capabilities(None);
        assert!(!capabilities.has(Capability::ExternalTurnStart));
        assert_eq!(capabilities.delivery_mode(), DeliveryMode::PullOnly);
    }

    #[test]
    fn codex_with_a_thread_activates_then_pulls() {
        let adapter = CodexAdapter {
            binary: "codex".into(),
            version: Some("codex-cli 0.151.0".into()),
        };
        let capabilities = adapter.capabilities(Some("thread-1"));
        assert!(capabilities.has(Capability::ExternalTurnStart));
        assert_eq!(capabilities.delivery_mode(), DeliveryMode::ActivateAndPull);
    }

    #[test]
    fn an_uninstalled_codex_loses_the_capability_rather_than_assuming_it() {
        let adapter = CodexAdapter {
            binary: "codex".into(),
            version: None,
        };
        assert!(
            !adapter
                .capabilities(Some("t1"))
                .has(Capability::ExternalTurnStart)
        );
    }

    #[test]
    fn a_missing_control_program_is_unavailable_not_a_crash() {
        let outcome = run_control("definitely-not-a-real-program-9f3a", &["x"]).unwrap();
        assert!(matches!(outcome, Activation::Unavailable(_)), "{outcome:?}");
    }

    #[test]
    fn a_failing_control_program_declines_with_bounded_detail() {
        #[cfg(unix)]
        let outcome = run_control("sh", &["-c", "echo 'no such thread' >&2; exit 1"]).unwrap();
        #[cfg(windows)]
        let outcome = run_control(
            "cmd.exe",
            &["/D", "/C", "echo no such thread >&2 & exit /b 1"],
        )
        .unwrap();
        match outcome {
            Activation::Declined(detail) => assert!(detail.contains("no such thread")),
            other => panic!("expected a decline, got {other:?}"),
        }
    }

    #[test]
    fn a_successful_control_program_starts_a_turn() {
        #[cfg(unix)]
        assert_eq!(run_control("true", &[]).unwrap(), Activation::Started);
        #[cfg(windows)]
        assert_eq!(
            run_control("cmd.exe", &["/D", "/C", "exit /b 0"]).unwrap(),
            Activation::Started
        );
    }

    #[test]
    fn detail_truncation_respects_char_boundaries() {
        let wide = "é".repeat(300);
        let cut = truncate(&wide, 201);
        assert!(cut.len() <= 204);
        assert!(cut.ends_with('…'));
    }
}
