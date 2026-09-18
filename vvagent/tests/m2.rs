//! The M2 exit criterion, end to end.
//!
//! > An agent in one session requests work from an agent in another, receives a correlated reply,
//! > and **no request or response payload appears in either PTY transcript**, with no `agent-read`
//! > call made.
//!
//! Two sessions are modelled as two `vvmux` runtime instances, which is exactly what
//! `runtime_instance_id` means — the mesh neither knows nor cares whether a session is real. The
//! "PTY transcript" is captured literally: the fake provider adapter appends everything that
//! reaches its input channel to a file, and the test asserts the payload is not in it. That is a
//! stronger check than reading a terminal would be, because it sees *everything* the activation
//! channel carried, not just what happened to be painted.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_vvagent");
/// Appears in the request. If it ever reaches the provider's input channel, M2 has failed.
const REQUEST_SECRET: &str = "REQUEST-PAYLOAD-4f21c8-do-not-leak";
/// Appears in the response, for the same reason.
const RESPONSE_SECRET: &str = "RESPONSE-PAYLOAD-9b73de-do-not-leak";

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "vvagent-m2-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        Self(base)
    }

    fn db(&self) -> PathBuf {
        self.0.join("state").join("mesh.sqlite")
    }

    fn transcript(&self) -> PathBuf {
        self.0.join("provider-input.log")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct Identity {
    endpoint_id: String,
    token_file: String,
}

fn command(db: &Path, identity: Option<&Identity>) -> Command {
    let mut command = Command::new(BIN);
    command.arg("--db").arg(db);
    command.env_remove("AGENT_MESH_ENDPOINT");
    command.env_remove("AGENT_MESH_TOKEN_FILE");
    if let Some(identity) = identity {
        command
            .env("AGENT_MESH_ENDPOINT", &identity.endpoint_id)
            .env("AGENT_MESH_TOKEN_FILE", &identity.token_file);
    }
    command
}

fn run(db: &Path, identity: Option<&Identity>, args: &[&str]) -> (i32, Value, String) {
    let output = command(db, identity)
        .args(args)
        .output()
        .expect("vvagent runs");
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let json = serde_json::from_str(&stdout)
        .or_else(|_| serde_json::from_str::<Value>(&stderr))
        .unwrap_or(Value::Null);
    (output.status.code().unwrap_or(-1), json, stderr)
}

fn ok(db: &Path, identity: Option<&Identity>, args: &[&str]) -> Value {
    let (code, json, stderr) = run(db, identity, args);
    assert_eq!(code, 0, "`vvagent {}` failed: {stderr}", args.join(" "));
    json
}

fn text(value: &Value, key: &str) -> String {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("expected a string at `{key}` in {value}"))
        .to_owned()
}

fn bind(db: &Path, alias: &str, instance: &str, provider: &str) -> Identity {
    let bound = ok(
        db,
        None,
        &[
            "bind",
            "--alias",
            alias,
            "--runtime",
            "vvmux",
            "--instance",
            instance,
            "--provider",
            provider,
        ],
    );
    Identity {
        endpoint_id: text(&bound, "endpoint_id"),
        token_file: text(&bound, "token_file"),
    }
}

/// A stand-in for a provider's control API. It records everything handed to it, which is what the
/// exit criterion is asserted against.
fn recording_provider(scratch: &Scratch) -> PathBuf {
    #[cfg(windows)]
    {
        let path = scratch.0.join("fake-activate.ps1");
        std::fs::write(&path, "Add-Content -LiteralPath $env:AGENT_MESH_TRANSCRIPT -Value ($args -join [Environment]::NewLine)\n").unwrap();
        path
    }
    #[cfg(unix)]
    {
        let path = scratch.0.join("fake-activate.sh");
        std::fs::write(
            &path,
            "#!/bin/sh\n\
         # $1 is the native session, $2 the activation text. Record both, verbatim.\n\
         printf 'session=%s\\ntext=%s\\n---\\n' \"$1\" \"$2\" >> \"$AGENT_MESH_TRANSCRIPT\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }
}

/// One pass of the watcher for a runtime instance, with a fake provider wired in.
fn watch_once(scratch: &Scratch, instance: &str, capabilities: &str) -> Value {
    let output = command(&scratch.db(), None)
        .args([
            "watch",
            "--runtime",
            "vvmux",
            "--instance",
            instance,
            "--once",
            "--backoff",
            "0ms",
        ])
        .env("AGENT_MESH_FAKE_ACTIVATE", recording_provider(scratch))
        .env("AGENT_MESH_FAKE_CAPABILITIES", capabilities)
        .env("AGENT_MESH_TRANSCRIPT", scratch.transcript())
        .output()
        .expect("watch runs");
    assert!(
        output.status.success(),
        "watch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap_or(Value::Null)
}

fn provider_transcript(scratch: &Scratch) -> String {
    std::fs::read_to_string(scratch.transcript()).unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// An MCP client, so the agent side of the loop goes through the real tool surface
// ---------------------------------------------------------------------------------------------

struct McpSession {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
    next_id: i64,
}

impl McpSession {
    fn start(db: &Path, identity: &Identity) -> Self {
        let mut child = command(db, Some(identity))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("mcp server starts");
        let reader = BufReader::new(child.stdout.take().unwrap());
        let mut session = Self {
            child,
            reader,
            next_id: 1,
        };
        let hello = session.request("initialize", json!({}));
        assert_eq!(hello["result"]["serverInfo"]["name"], "agent-mesh");
        session
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();

        let mut response = String::new();
        self.reader.read_line(&mut response).expect("a reply");
        let value: Value = serde_json::from_str(response.trim())
            .unwrap_or_else(|err| panic!("bad MCP reply {response:?}: {err}"));
        assert_eq!(value["id"], id, "replies are correlated to requests");
        value
    }

    /// Call a tool and return its structured content, asserting it did not error.
    fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let value = self.request("tools/call", json!({"name": name, "arguments": arguments}));
        let result = &value["result"];
        assert_eq!(
            result["isError"], false,
            "tool `{name}` failed: {}",
            result["structuredContent"]
        );
        result["structuredContent"].clone()
    }

    fn tool_error(&mut self, name: &str, arguments: Value) -> Value {
        let value = self.request("tools/call", json!({"name": name, "arguments": arguments}));
        let result = &value["result"];
        assert_eq!(result["isError"], true, "expected `{name}` to fail");
        result["structuredContent"]["error"].clone()
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------------------------
// The exit criterion
// ---------------------------------------------------------------------------------------------

#[test]
fn cross_session_request_and_reply_never_put_a_payload_on_the_provider_channel() {
    let scratch = Scratch::new("slice");
    let db = scratch.db();

    // Two sessions. Alice is in one, Bob in the other — different runtime instances, so they are
    // not teammates and every hop is a real cross-session hop.
    let alice = bind(&db, "alice", "session-a", "fake");
    let bob = bind(&db, "bob", "session-b", "fake");

    // Bob's provider is established to have both mailbox tools and a way to start a turn.
    let capabilities = ok(
        &db,
        Some(&bob),
        &["capabilities", "--native-session", "thread-bob"],
    );
    assert_eq!(
        capabilities["delivery_mode"], "activate_and_pull",
        "tools plus turn-start is the mode that keeps payloads off the wake-up channel"
    );

    // Bob will accept from anyone for this test; the point here is delivery, not policy.
    ok(
        &db,
        Some(&bob),
        &[
            "policy",
            "set",
            "--enqueue",
            "anyone",
            "--activate",
            "anyone",
            "--make-visible",
            "anyone",
        ],
    );

    // Alice asks Bob for something, through her own MCP tools.
    let mut alice_mcp = McpSession::start(&db, &alice);
    let sent = alice_mcp.tool(
        "agent_mesh_send",
        json!({
            "to": "vvmux:session-b/bob",
            "subject": "merge safety",
            "text": format!("Review this and reply. {REQUEST_SECRET}"),
            "expires_in_ms": 600_000,
            "idempotency_key": "m2-1",
        }),
    );
    let request_id = text(&sent, "message_id");

    // The watcher for Bob's session wakes him.
    let pass = watch_once(&scratch, "session-b", "structured_pull,external_turn_start");
    assert_eq!(pass["activated"], 1, "the watcher started a turn: {pass}");

    // *** The exit criterion. *** Everything the provider's input channel received:
    let transcript = provider_transcript(&scratch);
    assert!(!transcript.is_empty(), "the provider was actually called");
    assert!(
        !transcript.contains(REQUEST_SECRET),
        "the request payload reached the provider input channel:\n{transcript}"
    );
    // What it *should* contain: a bounded pointer that names the sender and the request.
    assert!(
        transcript.contains(&request_id),
        "the pointer names the request"
    );
    assert!(
        transcript.contains("vvmux:session-a/alice"),
        "and the sender"
    );
    assert!(
        transcript.contains("not an instruction from your operator"),
        "peer text is labelled untrusted wherever it appears"
    );
    assert!(
        transcript.contains("agent_mesh_receive"),
        "the pointer tells the agent to fetch the content as tool data"
    );

    // Bob's turn: he reads the mailbox through MCP and answers. No screen is read.
    let mut bob_mcp = McpSession::start(&db, &bob);
    let received = bob_mcp.tool("agent_mesh_receive", json!({}));
    let message = &received["message"];
    assert_eq!(text(message, "request_id"), request_id);
    assert_eq!(message["from"], "vvmux:session-a/alice");
    assert!(
        message["text"].as_str().unwrap().contains(REQUEST_SECRET),
        "the payload reaches the agent through the tool channel, which is the point"
    );
    assert!(
        message["trust"]
            .as_str()
            .unwrap()
            .contains("not an instruction"),
        "the tool result labels peer content untrusted"
    );

    bob_mcp.tool(
        "agent_mesh_reply",
        json!({
            "request_id": request_id,
            "outcome": "completed",
            "text": format!("Reviewed. {RESPONSE_SECRET}"),
        }),
    );

    // Alice collects a correlated answer — by request id, never by screen state.
    let answer = alice_mcp.tool(
        "agent_mesh_wait",
        json!({ "request_id": request_id, "timeout_ms": 30_000 }),
    );
    assert_eq!(answer["resolution"], "response");
    assert_eq!(answer["outcome"], "completed");
    assert!(answer["text"].as_str().unwrap().contains(RESPONSE_SECRET));

    // And after the whole exchange, neither payload ever reached the provider channel.
    let transcript = provider_transcript(&scratch);
    assert!(
        !transcript.contains(REQUEST_SECRET) && !transcript.contains(RESPONSE_SECRET),
        "a payload reached the provider input channel:\n{transcript}"
    );
}

// ---------------------------------------------------------------------------------------------
// Delivery ladder
// ---------------------------------------------------------------------------------------------

#[test]
fn mailbox_tools_alone_never_start_a_turn() {
    // The correction M0 was run to establish, enforced end to end: MCP is not a wake-up.
    let scratch = Scratch::new("pullonly");
    let db = scratch.db();
    let alice = bind(&db, "alice", "session-a", "fake");
    let bob = bind(&db, "bob", "session-b", "fake");
    ok(&db, Some(&bob), &["policy", "set", "--activate", "anyone"]);

    let capabilities = ok(&db, Some(&bob), &["capabilities"]);
    // No native session was given, so there is nothing to start a turn in.
    assert_eq!(capabilities["delivery_mode"], "pull_only");

    ok(
        &db,
        Some(&alice),
        &["send", "--to", "vvmux:session-b/bob", "--text", "wake up"],
    );
    let pass = watch_once(&scratch, "session-b", "structured_pull");
    assert_eq!(pass["considered"], 0, "nothing woke-able was considered");
    assert_eq!(pass["activated"], 0);
    assert!(
        provider_transcript(&scratch).is_empty(),
        "no provider call is made when nothing can be woken"
    );
}

#[test]
fn the_activate_gate_is_separate_from_enqueue() {
    let scratch = Scratch::new("gates");
    let db = scratch.db();
    let alice = bind(&db, "alice", "session-a", "fake");
    let bob = bind(&db, "bob", "session-b", "fake");
    ok(
        &db,
        Some(&bob),
        &["capabilities", "--native-session", "thread-bob"],
    );

    // Bob will hold anyone's mail, but only spend a turn on replies and teammates. Alice is in
    // another session, so her unsolicited request is queued but does not wake him.
    ok(
        &db,
        Some(&bob),
        &[
            "policy",
            "set",
            "--enqueue",
            "anyone",
            "--activate",
            "replies_and_team",
        ],
    );

    let sent = ok(
        &db,
        Some(&alice),
        &[
            "send",
            "--to",
            "vvmux:session-b/bob",
            "--text",
            "unsolicited",
        ],
    );
    assert_eq!(sent["state"], "queued", "accepting is not activating");

    let pass = watch_once(&scratch, "session-b", "structured_pull,external_turn_start");
    assert_eq!(pass["refused"], 1, "the activate gate refused: {pass}");
    assert_eq!(pass["activated"], 0);
    assert!(
        provider_transcript(&scratch).is_empty(),
        "no turn was spent"
    );

    // The refusal is auditable, with the rule that decided it.
    let explained = ok(&db, None, &["explain", &text(&sent, "message_id")]);
    let audit = explained["audit"].as_array().unwrap();
    let activation = audit
        .iter()
        .find(|row| row["operation"] == "activate")
        .expect("the attempt is recorded even though it was refused");
    assert_eq!(activation["result"], "policy_refused");
    assert_eq!(activation["rule"], "not_admitted");
}

#[test]
fn a_message_wakes_its_recipient_a_bounded_number_of_times() {
    // A peer must not be able to spend a target's tokens indefinitely by sending one message.
    let scratch = Scratch::new("backoff");
    let db = scratch.db();
    let alice = bind(&db, "alice", "session-a", "fake");
    let bob = bind(&db, "bob", "session-b", "fake");
    ok(
        &db,
        Some(&bob),
        &["capabilities", "--native-session", "thread-bob"],
    );
    ok(
        &db,
        Some(&bob),
        &[
            "policy",
            "set",
            "--enqueue",
            "anyone",
            "--activate",
            "anyone",
            "--make-visible",
            "anyone",
        ],
    );
    ok(
        &db,
        Some(&alice),
        &["send", "--to", "vvmux:session-b/bob", "--text", "ignored"],
    );

    // Bob never picks it up. The watcher tries, backs off, and eventually leaves it alone.
    let mut activations = 0;
    for _ in 0..6 {
        let pass = watch_once(&scratch, "session-b", "structured_pull,external_turn_start");
        activations += pass["activated"].as_u64().unwrap_or(0);
    }
    assert_eq!(activations, 3, "capped at max_attempts, not once per poll");
}

#[test]
fn an_unreachable_provider_leaves_the_message_queued() {
    let scratch = Scratch::new("unavailable");
    let db = scratch.db();
    let alice = bind(&db, "alice", "session-a", "fake");
    let bob = bind(&db, "bob", "session-b", "fake");
    ok(
        &db,
        Some(&bob),
        &["capabilities", "--native-session", "thread-bob"],
    );
    ok(
        &db,
        Some(&bob),
        &[
            "policy",
            "set",
            "--enqueue",
            "anyone",
            "--activate",
            "anyone",
            "--make-visible",
            "anyone",
        ],
    );
    let sent = ok(
        &db,
        Some(&alice),
        &["send", "--to", "vvmux:session-b/bob", "--text", "hello"],
    );

    // No AGENT_MESH_FAKE_ACTIVATE is set for this pass, so the control call cannot be made.
    let output = command(&db, None)
        .args([
            "watch",
            "--runtime",
            "vvmux",
            "--instance",
            "session-b",
            "--once",
            "--backoff",
            "0ms",
        ])
        .env(
            "AGENT_MESH_FAKE_CAPABILITIES",
            "structured_pull,external_turn_start",
        )
        .env_remove("AGENT_MESH_FAKE_ACTIVATE")
        .output()
        .unwrap();
    let pass: Value = serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();
    assert_eq!(pass["unavailable"], 1);
    assert_eq!(pass["activated"], 0);

    // The message is untouched and still deliverable — a failed wake-up loses nothing.
    let explained = ok(&db, None, &["explain", &text(&sent, "message_id")]);
    assert_eq!(explained["state"], "queued");
}

// ---------------------------------------------------------------------------------------------
// The MCP surface itself
// ---------------------------------------------------------------------------------------------

#[test]
fn the_mcp_server_advertises_exactly_the_six_mailbox_tools() {
    let scratch = Scratch::new("tools");
    let db = scratch.db();
    let alice = bind(&db, "alice", "session-a", "fake");
    let mut mcp = McpSession::start(&db, &alice);

    let listed = mcp.request("tools/list", json!({}));
    let mut names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            "agent_mesh_identity",
            "agent_mesh_list",
            "agent_mesh_receive",
            "agent_mesh_reply",
            "agent_mesh_send",
            "agent_mesh_wait",
        ]
    );

    // Every tool declares a closed schema, so a model cannot smuggle an unmodelled field through.
    for tool in listed["result"]["tools"].as_array().unwrap() {
        assert_eq!(
            tool["inputSchema"]["additionalProperties"], false,
            "tool {} accepts unmodelled arguments",
            tool["name"]
        );
    }
}

#[test]
fn a_failed_tool_returns_a_typed_error_not_a_broken_turn() {
    let scratch = Scratch::new("errors");
    let db = scratch.db();
    let alice = bind(&db, "alice", "session-a", "fake");
    // Both in sessions other than Alice's, so caller-scoped resolution cannot settle it and the
    // host-wide case is the one under test.
    bind(&db, "reviewer", "session-b", "fake");
    bind(&db, "reviewer", "session-c", "fake");
    let mut mcp = McpSession::start(&db, &alice);

    // Unknown recipient: the model sees the code, not an apology.
    let err = mcp.tool_error("agent_mesh_send", json!({"to": "nobody", "text": "hi"}));
    assert_eq!(err["code"], "agent_not_found");

    // Ambiguous alias across two sessions: the model is told what to retype.
    let err = mcp.tool_error("agent_mesh_send", json!({"to": "reviewer", "text": "hi"}));
    assert_eq!(err["code"], "agent_ambiguous");
    let candidates = err["candidates"].as_array().unwrap();
    assert!(candidates.iter().any(|c| c == "vvmux:session-b/reviewer"));

    // A protocol-level unknown method is still a protocol error.
    let response = mcp.request("no/such/method", json!({}));
    assert_eq!(response["error"]["code"], -32601);
}

#[test]
fn an_empty_mailbox_is_a_null_message_not_an_error() {
    let scratch = Scratch::new("empty");
    let db = scratch.db();
    let alice = bind(&db, "alice", "session-a", "fake");
    let mut mcp = McpSession::start(&db, &alice);

    let received = mcp.tool("agent_mesh_receive", json!({}));
    assert!(
        received["message"].is_null(),
        "nothing waiting is not a failure"
    );

    let identity = mcp.tool("agent_mesh_identity", json!({}));
    assert_eq!(identity["selector"], "vvmux:session-a/alice");
    assert_eq!(identity["principal"], "agent");
}

#[test]
fn agent_mesh_list_does_not_include_the_caller() {
    let scratch = Scratch::new("list");
    let db = scratch.db();
    let alice = bind(&db, "alice", "session-a", "fake");
    bind(&db, "bob", "session-b", "fake");
    let mut mcp = McpSession::start(&db, &alice);

    let listed = mcp.tool("agent_mesh_list", json!({}));
    let agents = listed["agents"].as_array().unwrap();
    let selectors: Vec<&str> = agents
        .iter()
        .map(|a| a["selector"].as_str().unwrap())
        .collect();
    assert!(selectors.contains(&"vvmux:session-b/bob"));
    assert!(
        !selectors.contains(&"vvmux:session-a/alice"),
        "an agent is not its own peer"
    );
}
