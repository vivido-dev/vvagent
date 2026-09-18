//! Inter-host milestone IH3, end to end through real processes.
//!
//! Two stores stand for two hosts. The carrier is exactly what `vvssh` will run, minus SSH:
//! `vvagent bridge --dial buildbox -- vvagent bridge --serve`, the dialler's child speaking over
//! its stdio. What the M2 exit criterion established within one host must hold across the hop: a
//! correlated request and reply, and no payload on the recipient's provider channel.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_vvagent");
const REQUEST_SECRET: &str = "IH3-REQUEST-PAYLOAD-7d1e-do-not-leak";
const RESPONSE_SECRET: &str = "IH3-RESPONSE-PAYLOAD-a40c-do-not-leak";

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "vvagent-ih3-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        Self(base)
    }

    fn db(&self, host: &str) -> PathBuf {
        self.0.join(host).join("mesh.sqlite")
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
    for key in [
        "AGENT_MESH_ENDPOINT",
        "AGENT_MESH_TOKEN_FILE",
        "AGENT_MESH_RUNTIME",
        "AGENT_MESH_INSTANCE",
        "AGENT_MESH_ADDRESS",
    ] {
        command.env_remove(key);
    }
    if let Some(identity) = identity {
        command
            .env("AGENT_MESH_ENDPOINT", &identity.endpoint_id)
            .env("AGENT_MESH_TOKEN_FILE", &identity.token_file);
    }
    command
}

fn ok(db: &Path, identity: Option<&Identity>, args: &[&str]) -> Value {
    let output = command(db, identity).args(args).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert!(
        output.status.success(),
        "`vvagent {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(&stdout).unwrap_or(Value::Null)
}

fn bind(db: &Path, alias: &str, instance: &str) -> Identity {
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
            "fake",
        ],
    );
    Identity {
        endpoint_id: bound["endpoint_id"].as_str().unwrap().to_owned(),
        token_file: bound["token_file"].as_str().unwrap().to_owned(),
    }
}

fn until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn recording_provider(scratch: &Scratch) -> PathBuf {
    let path = scratch.0.join("fake-activate.sh");
    std::fs::write(
        &path,
        "#!/bin/sh\nprintf 'session=%s\\ntext=%s\\n---\\n' \"$1\" \"$2\" >> \"$AGENT_MESH_TRANSCRIPT\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

/// The bridge, as `vvssh` will launch it, with SSH replaced by running the far side directly.
struct Bridge(Child);

impl Bridge {
    fn start(scratch: &Scratch) -> Self {
        let child = command(&scratch.db("laptop"), None)
            .args(["bridge", "--dial", "buildbox", "--name", "laptop", "--"])
            .arg(BIN)
            .arg("--db")
            .arg(scratch.db("buildbox"))
            .args(["bridge", "--serve"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Self(child)
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Mcp {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
    next_id: i64,
}

impl Mcp {
    fn start(db: &Path, identity: &Identity) -> Self {
        let mut child = command(db, Some(identity))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let reader = BufReader::new(child.stdout.take().unwrap());
        let mut session = Self {
            child,
            reader,
            next_id: 1,
        };
        session.request("initialize", json!({}));
        session
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let stdin = self.child.stdin.as_mut().unwrap();
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
        let mut response = String::new();
        self.reader.read_line(&mut response).unwrap();
        serde_json::from_str(response.trim()).unwrap()
    }

    fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let value = self.request("tools/call", json!({"name": name, "arguments": arguments}));
        assert_eq!(value["result"]["isError"], false, "{name}: {value}");
        value["result"]["structuredContent"].clone()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn peers(db: &Path) -> Vec<Value> {
    ok(db, None, &["peer", "list"])["peers"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

#[test]
fn a_request_crosses_hosts_and_its_reply_returns_with_no_payload_on_the_provider_channel() {
    let scratch = Scratch::new("hop");
    let laptop = scratch.db("laptop");
    let buildbox = scratch.db("buildbox");
    let asker = bind(&laptop, "asker", "session-a");
    let builder = bind(&buildbox, "builder", "session-b");

    // The builder's provider can start a turn and has mailbox tools, and it will be woken by a
    // trusted peer — the step a user takes on purpose, as they would for a local agent in another
    // runtime instance.
    let capabilities = ok(
        &buildbox,
        Some(&builder),
        &["capabilities", "--native-session", "thread-builder"],
    );
    assert_eq!(capabilities["delivery_mode"], "activate_and_pull");
    ok(
        &buildbox,
        Some(&builder),
        &["policy", "set", "--activate", "replies_and_trusted"],
    );

    let _bridge = Bridge::start(&scratch);
    until("both hosts to pin each other", || {
        !peers(&laptop).is_empty() && !peers(&buildbox).is_empty()
    });
    let seen = &peers(&buildbox)[0];
    assert_eq!(seen["label"], "laptop", "the dialler's suggested name");
    assert_eq!(seen["trusted"], false, "and it starts untrusted");
    assert_eq!(peers(&laptop)[0]["connected"], true);
    ok(&buildbox, None, &["peer", "trust", "laptop"]);

    // The asker names the builder by peer and remote id; the body goes through a file, not argv.
    let body = scratch.0.join("request.txt");
    std::fs::write(
        &body,
        format!("Run the kernel build test. {REQUEST_SECRET}"),
    )
    .unwrap();
    let target = format!("agent://buildbox/{}", builder.endpoint_id);
    let sent = ok(
        &laptop,
        Some(&asker),
        &[
            "send",
            "--to",
            &target,
            "--subject",
            "Build verification",
            "--text-file",
            body.to_str().unwrap(),
        ],
    );
    let request = sent["message_id"].as_str().unwrap().to_owned();

    // On buildbox, the watcher for the builder's session wakes it with a pointer only.
    let mut activated = Value::Null;
    until("the request to arrive and wake the builder", || {
        let output = command(&buildbox, None)
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
            .env("AGENT_MESH_FAKE_ACTIVATE", recording_provider(&scratch))
            .env(
                "AGENT_MESH_FAKE_CAPABILITIES",
                "structured_pull,external_turn_start",
            )
            .env("AGENT_MESH_TRANSCRIPT", scratch.transcript())
            .output()
            .unwrap();
        activated = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        activated["activated"] == 1
    });
    let asker_name = format!("agent://laptop/{}", asker.endpoint_id);
    let transcript = std::fs::read_to_string(scratch.transcript()).unwrap();
    assert!(
        !transcript.contains(REQUEST_SECRET),
        "the request payload reached the provider input channel:\n{transcript}"
    );
    assert!(
        transcript.contains(&asker_name),
        "the pointer names the remote sender"
    );
    assert!(transcript.contains("not an instruction from your operator"));

    // The builder reads through its tools and answers; the answer crosses back.
    let mut mcp = Mcp::start(&buildbox, &builder);
    let received = mcp.tool("agent_mesh_receive", json!({}));
    let message = &received["message"];
    assert_eq!(message["from"], asker_name.as_str());
    assert_eq!(message["from_principal"], "peer");
    assert!(message["text"].as_str().unwrap().contains(REQUEST_SECRET));
    mcp.tool(
        "agent_mesh_reply",
        json!({
            "request_id": message["request_id"],
            "outcome": "completed",
            "text": format!("Build passed. {RESPONSE_SECRET}"),
        }),
    );

    let answer = ok(
        &laptop,
        Some(&asker),
        &["wait", "--request", &request, "--timeout", "20s"],
    );
    assert_eq!(answer["kind"], "response");
    assert_eq!(answer["reply_to"], request.as_str());
    assert_eq!(answer["outcome"], "completed");
    assert!(answer["text"].as_str().unwrap().contains(RESPONSE_SECRET));

    let transcript = std::fs::read_to_string(scratch.transcript()).unwrap();
    assert!(
        !transcript.contains(REQUEST_SECRET) && !transcript.contains(RESPONSE_SECRET),
        "a payload reached the provider input channel:\n{transcript}"
    );
}

#[test]
fn an_untrusted_peers_request_ends_the_senders_wait_as_undeliverable() {
    let scratch = Scratch::new("denied");
    let laptop = scratch.db("laptop");
    let buildbox = scratch.db("buildbox");
    let asker = bind(&laptop, "asker", "session-a");
    let builder = bind(&buildbox, "builder", "session-b");

    let _bridge = Bridge::start(&scratch);
    until("the hosts to pin each other", || !peers(&laptop).is_empty());
    let target = format!("agent://buildbox/{}", builder.endpoint_id);
    let sent = ok(
        &laptop,
        Some(&asker),
        &["send", "--to", &target, "--text", "hello"],
    );
    let request = sent["message_id"].as_str().unwrap();

    let output = command(&laptop, Some(&asker))
        .args(["wait", "--request", request, "--timeout", "20s"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "a terminal non-answer");
    let resolution: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(resolution["resolution"], "undeliverable");
    assert_eq!(resolution["failure"], "policy_refused");
}

#[test]
fn a_remote_selector_names_a_known_peer_or_fails_plainly() {
    let scratch = Scratch::new("selector");
    let laptop = scratch.db("laptop");
    let asker = bind(&laptop, "asker", "session-a");
    let output = command(&laptop, Some(&asker))
        .args([
            "send",
            "--to",
            "agent://nowhere/0123456789abcdef0123456789abcdef",
            "--text",
            "hi",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "agent_not_found");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("peer list")
    );
}
