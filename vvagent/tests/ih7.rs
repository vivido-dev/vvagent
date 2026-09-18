//! Inter-host milestone IH7: `vvagent send --attach`, end to end over a real bridge.
//!
//! The bridge runs as if launched from Vivida window 12, the `vvssh` window. Vivido's `drop-file`
//! is played by a fake client that copies the file into a "remote" directory and replies as
//! Vivido does — or, when told to, lies about the hash, reports no receiver, or omits the path.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_vvagent");

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "vvagent-ih7-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(base.join("remote")).unwrap();
        let scratch = Self(base);
        let client = scratch.0.join("drop-client");
        std::fs::write(
            &client,
            r#"#!/bin/sh
# Invoked as: <client> msg drop-file PATH --window-id W --timeout T
echo "$*" >> "$FAKE_DROP_LOG"
path="$3"
if [ "$FAKE_DROP_MODE" = unbound ]; then
  echo 'Error: Custom { kind: Other, error: "no_file_drop_binding: no receiver is bound" }' >&2
  exit 1
fi
name=$(basename "$path")
dest="$FAKE_REMOTE_DIR/$name"
cp "$path" "$dest"
sha=$(sha256sum "$path" | cut -d' ' -f1)
if [ "$FAKE_DROP_MODE" = mismatch ]; then
  sha=0000000000000000000000000000000000000000000000000000000000000000
fi
bytes=$(wc -c < "$path" | tr -d ' ')
if [ "$FAKE_DROP_MODE" = nopath ]; then
  printf '{"result":"committed","basename":"%s","bytes":%s,"sha256":"%s"}\n' "$name" "$bytes" "$sha"
else
  printf '{"result":"committed","basename":"%s","bytes":%s,"sha256":"%s","remote_path":"%s"}\n' \
    "$name" "$bytes" "$sha" "$dest"
fi
"#,
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o700)).unwrap();
        scratch
    }

    fn db(&self, host: &str) -> PathBuf {
        self.0.join(host).join("mesh.sqlite")
    }

    fn remote(&self) -> PathBuf {
        self.0.join("remote")
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn drops(&self) -> Vec<String> {
        std::fs::read_to_string(self.0.join("drops.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
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

fn command(scratch: &Scratch, db: &Path, identity: Option<&Identity>) -> Command {
    let mut command = Command::new(BIN);
    command.arg("--db").arg(db);
    for key in [
        "AGENT_MESH_ENDPOINT",
        "AGENT_MESH_TOKEN_FILE",
        "AGENT_MESH_RUNTIME",
        "AGENT_MESH_INSTANCE",
        "AGENT_MESH_ADDRESS",
        "FAKE_DROP_MODE",
    ] {
        command.env_remove(key);
    }
    command
        .env("AGENT_MESH_DROP_CLIENT", scratch.0.join("drop-client"))
        .env("FAKE_DROP_LOG", scratch.0.join("drops.log"))
        .env("FAKE_REMOTE_DIR", scratch.remote());
    if let Some(identity) = identity {
        command
            .env("AGENT_MESH_ENDPOINT", &identity.endpoint_id)
            .env("AGENT_MESH_TOKEN_FILE", &identity.token_file);
    }
    command
}

fn run(
    scratch: &Scratch,
    db: &Path,
    identity: Option<&Identity>,
    args: &[&str],
    mode: Option<&str>,
) -> (bool, Value, Value) {
    let mut command = command(scratch, db, identity);
    if let Some(mode) = mode {
        command.env("FAKE_DROP_MODE", mode);
    }
    let output = command.args(args).output().unwrap();
    let parse = |bytes: &[u8]| serde_json::from_slice(bytes).unwrap_or(Value::Null);
    (
        output.status.success(),
        parse(&output.stdout),
        parse(&output.stderr),
    )
}

fn ok(scratch: &Scratch, db: &Path, identity: Option<&Identity>, args: &[&str]) -> Value {
    let (success, stdout, stderr) = run(scratch, db, identity, args, None);
    assert!(success, "`vvagent {}` failed: {stderr}", args.join(" "));
    stdout
}

fn refused(
    scratch: &Scratch,
    db: &Path,
    identity: Option<&Identity>,
    args: &[&str],
    mode: Option<&str>,
) -> Value {
    let (success, stdout, stderr) = run(scratch, db, identity, args, mode);
    assert!(!success, "`vvagent {}` succeeded: {stdout}", args.join(" "));
    stderr["error"].clone()
}

fn bind(scratch: &Scratch, db: &Path, args: &[&str]) -> Identity {
    let mut full = vec!["bind"];
    full.extend_from_slice(args);
    let bound = ok(scratch, db, None, &full);
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

/// A bridge leashed to a process the test controls, dialled from Vivida `main` window 12 when
/// `window` is set, or from a plain terminal when it is not.
struct Bridge {
    leash: Child,
    dialler: Child,
}

impl Bridge {
    fn start(scratch: &Scratch, window: bool) -> Self {
        let leash = Command::new("sleep").arg("600").spawn().unwrap();
        let mut dial = command(scratch, &scratch.db("laptop"), None);
        dial.args([
            "bridge",
            "--dial",
            "buildbox",
            "--name",
            "laptop",
            "--parent-pid",
            &leash.id().to_string(),
            "--",
        ])
        .arg(BIN)
        .arg("--db")
        .arg(scratch.db("buildbox"))
        .args(["bridge", "--serve"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        if window {
            dial.env("AGENT_MESH_RUNTIME", "vivida")
                .env("AGENT_MESH_INSTANCE", "main")
                .env("AGENT_MESH_ADDRESS", "s1t2w12");
        }
        let dialler = dial.spawn().unwrap();
        Self { leash, dialler }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.leash.kill();
        let _ = self.leash.wait();
        let _ = self.dialler.wait();
    }
}

struct Hosts {
    scratch: Scratch,
    asker: Identity,
    builder: Identity,
    _bridge: Bridge,
}

impl Hosts {
    /// The asker sits in Vivida `main` window 11; the bridge runs in window 12.
    fn new(name: &str, window: bool) -> Self {
        let scratch = Scratch::new(name);
        let asker = bind(
            &scratch,
            &scratch.db("laptop"),
            &[
                "--alias",
                "asker",
                "--runtime",
                "vivida",
                "--instance",
                "main",
                "--address",
                "s1t1w11",
            ],
        );
        let builder = bind(
            &scratch,
            &scratch.db("buildbox"),
            &[
                "--alias",
                "builder",
                "--runtime",
                "vvmux",
                "--instance",
                "dev",
            ],
        );
        let bridge = Bridge::start(&scratch, window);
        let peers = |db: &Path| {
            ok(&scratch, db, None, &["peer", "list"])["peers"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        };
        until("the connection", || {
            peers(&scratch.db("laptop"))
                .first()
                .is_some_and(|peer| peer["connected"] == true)
                && !peers(&scratch.db("buildbox")).is_empty()
        });
        ok(
            &scratch,
            &scratch.db("buildbox"),
            None,
            &["peer", "trust", "laptop"],
        );
        Self {
            scratch,
            asker,
            builder,
            _bridge: bridge,
        }
    }

    fn laptop(&self) -> PathBuf {
        self.scratch.db("laptop")
    }

    fn buildbox(&self) -> PathBuf {
        self.scratch.db("buildbox")
    }

    fn receive(&self) -> Value {
        let mut message = Value::Null;
        until("the message on buildbox", || {
            message = ok(
                &self.scratch,
                &self.buildbox(),
                Some(&self.builder),
                &["receive"],
            );
            message.get("message_id").is_some()
        });
        message
    }
}

#[test]
fn an_attachment_crosses_to_a_remote_agent_as_a_verified_copy() {
    let hosts = Hosts::new("crosses", true);
    let payload = b"\x7fELF firmware image, not text".repeat(100);
    let file = hosts.scratch.file("firmware.bin", &payload);

    let sent = ok(
        &hosts.scratch,
        &hosts.laptop(),
        Some(&hosts.asker),
        &[
            "send",
            "--to",
            "@buildbox:builder",
            "--text",
            "flash this",
            "--attach",
            file.to_str().unwrap(),
        ],
    );
    let drops = hosts.scratch.drops();
    assert_eq!(drops.len(), 1, "{drops:?}");
    assert!(
        drops[0].contains("drop-file") && drops[0].ends_with("--window-id 12 --timeout 10m"),
        "dropped through the bridge's window: {}",
        drops[0]
    );
    let sha = sent["refs"][0]["sha256"].as_str().unwrap().to_owned();

    // On buildbox the reference names the copy on buildbox, and receiving checks it.
    let message = hosts.receive();
    let copy = hosts.scratch.remote().join("firmware.bin");
    assert_eq!(message["refs"][0]["path"], copy.to_str().unwrap());
    assert!(message["refs"][0].get("host").is_none(), "on this host");
    assert_eq!(message["attachments"][0]["verified"], true);
    assert_eq!(message["attachments"][0]["sha256"], sha.as_str());

    // A copy that changes afterwards is caught, not trusted.
    std::fs::write(&copy, b"tampered").unwrap();
    let checked = ok(
        &hosts.scratch,
        &hosts.buildbox(),
        Some(&hosts.builder),
        &["ref", "verify", message["message_id"].as_str().unwrap()],
    );
    assert_eq!(checked["attachments"][0]["verified"], false);
    assert_eq!(checked["attachments"][0]["reason"], "length differs");

    // The audit trail says how much went where, and never what it was called or held.
    for db in [hosts.laptop(), hosts.buildbox()] {
        let conn = rusqlite::Connection::open(&db).unwrap();
        let mut stmt = conn
            .prepare("SELECT coalesce(operation,'') || ' ' || coalesce(rule,'') || ' ' || result FROM audit")
            .unwrap();
        let rows: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for row in &rows {
            assert!(
                !row.contains("firmware") && !row.contains(&sha) && !row.contains("remote"),
                "{row}"
            );
        }
        assert!(
            db != hosts.laptop() || rows.iter().any(|row| row.starts_with("attach")),
            "the copy is audited on the sending side"
        );
    }
}

#[test]
fn a_retried_key_reuses_its_copies_and_a_refused_enqueue_says_where_they_went() {
    let hosts = Hosts::new("retry", true);
    let file = hosts.scratch.file("report.pdf", b"%PDF-1.7 report");
    let send = |text: &str| {
        run(
            &hosts.scratch,
            &hosts.laptop(),
            Some(&hosts.asker),
            &[
                "send",
                "--to",
                "@buildbox:builder",
                "--text",
                text,
                "--idempotency-key",
                "handoff-1",
                "--attach",
                file.to_str().unwrap(),
            ],
            None,
        )
    };

    let (first_ok, first, _) = send("review this");
    assert!(first_ok);
    let (again_ok, again, _) = send("review this");
    assert!(again_ok);
    assert_eq!(
        again["message_id"], first["message_id"],
        "a replay, not a duplicate"
    );
    assert_eq!(
        hosts.scratch.drops().len(),
        1,
        "and the file was not copied twice"
    );

    // The same key with different content is refused — after the copy exists, so the error has
    // to say where it is.
    let (conflict_ok, _, error) = send("something else");
    assert!(!conflict_ok);
    assert_eq!(error["error"]["code"], "idempotency_conflict");
    let copy = hosts.scratch.remote().join("report.pdf");
    let message = error["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(copy.to_str().unwrap()) && message.contains("buildbox"),
        "{message}"
    );
    assert_eq!(hosts.scratch.drops().len(), 1);
}

#[test]
fn a_copy_that_does_not_match_what_was_read_fails_the_send() {
    let hosts = Hosts::new("mismatch", true);
    let file = hosts.scratch.file("image.raw", b"raw sensor data");
    let error = refused(
        &hosts.scratch,
        &hosts.laptop(),
        Some(&hosts.asker),
        &[
            "send",
            "--to",
            "@buildbox:builder",
            "--text",
            "x",
            "--attach",
            file.to_str().unwrap(),
        ],
        Some("mismatch"),
    );
    assert_eq!(error["code"], "attachment_mismatch");
    let missing_path = refused(
        &hosts.scratch,
        &hosts.laptop(),
        Some(&hosts.asker),
        &[
            "send",
            "--to",
            "@buildbox:builder",
            "--text",
            "x",
            "--attach",
            file.to_str().unwrap(),
        ],
        Some("nopath"),
    );
    assert_eq!(missing_path["code"], "file_drop_unavailable");
    assert!(
        missing_path["message"]
            .as_str()
            .unwrap()
            .contains("vvreceive")
    );
    let unbound = refused(
        &hosts.scratch,
        &hosts.laptop(),
        Some(&hosts.asker),
        &[
            "send",
            "--to",
            "@buildbox:builder",
            "--text",
            "x",
            "--attach",
            file.to_str().unwrap(),
        ],
        Some("unbound"),
    );
    assert_eq!(unbound["code"], "file_drop_unavailable");

    // Nothing was sent by any of them.
    let (_, _, _) = run(
        &hosts.scratch,
        &hosts.buildbox(),
        Some(&hosts.builder),
        &["receive"],
        None,
    );
    let inbox = ok(
        &hosts.scratch,
        &hosts.buildbox(),
        Some(&hosts.builder),
        &["inbox"],
    );
    assert_eq!(inbox["messages"].as_array().unwrap().len(), 0);
}

#[test]
fn a_local_recipient_gets_a_reference_and_nothing_is_copied() {
    let scratch = Scratch::new("local");
    let db = scratch.db("laptop");
    let asker = bind(&scratch, &db, &["--alias", "asker", "--instance", "a"]);
    let reader = bind(&scratch, &db, &["--alias", "reader", "--instance", "a"]);
    let file = scratch.file("notes.txt", b"local notes");
    let sent = ok(
        &scratch,
        &db,
        Some(&asker),
        &[
            "send",
            "--to",
            "reader",
            "--text",
            "see attached",
            "--attach",
            file.to_str().unwrap(),
        ],
    );
    assert!(
        scratch.drops().is_empty(),
        "no transfer for a local recipient"
    );
    assert_eq!(sent["refs"][0]["path"], file.to_str().unwrap());
    assert_eq!(sent["refs"][0]["bytes"], 11);
    let received = ok(&scratch, &db, Some(&reader), &["receive"]);
    assert_eq!(received["attachments"][0]["verified"], true);
}

#[test]
fn a_file_crosses_only_through_a_vvssh_window_of_the_senders_own_instance() {
    // Bridged from a plain terminal: there is no window for a file to cross through.
    let plain = Hosts::new("plain", false);
    let file = plain.scratch.file("a.bin", b"a");
    let error = refused(
        &plain.scratch,
        &plain.laptop(),
        Some(&plain.asker),
        &[
            "send",
            "--to",
            "@buildbox:builder",
            "--text",
            "x",
            "--attach",
            file.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(error["code"], "file_drop_unavailable");
    // The message itself can still go.
    ok(
        &plain.scratch,
        &plain.laptop(),
        Some(&plain.asker),
        &["send", "--to", "@buildbox:builder", "--text", "no file"],
    );

    // A sender in another Vivida instance cannot drive window 12 of `main`.
    let hosts = Hosts::new("instance", true);
    let stranger = bind(
        &hosts.scratch,
        &hosts.laptop(),
        &[
            "--alias",
            "stranger",
            "--runtime",
            "vivida",
            "--instance",
            "other",
            "--address",
            "s1t1w3",
        ],
    );
    let file = hosts.scratch.file("b.bin", b"b");
    let error = refused(
        &hosts.scratch,
        &hosts.laptop(),
        Some(&stranger),
        &[
            "send",
            "--to",
            "@buildbox:builder",
            "--text",
            "x",
            "--attach",
            file.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(error["code"], "file_drop_unavailable");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("vivida:main window 12")
    );
    assert!(hosts.scratch.drops().is_empty());
}

#[test]
fn the_attach_gate_and_bounds_hold_before_anything_is_copied() {
    let hosts = Hosts::new("gates", true);
    let file = hosts.scratch.file("big.bin", &[7u8; 64]);
    let attach = |extra: &[&str]| {
        let mut args = vec![
            "send",
            "--to",
            "@buildbox:builder",
            "--text",
            "x",
            "--attach",
            file.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        refused(
            &hosts.scratch,
            &hosts.laptop(),
            Some(&hosts.asker),
            &args,
            None,
        )
    };

    assert_eq!(
        attach(&["--max-attach-bytes", "10"])["code"],
        "invalid_request"
    );
    let nine: Vec<&str> = std::iter::repeat_n(["--attach", file.to_str().unwrap()], 8)
        .flatten()
        .collect();
    assert_eq!(attach(&nine)["code"], "invalid_request");
    let link = hosts.scratch.0.join("link.bin");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    let error = refused(
        &hosts.scratch,
        &hosts.laptop(),
        Some(&hosts.asker),
        &[
            "send",
            "--to",
            "@buildbox:builder",
            "--text",
            "x",
            "--attach",
            link.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("not a regular file")
    );

    ok(
        &hosts.scratch,
        &hosts.laptop(),
        Some(&hosts.asker),
        &["policy", "attach", "deny"],
    );
    assert_eq!(attach(&[])["code"], "not_authorized");
    assert!(
        hosts.scratch.drops().is_empty(),
        "every refusal came before a copy"
    );
}

/// One MCP tool call against `vvagent mcp`, as a provider would make it.
fn mcp_call(
    scratch: &Scratch,
    db: &Path,
    identity: &Identity,
    tool: &str,
    arguments: Value,
) -> Value {
    use std::io::{BufRead, BufReader, Write};
    let mut child = command(scratch, db, Some(identity))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    for (id, method, params) in [
        (1, "initialize", serde_json::json!({})),
        (
            2,
            "tools/call",
            serde_json::json!({"name": tool, "arguments": arguments}),
        ),
    ] {
        writeln!(
            stdin,
            "{}",
            serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
        )
        .unwrap();
        stdin.flush().unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
    }
    let _ = child.kill();
    let _ = child.wait();
    let reply: Value = serde_json::from_str(line.trim()).unwrap();
    reply["result"]["structuredContent"].clone()
}

#[test]
fn mcp_sends_attachments_and_reports_them_verified_on_receipt() {
    let scratch = Scratch::new("mcp");
    let db = scratch.db("laptop");
    let asker = bind(&scratch, &db, &["--alias", "asker", "--instance", "a"]);
    let reader = bind(&scratch, &db, &["--alias", "reader", "--instance", "a"]);
    let file = scratch.file("plot.png", b"\x89PNG not really");

    let sent = mcp_call(
        &scratch,
        &db,
        &asker,
        "agent_mesh_send",
        serde_json::json!({
            "to": "reader",
            "text": "the plot",
            "attachments": [file.to_str().unwrap()],
        }),
    );
    assert!(sent["message_id"].is_string(), "{sent}");
    let received = mcp_call(
        &scratch,
        &db,
        &reader,
        "agent_mesh_receive",
        serde_json::json!({}),
    );
    let attachment = &received["message"]["attachments"][0];
    assert_eq!(attachment["path"], file.to_str().unwrap());
    assert_eq!(attachment["verified"], true, "{received}");

    let bad = mcp_call(
        &scratch,
        &db,
        &asker,
        "agent_mesh_send",
        serde_json::json!({"to": "reader", "text": "x", "attachments": "not-a-list"}),
    );
    assert_eq!(bad["error"]["code"], "invalid_request", "{bad}");
}
