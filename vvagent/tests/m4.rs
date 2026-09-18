//! The M4 exit criteria.
//!
//! > A Vivida-hosted and a `vvmux`-hosted agent exchange a request and response; moving the Vivida
//! > window changes its address but not its `endpoint_id`, and everything holding the id keeps
//! > working; closing an unrelated window that reuses the vacated position changes nothing.
//!
//! Vivida's side is driven through a stub `vivida msg layout`, because what the mesh consumes is
//! the layout document — the same one every other automation caller reads. A test against the real
//! GUI would prove Vivida can draw windows, which is not what is in question here.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_vvagent");

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "vvagent-m4-{name}-{}-{}",
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

    /// A stand-in for `vivida msg layout`, rewritable so a test can move a window.
    fn layout_command(&self, layout: &Value) -> String {
        let path = self.0.join("layout.json");
        std::fs::write(&path, serde_json::to_string(layout).unwrap()).unwrap();
        #[cfg(unix)]
        {
            format!("cat '{}'", path.display())
        }
        #[cfg(windows)]
        {
            format!("type \"{}\"", path.display())
        }
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

fn run(db: &Path, identity: Option<&Identity>, args: &[&str]) -> (i32, Value) {
    let mut command = Command::new(BIN);
    command.arg("--db").arg(db).args(args);
    for key in [
        "AGENT_MESH_ENDPOINT",
        "AGENT_MESH_TOKEN_FILE",
        "AGENT_MESH_ADDRESS",
        "AGENT_MESH_RUNTIME",
        "AGENT_MESH_INSTANCE",
    ] {
        command.env_remove(key);
    }
    if let Some(identity) = identity {
        command
            .env("AGENT_MESH_ENDPOINT", &identity.endpoint_id)
            .env("AGENT_MESH_TOKEN_FILE", &identity.token_file);
    }
    let output = command.output().expect("vvagent runs");
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let json = serde_json::from_str(&stdout)
        .or_else(|_| serde_json::from_str::<Value>(&stderr))
        .unwrap_or(Value::Null);
    (output.status.code().unwrap_or(-1), json)
}

fn ok(db: &Path, identity: Option<&Identity>, args: &[&str]) -> Value {
    let (code, json) = run(db, identity, args);
    assert_eq!(code, 0, "`vvagent {}` failed: {json}", args.join(" "));
    json
}

fn text(value: &Value, key: &str) -> String {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("expected a string at `{key}` in {value}"))
        .to_owned()
}

fn bind(db: &Path, alias: &str, runtime: &str, instance: &str, address: &str) -> Identity {
    let bound = ok(
        db,
        None,
        &[
            "bind",
            "--alias",
            alias,
            "--runtime",
            runtime,
            "--instance",
            instance,
            "--address",
            address,
        ],
    );
    Identity {
        endpoint_id: text(&bound, "endpoint_id"),
        token_file: text(&bound, "token_file"),
    }
}

fn address_of(db: &Path, alias: &str) -> String {
    let listed = ok(db, None, &["list"]);
    listed["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["alias"] == alias)
        .unwrap_or_else(|| panic!("no endpoint aliased `{alias}`"))["address"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// A Vivida layout with one pane per (space, tab, window) triple.
fn layout(panes: &[(u32, u32, u32)]) -> Value {
    let mut workspaces: Vec<Value> = Vec::new();
    for (space, tab, window) in panes {
        let workspace = workspaces
            .iter_mut()
            .find(|w| w["workspace_index"] == json!(space));
        let workspace = match workspace {
            Some(existing) => existing,
            None => {
                workspaces.push(json!({ "workspace_index": space, "tabs": [] }));
                workspaces.last_mut().unwrap()
            }
        };
        let tabs = workspace["tabs"].as_array_mut().unwrap();
        match tabs.iter_mut().find(|t| t["tab_index"] == json!(tab)) {
            Some(existing) => existing["panes"]
                .as_array_mut()
                .unwrap()
                .push(json!({ "window_id": window })),
            None => tabs.push(json!({
                "tab_index": tab,
                "panes": [{ "window_id": window }]
            })),
        }
    }
    json!({ "workspaces": workspaces })
}

// ---------------------------------------------------------------------------------------------
// The exit criteria
// ---------------------------------------------------------------------------------------------

#[test]
fn a_vivida_hosted_and_a_vvmux_hosted_agent_exchange_a_request_and_response() {
    let scratch = Scratch::new("exchange");
    let db = scratch.db();

    // Two different runtimes, two different instances — every hop is cross-runtime.
    let in_vivida = bind(&db, "designer", "vivida", "main", "s2t3w42");
    let in_vvmux = bind(&db, "builder", "vvmux", "dev", "f1p2");
    ok(
        &db,
        Some(&in_vvmux),
        &["policy", "trust", &in_vivida.endpoint_id],
    );

    let sent = ok(
        &db,
        Some(&in_vivida),
        &[
            "send",
            "--to",
            "vvmux:dev/builder",
            "--subject",
            "build it",
            "--text",
            "please build the branch",
        ],
    );
    let request_id = text(&sent, "message_id");
    assert_eq!(text(&sent, "to"), in_vvmux.endpoint_id);

    // The vvmux-hosted agent reads it and answers.
    let received = ok(&db, Some(&in_vvmux), &["receive"]);
    assert_eq!(text(&received, "message_id"), request_id);
    ok(
        &db,
        Some(&in_vvmux),
        &[
            "reply",
            "--to-request",
            &request_id,
            "--outcome",
            "completed",
            "--text",
            "built",
        ],
    );

    let answer = ok(
        &db,
        Some(&in_vivida),
        &["wait", "--request", &request_id, "--timeout", "30s"],
    );
    assert_eq!(answer["outcome"], "completed");
    assert_eq!(answer["text"], "built");
    assert_eq!(text(&answer, "reply_to"), request_id);

    // Each is addressable by its own runtime's vocabulary.
    let listed = ok(&db, None, &["list"]);
    let selectors: Vec<&str> = listed["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["selector"].as_str().unwrap())
        .collect();
    assert!(selectors.contains(&"vivida:main/designer"));
    assert!(selectors.contains(&"vvmux:dev/builder"));
}

#[test]
fn moving_a_vivida_window_changes_its_address_and_nothing_else() {
    let scratch = Scratch::new("moved");
    let db = scratch.db();

    let sender = bind(&db, "sender", "vivida", "main", "s1t1w7");
    let target = bind(&db, "target", "vivida", "main", "s2t3w42");
    let sent = ok(
        &db,
        Some(&sender),
        &["send", "--to", "w42", "--text", "before the move"],
    );

    // The user drags that window into space 3, tab 1. Vivida's layout is the only thing that
    // changes; nothing tells the mesh an endpoint id.
    let moved_layout = layout(&[(1, 1, 7), (3, 1, 42)]);
    let result = ok(
        &db,
        None,
        &[
            "reconcile",
            "--runtime",
            "vivida",
            "--instance",
            "main",
            "--from",
            &scratch.layout_command(&moved_layout),
        ],
    );
    assert_eq!(result["seen"], 2, "both panes were read: {result}");
    let moved = result["moved"].as_array().unwrap();
    assert_eq!(moved.len(), 1, "only the one that actually moved: {result}");
    assert_eq!(moved[0]["was"], "s2t3w42");
    assert_eq!(moved[0]["now"], "s3t1w42");
    assert_eq!(
        text(&moved[0], "endpoint_id"),
        target.endpoint_id,
        "the same endpoint, found by the window id that survived the move"
    );

    assert_eq!(address_of(&db, "target"), "s3t1w42");
    assert_eq!(
        address_of(&db, "sender"),
        "s1t1w7",
        "an unmoved pane is left alone"
    );

    // Everything holding the id still works: the mail is where it was.
    let inbox = ok(&db, Some(&target), &["inbox"]);
    let messages = inbox["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["text"], "before the move");
    assert_eq!(
        ok(&db, None, &["explain", &text(&sent, "message_id")])["state"],
        "queued"
    );

    // And it answers to where it is now, not where it was.
    ok(
        &db,
        Some(&sender),
        &["send", "--to", "s3t1w42", "--text", "after the move"],
    );
    let (code, json) = run(
        &db,
        Some(&sender),
        &["send", "--to", "s2t3w42", "--text", "at the old address"],
    );
    assert_eq!(code, 1, "the vacated address names nothing: {json}");
    assert_eq!(json["error"]["code"], "agent_not_found");
}

#[test]
fn a_window_that_takes_a_vacated_position_inherits_nothing() {
    let scratch = Scratch::new("vacated");
    let db = scratch.db();

    let sender = bind(&db, "sender", "vivida", "main", "s1t1w7");
    let original = bind(&db, "original", "vivida", "main", "s2t3w42");
    ok(
        &db,
        Some(&sender),
        &["send", "--to", "w42", "--text", "for the original"],
    );

    // The original moves away; an unrelated window opens where it used to be. Note the newcomer
    // has a *different* window id — position is reused, identity is not.
    let newcomer = bind(&db, "newcomer", "vivida", "main", "s9t9w99");
    ok(
        &db,
        None,
        &[
            "reconcile",
            "--runtime",
            "vivida",
            "--instance",
            "main",
            "--from",
            &scratch.layout_command(&layout(&[(1, 1, 7), (4, 1, 42), (2, 3, 99)])),
        ],
    );
    assert_eq!(address_of(&db, "original"), "s4t1w42");
    assert_eq!(address_of(&db, "newcomer"), "s2t3w99");

    // The newcomer sits exactly where the original was, and has none of its mail.
    let inherited = ok(&db, Some(&newcomer), &["inbox"]);
    assert!(
        inherited["messages"].as_array().unwrap().is_empty(),
        "a reused position must not carry a mailbox with it"
    );
    let kept = ok(&db, Some(&original), &["inbox"]);
    assert_eq!(kept["messages"].as_array().unwrap().len(), 1);

    // Closing the newcomer leaves the original untouched — the owner-scoped rule, at window level.
    ok(
        &db,
        None,
        &[
            "unbind",
            "--endpoint",
            &newcomer.endpoint_id,
            "--incarnation",
            &text(
                &ok(&db, None, &["list"])["endpoints"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|e| e["alias"] == "newcomer")
                    .unwrap()
                    .clone(),
                "incarnation_id",
            ),
        ],
    );
    assert_eq!(address_of(&db, "original"), "s4t1w42");
    assert_eq!(
        ok(&db, Some(&original), &["inbox"])["messages"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------------------------
// Reconciliation behaviour
// ---------------------------------------------------------------------------------------------

#[test]
fn reconciling_an_unchanged_layout_moves_nothing() {
    let scratch = Scratch::new("stable");
    let db = scratch.db();
    bind(&db, "one", "vivida", "main", "s1t1w7");

    let command = scratch.layout_command(&layout(&[(1, 1, 7)]));
    for _ in 0..3 {
        let result = ok(
            &db,
            None,
            &[
                "reconcile",
                "--runtime",
                "vivida",
                "--instance",
                "main",
                "--from",
                &command,
            ],
        );
        assert_eq!(result["seen"], 1);
        assert!(result["moved"].as_array().unwrap().is_empty());
    }
    assert_eq!(address_of(&db, "one"), "s1t1w7");
}

#[test]
fn reconciliation_is_scoped_to_one_runtime_instance() {
    // Two instances may both have a window 42; a layout from one must not move the other's.
    let scratch = Scratch::new("scoped");
    let db = scratch.db();
    bind(&db, "mine", "vivida", "main", "s1t1w42");
    bind(&db, "theirs", "vivida", "other", "s1t1w42");

    ok(
        &db,
        None,
        &[
            "reconcile",
            "--runtime",
            "vivida",
            "--instance",
            "main",
            "--from",
            &scratch.layout_command(&layout(&[(5, 5, 42)])),
        ],
    );
    assert_eq!(address_of(&db, "mine"), "s5t5w42");
    assert_eq!(
        address_of(&db, "theirs"),
        "s1t1w42",
        "another instance's window 42 is a different window"
    );
}

#[test]
fn a_broken_layout_command_is_an_error_rather_than_an_empty_layout() {
    // Treating a failed layout read as "no panes" would quietly stop reconciling and leave every
    // address stale with no sign of trouble.
    let scratch = Scratch::new("broken");
    let db = scratch.db();
    bind(&db, "one", "vivida", "main", "s1t1w7");

    for command in ["exit 7", "echo not json"] {
        let (code, json) = run(
            &db,
            None,
            &[
                "reconcile",
                "--runtime",
                "vivida",
                "--instance",
                "main",
                "--from",
                command,
            ],
        );
        assert_eq!(code, 1, "`{command}` should fail: {json}");
    }
    assert_eq!(address_of(&db, "one"), "s1t1w7", "and nothing was changed");
}

#[test]
fn readdress_moves_one_endpoint_by_the_part_that_survived() {
    let scratch = Scratch::new("readdress");
    let db = scratch.db();
    let target = bind(&db, "target", "vivido", "main", "w42");

    let moved = ok(
        &db,
        None,
        &[
            "readdress",
            "--runtime",
            "vivido",
            "--instance",
            "main",
            "--address",
            "t3w42",
        ],
    );
    assert_eq!(text(&moved, "endpoint_id"), target.endpoint_id);
    assert_eq!(moved["was"], "w42");
    assert_eq!(moved["now"], "t3w42");

    // An address of positions alone identifies nothing that moved.
    let (code, json) = run(
        &db,
        None,
        &[
            "readdress",
            "--runtime",
            "vivido",
            "--instance",
            "main",
            "--address",
            "s2t3",
        ],
    );
    assert_eq!(code, 1);
    assert_eq!(json["error"]["code"], "invalid_request");
}
