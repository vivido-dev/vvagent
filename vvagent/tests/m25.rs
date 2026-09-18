//! The M2.5 exit criteria, through the real CLI.
//!
//! > `s2t2w3f1p2` and `vvmux:dev/f1p2` both resolve; `p2` from a vvmux pane resolves to pane 2 in
//! > another frame, proving segments are wildcards rather than values inherited from the caller;
//! > `t2` with several spaces prefers the caller's own and is otherwise `agent_ambiguous`; a
//! > malformed or out-of-order address is refused with a reason; an address naming a container of
//! > several agents is `agent_ambiguous` listing the addresses inside it; and no durable row
//! > anywhere stores an address where an `endpoint_id` belongs.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_vvagent");

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "vvagent-m25-{name}-{}-{}",
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
    command.env_remove("AGENT_MESH_ENDPOINT");
    command.env_remove("AGENT_MESH_TOKEN_FILE");
    command.env_remove("AGENT_MESH_ADDRESS");
    command.env_remove("AGENT_MESH_RUNTIME");
    command.env_remove("AGENT_MESH_INSTANCE");
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

/// Bind an endpoint at an explicit address.
fn at(db: &Path, alias: Option<&str>, instance: &str, address: &str) -> Identity {
    let mut args = vec![
        "bind",
        "--runtime",
        "vvmux",
        "--instance",
        instance,
        "--address",
        address,
    ];
    if let Some(alias) = alias {
        args.push("--alias");
        args.push(alias);
    }
    let bound = ok(db, None, &args);
    Identity {
        endpoint_id: text(&bound, "endpoint_id"),
        token_file: text(&bound, "token_file"),
    }
}

// ---------------------------------------------------------------------------------------------
// Partial addresses
// ---------------------------------------------------------------------------------------------

#[test]
fn a_bare_pane_resolves_across_frames() {
    // The heart of M2.5. An implementation that completed `p2` from the caller's own address would
    // look in frame 1 and never find this pane.
    let scratch = Scratch::new("pane");
    let db = scratch.db();

    let caller = at(&db, Some("caller"), "dev", "s2t2w3f1p7");
    let elsewhere = at(&db, Some("elsewhere"), "dev", "s2t2w3f2p2");

    let sent = ok(
        &db,
        Some(&caller),
        &["send", "--to", "p2", "--text", "hello"],
    );
    assert_eq!(
        text(&sent, "to"),
        elsewhere.endpoint_id,
        "p2 must cross the frame boundary"
    );

    // The fully qualified form names the same endpoint.
    let same = ok(
        &db,
        Some(&caller),
        &["send", "--to", "s2t2w3f2p2", "--text", "again"],
    );
    assert_eq!(text(&same, "to"), elsewhere.endpoint_id);

    // And so does the runtime-qualified form.
    let qualified = ok(
        &db,
        Some(&caller),
        &["send", "--to", "vvmux:dev/f2p2", "--text", "third"],
    );
    assert_eq!(text(&qualified, "to"), elsewhere.endpoint_id);
}

#[test]
fn a_bare_window_resolves_across_spaces_and_tabs() {
    let scratch = Scratch::new("window");
    let db = scratch.db();
    let caller = at(&db, Some("caller"), "main", "s1t1w1");
    let far = at(&db, Some("far"), "main", "s3t7w5");

    let sent = ok(&db, Some(&caller), &["send", "--to", "w5", "--text", "hi"]);
    assert_eq!(text(&sent, "to"), far.endpoint_id);
}

#[test]
fn a_bare_tab_prefers_the_callers_own_space_and_is_otherwise_ambiguous() {
    let scratch = Scratch::new("tab");
    let db = scratch.db();

    let caller = at(&db, Some("caller"), "main", "s2t1w1");
    at(&db, Some("in_space_one"), "main", "s1t2w9");
    let mine = at(&db, Some("in_my_space"), "main", "s2t2w8");
    at(&db, Some("in_space_three"), "main", "s3t2w7");

    // The caller's own space settles it.
    let sent = ok(&db, Some(&caller), &["send", "--to", "t2", "--text", "hi"]);
    assert_eq!(text(&sent, "to"), mine.endpoint_id);

    // A shell has no space of its own, so the same token is ambiguous — correctly.
    let (code, json) = run(&db, None, &["send", "--to", "t2", "--text", "hi"]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["code"], "agent_ambiguous");
    assert!(
        json["error"]["candidates"].as_array().unwrap().len() >= 3,
        "the caller is told what to retype: {json}"
    );
}

#[test]
fn an_address_naming_a_container_of_several_agents_is_ambiguous() {
    let scratch = Scratch::new("container");
    let db = scratch.db();
    let caller = at(&db, Some("caller"), "dev", "s1t1w1");
    at(&db, Some("first"), "dev", "s2t2w3f1p1");
    at(&db, Some("second"), "dev", "s2t2w3f1p2");

    let (code, json) = run(&db, Some(&caller), &["send", "--to", "w3", "--text", "hi"]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["code"], "agent_ambiguous");
    assert_eq!(json["error"]["candidates"].as_array().unwrap().len(), 2);
}

#[test]
fn a_malformed_address_is_refused_with_a_reason() {
    let scratch = Scratch::new("malformed");
    let db = scratch.db();

    // Out of containment order, at bind time.
    let (code, json) = run(
        &db,
        None,
        &[
            "bind",
            "--alias",
            "bad",
            "--runtime",
            "vvmux",
            "--instance",
            "dev",
            "--address",
            "p1f2",
        ],
    );
    assert_eq!(code, 1);
    assert_eq!(json["error"]["code"], "invalid_request");
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("containment order"),
        "the reason is specific: {json}"
    );

    for bad in ["p0", "p01", "p1p2", "x1"] {
        let (code, json) = run(
            &db,
            None,
            &[
                "bind",
                "--alias",
                "bad",
                "--runtime",
                "vvmux",
                "--instance",
                "dev",
                "--address",
                bad,
            ],
        );
        assert_eq!(code, 1, "`{bad}` should be refused");
        assert_eq!(json["error"]["code"], "invalid_request", "for `{bad}`");
    }
}

#[test]
fn a_host_supplied_prefix_joins_onto_the_levels_a_runtime_adds() {
    // How a vvmux session inside a Vivida window learns its whole path: the host exports the part
    // it owns, and vvmux contributes only `f`/`p`.
    let scratch = Scratch::new("prefix");
    let db = scratch.db();

    let output = Command::new(BIN)
        .arg("--db")
        .arg(&db)
        .args([
            "bind",
            "--alias",
            "nested",
            "--runtime",
            "vvmux",
            "--instance",
            "dev",
            "--address",
            "f1p2",
        ])
        .env("AGENT_MESH_ADDRESS", "s2t2w3")
        .env_remove("AGENT_MESH_ENDPOINT")
        .env_remove("AGENT_MESH_TOKEN_FILE")
        .output()
        .unwrap();
    assert!(output.status.success());

    let listed = ok(&db, None, &["list"]);
    let nested = listed["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["alias"] == "nested")
        .unwrap()
        .clone();
    assert_eq!(text(&nested, "address"), "s2t2w3f1p2");
}

// ---------------------------------------------------------------------------------------------
// An address is a locator, never an identity
// ---------------------------------------------------------------------------------------------

#[test]
fn moving_an_endpoint_changes_its_address_but_nothing_that_was_stored() {
    let scratch = Scratch::new("moved");
    let db = scratch.db();

    let sender = at(&db, Some("sender"), "dev", "f1p1");
    let target = at(&db, Some("target"), "dev", "f1p2");
    let sent = ok(
        &db,
        Some(&sender),
        &["send", "--to", "p2", "--text", "before the move"],
    );
    let message_id = text(&sent, "message_id");

    // The pane is moved to another frame: same alias, same instance, new position.
    let rebound = at(&db, Some("target"), "dev", "f9p2");
    assert_eq!(
        rebound.endpoint_id, target.endpoint_id,
        "the durable slot survives a move"
    );

    let listed = ok(&db, None, &["list"]);
    let moved = listed["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["alias"] == "target")
        .unwrap()
        .clone();
    assert_eq!(text(&moved, "address"), "f9p2", "the address followed it");

    // Everything durable still resolves, because it holds the id and not the position.
    let explained = ok(&db, None, &["explain", &message_id]);
    assert_eq!(explained["state"], "queued");
    let inbox = ok(&db, Some(&rebound), &["inbox"]);
    let messages = inbox["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["text"], "before the move");
}

#[test]
fn a_vacated_position_reused_by_another_endpoint_captures_nothing() {
    let scratch = Scratch::new("vacated");
    let db = scratch.db();

    let sender = at(&db, Some("sender"), "dev", "f1p1");
    let original = at(&db, Some("original"), "dev", "f1p2");
    let sent = ok(
        &db,
        Some(&sender),
        &["send", "--to", "p2", "--text", "for the original"],
    );

    // The original moves away and something unrelated takes its old position. Rebinding mints a
    // fresh incarnation, so the moved endpoint speaks with a new token.
    let moved = at(&db, Some("original"), "dev", "f1p7");
    assert_eq!(moved.endpoint_id, original.endpoint_id);
    let squatter = at(&db, Some("squatter"), "dev", "f1p2");
    assert_ne!(squatter.endpoint_id, original.endpoint_id);

    // The message stayed with the endpoint it was addressed to, not with the position.
    let squatter_inbox = ok(&db, Some(&squatter), &["inbox"]);
    assert!(
        squatter_inbox["messages"].as_array().unwrap().is_empty(),
        "an endpoint that inherited a position must not inherit its mail"
    );
    let original_inbox = ok(&db, Some(&moved), &["inbox"]);
    assert_eq!(original_inbox["messages"].as_array().unwrap().len(), 1);
    assert_eq!(
        text(&sent, "to"),
        original.endpoint_id,
        "the envelope recorded an endpoint id, not an address"
    );
}

#[test]
fn no_durable_table_stores_an_address_where_an_endpoint_id_belongs() {
    // The one way this scheme could undo §6.1, asserted against the real schema rather than
    // assumed from the code that writes it.
    let scratch = Scratch::new("schema");
    let db = scratch.db();
    let sender = at(&db, Some("sender"), "dev", "f1p1");
    at(&db, Some("target"), "dev", "f1p2");
    ok(&db, Some(&sender), &["send", "--to", "p2", "--text", "hi"]);

    let conn = rusqlite::Connection::open(&db).unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .unwrap();
    let tables: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    drop(stmt);
    assert!(tables.contains(&"message".to_string()));

    for table in &tables {
        let mut columns = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let names: Vec<String> = columns
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        if table == "endpoint" {
            assert!(
                names.contains(&"address".to_string()),
                "the endpoint's own position lives here"
            );
            for gone in ["workspace", "tab", "pane_id", "window_id"] {
                assert!(
                    !names.contains(&gone.to_string()),
                    "`{gone}` should have collapsed into one canonical address"
                );
            }
        } else {
            assert!(
                !names.contains(&"address".to_string()),
                "table `{table}` stores an address; it should store an endpoint_id"
            );
        }
    }

    // And the ids that *are* stored are opaque ids, not positions.
    let (to, from): (String, Option<String>) = conn
        .query_row(
            "SELECT to_endpoint, from_endpoint FROM message LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    for id in [Some(to), from].into_iter().flatten() {
        assert_eq!(id.len(), 32, "`{id}` is not an opaque endpoint id");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "`{id}`");
    }
}
