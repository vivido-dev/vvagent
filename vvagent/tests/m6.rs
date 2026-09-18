//! The M6 group and quorum tests.
//!
//! > Group send must snapshot membership and report partial admission; it must not make N inserts
//! > appear atomic when some mailboxes are full.
//!
//! Those three clauses are the whole specification, and each has a test that fails if it stops
//! being true.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_vvagent");

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "vvagent-m6-{name}-{}-{}",
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

fn bind(db: &Path, alias: &str) -> Identity {
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
            "dev",
        ],
    );
    Identity {
        endpoint_id: text(&bound, "endpoint_id"),
        token_file: text(&bound, "token_file"),
    }
}

/// The per-member outcomes of a fan-out, as `endpoint_id -> result`.
fn results(send: &Value) -> Vec<(String, String)> {
    send["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (text(row, "endpoint_id"), text(row, "result")))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------------------------

#[test]
fn a_group_stores_ids_so_it_cannot_follow_a_name() {
    let scratch = Scratch::new("ids");
    let db = scratch.db();
    let alice = bind(&db, "alice");
    let bob = bind(&db, "bob");

    let created = ok(
        &db,
        None,
        &[
            "group",
            "create",
            "reviewers",
            "--member",
            "alice",
            "--member",
            "bob",
        ],
    );
    let ids: Vec<String> = created["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| text(m, "endpoint_id"))
        .collect();
    assert!(ids.contains(&alice.endpoint_id));
    assert!(ids.contains(&bob.endpoint_id));

    // Membership is by id, so a rebind under the same alias is still the same member, and an
    // unrelated agent taking the name later is not.
    let listed = ok(&db, None, &["group", "list"]);
    let group = &listed["groups"].as_array().unwrap()[0];
    assert_eq!(group["group"], "reviewers");
    assert_eq!(group["members"].as_array().unwrap().len(), 2);
}

#[test]
fn members_can_be_added_and_removed_without_rewriting_the_group() {
    let scratch = Scratch::new("edit");
    let db = scratch.db();
    let alice = bind(&db, "alice");
    let bob = bind(&db, "bob");
    ok(&db, None, &["group", "create", "team", "--member", "alice"]);

    let added = ok(&db, None, &["group", "add", "team", "bob"]);
    assert_eq!(added["members"].as_array().unwrap().len(), 2);

    // Adding twice is not a duplicate.
    let again = ok(&db, None, &["group", "add", "team", "bob"]);
    assert_eq!(again["members"].as_array().unwrap().len(), 2);

    let removed = ok(&db, None, &["group", "remove", "team", &bob.endpoint_id]);
    let left: Vec<String> = removed["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| text(m, "endpoint_id"))
        .collect();
    assert_eq!(left, vec![alice.endpoint_id]);

    assert_eq!(ok(&db, None, &["group", "delete", "team"])["deleted"], true);
    let (code, _) = run(&db, None, &["group", "add", "team", "alice"]);
    assert_eq!(code, 1, "a deleted group is gone");
}

// ---------------------------------------------------------------------------------------------
// The three clauses
// ---------------------------------------------------------------------------------------------

#[test]
fn a_fan_out_reports_every_member_separately_and_never_as_one_result() {
    // The clause that matters most: N inserts must not look atomic. One member's mailbox is full,
    // another's policy refuses, a third accepts — and the caller is told all three.
    let scratch = Scratch::new("partial");
    let db = scratch.db();
    let sender = bind(&db, "sender");
    let willing = bind(&db, "willing");
    let full = bind(&db, "full");
    let refusing = bind(&db, "refusing");

    // `full` will take one message and no more.
    ok(
        &db,
        Some(&full),
        &["policy", "set", "--max-inbound-per-minute", "1"],
    );
    ok(
        &db,
        Some(&sender),
        &["send", "--to", "full", "--text", "fills it"],
    );
    // `refusing` admits only replies and teammates; the sender is a teammate, so close that too.
    ok(
        &db,
        Some(&refusing),
        &[
            "policy",
            "set",
            "--enqueue",
            "replies_only",
            "--team",
            "off",
        ],
    );

    ok(
        &db,
        None,
        &[
            "group", "create", "everyone", "--member", "willing", "--member", "full", "--member",
            "refusing",
        ],
    );
    let send = ok(
        &db,
        Some(&sender),
        &["send", "--group", "everyone", "--text", "please review"],
    );

    assert_eq!(send["members"], 3);
    assert_eq!(send["accepted"], 1, "only one could take it: {send}");
    assert_eq!(send["rejected"], 2);

    let by_endpoint: std::collections::HashMap<String, String> =
        results(&send).into_iter().collect();
    assert_eq!(by_endpoint[&willing.endpoint_id], "accepted");
    assert_eq!(by_endpoint[&full.endpoint_id], "rate_limited");
    assert_eq!(by_endpoint[&refusing.endpoint_id], "policy_refused");

    // Each accepted member got its own message, not a shared one.
    let delivered = ok(&db, Some(&willing), &["inbox"]);
    assert_eq!(delivered["messages"].as_array().unwrap().len(), 1);
    assert!(
        ok(&db, Some(&refusing), &["inbox"])["messages"]
            .as_array()
            .unwrap()
            .is_empty(),
        "a refused member received nothing"
    );
}

#[test]
fn a_quorum_counts_the_membership_the_send_was_made_to() {
    // The snapshot clause. Changing the group afterwards must not change what the send meant, or
    // a quorum could be reached by adding members who were never asked.
    let scratch = Scratch::new("snapshot");
    let db = scratch.db();
    let sender = bind(&db, "sender");
    let one = bind(&db, "one");
    let two = bind(&db, "two");
    bind(&db, "three");

    ok(
        &db,
        None,
        &[
            "group", "create", "pair", "--member", "one", "--member", "two",
        ],
    );
    let send = ok(
        &db,
        Some(&sender),
        &["send", "--group", "pair", "--text", "question"],
    );
    let send_id = text(&send, "group_send_id");
    assert_eq!(send["accepted"], 2);

    // The group grows after the fact. The fan-out is unaffected.
    ok(&db, None, &["group", "add", "pair", "three"]);

    let answer = |who: &Identity| {
        let received = ok(&db, Some(who), &["receive"]);
        ok(
            &db,
            Some(who),
            &[
                "reply",
                "--to-request",
                &text(&received, "message_id"),
                "--text",
                "answered",
            ],
        );
    };
    answer(&one);
    answer(&two);

    let waited = ok(
        &db,
        Some(&sender),
        &["wait", "--group-send", &send_id, "--timeout", "10s"],
    );
    assert_eq!(waited["asked"], 2, "the third member was never asked");
    assert_eq!(waited["quorum"], 2);
    assert_eq!(waited["answered"], 2);
    assert_eq!(waited["resolution"], "quorum");
}

#[test]
fn a_quorum_resolves_on_enough_answers_without_waiting_for_the_rest() {
    let scratch = Scratch::new("quorum");
    let db = scratch.db();
    let sender = bind(&db, "sender");
    let quick = bind(&db, "quick");
    let alsoquick = bind(&db, "alsoquick");
    bind(&db, "slow");

    ok(
        &db,
        None,
        &[
            "group",
            "create",
            "trio",
            "--member",
            "quick",
            "--member",
            "alsoquick",
            "--member",
            "slow",
        ],
    );
    let send = ok(
        &db,
        Some(&sender),
        &["send", "--group", "trio", "--text", "q"],
    );
    let send_id = text(&send, "group_send_id");
    assert_eq!(send["accepted"], 3);

    for who in [&quick, &alsoquick] {
        let received = ok(&db, Some(who), &["receive"]);
        ok(
            &db,
            Some(who),
            &[
                "reply",
                "--to-request",
                &text(&received, "message_id"),
                "--text",
                "done",
            ],
        );
    }

    let waited = ok(
        &db,
        Some(&sender),
        &[
            "wait",
            "--group-send",
            &send_id,
            "--quorum",
            "2",
            "--timeout",
            "10s",
        ],
    );
    assert_eq!(waited["resolution"], "quorum");
    assert_eq!(waited["answered"], 2);
    // The one that never answered is reported, not silently dropped.
    let outstanding = waited["outstanding"].as_array().unwrap();
    assert_eq!(outstanding.len(), 1);
    assert_eq!(outstanding[0]["state"], "queued");
}

#[test]
fn a_quorum_that_cannot_be_reached_times_out_and_says_who_is_missing() {
    let scratch = Scratch::new("timeout");
    let db = scratch.db();
    let sender = bind(&db, "sender");
    let willing = bind(&db, "willing");
    bind(&db, "silent");

    ok(
        &db,
        None,
        &[
            "group", "create", "pair", "--member", "willing", "--member", "silent",
        ],
    );
    let send = ok(
        &db,
        Some(&sender),
        &["send", "--group", "pair", "--text", "q"],
    );
    let send_id = text(&send, "group_send_id");

    let received = ok(&db, Some(&willing), &["receive"]);
    ok(
        &db,
        Some(&willing),
        &[
            "reply",
            "--to-request",
            &text(&received, "message_id"),
            "--text",
            "only me",
        ],
    );

    let (code, waited) = run(
        &db,
        Some(&sender),
        &[
            "wait",
            "--group-send",
            &send_id,
            "--quorum",
            "2",
            "--timeout",
            "400ms",
            "--poll",
            "50ms",
        ],
    );
    assert_eq!(code, 4, "a timeout has its own exit code");
    assert_eq!(waited["resolution"], "timeout");
    assert_eq!(waited["answered"], 1);
    assert_eq!(waited["outstanding"].as_array().unwrap().len(), 1);
    // The answer that did arrive is still reported — a timeout is not a failure of the whole send.
    assert_eq!(
        waited["responses"].as_array().unwrap()[0]["text"],
        "only me"
    );
}

#[test]
fn a_quorum_is_never_larger_than_the_number_actually_asked() {
    // Asking for more answers than there are recipients would wait forever for nobody.
    let scratch = Scratch::new("clamp");
    let db = scratch.db();
    let sender = bind(&db, "sender");
    let only = bind(&db, "only");
    ok(&db, None, &["group", "create", "solo", "--member", "only"]);
    let send = ok(
        &db,
        Some(&sender),
        &["send", "--group", "solo", "--text", "q"],
    );

    let received = ok(&db, Some(&only), &["receive"]);
    ok(
        &db,
        Some(&only),
        &[
            "reply",
            "--to-request",
            &text(&received, "message_id"),
            "--text",
            "ok",
        ],
    );

    let waited = ok(
        &db,
        Some(&sender),
        &[
            "wait",
            "--group-send",
            &text(&send, "group_send_id"),
            "--quorum",
            "99",
            "--timeout",
            "5s",
        ],
    );
    assert_eq!(waited["quorum"], 1, "clamped to who was asked");
    assert_eq!(waited["resolution"], "quorum");
}

// ---------------------------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------------------------

#[test]
fn retrying_a_fan_out_replays_what_landed_and_completes_what_did_not() {
    // A sender that crashed mid-fan-out does not know how far it got. Retrying with the same key
    // must not deliver anything twice.
    let scratch = Scratch::new("retry");
    let db = scratch.db();
    let sender = bind(&db, "sender");
    let one = bind(&db, "one");
    let two = bind(&db, "two");
    ok(
        &db,
        None,
        &[
            "group", "create", "pair", "--member", "one", "--member", "two",
        ],
    );

    let first = ok(
        &db,
        Some(&sender),
        &[
            "send",
            "--group",
            "pair",
            "--text",
            "q",
            "--idempotency-key",
            "k1",
        ],
    );
    assert_eq!(first["accepted"], 2);

    let retry = ok(
        &db,
        Some(&sender),
        &[
            "send",
            "--group",
            "pair",
            "--text",
            "q",
            "--idempotency-key",
            "k1",
        ],
    );
    assert_eq!(
        retry["accepted"], 2,
        "the retry replays rather than refusing"
    );

    for who in [&one, &two] {
        assert_eq!(
            ok(&db, Some(who), &["inbox"])["messages"]
                .as_array()
                .unwrap()
                .len(),
            1,
            "each member has exactly one copy"
        );
    }

    // The replayed messages are the originals, not new ones.
    let ids = |send: &Value| -> Vec<String> {
        send["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| text(row, "message_id"))
            .collect()
    };
    assert_eq!(ids(&first), ids(&retry));
}

#[test]
fn an_empty_group_is_refused_rather_than_reported_as_a_send_to_nobody() {
    let scratch = Scratch::new("empty");
    let db = scratch.db();
    let sender = bind(&db, "sender");
    let only = bind(&db, "only");
    ok(
        &db,
        None,
        &["group", "create", "shrinking", "--member", "only"],
    );
    ok(
        &db,
        None,
        &["group", "remove", "shrinking", &only.endpoint_id],
    );

    let (code, json) = run(
        &db,
        Some(&sender),
        &["send", "--group", "shrinking", "--text", "anyone?"],
    );
    assert_eq!(code, 1);
    assert_eq!(json["error"]["code"], "invalid_request");

    let (code, json) = run(
        &db,
        Some(&sender),
        &["send", "--group", "nosuchgroup", "--text", "hello"],
    );
    assert_eq!(code, 1);
    assert_eq!(json["error"]["code"], "not_found");
}
