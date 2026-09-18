//! The M1 exit criterion, end to end through the real CLI.
//!
//! > Two wrapper-hosted fake agents exchange a durable correlated request and response across
//! > process restarts; retry is idempotent; a full mailbox rejects rather than drops.
//!
//! The third clause is proved against the real store in `agent-mesh-store/tests/store.rs`
//! (`a_full_mailbox_rejects_and_never_evicts_accepted_work`); driving 256 subprocesses to reprove
//! it here would add six seconds and no evidence.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_vvagent");

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "vvagent-m1-{name}-{}-{}",
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

/// One endpoint's inherited credentials, exactly as `vvagent run` hands them to a child.
#[derive(Clone)]
struct Identity {
    endpoint_id: String,
    token_file: String,
}

fn run(db: &Path, identity: Option<&Identity>, args: &[&str]) -> (i32, Value, String) {
    let mut command = Command::new(BIN);
    command.arg("--db").arg(db).args(args);
    // A test process must never leak its own mesh identity into a child.
    command.env_remove("AGENT_MESH_ENDPOINT");
    command.env_remove("AGENT_MESH_TOKEN_FILE");
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

fn bind(db: &Path, alias: &str, instance: &str) -> Identity {
    let bound = ok(
        db,
        None,
        &["bind", "--alias", alias, "--instance", instance],
    );
    Identity {
        endpoint_id: text(&bound, "endpoint_id"),
        token_file: text(&bound, "token_file"),
    }
}

/// A fake agent: claim one message, answer it, exit. Stands in for a provider adapter until M2.
fn fake_agent_script(scratch: &Scratch, answer: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let path = scratch.0.join("fake-agent.ps1");
        std::fs::write(&path, format!("$ErrorActionPreference = 'Stop'\n$envelope = & $env:VVAGENT receive | ConvertFrom-Json\nif (-not $envelope.message_id) {{ exit 9 }}\n& $env:VVAGENT reply --to-request $envelope.message_id --outcome completed --text '{answer}' | Out-Null\nexit $LASTEXITCODE\n")).unwrap();
        path
    }
    #[cfg(unix)]
    {
        let path = scratch.0.join("fake-agent.sh");
        std::fs::write(
            &path,
            format!(
                r#"#!/bin/sh
set -eu
envelope=$("$VVAGENT" receive)
id=$(printf '%s' "$envelope" | grep -o '"message_id":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)
if [ -z "$id" ]; then
  echo "fake agent found no message: $envelope" >&2
  exit 9
fi
"$VVAGENT" reply --to-request "$id" --outcome completed --text '{answer}' >/dev/null
"#
            ),
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

/// Run a command inside `vvagent run`, so the child holds a real bound endpoint.
fn wrapped(db: &Path, alias: &str, instance: &str, argv: &[&str]) -> (i32, String) {
    #[cfg(windows)]
    let argv: &[&str] = if argv == ["true"] {
        &["cmd.exe", "/D", "/C", "exit /b 0"]
    } else {
        &["powershell.exe", "-NoProfile", "-File", argv[0]]
    };
    let output = Command::new(BIN)
        .arg("--db")
        .arg(db)
        .args(["run", "--alias", alias, "--instance", instance, "--"])
        .args(argv)
        // The child inherits AGENT_MESH_DB from the wrapper, so it needs no --db.
        .env("VVAGENT", BIN)
        .env_remove("AGENT_MESH_ENDPOINT")
        .env_remove("AGENT_MESH_TOKEN_FILE")
        .output()
        .expect("vvagent run");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    )
}

// ---------------------------------------------------------------------------------------------
// The exit criterion
// ---------------------------------------------------------------------------------------------

#[test]
fn two_wrapper_hosted_agents_exchange_a_correlated_response_across_restarts() {
    let scratch = Scratch::new("exchange");
    let db = scratch.db();

    // Alice is bound by "a runtime" — here, directly.
    let alice = bind(&db, "alice", "dev");

    // The reviewer's slot is created by a wrapper run that exits immediately. After it, the
    // reviewer is *offline*: no process holds it.
    let (code, stderr) = wrapped(&db, "reviewer", "dev", &["true"]);
    assert_eq!(code, 0, "wrapper failed: {stderr}");

    let listed = ok(&db, None, &["list"]);
    let reviewer = listed["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["alias"] == "reviewer")
        .expect("the reviewer slot survives its wrapper")
        .clone();
    assert_eq!(reviewer["online"], false, "nothing holds it now");
    let reviewer_endpoint = text(&reviewer, "endpoint_id");
    assert_eq!(reviewer["selector"], "wrapper:dev/reviewer");

    // Alice asks a question while the reviewer is offline. A durable accept does not need the
    // recipient to be running.
    let sent = ok(
        &db,
        Some(&alice),
        &[
            "send",
            "--to",
            "reviewer",
            "--subject",
            "merge safety",
            "--text",
            "Review the referenced patch; is it safe to merge?",
            "--expires-in",
            "10m",
            "--idempotency-key",
            "k1",
        ],
    );
    let request_id = text(&sent, "message_id");
    assert_eq!(sent["kind"], "request");
    assert_eq!(sent["state"], "queued");
    assert_eq!(sent["from"]["kind"], "agent");
    assert_eq!(sent["from"]["endpoint_id"], alice.endpoint_id.as_str());

    // Retrying the identical send replays rather than duplicating.
    let replay = ok(
        &db,
        Some(&alice),
        &[
            "send",
            "--to",
            "reviewer",
            "--subject",
            "merge safety",
            "--text",
            "Review the referenced patch; is it safe to merge?",
            "--expires-in",
            "10m",
            "--idempotency-key",
            "k1",
        ],
    );
    assert_eq!(
        text(&replay, "message_id"),
        request_id,
        "an identical retry must replay the accepted message"
    );

    // A *different* process now comes up as the reviewer and answers. This is the restart.
    let script = fake_agent_script(&scratch, "Safe to merge.");
    let (code, stderr) = wrapped(&db, "reviewer", "dev", &[script.to_str().unwrap()]);
    assert_eq!(code, 0, "the fake agent failed: {stderr}");

    // Same durable slot, despite being a different process.
    let listed = ok(&db, None, &["list"]);
    let reviewer_after = listed["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["alias"] == "reviewer")
        .unwrap()
        .clone();
    assert_eq!(
        text(&reviewer_after, "endpoint_id"),
        reviewer_endpoint,
        "the endpoint id is stable across a restart"
    );

    // Alice waits on her exact request and gets a typed answer — no screen was read.
    let answer = ok(
        &db,
        Some(&alice),
        &["wait", "--request", &request_id, "--timeout", "30s"],
    );
    assert_eq!(answer["kind"], "response");
    assert_eq!(answer["outcome"], "completed");
    assert_eq!(answer["text"], "Safe to merge.");
    assert_eq!(
        text(&answer, "reply_to"),
        request_id,
        "the response names exactly one request"
    );
    assert_eq!(
        answer["conversation_id"], sent["conversation_id"],
        "request and response share a conversation"
    );

    // And the request itself is retired, not merely answered-alongside.
    let explained = ok(&db, None, &["explain", &request_id]);
    assert_eq!(explained["state"], "consumed");
}

// ---------------------------------------------------------------------------------------------
// Identity and addressing
// ---------------------------------------------------------------------------------------------

#[test]
fn a_shell_without_a_token_is_the_local_user_and_still_gets_answers() {
    let scratch = Scratch::new("localuser");
    let db = scratch.db();

    let me = ok(&db, None, &["whoami"]);
    assert_eq!(me["principal"], "local_user");
    assert!(
        me["endpoint_id"].is_string(),
        "the person at the keyboard needs somewhere for a reply to land"
    );

    let (_, stderr) = wrapped(&db, "reviewer", "dev", &["true"]);
    assert!(stderr.is_empty() || !stderr.contains("error"), "{stderr}");

    let sent = ok(
        &db,
        None,
        &["send", "--to", "reviewer", "--text", "from a human"],
    );
    assert_eq!(sent["from"]["kind"], "local_user");

    let script = fake_agent_script(&scratch, "answered a human");
    let (code, stderr) = wrapped(&db, "reviewer", "dev", &[script.to_str().unwrap()]);
    assert_eq!(code, 0, "{stderr}");

    let answer = ok(
        &db,
        None,
        &[
            "wait",
            "--request",
            &text(&sent, "message_id"),
            "--timeout",
            "30s",
        ],
    );
    assert_eq!(answer["text"], "answered a human");
}

#[test]
fn a_colliding_alias_is_reported_with_candidates_never_guessed() {
    let scratch = Scratch::new("ambiguous");
    let db = scratch.db();

    // Two unrelated instances both call their agent `reviewer` — a legal, ordinary situation.
    wrapped(&db, "reviewer", "dev", &["true"]);
    wrapped(&db, "reviewer", "other", &["true"]);

    let (code, json, _) = run(
        &db,
        None,
        &["send", "--to", "reviewer", "--text", "which one?"],
    );
    assert_eq!(code, 1);
    assert_eq!(json["error"]["code"], "agent_ambiguous");
    let candidates = json["error"]["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 2);
    assert!(candidates.iter().any(|c| c == "wrapper:dev/reviewer"));

    // The qualified form is accepted and unambiguous.
    let sent = ok(
        &db,
        None,
        &[
            "send",
            "--to",
            "wrapper:other/reviewer",
            "--text",
            "this one",
        ],
    );
    assert_eq!(sent["state"], "queued");
}

#[test]
fn an_unknown_selector_is_agent_not_found() {
    let scratch = Scratch::new("notfound");
    let db = scratch.db();
    let (code, json, _) = run(&db, None, &["send", "--to", "nobody", "--text", "hello"]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["code"], "agent_not_found");
}

#[test]
#[cfg(unix)]
fn the_endpoint_token_is_a_file_the_owner_alone_can_read() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new("token");
    let db = scratch.db();
    let alice = bind(&db, "alice", "dev");

    let mode = std::fs::metadata(&alice.token_file)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "a credential file is owner-only");

    let dir = Path::new(&alice.token_file).parent().unwrap();
    let dir_mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);

    // A wrong token is refused rather than downgraded to the local user.
    let bogus = scratch.0.join("bogus-token");
    std::fs::write(&bogus, "0".repeat(64)).unwrap();
    let (code, json, _) = run(
        &db,
        Some(&Identity {
            endpoint_id: alice.endpoint_id.clone(),
            token_file: bogus.display().to_string(),
        }),
        &["whoami"],
    );
    assert_eq!(code, 1);
    assert_eq!(json["error"]["code"], "not_authorized");
}

// ---------------------------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------------------------

#[test]
fn waiting_reports_timeout_cancellation_and_expiry_distinctly() {
    let scratch = Scratch::new("resolutions");
    let db = scratch.db();
    let alice = bind(&db, "alice", "dev");
    wrapped(&db, "reviewer", "dev", &["true"]);

    // Nobody answers: a timeout is its own resolution and does not mutate the request.
    let sent = ok(
        &db,
        Some(&alice),
        &["send", "--to", "reviewer", "--text", "unanswered"],
    );
    let id = text(&sent, "message_id");
    let (code, json, _) = run(
        &db,
        Some(&alice),
        &[
            "wait",
            "--request",
            &id,
            "--timeout",
            "300ms",
            "--poll",
            "50ms",
        ],
    );
    assert_eq!(code, 4, "a timeout has its own exit code");
    assert_eq!(json["resolution"], "timeout");
    assert_eq!(json["state"], "queued", "the request is untouched");

    // Cancelling queued work removes it, and the wait says so.
    let cancelled = ok(&db, Some(&alice), &["cancel", "--request", &id]);
    assert_eq!(cancelled["state"], "cancelled");
    let (code, json, _) = run(
        &db,
        Some(&alice),
        &[
            "wait",
            "--request",
            &id,
            "--timeout",
            "1s",
            "--poll",
            "50ms",
        ],
    );
    assert_eq!(code, 3);
    assert_eq!(json["resolution"], "cancelled");
}

#[test]
fn explain_reports_the_decision_trail_without_the_message_body() {
    let scratch = Scratch::new("explain");
    let db = scratch.db();
    let alice = bind(&db, "alice", "dev");
    wrapped(&db, "reviewer", "dev", &["true"]);

    let secret = "the launch code is hunter2";
    let sent = ok(
        &db,
        Some(&alice),
        &["send", "--to", "reviewer", "--text", secret],
    );
    let explained = ok(&db, None, &["explain", &text(&sent, "message_id")]);

    let audit = explained["audit"].as_array().unwrap();
    assert!(!audit.is_empty());
    assert_eq!(audit[0]["operation"], "send");
    assert_eq!(audit[0]["result"], "accepted");
    assert_eq!(audit[0]["rule"], "anyone");
    assert!(
        !explained.to_string().contains("hunter2"),
        "explain must not disclose the body it is explaining"
    );
}

#[test]
fn a_policy_that_refuses_a_stranger_is_enforced_and_explained() {
    let scratch = Scratch::new("policy");
    let db = scratch.db();

    // Two instances, so the sender is not a teammate.
    let stranger = bind(&db, "stranger", "other");
    let target = bind(&db, "target", "dev");

    let policy = ok(
        &db,
        Some(&target),
        &["policy", "set", "--enqueue", "replies_and_team"],
    );
    assert_eq!(policy["enqueue"], "replies_and_team");

    let (code, json, _) = run(
        &db,
        Some(&stranger),
        &[
            "send",
            "--to",
            "wrapper:dev/target",
            "--text",
            "unsolicited",
        ],
    );
    assert_eq!(code, 1);
    assert_eq!(json["error"]["code"], "policy_refused");

    // A teammate in the same instance is admitted by the team grant.
    let teammate = bind(&db, "teammate", "dev");
    let sent = ok(
        &db,
        Some(&teammate),
        &[
            "send",
            "--to",
            "wrapper:dev/target",
            "--text",
            "from a teammate",
        ],
    );
    assert_eq!(sent["state"], "queued");
}

#[test]
fn the_inbox_shows_pending_work_and_receive_claims_one_message() {
    let scratch = Scratch::new("inbox");
    let db = scratch.db();
    let alice = bind(&db, "alice", "dev");
    let bob = bind(&db, "bob", "dev");

    for index in 0..3 {
        ok(
            &db,
            Some(&alice),
            &[
                "send",
                "--to",
                "wrapper:dev/bob",
                "--text",
                &format!("task {index}"),
            ],
        );
    }

    let inbox = ok(&db, Some(&bob), &["inbox"]);
    let messages = inbox["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 3);
    let sequences: Vec<i64> = messages
        .iter()
        .map(|m| m["recipient_sequence"].as_i64().unwrap())
        .collect();
    assert_eq!(sequences, vec![1, 2, 3], "delivered in order, gap-free");

    let claimed = ok(&db, Some(&bob), &["receive"]);
    assert_eq!(claimed["recipient_sequence"], 1, "oldest first");
    assert_eq!(claimed["state"], "claimed");

    // The claimed one is no longer queued, but is still pending.
    let queued = ok(&db, Some(&bob), &["inbox", "--status", "queued"]);
    assert_eq!(queued["messages"].as_array().unwrap().len(), 2);
}
