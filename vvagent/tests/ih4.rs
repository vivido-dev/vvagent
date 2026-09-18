//! Inter-host milestone IH4: naming agents on a peer host, end to end through real processes.
//!
//! `@buildbox:<selector>` is resolved by buildbox, through the bridge, while one is connected; an
//! exact id queues while none is; and `s1t2w12f1p2` reaches through the window a bridge was
//! launched from (`docs/vvagent-inter-host-plan.md` §5).
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
            "vvagent-ih4-{name}-{}-{}",
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

/// Run and return (success, stdout JSON, stderr JSON).
fn run(db: &Path, identity: Option<&Identity>, args: &[&str]) -> (bool, Value, Value) {
    let output = command(db, identity).args(args).output().unwrap();
    let parse = |bytes: &[u8]| serde_json::from_slice(bytes).unwrap_or(Value::Null);
    (
        output.status.success(),
        parse(&output.stdout),
        parse(&output.stderr),
    )
}

fn ok(db: &Path, identity: Option<&Identity>, args: &[&str]) -> Value {
    let (success, stdout, stderr) = run(db, identity, args);
    assert!(success, "`vvagent {}` failed: {stderr}", args.join(" "));
    stdout
}

fn refused(db: &Path, identity: Option<&Identity>, args: &[&str]) -> Value {
    let (success, stdout, stderr) = run(db, identity, args);
    assert!(!success, "`vvagent {}` succeeded: {stdout}", args.join(" "));
    stderr["error"].clone()
}

fn bind(db: &Path, args: &[&str]) -> Identity {
    let mut full = vec!["bind"];
    full.extend_from_slice(args);
    let bound = ok(db, None, &full);
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

fn peers(db: &Path) -> Vec<Value> {
    ok(db, None, &["peer", "list"])["peers"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn connected(db: &Path) -> bool {
    peers(db)
        .first()
        .is_some_and(|peer| peer["connected"] == true)
}

/// A dialling bridge leashed to a process the test controls, so it can be stopped cleanly — its
/// lease released at once — by ending the leash, as a closing `vvssh` window would.
struct Bridge {
    leash: Child,
    dialler: Child,
}

impl Bridge {
    fn start(scratch: &Scratch, window: Option<&str>) -> Self {
        let leash = Command::new("sleep").arg("600").spawn().unwrap();
        let mut dial = command(&scratch.db("laptop"), None);
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
        if let Some(address) = window {
            dial.env("AGENT_MESH_RUNTIME", "vivida")
                .env("AGENT_MESH_INSTANCE", "main")
                .env("AGENT_MESH_ADDRESS", address);
        }
        let dialler = dial.spawn().unwrap();
        Self { leash, dialler }
    }

    fn stop(mut self) {
        let _ = self.leash.kill();
        let _ = self.leash.wait();
        let status = self.dialler.wait().unwrap();
        assert!(status.success(), "the dialler left cleanly: {status}");
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.leash.kill();
        let _ = self.dialler.kill();
        let _ = self.leash.wait();
        let _ = self.dialler.wait();
    }
}

/// Buildbox with a named builder and three unnamed panes: two sessions both have an `f1p2`.
struct Buildbox {
    builder: Identity,
    lone: Identity,
}

fn populate(db: &Path) -> Buildbox {
    let builder = bind(
        db,
        &[
            "--alias",
            "builder",
            "--runtime",
            "vvmux",
            "--instance",
            "dev",
            "--address",
            "f1p1",
        ],
    );
    bind(
        db,
        &[
            "--runtime",
            "vvmux",
            "--instance",
            "dev",
            "--address",
            "f1p2",
        ],
    );
    bind(
        db,
        &[
            "--runtime",
            "vvmux",
            "--instance",
            "ci",
            "--address",
            "f1p2",
        ],
    );
    let lone = bind(
        db,
        &[
            "--runtime",
            "vvmux",
            "--instance",
            "ci",
            "--address",
            "f2p5",
        ],
    );
    Buildbox { builder, lone }
}

fn received(db: &Path, identity: &Identity) -> Option<Value> {
    let message = ok(db, Some(identity), &["receive"]);
    message.get("message_id").is_some().then_some(message)
}

#[test]
fn a_name_on_a_peer_is_resolved_by_that_peer_while_connected() {
    let scratch = Scratch::new("named");
    let laptop = scratch.db("laptop");
    let buildbox = scratch.db("buildbox");
    let asker = bind(&laptop, &["--alias", "asker", "--instance", "a"]);
    let remote = populate(&buildbox);

    let _bridge = Bridge::start(&scratch, None);
    until("a connection", || connected(&laptop));
    until("buildbox to know the laptop", || {
        !peers(&buildbox).is_empty()
    });
    ok(&buildbox, None, &["peer", "trust", "laptop"]);

    let sent = ok(
        &laptop,
        Some(&asker),
        &["send", "--to", "@buildbox:builder", "--text", "build it"],
    );
    let request = sent["message_id"].as_str().unwrap().to_owned();
    let mut arrived = None;
    until("the request on buildbox", || {
        arrived = received(&buildbox, &remote.builder);
        arrived.is_some()
    });
    let arrived = arrived.unwrap();
    assert_eq!(arrived["text"], "build it");
    ok(
        &buildbox,
        Some(&remote.builder),
        &[
            "reply",
            "--to-request",
            arrived["message_id"].as_str().unwrap(),
            "--text",
            "built",
        ],
    );
    let answer = ok(
        &laptop,
        Some(&asker),
        &["wait", "--request", &request, "--timeout", "20s"],
    );
    assert_eq!(answer["text"], "built");

    // Two sessions on buildbox have an `f1p2`. Buildbox says so, and the laptop offers both in a
    // form it can retype.
    let ambiguous = refused(
        &laptop,
        Some(&asker),
        &["send", "--to", "@buildbox:f1p2", "--text", "which?"],
    );
    assert_eq!(ambiguous["code"], "agent_ambiguous");
    let candidates: Vec<&str> = ambiguous["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|candidate| candidate.as_str().unwrap())
        .collect();
    assert!(
        candidates.contains(&"@buildbox:vvmux:dev/f1p2"),
        "{candidates:?}"
    );
    assert!(
        candidates.contains(&"@buildbox:vvmux:ci/f1p2"),
        "{candidates:?}"
    );
    // Either candidate, retyped, is unambiguous.
    ok(
        &laptop,
        Some(&asker),
        &["send", "--to", "@buildbox:vvmux:ci/f1p2", "--text", "you"],
    );
    let missing = refused(
        &laptop,
        Some(&asker),
        &["send", "--to", "@buildbox:nobody", "--text", "hello?"],
    );
    assert_eq!(missing["code"], "agent_not_found");

    // What the laptop has addressed on buildbox, with the exact form that queues offline.
    let agents = ok(&laptop, None, &["peer", "agents", "buildbox"]);
    let listed = agents["agents"].as_array().unwrap();
    let builder = listed
        .iter()
        .find(|agent| agent["display"] == "vvmux:dev/builder")
        .expect("the builder is known by what buildbox calls it");
    assert_eq!(
        builder["selector"],
        format!("agent://buildbox/{}", remote.builder.endpoint_id)
    );
}

#[test]
fn an_exact_id_queues_while_the_peer_is_away_and_a_name_does_not() {
    let scratch = Scratch::new("offline");
    let laptop = scratch.db("laptop");
    let buildbox = scratch.db("buildbox");
    let asker = bind(&laptop, &["--alias", "asker", "--instance", "a"]);
    let remote = populate(&buildbox);

    // Meet once, so each side knows the other, then disconnect cleanly.
    let bridge = Bridge::start(&scratch, None);
    until("a connection", || connected(&laptop));
    until("buildbox to know the laptop", || {
        !peers(&buildbox).is_empty()
    });
    ok(&buildbox, None, &["peer", "trust", "laptop"]);
    bridge.stop();
    assert!(!connected(&laptop), "stopping released the lease at once");

    let away = refused(
        &laptop,
        Some(&asker),
        &["send", "--to", "@buildbox:builder", "--text", "hi"],
    );
    assert_eq!(away["code"], "peer_unreachable");
    assert!(away["message"].as_str().unwrap().contains("exact id"));

    let exact = format!("@buildbox:{}", remote.builder.endpoint_id);
    let queued = ok(
        &laptop,
        Some(&asker),
        &["send", "--to", &exact, "--text", "waiting for you"],
    );
    assert_eq!(queued["state"], "queued");

    let _bridge = Bridge::start(&scratch, None);
    let mut arrived = None;
    until("the queued mail to arrive once the peer is back", || {
        arrived = received(&buildbox, &remote.builder);
        arrived.is_some()
    });
    assert_eq!(arrived.unwrap()["text"], "waiting for you");
    let _ = remote.lone;
}

#[test]
fn the_positional_form_reaches_through_the_window_a_bridge_runs_in() {
    let scratch = Scratch::new("positional");
    let laptop = scratch.db("laptop");
    let buildbox = scratch.db("buildbox");
    // The asker sits in Vivida window 11; the bridge runs in window 12, the vvssh window.
    let asker = bind(
        &laptop,
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
    let remote = populate(&buildbox);

    let _bridge = Bridge::start(&scratch, Some("s1t2w12"));
    until("a connection", || connected(&laptop));
    until("buildbox to know the laptop", || {
        !peers(&buildbox).is_empty()
    });
    ok(&buildbox, None, &["peer", "trust", "laptop"]);
    let window = &peers(&laptop)[0]["window"];
    assert_eq!(window["runtime"], "vivida");
    assert_eq!(window["instance"], "main");
    assert_eq!(window["window"], 12);

    ok(
        &laptop,
        Some(&asker),
        &[
            "send",
            "--to",
            "s1t2w12f2p5",
            "--text",
            "through the window",
        ],
    );
    let mut arrived = None;
    until("the positional send to arrive", || {
        arrived = received(&buildbox, &remote.lone);
        arrived.is_some()
    });
    assert_eq!(arrived.unwrap()["text"], "through the window");

    // The space and tab are positions and are not consulted; the window is what anchors.
    ok(
        &laptop,
        Some(&asker),
        &["send", "--to", "s9t9w12f2p5", "--text", "same window"],
    );

    // No bridge on window 13: this is an ordinary local selector, and nothing local matches.
    let nowhere = refused(
        &laptop,
        Some(&asker),
        &["send", "--to", "s1t2w13f2p5", "--text", "nobody"],
    );
    assert_eq!(nowhere["code"], "agent_not_found");

    // Ambiguity on the far side comes back retypeable through the positional form too.
    let ambiguous = refused(
        &laptop,
        Some(&asker),
        &["send", "--to", "s1t2w12f1p2", "--text", "which?"],
    );
    assert_eq!(ambiguous["code"], "agent_ambiguous");
}
