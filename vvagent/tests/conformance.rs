//! The adapter conformance suite (plan §13 M3).
//!
//! > Every supported provider passes the same adapter conformance suite, and a version mismatch
//! > removes unsafe capabilities with a clear diagnostic.
//!
//! These run against whatever is actually installed, so the suite asserts *invariants* rather than
//! outcomes: an adapter on a machine with no providers must still be honest about having nothing.
//! The invariants are the ones that keep a capability from being assumed — the failure M0 existed
//! to catch — so a new adapter that quietly grants itself turn-start fails here rather than in
//! somebody's terminal.
//!
//! Version gating and the per-provider specifics are unit-tested in `src/adapter.rs`, where an
//! adapter can be constructed with an arbitrary version.

use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_vvagent");

/// Every provider with an adapter, read from the binary itself rather than duplicated here — so a
/// new adapter is covered by this suite the moment it is registered, instead of silently skipped.
fn providers() -> Vec<String> {
    let scratch = Scratch::new("providers");
    let listed = json(&scratch.db(), None, &["providers"]);
    listed["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["provider"].as_str().unwrap().to_owned())
        .collect()
}

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "vvagent-conf-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        Self(base)
    }

    fn db(&self) -> std::path::PathBuf {
        self.0.join("state").join("mesh.sqlite")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Bind one endpoint for `provider` and report what its adapter grants.
fn capabilities(scratch: &Scratch, provider: &str, native_session: Option<&str>) -> Value {
    let db = scratch.db();
    let bound = json(
        &db,
        None,
        &[
            "bind",
            "--alias",
            "probe",
            "--provider",
            provider,
            "--runtime",
            "wrapper",
            "--instance",
            provider,
        ],
    );
    let identity = (
        bound["endpoint_id"].as_str().unwrap().to_owned(),
        bound["token_file"].as_str().unwrap().to_owned(),
    );
    let mut args = vec!["capabilities"];
    if let Some(session) = native_session {
        args.push("--native-session");
        args.push(session);
    }
    json(&db, Some(&identity), &args)
}

fn json(db: &std::path::Path, identity: Option<&(String, String)>, args: &[&str]) -> Value {
    let mut command = Command::new(BIN);
    command.arg("--db").arg(db).args(args);
    for key in [
        "AGENT_MESH_ENDPOINT",
        "AGENT_MESH_TOKEN_FILE",
        "AGENT_MESH_ADDRESS",
        "AGENT_MESH_RUNTIME",
        "AGENT_MESH_INSTANCE",
        "OPENCODE_SERVER",
    ] {
        command.env_remove(key);
    }
    if let Some((endpoint, token)) = identity {
        command
            .env("AGENT_MESH_ENDPOINT", endpoint)
            .env("AGENT_MESH_TOKEN_FILE", token);
    }
    let output = command.output().expect("vvagent runs");
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    assert!(
        output.status.success(),
        "`vvagent {}` failed: {stderr}",
        args.join(" ")
    );
    serde_json::from_str(&stdout).unwrap_or_else(|err| panic!("bad JSON {stdout:?}: {err}"))
}

fn granted(value: &Value) -> Vec<String> {
    value["granted"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Invariants every adapter must satisfy
// ---------------------------------------------------------------------------------------------

#[test]
fn no_adapter_grants_turn_start_with_nothing_to_start_a_turn_in() {
    // The rule that keeps a capability from being nominal: with no native session there is no
    // thread, session or window to act on, so the capability is *absent*, not merely unused.
    for provider in &providers() {
        let scratch = Scratch::new(&format!("nosession-{provider}"));
        let value = capabilities(&scratch, provider, None);
        assert!(
            !granted(&value).contains(&"external_turn_start".to_string()),
            "{provider} granted turn-start with no session: {value}"
        );
        assert_eq!(
            value["delivery_mode"], "pull_only",
            "{provider} should fall back to pull-only: {value}"
        );
    }
}

#[test]
fn an_absent_turn_start_never_yields_an_activating_delivery_mode() {
    for provider in &providers() {
        let scratch = Scratch::new(&format!("mode-{provider}"));
        for session in [None, Some("probe-session")] {
            let value = capabilities(&scratch, provider, session);
            let activates = matches!(
                value["delivery_mode"].as_str(),
                Some("activate_and_pull") | Some("activate_with_payload")
            );
            assert_eq!(
                activates,
                granted(&value).contains(&"external_turn_start".to_string()),
                "{provider} delivery mode disagrees with its capabilities: {value}"
            );
        }
    }
}

#[test]
fn every_withheld_capability_is_explained() {
    // An absent capability with no note is indistinguishable from one nobody thought about, and
    // the difference is exactly what a person needs when delivery is quieter than expected.
    for provider in &providers() {
        let scratch = Scratch::new(&format!("notes-{provider}"));
        let value = capabilities(&scratch, provider, None);
        let notes = value["notes"].as_array().cloned().unwrap_or_default();
        assert!(
            !notes.is_empty(),
            "{provider} withheld turn-start with no explanation: {value}"
        );
        for note in &notes {
            let text = note.as_str().unwrap();
            assert!(
                !text.is_empty() && text.len() <= 300,
                "unbounded note: {text}"
            );
            // A diagnostic a person reads should not carry the wrapping of the source it was
            // written in.
            assert!(
                !text.contains("  "),
                "note has collapsed whitespace: {text:?}"
            );
            assert!(!text.contains('\n'), "note spans lines: {text:?}");
        }
    }
}

#[test]
fn an_uninstalled_provider_is_reported_not_assumed() {
    // A provider that is not on this machine must lose its actuating capabilities and say so,
    // rather than being driven on the assumption that it is there.
    let scratch = Scratch::new("uninstalled");
    let db = scratch.db();
    let bound = json(
        &db,
        None,
        &[
            "bind",
            "--alias",
            "ghost",
            "--provider",
            "codex",
            "--runtime",
            "wrapper",
            "--instance",
            "ghost",
        ],
    );
    let identity = (
        bound["endpoint_id"].as_str().unwrap().to_owned(),
        bound["token_file"].as_str().unwrap().to_owned(),
    );

    let output = Command::new(BIN)
        .arg("--db")
        .arg(&db)
        .args(["capabilities", "--native-session", "thread-1"])
        .env("AGENT_MESH_ENDPOINT", &identity.0)
        .env("AGENT_MESH_TOKEN_FILE", &identity.1)
        // Point the adapter at something that does not exist.
        .env("AGENT_MESH_CODEX_BIN", "definitely-not-installed-9f3a")
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();

    assert!(value["version"].is_null(), "no version should be reported");
    assert!(!granted(&value).contains(&"external_turn_start".to_string()));
    assert_eq!(value["delivery_mode"], "pull_only");
    let notes = value["notes"].as_array().unwrap();
    assert!(
        notes
            .iter()
            .any(|n| n.as_str().unwrap().contains("not installed")),
        "the diagnostic should say the provider is missing: {notes:?}"
    );
}

#[test]
fn an_unknown_provider_has_no_control_surface_and_says_so() {
    let scratch = Scratch::new("unknown");
    let value = capabilities(&scratch, "some-agent-from-2031", Some("session-1"));
    assert_eq!(value["delivery_mode"], "queued");
    assert!(granted(&value).is_empty());
}

#[test]
fn no_adapter_grants_the_pty_pointer_nudge() {
    // The nudge is the one delivery path that touches a terminal, and the plan admits it only for
    // a provider version with passing race and widget fixtures. None has any, so none has it.
    // When the first fixture lands, this test is what says so out loud.
    for provider in &providers() {
        let scratch = Scratch::new(&format!("nudge-{provider}"));
        for session in [None, Some("probe-session")] {
            let value = capabilities(&scratch, provider, session);
            assert!(
                !granted(&value).contains(&"pty_pointer_nudge".to_string()),
                "{provider} granted a PTY nudge without a passing fixture: {value}"
            );
        }
    }
}

#[test]
fn capabilities_are_deterministic() {
    // Two probes moments apart must agree; a capability that flickers is one that was guessed.
    for provider in &providers() {
        let scratch = Scratch::new(&format!("stable-{provider}"));
        let first = capabilities(&scratch, provider, Some("session-1"));
        let second = capabilities(&scratch, provider, Some("session-1"));
        assert_eq!(
            granted(&first),
            granted(&second),
            "{provider} is not deterministic"
        );
        assert_eq!(first["delivery_mode"], second["delivery_mode"]);
    }
}

#[test]
fn the_provider_list_matches_the_adapter_registry() {
    // If someone adds an adapter without adding it here, the suite would silently skip it.
    let scratch = Scratch::new("registry");
    for provider in &providers() {
        let value = capabilities(&scratch, provider, None);
        assert_eq!(
            value["provider"], *provider,
            "`{provider}` has no adapter, or it reports a different id"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// What is actually installed on this machine
// ---------------------------------------------------------------------------------------------

#[test]
fn installed_providers_report_the_capabilities_m0_established() {
    // Not a requirement — a machine may have none of them — but where a provider *is* present, its
    // adapter must agree with what M0 recorded. This is what catches a provider upgrade silently
    // changing the picture.
    let scratch = Scratch::new("installed");
    for provider in ["codex", "claude", "hermes"] {
        let value = capabilities(&scratch, provider, Some("session-1"));
        let Some(version) = value["version"].as_str() else {
            continue; // not installed here
        };
        let modes = granted(&value);
        let gated = value["notes"].as_array().unwrap().iter().any(|note| {
            let note = note.as_str().unwrap_or_default();
            note.contains("below the tested floor") || note.contains("cannot read a version")
        });
        assert!(
            modes.contains(&"structured_pull".to_string()),
            "{provider} {version} should have mailbox tools: {value}"
        );
        match provider {
            // M0 §2.1: Codex is the one provider with a proven external turn-start.
            "codex" => assert!(
                modes.contains(&"external_turn_start".to_string()) != gated,
                "codex {version} lost turn-start: {value}"
            ),
            // M0 §2.3 and §2.4: neither has an established way into a running TUI.
            _ => assert!(
                !modes.contains(&"external_turn_start".to_string()),
                "{provider} {version} claims an unestablished turn-start: {value}"
            ),
        }
    }
}

/// A rejected reference explains itself in one clean line.
///
/// The same source-wrapping bug that once reached a capability note reached this parser too: a
/// string continued across lines in the source carries that indentation into what a person reads.
#[test]
fn a_refused_reference_reports_a_clean_diagnostic() {
    let scratch = Scratch::new("refs");

    for (reference, expected) in [
        ("nonsense:x", "a reference is"),
        (
            "media:00000000000000000000000000000001/abc",
            "names its binding",
        ),
        (
            "media:00000000000000000000000000000001/abc@latest",
            "`pinned` or `live`",
        ),
    ] {
        // Not the shared `json` helper: that asserts success, and a refused reference is the point.
        let output = Command::new(BIN)
            .arg("--db")
            .arg(scratch.db())
            .args(["send", "--to", "nobody", "--text", "x", "--ref", reference])
            .env_remove("AGENT_MESH_ADDRESS")
            .env_remove("AGENT_MESH_RUNTIME")
            .env_remove("AGENT_MESH_INSTANCE")
            .output()
            .expect("vvagent runs");
        // Errors go to stderr, as JSON, so a caller piping stdout is never handed half an answer.
        let value: Value = serde_json::from_slice(&output.stderr)
            .unwrap_or_else(|err| panic!("vvagent prints JSON even for errors: {err}"));
        let message = value["error"]["message"]
            .as_str()
            .unwrap_or_else(|| panic!("expected an error for {reference:?}: {value}"));

        assert!(
            message.contains(expected),
            "{reference:?} explained itself as {message:?}"
        );
        assert!(
            !message.contains("  "),
            "diagnostic carries its source wrapping: {message:?}"
        );
        assert!(
            !message.contains('\n'),
            "diagnostic spans lines: {message:?}"
        );
    }
}
