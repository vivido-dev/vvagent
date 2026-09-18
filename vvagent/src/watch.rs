//! The per-runtime-instance watcher.
//!
//! This is what makes M1's no-daemon decision work (plan §3.2). A runtime — `vvmux`, Vivido,
//! Vivida — spawns and supervises **one** of these per instance, exactly as `vvmux` already
//! supervises plugin runtimes. It owns the store connection and activates only *its own*
//! endpoints, which gives three properties for free:
//!
//! - no runtime links SQLite;
//! - no runtime speaks another runtime's protocol; and
//! - "keep mesh work off the session actor" is structural rather than a rule to remember, because
//!   the watcher is a separate process.
//!
//! A watcher dies with its runtime instance. That is precisely what distinguishes it from a
//! daemon: the owning runtime starts it, nothing must survive a logout, and if it crashes, every durable
//! guarantee still holds — only promptness is lost, because activation is the one thing it does.

use std::time::Duration;

use agent_mesh_core::{Capabilities, DeliveryMode, Opaque, Result, activation_text, time::now_ms};
use agent_mesh_store::Store;

use crate::adapter::{self, Activation};

/// How long after an activation attempt before the same message may be activated again.
///
/// An agent that was woken and did not pick the message up is not woken again immediately: each
/// attempt costs the user a model turn.
const DEFAULT_BACKOFF_MS: i64 = 60_000;
/// How many times one message may wake its recipient before the watcher gives up on it and leaves
/// it for a human. A peer must not be able to create an unbounded turn loop.
const DEFAULT_MAX_ATTEMPTS: i64 = 3;

pub struct Options {
    pub scope: Opaque,
    pub poll: Duration,
    pub backoff_ms: i64,
    pub max_attempts: i64,
    /// Run one pass and stop. Used by tests and by `vvagent watch --once`.
    pub once: bool,
    /// Report each decision on stdout as NDJSON.
    pub verbose: bool,
    /// Stop when this process is gone. See `--parent-pid`.
    pub parent_pid: Option<u32>,
    /// A layout command to re-derive addresses from each pass.
    pub reconcile: Option<String>,
}

impl Options {
    pub fn new(scope: Opaque) -> Self {
        Self {
            scope,
            poll: Duration::from_millis(1_000),
            backoff_ms: DEFAULT_BACKOFF_MS,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            once: false,
            verbose: false,
            parent_pid: None,
            reconcile: None,
        }
    }
}

/// One pass's outcome, for tests and `--verbose`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pass {
    pub considered: usize,
    pub activated: usize,
    pub refused: usize,
    pub unavailable: usize,
    pub rate_limited: usize,
}

pub fn run(store: &mut Store, options: &Options) -> Result<Pass> {
    let mut total = Pass::default();
    loop {
        if options.parent_pid.is_some_and(|pid| !process_is_alive(pid)) {
            return Ok(total);
        }
        let pass = one_pass(store, options)?;
        total.considered += pass.considered;
        total.activated += pass.activated;
        total.refused += pass.refused;
        total.unavailable += pass.unavailable;
        total.rate_limited += pass.rate_limited;
        if options.once {
            return Ok(total);
        }
        if let Some(pid) = options.parent_pid
            && !process_is_alive(pid)
        {
            // The runtime this watcher belongs to has gone. Nothing durable depends on us being
            // here — only promptness does — so leaving is the whole of the cleanup.
            return Ok(total);
        }
        std::thread::sleep(options.poll);
    }
}

pub fn one_pass(store: &mut Store, options: &Options) -> Result<Pass> {
    // Any process may sweep; correctness never depends on a sweeper running, only promptness.
    let _ = store.sweep(now_ms());

    // Positions first: an endpoint that moved should be woken at where it is now, and a failing
    // layout command must not stop mail being delivered.
    if let Some(command) = &options.reconcile
        && let Err(err) = crate::reconcile::run(store, &options.scope, command)
    {
        report(
            options,
            &options.scope,
            "reconcile_failed",
            Some(&err.message),
        );
    }

    let mut pass = Pass::default();
    let candidates = store.activatable(
        &options.scope,
        now_ms(),
        options.backoff_ms,
        options.max_attempts,
    )?;

    for candidate in candidates {
        pass.considered += 1;
        // The activate gate is a separate decision from enqueue: a message may sit legitimately in
        // a mailbox that its recipient's policy will not spend a turn on.
        if !candidate.decision.allowed {
            pass.refused += 1;
            store.record_activation(
                &candidate.message.message_id,
                &candidate.endpoint_id,
                candidate.mode,
                candidate.decision.rule,
                "policy_refused",
            )?;
            report(
                options,
                &candidate.message.message_id,
                "policy_refused",
                None,
            );
            continue;
        }

        // Each wake-up spends the user's tokens, so a peer allowed to write is not thereby
        // allowed to keep a model busy. The budget is per endpoint and per minute.
        // A peer host has a budget of its own across every local agent, so it cannot spend the
        // full allowance of each of them at once (`vvagent-inter-host-plan.md` §6.3).
        if !store.activation_budget_left(&candidate.endpoint_id, now_ms())?
            || !store.peer_activation_budget_left(&candidate.message.from, now_ms())?
        {
            pass.rate_limited += 1;
            store.record_activation(
                &candidate.message.message_id,
                &candidate.endpoint_id,
                candidate.mode,
                candidate.decision.rule,
                "rate_limited",
            )?;
            report(options, &candidate.message.message_id, "rate_limited", None);
            continue;
        }

        let outcome = activate(&candidate.capabilities, candidate.mode, &candidate, store);
        let (label, detail) = match &outcome {
            Ok(Activation::Started) => {
                pass.activated += 1;
                ("started", None)
            }
            Ok(other) => {
                pass.unavailable += 1;
                (other.as_str(), other.detail().map(str::to_owned))
            }
            Err(err) => {
                pass.unavailable += 1;
                ("error", Some(err.message.clone()))
            }
        };

        store.record_activation(
            &candidate.message.message_id,
            &candidate.endpoint_id,
            candidate.mode,
            candidate.decision.rule,
            label,
        )?;
        report(
            options,
            &candidate.message.message_id,
            label,
            detail.as_deref(),
        );
    }
    Ok(pass)
}

fn activate(
    capabilities: &Capabilities,
    mode: DeliveryMode,
    candidate: &agent_mesh_store::Activatable,
    store: &Store,
) -> Result<Activation> {
    let Some(provider) = capabilities.provider.as_deref() else {
        return Ok(Activation::Unavailable("no provider recorded".into()));
    };
    let Some(adapter) = adapter::for_provider(provider) else {
        return Ok(Activation::Unavailable(format!(
            "no adapter for provider `{provider}`"
        )));
    };
    let Some(native) = capabilities.native_session.as_deref() else {
        return Ok(Activation::Unavailable(
            "no native session to start a turn in".into(),
        ));
    };
    // `activate_with_payload` carries the message body. An adapter that can only reach its
    // provider through argv would put that body where every process this user runs can read it,
    // so it is refused rather than sent. The message stays queued for the agent's next turn.
    if mode == DeliveryMode::ActivateWithPayload && adapter.carries_payload_in_argv() {
        return Ok(Activation::Unavailable(
            "this provider can only be woken through argv, which would expose the message body; \
             give it mailbox tools so a pointer is enough"
                .into(),
        ));
    }

    // Name the sender by the selector a reader could retype, never by a raw id alone.
    let sender = candidate
        .message
        .from
        .endpoint_id
        .as_ref()
        .and_then(|id| store.endpoint(id).ok())
        .map(|endpoint| store.name_of(&endpoint))
        .unwrap_or_else(|| candidate.message.from.kind.as_str().to_owned());

    // In `activate_and_pull` this carries no body — the agent fetches content through its mailbox
    // tools, so the payload never rides the activation channel. That is what keeps the M2 exit
    // criterion true: no request or response payload reaches a PTY or a provider argv.
    let text = activation_text(
        &sender,
        candidate.message.message_id.as_str(),
        mode,
        candidate.message.subject.as_deref(),
        Some(&candidate.message.text),
        candidate.message.kind,
    );

    adapter.activate(native, &text)
}

/// Whether a process still exists.
///
/// Signal zero performs the permission and existence checks without delivering anything, which is
/// exactly the question being asked.
#[cfg(unix)]
pub(crate) fn process_is_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
        || unsafe { libc_kill(pid as i32, 0) } == 0
}

#[cfg(unix)]
unsafe fn libc_kill(pid: i32, signal: i32) -> i32 {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe { kill(pid, signal) }
}

#[cfg(windows)]
pub(crate) fn process_is_alive(pid: u32) -> bool {
    agent_mesh_store::windows::process_is_alive(pid)
}

fn report(options: &Options, message: &Opaque, result: &str, detail: Option<&str>) {
    if !options.verbose {
        return;
    }
    let line = serde_json::json!({
        "message_id": message.as_str(),
        "result": result,
        "detail": detail,
        "at": agent_mesh_core::time::rfc3339(now_ms()),
    });
    println!("{line}");
}
