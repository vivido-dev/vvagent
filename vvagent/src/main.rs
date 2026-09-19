//! `vvagent` — the agent mesh command line.
//!
//! One command surface for every host, so there is no `vvmux agent` / `vivido agent` dialect to
//! keep in step (plan §11.1). Every subcommand prints JSON on stdout and a typed
//! `{"error": {"code", "message"}}` on stderr, because the primary caller is an agent, not a
//! person: an agent that has to parse prose is back where it started.

mod adapter;
mod attach;
mod bridge;
mod mcp;
mod reconcile;
mod remote;
mod watch;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command as ChildCommand;

use agent_mesh_core::time::{now_ms, parse_duration_ms, rfc3339};
use agent_mesh_core::{
    Address, Admit, AgentState, Alias, Draft, ENVELOPE_SCHEMA, Endpoint, Envelope, ErrorCode, Kind,
    Locator, MediaBinding, MeshError, Opaque, Origin, Outcome, Principal, Ref, RuntimeKind,
    Selector, State, hex, qualified_name, resolve,
};
use agent_mesh_store::{Binding, Caller, Message, Store, tokens};
use clap::{Args, Parser, Subcommand};
use serde_json::json;

const ENV_ENDPOINT: &str = "AGENT_MESH_ENDPOINT";
const ENV_TOKEN_FILE: &str = "AGENT_MESH_TOKEN_FILE";
const ENV_INSTANCE: &str = "AGENT_MESH_INSTANCE";
const ENV_RUNTIME: &str = "AGENT_MESH_RUNTIME";
const ENV_ADDRESS: &str = "AGENT_MESH_ADDRESS";

#[derive(Parser)]
#[command(
    name = "vvagent",
    version,
    about = "Address, message, and answer agents across terminal runtimes",
    disable_help_subcommand = true
)]
struct Cli {
    /// Store path. Defaults to `$AGENT_MESH_DB`, else `$XDG_STATE_HOME/vivido/agent-mesh`.
    #[arg(long, global = true)]
    db: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report who this process is to the mesh.
    Whoami,
    /// List every endpoint, live or durable.
    List {
        /// Only endpoints currently bound.
        #[arg(long)]
        online: bool,
    },
    /// Bind an endpoint without running a child. For runtimes that own their own process.
    Bind(BindArgs),
    /// Release a binding. The mailbox and its pending work survive.
    Unbind {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        incarnation: String,
    },
    /// Bind an endpoint, run a command as that agent, and release the binding when it exits.
    Run {
        #[command(flatten)]
        bind: BindArgs,
        /// The command to run, after `--`.
        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
    },
    /// Report this endpoint's lifecycle state, bumping its generation.
    State {
        #[arg(long)]
        state: String,
    },
    /// Send a request or notice, to one agent or to a group.
    Send {
        /// An endpoint id, `runtime:instance/alias`, or a bare alias.
        #[arg(long, conflicts_with = "group", required_unless_present = "group")]
        to: Option<String>,
        /// Peer host when addressing an agent on a remote host (e.g. `--peer 9600x --to builder`).
        /// Avoids PowerShell splatting with `@host:alias`.
        #[arg(long)]
        peer: Option<String>,
        /// Fan out to every member of a group. Each member gets its own message and its own
        /// outcome; a group send is never reported as one atomic result.
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        subject: Option<String>,
        /// The message body. Prefer `--text-file` for anything sensitive: argv is readable by
        /// every process this user runs.
        #[arg(long, conflicts_with = "text_file")]
        text: Option<String>,
        /// Read the body from a file, or from stdin with `-`.
        #[arg(long)]
        text_file: Option<String>,
        /// `file:/absolute/path` or `media:<instance>/<resource>@pinned|live`. Repeatable, up to 16.
        #[arg(long = "ref")]
        refs: Vec<String>,
        /// How long the request stays deliverable, e.g. `10m`.
        #[arg(long, value_parser = parse_duration_ms)]
        expires_in: Option<i64>,
        /// Retrying with the same key and the same content replays instead of duplicating.
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Send a `notice`, which expects no answer.
        #[arg(long)]
        notice: bool,
        /// A local file to hand the recipient. Repeatable, up to 8. For an agent on another host
        /// the file is first copied there through the vvssh window carrying that host's bridge,
        /// and the message refers to the verified copy.
        #[arg(long = "attach", value_name = "FILE")]
        attachments: Vec<String>,
        /// The largest attachment to accept, in bytes. Default 1 GiB.
        #[arg(long)]
        max_attach_bytes: Option<u64>,
    },
    /// Check a message's file references against the files they name on this host.
    Ref {
        #[command(subcommand)]
        command: RefCommand,
    },
    /// List this endpoint's mailbox.
    Inbox {
        /// Repeatable. Default: everything still pending.
        #[arg(long = "status")]
        statuses: Vec<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Claim the oldest queued message under a bounded lease.
    Receive {
        #[arg(long, value_parser = parse_duration_ms)]
        lease: Option<i64>,
    },
    /// Answer a request that was addressed to this endpoint.
    Reply {
        #[arg(long)]
        to_request: String,
        /// completed | answered | refused | failed | cancelled
        #[arg(long, default_value = "completed")]
        outcome: String,
        #[arg(long, conflicts_with = "text_file")]
        text: Option<String>,
        /// Read the reply from a file, or from stdin with `-`.
        #[arg(long)]
        text_file: Option<String>,
        #[arg(long = "ref")]
        refs: Vec<String>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Block until a request is answered, cancelled, or expires.
    ///
    /// With `--group-send`, waits for a quorum of the members the fan-out actually reached.
    Wait {
        #[arg(
            long,
            conflicts_with = "group_send",
            required_unless_present = "group_send"
        )]
        request: Option<String>,
        /// The fan-out to wait on, from `send --group`.
        #[arg(long)]
        group_send: Option<String>,
        /// How many answers are enough. Defaults to every member that accepted the request.
        #[arg(long)]
        quorum: Option<usize>,
        #[arg(long, default_value = "10m", value_parser = parse_duration_ms)]
        timeout: i64,
        #[arg(long, default_value = "250ms", value_parser = parse_duration_ms)]
        poll: i64,
    },
    /// Ask that a request stop. Queued work is removed; delivered work is only asked.
    Cancel {
        #[arg(long)]
        request: String,
    },
    /// Why a message was accepted, refused, or moved. Metadata only, never its body.
    Explain { message_id: String },
    /// Show or change an endpoint's policy gates.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Move an endpoint to a new position after its window, frame or pane was rearranged.
    ///
    /// A runtime calls this when its layout changes. It needs no endpoint id: the endpoint is
    /// found by the part of the address that survives a move — a window id, frame or pane keeps
    /// its number when it is dragged to another space or tab.
    Readdress {
        /// The endpoint's new full address, e.g. `s3t1w42`.
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "wrapper")]
        runtime: String,
        #[arg(long)]
        instance: Option<String>,
        #[arg(long)]
        instance_id: Option<String>,
    },
    /// Manage named sets of agents.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    /// Re-derive endpoint addresses from a runtime's own layout.
    ///
    /// Positions move — a window dragged to another space changes `s`, reordering tabs changes
    /// `t` — and the environment a pane inherited at creation cannot be edited afterwards. This
    /// asks the runtime where everything is now and corrects any address that has drifted. Only
    /// the address changes; ids, mailboxes and pending work are untouched.
    Reconcile {
        /// A command printing layout JSON, e.g. `vivida msg layout`.
        #[arg(long)]
        from: String,
        #[arg(long, default_value = "wrapper")]
        runtime: String,
        #[arg(long)]
        instance: Option<String>,
        #[arg(long)]
        instance_id: Option<String>,
    },
    /// List every provider with an adapter and what it can do on this machine.
    ///
    /// Answers "why is nothing waking my agent" without needing an endpoint: it reports the
    /// installed version, what was granted, and why anything is missing.
    Providers,
    /// Return lapsed claims to the queue and retire messages past their deadline.
    Sweep,
    /// Serve the mailbox as MCP tools over stdio. Point a provider's MCP config at this.
    ///
    /// This is `structured_pull`: it lets a *running* model read its mailbox and answer. It does
    /// not wake an idle agent — that is the watcher's job.
    Mcp,
    /// Establish and record what an endpoint's provider can actually do.
    ///
    /// Capabilities belong to one provider version and one binding. Re-run this after a provider
    /// upgrade; a version that has not been tested loses the capability rather than keeping it.
    Capabilities {
        /// The provider's own session/thread handle, needed to start a turn in it.
        #[arg(long)]
        native_session: Option<String>,
        /// Record for another endpoint instead of the caller's own.
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Carry mail between this host and one peer host over a byte stream.
    ///
    /// `--dial PEER -- COMMAND…` runs COMMAND — normally `ssh HOST vvagent bridge --serve` — and
    /// bridges over its stdin and stdout. `--serve` bridges over this process's own, which is what
    /// that command runs on the far side. One bridge per peer is active; another stands aside.
    ///
    /// The exit status says what a supervisor should do next: 0 the connection closed after
    /// working, 75 another bridge already serves this peer, 69 nothing answered (no connection,
    /// or no `vvagent` on the far side), 74 the carrier broke mid-session, 1 refused — a pinned
    /// label answered by a different store, or a protocol the two ends do not share.
    Bridge {
        /// The peer's label, pinned to whichever store answers. An SSH destination such as
        /// `user@Build.Example.com` is accepted and names the peer by its host.
        #[arg(long, conflicts_with = "serve", required_unless_present = "serve")]
        dial: Option<String>,
        #[arg(long)]
        serve: bool,
        /// When serving: call the dialling host this instead of the name it suggests.
        #[arg(long, requires = "serve")]
        label: Option<String>,
        /// The name to suggest the other end call this host. Defaults to the host name.
        #[arg(long)]
        name: Option<String>,
        /// Exit when this process does.
        #[arg(long)]
        parent_pid: Option<u32>,
        /// With `--dial`: exit, cleanly, when this process's own stdin reaches end of file. How a
        /// supervisor ends a bridge so both ends release their leases at once.
        #[arg(long, requires = "dial")]
        stdin_leash: bool,
        /// With `--dial`: the command whose stdin and stdout are the carrier.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// See and manage the peer hosts this store exchanges mail with.
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
    /// Watch this runtime instance's endpoints and wake them when mail arrives.
    ///
    /// A runtime spawns and supervises one of these per instance. It activates only its own
    /// endpoints, so no runtime needs the store or another runtime's protocol.
    Watch {
        /// The runtime instance to watch. Defaults to the caller's own.
        #[arg(long)]
        instance_id: Option<String>,
        #[arg(long)]
        instance: Option<String>,
        #[arg(long, default_value = "wrapper")]
        runtime: String,
        #[arg(long, default_value = "1s", value_parser = parse_duration_ms)]
        poll: i64,
        /// How long before the same message may wake its recipient again.
        #[arg(long, default_value = "60s", value_parser = parse_duration_ms)]
        backoff: i64,
        /// How many times one message may wake its recipient before it waits for a human.
        #[arg(long, default_value_t = 3)]
        max_attempts: i64,
        /// Run one pass and exit.
        #[arg(long)]
        once: bool,
        /// Print each decision as NDJSON.
        #[arg(long)]
        verbose: bool,
        /// Exit when this process does.
        ///
        /// A watcher must not outlive its runtime instance. Rather than every runtime growing a
        /// supervisor, the watcher holds its own leash: it checks the pid each pass and stops when
        /// it is gone. A recycled pid can only keep it alive a little longer, which costs nothing
        /// — a watcher whose endpoints are all offline activates nothing.
        #[arg(long)]
        parent_pid: Option<u32>,
        /// Re-derive addresses from this layout command each pass, e.g. `vivida msg layout`.
        #[arg(long)]
        reconcile: Option<String>,
    },
}

#[derive(Args, Clone)]
struct BindArgs {
    #[arg(long)]
    alias: Option<String>,
    #[arg(long)]
    provider: Option<String>,
    /// vvmux | vivido | vivida | wrapper
    #[arg(long, default_value = "wrapper")]
    runtime: String,
    /// The runtime instance's name. With `--runtime wrapper` it also derives the instance id, so
    /// the same name rebinds the same durable slot after a restart.
    #[arg(long)]
    instance: Option<String>,
    /// An explicit runtime instance id, for a runtime that already has one.
    #[arg(long)]
    instance_id: Option<String>,
    /// Where this endpoint sits: an address like `f1p2` or `s2t2w3f1p2` (§6.3). A runtime supplies
    /// the levels it owns; anything a host already covers arrives through `AGENT_MESH_ADDRESS`.
    #[arg(long)]
    address: Option<String>,
}

#[derive(Subcommand)]
enum GroupCommand {
    /// Create a group, or replace its membership.
    Create {
        name: String,
        /// A selector per member: alias, address, or endpoint id. Repeatable.
        #[arg(long = "member", required = true)]
        members: Vec<String>,
    },
    /// Add one member, leaving the rest alone.
    Add {
        name: String,
        selector: String,
    },
    /// Remove one member.
    Remove {
        name: String,
        selector: String,
    },
    /// Show every group and who is in it.
    List,
    Delete {
        name: String,
    },
}

#[derive(Subcommand)]
enum RefCommand {
    /// Open each file a message refers to on this host and check its length and SHA-256, however
    /// large. `receive` does this inline for files up to 256 MiB.
    Verify { message_id: String },
}

#[derive(Subcommand)]
enum PeerCommand {
    /// Connect to a peer over SSH and bridge in the foreground until the connection closes.
    ///
    /// `vvssh` does this for you. From a plain terminal: `vvagent peer connect buildbox`, with any
    /// extra SSH options after `--`.
    Connect {
        /// The SSH destination, which also names the peer.
        destination: String,
        #[arg(trailing_var_arg = true)]
        ssh_options: Vec<String>,
    },
    /// Every peer, whether a bridge is connected, and how many of its agents this store knows.
    List,
    /// The agents on one peer that this store has addressed or heard from, with the exact
    /// `agent://<peer>/<id>` selector for each — the form that queues while the peer is away.
    Agents {
        label: String,
    },
    /// Admit remote-originated requests and notices from every agent on this peer, where a gate
    /// admits trust. Replies to your own requests never need it.
    Trust {
        label: String,
    },
    Untrust {
        label: String,
    },
    /// Forget a peer: its waiting mail becomes undeliverable, and its label is freed for another
    /// store. A later connection under the same label is a new peer.
    Forget {
        label: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    Show,
    /// Admit a peer by name, stored as its endpoint id.
    ///
    /// A rule that kept the alias would follow the name to whatever answered to it next; storing
    /// the id means the rule keeps meaning the agent it was written about.
    Trust {
        /// An alias, address, or endpoint id — anything `send --to` accepts.
        selector: String,
    },
    /// Withdraw a peer's trust.
    Untrust {
        selector: String,
    },
    /// Allow or forbid this endpoint to send files with `--attach`.
    Attach {
        /// allow | deny
        mode: String,
    },
    Set {
        /// nobody | replies_only | replies_and_team | replies_and_trusted | anyone
        #[arg(long)]
        enqueue: Option<String>,
        #[arg(long)]
        make_visible: Option<String>,
        #[arg(long)]
        activate: Option<String>,
        #[arg(long)]
        pty_nudge: Option<bool>,
        #[arg(long)]
        interrupt: Option<bool>,
        /// off | runtime_instance | space
        #[arg(long)]
        team: Option<String>,
        /// Messages accepted per minute, whoever sends them.
        #[arg(long)]
        max_inbound_per_minute: Option<u32>,
        /// Turns this endpoint may be woken for per minute.
        #[arg(long)]
        max_auto_turns_per_minute: Option<u32>,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            let body = json!({"error": {"code": err.code.as_str(), "message": err.message,
                                        "candidates": err.candidates}});
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr, "{body}");
            std::process::ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> agent_mesh_core::Result<std::process::ExitCode> {
    let path = match cli.db {
        Some(path) => path,
        None => Store::default_path()?,
    };
    let mut store = Store::open(&path)?;

    match cli.command {
        Command::Whoami => {
            let caller = authenticate(&mut store)?;
            let endpoint = caller
                .principal
                .endpoint_id
                .as_ref()
                .map(|id| store.endpoint(id))
                .transpose()?;
            emit(&json!({
                "principal": caller.principal.kind.as_str(),
                "endpoint_id": caller.principal.endpoint_id.as_ref().map(Opaque::as_str),
                "incarnation_id": caller.principal.incarnation_id.as_ref().map(Opaque::as_str),
                "runtime_instance_id": caller.scope.as_ref().map(Opaque::as_str),
                "runtime": endpoint.as_ref().map(|e| e.locator.kind.as_str()),
                "instance": endpoint.as_ref().and_then(|e| e.locator.instance_name.as_deref()),
                "address": endpoint.as_ref().and_then(|e| e.locator.address.as_ref()).map(ToString::to_string),
                "store": path.display().to_string(),
            }));
        }
        Command::List { online } => {
            let endpoints = store.list_endpoints()?;
            let rows: Vec<_> = endpoints
                .iter()
                .filter(|endpoint| !online || endpoint.online)
                .map(endpoint_json)
                .collect();
            emit(&json!({"endpoints": rows}));
        }
        Command::Bind(args) => {
            let bound = store.bind(&binding_from(&args)?)?;
            let token_file =
                tokens::write(&bound.endpoint_id, &bound.incarnation_id, &bound.token)?;
            emit(&json!({
                "endpoint_id": bound.endpoint_id.as_str(),
                "incarnation_id": bound.incarnation_id.as_str(),
                "rebound": bound.rebound,
                "token_file": token_file.display().to_string(),
            }));
        }
        Command::Unbind {
            endpoint,
            incarnation,
        } => {
            let endpoint = Opaque::parse(&endpoint)?;
            let incarnation = Opaque::parse(&incarnation)?;
            store.unbind(&endpoint, &incarnation)?;
            tokens::remove(&endpoint, &incarnation)?;
            emit(&json!({"unbound": endpoint.as_str()}));
        }
        Command::Run { bind, argv } => {
            return run_wrapped(&mut store, &bind, &argv);
        }
        Command::State { state } => {
            let caller = authenticate(&mut store)?;
            let (endpoint, _) = require_agent(&caller)?;
            let generation = store.set_state(&endpoint, AgentState::parse(&state)?)?;
            emit(&json!({"endpoint_id": endpoint.as_str(), "state": state,
                         "state_generation": generation}));
        }
        Command::Send {
            to,
            peer,
            group,
            subject,
            text,
            text_file,
            refs,
            expires_in,
            idempotency_key,
            notice,
            attachments,
            max_attach_bytes,
        } => {
            let caller = authenticate(&mut store)?;
            if group.is_some() && !attachments.is_empty() {
                return Err(MeshError::new(
                    ErrorCode::InvalidRequest,
                    "attachments go to one agent at a time; send them with --to",
                ));
            }
            let body = body_of(text, text_file)?;
            let refs = parse_refs(&refs)?;
            let kind = if notice { Kind::Notice } else { Kind::Request };
            let key = idempotency_key.unwrap_or_else(fresh_key);

            match group {
                Some(name) => {
                    let name = Alias::parse(&name)?;
                    let members = store.group_members(&name)?;
                    if members.is_empty() {
                        return Err(MeshError::new(
                            ErrorCode::InvalidRequest,
                            format!("group `{name}` has no members"),
                        ));
                    }
                    // The membership is snapshotted here, before anything is sent, so later
                    // changes to the group cannot change what this send meant.
                    let send_id = store.open_group_send(&name, &caller, &members)?;

                    // Each member is its own insert with its own outcome. A group send is never
                    // reported as one atomic result: some mailboxes may be full, some policies may
                    // refuse, and saying "sent" over the top of that would be a lie.
                    let mut rows = Vec::new();
                    let (mut accepted, mut rejected) = (0usize, 0usize);
                    for member in &members {
                        let draft = Draft {
                            to: member.clone(),
                            kind,
                            reply_to: None,
                            outcome: None,
                            subject: subject.clone(),
                            text: body.clone(),
                            refs: refs.clone(),
                            // Per-member, so a retry of the whole fan-out replays what landed and
                            // completes what did not.
                            idempotency_key: format!("{key}:{member}"),
                            expires_in_ms: expires_in,
                        };
                        let selector = store
                            .endpoint(member)
                            .ok()
                            .map(|endpoint| qualified_name(&endpoint));
                        match store.send(&caller, &draft) {
                            Ok(message) => {
                                store.attach_to_group_send(&message.message_id, &send_id)?;
                                accepted += 1;
                                rows.push(json!({
                                    "endpoint_id": member.as_str(),
                                    "selector": selector,
                                    "result": "accepted",
                                    "message_id": message.message_id.as_str(),
                                }));
                            }
                            Err(err) => {
                                rejected += 1;
                                rows.push(json!({
                                    "endpoint_id": member.as_str(),
                                    "selector": selector,
                                    "result": err.code.as_str(),
                                    "message": err.message,
                                }));
                            }
                        }
                    }
                    emit(&json!({
                        "group": name.as_str(),
                        "group_send_id": send_id.as_str(),
                        "members": members.len(),
                        "accepted": accepted,
                        "rejected": rejected,
                        "results": rows,
                    }));
                }
                None => {
                    let to = to.expect("clap requires --to without --group");
                    let destination = match peer.as_deref() {
                        Some(p) => {
                            if to.starts_with('@')
                                || to.starts_with("agent://")
                                || to.starts_with("peer:")
                            {
                                to
                            } else {
                                format!("@{p}:{to}")
                            }
                        }
                        None => to,
                    };
                    let target = resolve_selector(&mut store, &destination, &caller)?;
                    let attached = attach::attach(
                        &mut store,
                        &caller,
                        &target,
                        &key,
                        &attachments,
                        max_attach_bytes,
                    )?;
                    let mut refs = refs;
                    refs.extend(attached.refs.iter().cloned());
                    let draft = Draft {
                        to: target.endpoint_id.clone(),
                        kind,
                        reply_to: None,
                        outcome: None,
                        subject,
                        text: body,
                        refs,
                        idempotency_key: key,
                        expires_in_ms: expires_in,
                    };
                    let message = store
                        .send(&caller, &draft)
                        .map_err(|err| attached.explain(err))?;
                    emit(&envelope_json(&message));
                }
            }
        }
        Command::Inbox { statuses, limit } => {
            let caller = authenticate(&mut store)?;
            let (endpoint, _) = require_agent(&caller)?;
            let states = if statuses.is_empty() {
                vec![
                    State::Queued,
                    State::Claimed,
                    State::Delivered,
                    State::CancellationRequested,
                ]
            } else {
                statuses
                    .iter()
                    .map(|value| State::parse(value))
                    .collect::<agent_mesh_core::Result<_>>()?
            };
            let messages = store.inbox(&endpoint, &states, limit)?;
            emit(&json!({"messages": messages.iter().map(envelope_json)
                                             .collect::<Vec<_>>()}));
        }
        Command::Receive { lease } => {
            let caller = authenticate(&mut store)?;
            match store.claim(&caller, lease)? {
                Some(message) => {
                    // Files named on this host are checked as the message is taken: a reference
                    // is a peer's claim until the bytes match it.
                    let mut rendered = envelope_json(&message);
                    let checked = attach::verify_inline(&message.refs);
                    if !checked.is_empty() {
                        rendered["attachments"] = json!(checked);
                    }
                    emit(&rendered);
                }
                None => emit(&json!({"messages": []})),
            }
        }
        Command::Reply {
            to_request,
            outcome,
            text,
            text_file,
            refs,
            idempotency_key,
        } => {
            let caller = authenticate(&mut store)?;
            let request_id = Opaque::parse(&to_request)?;
            let response = store.respond(
                &caller,
                &request_id,
                Outcome::parse(&outcome)?,
                &body_of(text, text_file)?,
                parse_refs(&refs)?,
                &idempotency_key.unwrap_or_else(|| format!("reply-{to_request}")),
            )?;
            emit(&envelope_json(&response));
        }
        Command::Wait {
            request,
            group_send,
            quorum,
            timeout,
            poll,
        } => {
            let deadline = now_ms().saturating_add(timeout);
            let poll = poll.clamp(10, 5_000);

            if let Some(send) = group_send {
                let send = Opaque::parse(&send)?;
                // A quorum counts against the members this fan-out actually reached, not against
                // the group's membership now and not against members whose mailbox refused it.
                let asked: Vec<Opaque> = store
                    .group_send_requests(&send)?
                    .into_iter()
                    .map(|message| message.message_id)
                    .collect();
                let needed = quorum.unwrap_or(asked.len()).min(asked.len());
                loop {
                    let _ = store.sweep(now_ms());
                    let mut answered = Vec::new();
                    let mut outstanding = Vec::new();
                    for request_id in &asked {
                        match store.response_for(request_id)? {
                            Some(response) => answered.push(json!({
                                "request": request_id.as_str(),
                                "outcome": response.outcome.map(Outcome::as_str),
                                "text": response.text,
                            })),
                            None => {
                                let state = store.message(request_id)?.state;
                                outstanding.push(json!({
                                    "request": request_id.as_str(),
                                    "state": state.as_str(),
                                }));
                            }
                        }
                    }
                    let reached = answered.len() >= needed;
                    if reached || now_ms() >= deadline {
                        emit(&json!({
                            "group_send_id": send.as_str(),
                            "resolution": if reached { "quorum" } else { "timeout" },
                            "asked": asked.len(),
                            "quorum": needed,
                            "answered": answered.len(),
                            "responses": answered,
                            "outstanding": outstanding,
                        }));
                        return Ok(if reached {
                            std::process::ExitCode::SUCCESS
                        } else {
                            std::process::ExitCode::from(4)
                        });
                    }
                    std::thread::sleep(std::time::Duration::from_millis(poll as u64));
                }
            }

            let request_id = Opaque::parse(&request.expect("clap requires one of the two"))?;
            loop {
                // Any process may sweep; correctness never depends on a sweeper running.
                let _ = store.sweep(now_ms());
                if let Some(response) = store.response_for(&request_id)? {
                    emit(&envelope_json(&response));
                    return Ok(std::process::ExitCode::SUCCESS);
                }
                let request = store.message(&request_id)?;
                if matches!(
                    request.state,
                    State::Cancelled | State::Expired | State::Undeliverable
                ) {
                    emit(&json!({
                        "request": request_id.as_str(),
                        "resolution": request.state.as_str(),
                        "failure": request.failure,
                    }));
                    return Ok(std::process::ExitCode::from(3));
                }
                if now_ms() >= deadline {
                    // A client timeout never mutates the request (plan §7.2 rule 6).
                    emit(&json!({
                        "request": request_id.as_str(),
                        "resolution": "timeout",
                        "state": request.state.as_str(),
                    }));
                    return Ok(std::process::ExitCode::from(4));
                }
                std::thread::sleep(std::time::Duration::from_millis(poll as u64));
            }
        }
        Command::Cancel { request } => {
            let caller = authenticate(&mut store)?;
            let request_id = Opaque::parse(&request)?;
            let mut state = store.cancel(&caller, &request_id)?;
            if let Some(incarnation) = store.interrupt_target(&request_id)? {
                let message = store.message(&request_id)?;
                let capabilities = store.capabilities(&message.to_endpoint)?;
                if capabilities.has(agent_mesh_core::Capability::ExternalInterrupt)
                    && let (Some(provider), Some(native)) =
                        (&capabilities.provider, &capabilities.native_session)
                    && let Some(adapter) = adapter::for_provider(provider)
                    && adapter.interrupt(native)? == adapter::Interruption::Confirmed
                {
                    state = store.confirm_interrupt(&request_id, &incarnation)?;
                }
            }
            emit(&json!({"request": request_id.as_str(), "state": state.as_str()}));
        }
        Command::Explain { message_id } => {
            let id = Opaque::parse(&message_id)?;
            let message = store.message(&id)?;
            let rows: Vec<_> = store
                .audit_for(&id)?
                .into_iter()
                .map(|row| {
                    json!({
                        "at": rfc3339(row.at_ms),
                        "operation": row.operation,
                        "from_state": row.from_state,
                        "to_state": row.to_state,
                        "rule": row.rule,
                        "bytes": row.bytes,
                        "result": row.result,
                    })
                })
                .collect();
            emit(&json!({
                "message_id": id.as_str(),
                "state": message.state.as_str(),
                "kind": message.kind.as_str(),
                "audit": rows,
            }));
        }
        Command::Policy { command } => {
            let caller = authenticate(&mut store)?;
            let (endpoint, _) = require_agent(&caller)?;
            match command {
                PolicyCommand::Show => {
                    let policy = store.policy(&endpoint)?;
                    emit(&serde_json::to_value(&policy).map_err(json_err)?);
                }
                PolicyCommand::Trust { selector } => {
                    let peer = resolve_selector(&mut store, &selector, &caller)?;
                    let mut policy = store.policy(&endpoint)?;
                    if !policy.trusted.contains(&peer.endpoint_id) {
                        policy.trusted.push(peer.endpoint_id.clone());
                    }
                    store.set_policy(&endpoint, &policy)?;
                    emit(&json!({
                        "trusted": peer.endpoint_id.as_str(),
                        "selector": qualified_name(&peer),
                    }));
                }
                PolicyCommand::Untrust { selector } => {
                    let mut policy = store.policy(&endpoint)?;
                    // Resolve if we can, but a peer that has gone should still be removable by the
                    // id a rule was written with.
                    let target = resolve_selector(&mut store, &selector, &caller)
                        .map(|peer| peer.endpoint_id)
                        .or_else(|_| Opaque::parse(&selector))?;
                    let before = policy.trusted.len();
                    policy.trusted.retain(|id| id != &target);
                    store.set_policy(&endpoint, &policy)?;
                    emit(&json!({
                        "untrusted": target.as_str(),
                        "was_trusted": policy.trusted.len() < before,
                    }));
                }
                PolicyCommand::Attach { mode } => {
                    let mut policy = store.policy(&endpoint)?;
                    policy.attach = match mode.as_str() {
                        "allow" => true,
                        "deny" => false,
                        other => {
                            return Err(MeshError::new(
                                ErrorCode::InvalidRequest,
                                format!("`{other}` is not allow or deny"),
                            ));
                        }
                    };
                    store.set_policy(&endpoint, &policy)?;
                    emit(&json!({ "endpoint_id": endpoint.as_str(), "attach": policy.attach }));
                }
                PolicyCommand::Set {
                    enqueue,
                    make_visible,
                    activate,
                    pty_nudge,
                    interrupt,
                    team,
                    max_inbound_per_minute,
                    max_auto_turns_per_minute,
                } => {
                    let mut policy = store.policy(&endpoint)?;
                    if let Some(value) = enqueue {
                        policy.enqueue = parse_admit(&value)?;
                    }
                    if let Some(value) = make_visible {
                        policy.make_visible = parse_admit(&value)?;
                    }
                    if let Some(value) = activate {
                        policy.activate = parse_admit(&value)?;
                    }
                    if let Some(value) = pty_nudge {
                        policy.pty_nudge = value;
                    }
                    if let Some(value) = interrupt {
                        policy.interrupt = value;
                    }
                    if let Some(value) = team {
                        policy.team = agent_mesh_core::TeamScope::parse(&value)?;
                    }
                    if let Some(value) = max_inbound_per_minute {
                        policy.max_inbound_per_minute = value;
                    }
                    if let Some(value) = max_auto_turns_per_minute {
                        policy.max_auto_turns_per_minute = value;
                    }
                    store.set_policy(&endpoint, &policy)?;
                    emit(&serde_json::to_value(&policy).map_err(json_err)?);
                }
            }
        }
        Command::Mcp => {
            let caller = authenticate(&mut store)?;
            mcp::serve(&mut store, &caller)?;
        }
        Command::Capabilities {
            native_session,
            endpoint,
        } => {
            let caller = authenticate(&mut store)?;
            let target = match endpoint {
                Some(id) => Opaque::parse(&id)?,
                None => require_agent(&caller)?.0,
            };
            let record = store.endpoint(&target)?;
            let provider = record.provider.clone().ok_or_else(|| {
                MeshError::new(
                    ErrorCode::InvalidRequest,
                    "this endpoint has no provider, so there is nothing to establish",
                )
            })?;
            let capabilities = match adapter::for_provider(&provider) {
                Some(adapter) => adapter.capabilities(native_session.as_deref()),
                None => agent_mesh_core::Capabilities {
                    provider: Some(provider.clone()),
                    native_session: native_session.clone(),
                    ..Default::default()
                },
            };
            store.set_capabilities(&target, &capabilities)?;
            emit(&json!({
                "endpoint_id": target.as_str(),
                "provider": capabilities.provider,
                "version": capabilities.version,
                "native_session": capabilities.native_session,
                "granted": capabilities.granted.iter()
                    .map(|c| c.as_str()).collect::<Vec<_>>(),
                // Why anything is missing. An unexplained absence is indistinguishable from one
                // nobody thought about, and that difference is what a person needs when delivery
                // is quieter than they expected.
                "notes": capabilities.notes,
                "delivery_mode": capabilities.delivery_mode().as_str(),
            }));
        }
        Command::Watch {
            instance_id,
            instance,
            runtime,
            poll,
            backoff,
            max_attempts,
            once,
            verbose,
            parent_pid,
            reconcile: reconcile_from,
        } => {
            let scope = match instance_id {
                Some(id) => Opaque::parse(&id)?,
                None => match instance {
                    Some(name) => derived_instance_id(RuntimeKind::parse(&runtime)?, &name),
                    None => {
                        let caller = authenticate(&mut store)?;
                        caller.scope.clone().ok_or_else(|| {
                            MeshError::new(
                                ErrorCode::InvalidRequest,
                                "give --instance NAME or --instance-id ID to say what to watch",
                            )
                        })?
                    }
                },
            };
            let options = watch::Options {
                poll: std::time::Duration::from_millis(poll.max(50) as u64),
                backoff_ms: backoff,
                max_attempts,
                once,
                verbose,
                parent_pid,
                reconcile: reconcile_from,
                ..watch::Options::new(scope)
            };
            let pass = watch::run(&mut store, &options)?;
            if once {
                emit(&json!({
                    "considered": pass.considered,
                    "activated": pass.activated,
                    "refused": pass.refused,
                    "unavailable": pass.unavailable,
                    "rate_limited": pass.rate_limited,
                }));
            }
        }
        Command::Ref {
            command: RefCommand::Verify { message_id },
        } => {
            let caller = authenticate(&mut store)?;
            let message = store.message(&Opaque::parse(&message_id)?)?;
            let party = caller.principal.endpoint_id.as_ref();
            if party != Some(&message.to_endpoint) && party != message.from.endpoint_id.as_ref() {
                return Err(MeshError::new(
                    ErrorCode::NotAuthorized,
                    "only the sender or the recipient of a message may check its references",
                ));
            }
            emit(&json!({
                "message_id": message.message_id.as_str(),
                "attachments": attach::verify(&message.refs, u64::MAX),
            }));
        }
        Command::Bridge {
            dial,
            serve,
            label,
            name,
            parent_pid,
            stdin_leash,
            command,
        } => {
            let options = BridgeOptions {
                dial,
                serve,
                label,
                name,
                parent_pid,
                stdin_leash,
            };
            return run_bridge(&mut store, options, command);
        }
        Command::Peer { command } => match command {
            PeerCommand::Connect {
                destination,
                ssh_options,
            } => {
                let ssh = std::env::var("AGENT_MESH_SSH").unwrap_or_else(|_| "ssh".into());
                let mut carrier = vec![ssh, "-T".into()];
                carrier.extend(ssh_options);
                carrier.push(destination.clone());
                carrier.push("vvagent bridge --serve".into());
                let options = BridgeOptions {
                    dial: Some(destination),
                    serve: false,
                    label: None,
                    name: None,
                    parent_pid: None,
                    stdin_leash: false,
                };
                return run_bridge(&mut store, options, carrier);
            }
            PeerCommand::List => {
                let now = now_ms();
                let mut rows = Vec::new();
                for peer in store.list_peers()? {
                    let proxies = store.list_proxies(&peer.peer_id)?;
                    let lease = peer.lease.as_ref().filter(|lease| lease.is_live(now));
                    rows.push(json!({
                        "label": peer.label.as_str(),
                        "peer_id": peer.peer_id.as_str(),
                        "host_id": peer.host_id.as_str(),
                        "trusted": peer.trusted,
                        "connected": lease.is_some(),
                        "window": lease.and_then(|lease| lease.anchor.as_ref()).map(|anchor| {
                            json!({
                                "runtime": anchor.runtime.as_str(),
                                "instance": anchor.instance,
                                "window": anchor.window,
                            })
                        }),
                        "agents": proxies.len(),
                    }));
                }
                emit(&json!({ "peers": rows }));
            }
            PeerCommand::Agents { label } => {
                let label = agent_mesh_core::PeerLabel::parse(&label)?;
                let peer = store.peer(&label)?;
                let rows: Vec<_> = store
                    .list_proxies(&peer.peer_id)?
                    .into_iter()
                    .map(|proxy| {
                        json!({
                            "selector": format!("agent://{label}/{}", proxy.remote_endpoint_id),
                            "remote_endpoint_id": proxy.remote_endpoint_id.as_str(),
                            "proxy_endpoint_id": proxy.endpoint_id.as_str(),
                            "display": proxy.display,
                        })
                    })
                    .collect();
                emit(&json!({ "peer": label.as_str(), "agents": rows }));
            }
            PeerCommand::Trust { label } => {
                let label = agent_mesh_core::PeerLabel::parse(&label)?;
                store.set_peer_trust(&label, true)?;
                emit(&json!({ "peer": label.as_str(), "trusted": true }));
            }
            PeerCommand::Untrust { label } => {
                let label = agent_mesh_core::PeerLabel::parse(&label)?;
                store.set_peer_trust(&label, false)?;
                emit(&json!({ "peer": label.as_str(), "trusted": false }));
            }
            PeerCommand::Forget { label } => {
                let label = agent_mesh_core::PeerLabel::parse(&label)?;
                let retired = store.retire_peer(&label)?;
                emit(&json!({
                    "peer": label.as_str(),
                    "forgotten": true,
                    "agents": retired.proxies,
                    "undeliverable": retired.undeliverable,
                    "withdrawn": retired.withdrawn,
                }));
            }
        },
        Command::Group { command } => {
            let caller = authenticate(&mut store)?;
            match command {
                GroupCommand::Create { name, members } => {
                    let name = Alias::parse(&name)?;
                    let ids = members
                        .iter()
                        .map(|selector| {
                            resolve_selector(&mut store, selector, &caller)
                                .map(|endpoint| endpoint.endpoint_id)
                        })
                        .collect::<agent_mesh_core::Result<Vec<_>>>()?;
                    store.set_group(&name, &ids)?;
                    emit(&group_json(&store, &name, &ids));
                }
                GroupCommand::Add { name, selector } => {
                    let name = Alias::parse(&name)?;
                    let mut ids = store.group_members(&name)?;
                    let peer = resolve_selector(&mut store, &selector, &caller)?;
                    if !ids.contains(&peer.endpoint_id) {
                        ids.push(peer.endpoint_id);
                    }
                    store.set_group(&name, &ids)?;
                    emit(&group_json(&store, &name, &ids));
                }
                GroupCommand::Remove { name, selector } => {
                    let name = Alias::parse(&name)?;
                    let mut ids = store.group_members(&name)?;
                    // Resolvable or not: a member that has gone must still be removable by the id
                    // the group was written with.
                    let target = resolve_selector(&mut store, &selector, &caller)
                        .map(|peer| peer.endpoint_id)
                        .or_else(|_| Opaque::parse(&selector))?;
                    ids.retain(|id| id != &target);
                    store.set_group(&name, &ids)?;
                    emit(&group_json(&store, &name, &ids));
                }
                GroupCommand::List => {
                    let rows: Vec<_> = store
                        .list_groups()?
                        .into_iter()
                        .map(|(name, members)| group_json(&store, &name, &members))
                        .collect();
                    emit(&json!({ "groups": rows }));
                }
                GroupCommand::Delete { name } => {
                    let name = Alias::parse(&name)?;
                    emit(&json!({
                        "group": name.as_str(),
                        "deleted": store.delete_group(&name)?,
                    }));
                }
            }
        }
        Command::Reconcile {
            from,
            runtime,
            instance,
            instance_id,
        } => {
            let scope = instance_scope(&runtime, instance, instance_id)?;
            let result = reconcile::run(&mut store, &scope, &from)?;
            emit(&json!({
                "seen": result.seen,
                "moved": result.moved.iter()
                    .map(|(endpoint, was, now)| json!({
                        "endpoint_id": endpoint, "was": was, "now": now
                    }))
                    .collect::<Vec<_>>(),
            }));
        }
        Command::Readdress {
            address,
            runtime,
            instance,
            instance_id,
        } => {
            let scope = instance_scope(&runtime, instance, instance_id)?;
            let moved = Address::parse(&address)?;
            let anchor = moved.stable_anchor().ok_or_else(|| {
                MeshError::new(
                    ErrorCode::InvalidRequest,
                    "an address of positions alone cannot identify what moved; include the \
                     window, frame or pane that kept its number",
                )
            })?;
            let anchor_only = Address::new(vec![anchor])?;

            let candidates: Vec<_> = store
                .list_endpoints()?
                .into_iter()
                .filter(|endpoint| endpoint.locator.runtime_instance_id == scope)
                .filter(|endpoint| {
                    endpoint
                        .locator
                        .address
                        .as_ref()
                        .is_some_and(|current| current.satisfies(&anchor_only))
                })
                .collect();
            match candidates.len() {
                0 => {
                    return Err(MeshError::new(
                        ErrorCode::AgentNotFound,
                        format!("nothing in that instance is at `{anchor_only}`"),
                    ));
                }
                1 => {}
                _ => {
                    return Err(MeshError::new(
                        ErrorCode::AgentAmbiguous,
                        format!("several endpoints are at `{anchor_only}`"),
                    )
                    .with_candidates(candidates.iter().map(qualified_name).collect()));
                }
            }
            let endpoint = &candidates[0];
            let was = endpoint.locator.address.as_ref().map(ToString::to_string);
            store.set_address(&endpoint.endpoint_id, Some(&moved))?;
            emit(&json!({
                "endpoint_id": endpoint.endpoint_id.as_str(),
                "was": was,
                "now": moved.to_string(),
            }));
        }
        Command::Providers => {
            let rows: Vec<_> = adapter::PROVIDERS
                .iter()
                .map(|provider| {
                    let capabilities = match adapter::for_provider(provider) {
                        // Probed with a placeholder session, so the report shows what the provider
                        // could do once bound rather than only what it can do bound to nothing.
                        Some(adapter) => adapter.capabilities(Some("<session>")),
                        None => agent_mesh_core::Capabilities::default(),
                    };
                    json!({
                        "provider": provider,
                        "installed": capabilities.version.is_some(),
                        "version": capabilities.version,
                        "granted": capabilities.granted.iter()
                            .map(|c| c.as_str()).collect::<Vec<_>>(),
                        "delivery_mode": capabilities.delivery_mode().as_str(),
                        "notes": capabilities.notes,
                    })
                })
                .collect();
            emit(&json!({ "providers": rows }));
        }
        Command::Sweep => {
            let (reclaimed, expired) = store.sweep(now_ms())?;
            emit(&json!({"reclaimed_claims": reclaimed, "expired": expired}));
        }
    }
    Ok(std::process::ExitCode::SUCCESS)
}

// -------------------------------------------------------------------------------------------
// The wrapper
// -------------------------------------------------------------------------------------------

/// Bind an endpoint, run a child as that agent, and release the binding when it exits.
///
/// The wrapper is what lets an ordinary provider — or, in M1, a shell script standing in for one —
/// hold a mesh identity with no runtime integration. Because it is long-lived it also owns
/// activation for its endpoint, which is why M1 needs no daemon (plan §3.2).
fn run_wrapped(
    store: &mut Store,
    args: &BindArgs,
    argv: &[String],
) -> agent_mesh_core::Result<std::process::ExitCode> {
    let bound = store.bind(&binding_from(args)?)?;
    let token_file = tokens::write(&bound.endpoint_id, &bound.incarnation_id, &bound.token)?;
    store.set_state(&bound.endpoint_id, AgentState::Idle)?;

    let status = ChildCommand::new(&argv[0])
        .args(&argv[1..])
        .env(ENV_ENDPOINT, bound.endpoint_id.as_str())
        .env(ENV_TOKEN_FILE, &token_file)
        .env("AGENT_MESH_DB", store.path())
        .status();

    // Release the binding whatever happened to the child, then report.
    store.unbind(&bound.endpoint_id, &bound.incarnation_id)?;
    let _ = std::fs::remove_file(&token_file);

    match status {
        Ok(status) => Ok(std::process::ExitCode::from(
            u8::try_from(status.code().unwrap_or(1)).unwrap_or(1),
        )),
        Err(err) => Err(MeshError::new(
            ErrorCode::Io,
            format!("could not run `{}`: {err}", argv[0]),
        )),
    }
}

// -------------------------------------------------------------------------------------------
// Identity plumbing
// -------------------------------------------------------------------------------------------

/// Authenticate from the inherited endpoint token, or fall back to the local user.
///
/// A shell with no token is `local_user`: it can send, but it cannot assert that it is an agent
/// (plan §6.4). The token is read from a file whose path arrives in the environment — never from
/// argv, where it would land in every process listing.
fn authenticate(store: &mut Store) -> agent_mesh_core::Result<Caller> {
    let (Some(endpoint), Some(token_file)) = (
        std::env::var_os(ENV_ENDPOINT),
        std::env::var_os(ENV_TOKEN_FILE),
    ) else {
        // No token: the person at the keyboard. They get their own durable mailbox so a reply has
        // somewhere to land, but they remain `local_user` and cannot claim to be an agent.
        return store.ensure_local_user();
    };
    let endpoint = Opaque::parse(&endpoint.to_string_lossy())?;
    let token = tokens::read(std::path::Path::new(&token_file))?;
    store.authenticate(&endpoint, &token)
}

fn require_agent(caller: &Caller) -> agent_mesh_core::Result<(Opaque, Opaque)> {
    match (
        caller.principal.endpoint_id.clone(),
        caller.principal.incarnation_id.clone(),
    ) {
        (Some(endpoint), Some(incarnation)) => Ok((endpoint, incarnation)),
        _ => Err(MeshError::new(
            ErrorCode::NotAuthorized,
            "this command needs a bound endpoint; run it inside `vvagent run` or set \
             AGENT_MESH_ENDPOINT and AGENT_MESH_TOKEN_FILE",
        )),
    }
}

fn binding_from(args: &BindArgs) -> agent_mesh_core::Result<Binding> {
    // A runtime advertises itself in the pane environment, so an agent inside a vvmux session or
    // a Vivido window binds with the right coordinates without being told. An explicit --runtime
    // still wins, since it is the caller being specific.
    let kind = if args.runtime == "wrapper" {
        match std::env::var(ENV_RUNTIME) {
            Ok(value) => RuntimeKind::parse(&value)?,
            Err(_) => RuntimeKind::Wrapper,
        }
    } else {
        RuntimeKind::parse(&args.runtime)?
    };
    let instance_name = args
        .instance
        .clone()
        .or_else(|| std::env::var(ENV_INSTANCE).ok());
    let runtime_instance_id = match &args.instance_id {
        Some(id) => Opaque::parse(id)?,
        None => {
            let name = instance_name.as_deref().ok_or_else(|| {
                MeshError::new(
                    ErrorCode::InvalidRequest,
                    "give --instance NAME or --instance-id ID so the endpoint has a scope",
                )
            })?;
            // Deterministic, so restarting the same wrapper rebinds the same durable slot rather
            // than stranding its mailbox behind a new id.
            derived_instance_id(kind, name)
        }
    };
    Ok(Binding {
        alias: args.alias.as_deref().map(Alias::parse).transpose()?,
        provider: args.provider.clone(),
        locator: Locator {
            kind,
            runtime_instance_id,
            instance_name,
            address: resolve_address(args.address.as_deref())?,
        },
    })
}

/// Compose this endpoint's address from what its host already covers and what it adds itself.
///
/// A `vvmux` session running inside a Vivida window is told `s2t2w3` through the environment and
/// contributes `f1p2`; the endpoint's address is the join. Passing a `--address` that already
/// carries the host's levels is accepted as the whole thing, so a runtime that knows its full path
/// does not have to take the prefix apart.
fn resolve_address(own: Option<&str>) -> agent_mesh_core::Result<Option<Address>> {
    let prefix = std::env::var(ENV_ADDRESS)
        .ok()
        .map(|value| Address::parse(&value))
        .transpose()?;
    let own = own.map(Address::parse).transpose()?;
    Ok(match (prefix, own) {
        (Some(prefix), Some(own)) => match Address::join(&prefix, &own) {
            Ok(joined) => Some(joined),
            // The two overlap, which means the caller passed a full path rather than a suffix.
            Err(_) => Some(own),
        },
        (Some(prefix), None) => Some(prefix),
        (None, own) => own,
    })
}

/// Which runtime instance a command is about, from a name, an explicit id, or the environment.
fn instance_scope(
    runtime: &str,
    instance: Option<String>,
    instance_id: Option<String>,
) -> agent_mesh_core::Result<Opaque> {
    if let Some(id) = instance_id {
        return Opaque::parse(&id);
    }
    let kind = RuntimeKind::parse(runtime)?;
    let name = instance
        .or_else(|| std::env::var(ENV_INSTANCE).ok())
        .ok_or_else(|| {
            MeshError::new(
                ErrorCode::InvalidRequest,
                "give --instance NAME or --instance-id ID to say which runtime instance",
            )
        })?;
    Ok(derived_instance_id(kind, &name))
}

fn derived_instance_id(kind: RuntimeKind, name: &str) -> Opaque {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"agent-mesh runtime instance v1\0");
    hasher.update(kind.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(name.as_bytes());
    Opaque::parse(&hex(&hasher.finalize()[..16])).expect("a 16-byte digest is a valid identifier")
}

// -------------------------------------------------------------------------------------------
// The bridge
// -------------------------------------------------------------------------------------------

struct BridgeOptions {
    dial: Option<String>,
    serve: bool,
    label: Option<String>,
    name: Option<String>,
    parent_pid: Option<u32>,
    stdin_leash: bool,
}

/// Exit statuses of `vvagent bridge`, so a supervisor knows whether trying again can help.
mod bridge_exit {
    /// The connection worked and then closed.
    pub const CLOSED: u8 = 0;
    /// Refused, or failed in a way retrying will not change.
    pub const REFUSED: u8 = 1;
    /// Nothing answered: no connection, or no `vvagent` on the far side.
    pub const UNREACHABLE: u8 = 69;
    /// The carrier broke mid-session, or this bridge lost its lease.
    pub const BROKEN: u8 = 74;
    /// Another bridge already serves this peer.
    pub const STANDBY: u8 = 75;
}

fn run_bridge(
    store: &mut Store,
    options: BridgeOptions,
    command: Vec<String>,
) -> agent_mesh_core::Result<std::process::ExitCode> {
    use agent_mesh_core::PeerLabel;
    use agent_mesh_core::bridge::Role;

    let role = if options.serve {
        Role::Serve
    } else {
        Role::Dial
    };
    let name = match options.name {
        Some(name) => Some(PeerLabel::parse(&name)?.as_str().to_owned()),
        None => host_name(),
    };
    let stop = options.stdin_leash.then(|| {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        // Read and discard until end of file; a supervisor closing our stdin is the signal.
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        stop
    });
    let config = bridge::Config {
        label: match (&options.dial, &options.label) {
            // A label, or an SSH destination that names one.
            (Some(dial), _) => {
                Some(PeerLabel::parse(dial).or_else(|_| PeerLabel::from_destination(dial))?)
            }
            (None, Some(label)) => Some(PeerLabel::parse(label)?),
            (None, None) => None,
        },
        name,
        anchor: if options.serve { None } else { lease_anchor() },
        parent_pid: options.parent_pid,
        stop,
        ..bridge::Config::new(role)
    };

    if options.serve {
        if !command.is_empty() {
            return Err(MeshError::new(
                ErrorCode::InvalidRequest,
                "`--serve` bridges over its own stdin and stdout and runs no command",
            ));
        }
        // stdout is the carrier from here on: nothing else may be printed to it.
        let ended = bridge::run(store, &config, std::io::stdin(), std::io::stdout().lock());
        return Ok(finish_bridge(ended, &mut std::io::stderr()));
    }

    let Some((program, args)) = command.split_first() else {
        return Err(MeshError::new(
            ErrorCode::InvalidRequest,
            "give the carrier command after `--`, e.g. `-- ssh -T HOST vvagent bridge --serve`",
        ));
    };
    let mut child = ChildCommand::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|err| MeshError::new(ErrorCode::Io, format!("cannot run `{program}`: {err}")))?;
    let (stdin, stdout) = (
        child.stdin.take().expect("piped"),
        child.stdout.take().expect("piped"),
    );
    // `run` owned the child's stdin and has dropped it, so the far side has seen end of stream
    // and is releasing its own lease. Give it that moment: killing it outright would leave its
    // lease live until it lapsed, and the next connection's server would stand aside until then.
    let ended = bridge::run(store, &config, stdout, stdin);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while matches!(child.try_wait(), Ok(None)) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(finish_bridge(ended, &mut std::io::stdout()))
}

/// Report how a bridge ended, as JSON, and choose the exit status a supervisor acts on.
fn finish_bridge(
    ended: agent_mesh_core::Result<bridge::Ended>,
    report: &mut impl std::io::Write,
) -> std::process::ExitCode {
    let code = match &ended {
        Ok(ended) => {
            report_ended(ended, report);
            match ended {
                bridge::Ended::Closed(_) => bridge_exit::CLOSED,
                bridge::Ended::Standby(_) => bridge_exit::STANDBY,
            }
        }
        Err(err) => {
            let body = json!({"error": {"code": err.code.as_str(), "message": err.message}});
            let _ = writeln!(std::io::stderr(), "{body}");
            match err.code {
                ErrorCode::PeerUnreachable => bridge_exit::UNREACHABLE,
                ErrorCode::Io | ErrorCode::ClaimLost => bridge_exit::BROKEN,
                _ => bridge_exit::REFUSED,
            }
        }
    };
    std::process::ExitCode::from(code)
}

fn report_ended(ended: &bridge::Ended, out: &mut impl std::io::Write) {
    let (peer, how) = match ended {
        bridge::Ended::Closed(peer) => (peer, "closed"),
        bridge::Ended::Standby(peer) => (peer, "standby"),
    };
    let _ = writeln!(out, "{}", json!({ "peer": peer.as_str(), "ended": how }));
}

/// This machine's name, as a peer label, for the other end to call it by.
fn host_name() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())?;
    let first = raw.trim().split('.').next()?.to_ascii_lowercase();
    agent_mesh_core::PeerLabel::parse(&first)
        .ok()
        .map(|label| label.as_str().to_owned())
}

/// The window this process runs in, from the coordinates its runtime exported.
fn lease_anchor() -> Option<agent_mesh_store::LeaseAnchor> {
    let runtime = RuntimeKind::parse(&std::env::var(ENV_RUNTIME).ok()?).ok()?;
    let instance = std::env::var(ENV_INSTANCE).ok()?;
    let address = Address::parse(&std::env::var(ENV_ADDRESS).ok()?).ok()?;
    let window = address.get(agent_mesh_core::Level::Window)?;
    Some(agent_mesh_store::LeaseAnchor {
        runtime,
        instance,
        window,
    })
}

// -------------------------------------------------------------------------------------------
// Rendering
// -------------------------------------------------------------------------------------------

/// Where the caller is, so resolution can prefer its own neighbourhood (§6.3).
fn origin_of(store: &Store, caller: &Caller) -> Option<Address> {
    caller
        .principal
        .endpoint_id
        .as_ref()
        .and_then(|id| store.endpoint(id).ok())
        .and_then(|endpoint| endpoint.locator.address)
}

/// Whatever a selector names: a proxy for an agent on a peer host, or a local endpoint.
fn resolve_selector(
    store: &mut Store,
    selector: &str,
    caller: &Caller,
) -> agent_mesh_core::Result<Endpoint> {
    if let Some(remote) = remote::resolve(store, selector, caller)? {
        return Ok(remote);
    }
    let endpoints = store.list_endpoints()?;
    let here = origin_of(store, caller);
    resolve(
        &Selector::parse(selector)?,
        &endpoints,
        Origin {
            scope: caller.scope.as_ref(),
            address: here.as_ref(),
            endpoint: caller.principal.endpoint_id.as_ref(),
        },
    )
    .cloned()
}

/// A message body, from `--text`, a file, or stdin.
///
/// The file and stdin forms exist because argv is readable by every process this user runs, so a
/// body on the command line is a body on display. Neither form is required — a short note is fine
/// as an argument — but anything sensitive has somewhere better to go.
fn body_of(text: Option<String>, from_file: Option<String>) -> agent_mesh_core::Result<String> {
    match (text, from_file) {
        (Some(text), _) => Ok(text),
        (None, Some(path)) => {
            if path == "-" {
                let mut body = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut body)
                    .map_err(|err| MeshError::new(ErrorCode::Io, err.to_string()))?;
                Ok(body)
            } else {
                std::fs::read_to_string(&path).map_err(|err| {
                    MeshError::new(ErrorCode::Io, format!("cannot read {path}: {err}"))
                })
            }
        }
        (None, None) => Ok(String::new()),
    }
}

fn parse_refs(values: &[String]) -> agent_mesh_core::Result<Vec<Ref>> {
    values.iter().map(|value| parse_ref(value)).collect()
}

fn parse_ref(value: &str) -> agent_mesh_core::Result<Ref> {
    let reference = if let Some(path) = value.strip_prefix("file:") {
        Ref::File {
            path: path.to_owned(),
            sha256: None,
            bytes: None,
            host: None,
        }
    } else if let Some(rest) = value.strip_prefix("media:") {
        // `media:<runtime-instance-id>/<resource-id>@pinned|live`. The binding is required rather
        // than defaulted: a reader that cannot tell which kind it holds has to guess, and the wrong
        // guess is sometimes a wrong picture instead of an error (plan §10.1).
        let (scope, binding) = rest.rsplit_once('@').ok_or_else(|| {
            MeshError::new(
                ErrorCode::InvalidRequest,
                "a media reference names its binding, `@pinned` or `@live`",
            )
        })?;
        let (instance, resource_id) = scope.split_once('/').ok_or_else(|| {
            MeshError::new(
                ErrorCode::InvalidRequest,
                "a media reference is `media:<instance>/<resource>@pinned|live`",
            )
        })?;
        Ref::Media {
            runtime_instance_id: Opaque::parse(instance)?,
            resource_id: resource_id.to_owned(),
            binding: MediaBinding::parse(binding)?,
        }
    } else {
        return Err(MeshError::new(
            ErrorCode::InvalidRequest,
            "a reference is `file:/absolute/path` or `media:<instance>/<resource>@pinned|live`",
        ));
    };
    reference.validate()?;
    Ok(reference)
}

fn parse_admit(value: &str) -> agent_mesh_core::Result<Admit> {
    match value {
        "nobody" => Ok(Admit::Nobody),
        "replies_only" => Ok(Admit::RepliesOnly),
        "replies_and_team" => Ok(Admit::RepliesAndTeam),
        "replies_and_trusted" => Ok(Admit::RepliesAndTrusted),
        "anyone" => Ok(Admit::Anyone),
        other => Err(MeshError::new(
            ErrorCode::InvalidRequest,
            format!("unknown admit rule `{other}`"),
        )),
    }
}

fn envelope(message: &Message) -> Envelope {
    Envelope {
        schema: ENVELOPE_SCHEMA,
        message_id: message.message_id.clone(),
        recipient_sequence: message.recipient_sequence,
        from: Principal {
            kind: message.from.kind,
            endpoint_id: message.from.endpoint_id.clone(),
            incarnation_id: message.from.incarnation_id.clone(),
        },
        to: message.to_endpoint.clone(),
        kind: message.kind,
        conversation_id: message.conversation_id.clone(),
        reply_to: message.reply_to.clone(),
        outcome: message.outcome,
        state: message.state,
        created_at: rfc3339(message.created_at_ms),
        expires_at: message.expires_at_ms.map(rfc3339),
        subject: message.subject.clone(),
        text: message.text.clone(),
        refs: message.refs.clone(),
    }
}

fn envelope_json(message: &Message) -> serde_json::Value {
    serde_json::to_value(envelope(message)).unwrap_or_else(|err| json!({"error": err.to_string()}))
}

fn group_json(store: &Store, name: &Alias, members: &[Opaque]) -> serde_json::Value {
    json!({
        "group": name.as_str(),
        "members": members.iter().map(|id| {
            json!({
                "endpoint_id": id.as_str(),
                // A member that has gone still shows its id, because that is what the group holds.
                "selector": store.endpoint(id).ok().as_ref().map(qualified_name),
            })
        }).collect::<Vec<_>>(),
    })
}

fn endpoint_json(endpoint: &Endpoint) -> serde_json::Value {
    json!({
        "endpoint_id": endpoint.endpoint_id.as_str(),
        "incarnation_id": endpoint.incarnation_id.as_ref().map(Opaque::as_str),
        "alias": endpoint.alias.as_ref().map(Alias::as_str),
        "provider": endpoint.provider,
        "selector": qualified_name(endpoint),
        "runtime": endpoint.locator.kind.as_str(),
        "runtime_instance_id": endpoint.locator.runtime_instance_id.as_str(),
        "instance": endpoint.locator.instance_name,
        "address": endpoint.locator.address.as_ref().map(Address::to_string),
        "online": endpoint.online,
        "state": endpoint.state.as_str(),
        "state_generation": endpoint.state_generation,
        "pending": endpoint.pending,
    })
}

fn fresh_key() -> String {
    // A caller that does not supply a key gets a unique one, so an unkeyed retry is a new message
    // rather than an accidental replay.
    Opaque::generate().as_str().to_owned()
}

fn json_err(err: serde_json::Error) -> MeshError {
    MeshError::new(ErrorCode::Io, err.to_string())
}

fn emit(value: &serde_json::Value) {
    println!("{value}");
}
