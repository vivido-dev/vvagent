# vvagent commands

Everything prints JSON, including errors (`{"error":{"code","message"}}`). Every subcommand takes
`--db` to override the store path (`$AGENT_MESH_DB`, else `$XDG_STATE_HOME/vivido/agent-mesh`).
Commands that act *as an endpoint* (`capabilities`, `state`, `inbox`, `receive`, `reply`, `cancel`,
`policy`) need the caller authenticated: inherited from `vvagent run`, or from
`AGENT_MESH_ENDPOINT` + `AGENT_MESH_TOKEN_FILE`.

## Identity

| Command | Purpose |
|---|---|
| `whoami` | Who this process is: principal, endpoint/incarnation id, runtime, instance, address |
| `list [--online]` | Every endpoint, live or durable |
| `bind [--alias A] [--provider P] [--runtime R] [--instance I] [--address A]` | Bind an endpoint without running a child. In a pane the runtime/instance/address arrive through the environment |
| `unbind --endpoint ID --incarnation ID` | Release a binding; the mailbox and pending work survive |
| `run [bind options] -- CMD…` | Bind, run a command as that agent with the token env set, release on exit |
| `state --state S` | Report the endpoint's lifecycle state, bumping its generation |
| `capabilities [--native-session HANDLE] [--endpoint ID]` | Establish and record what the provider can do. Re-run after a provider upgrade; an untested version loses capabilities |

`bind` prints `endpoint_id`, `incarnation_id`, and `token_file`. A pane shell must export
`AGENT_MESH_ENDPOINT` and `AGENT_MESH_TOKEN_FILE` from that output to run authenticated commands;
`run` does it for its child.

## Mail

| Command | Purpose |
|---|---|
| `send --to SELECTOR [options]` | Send a request (or `--notice`). See flags below |
| `send --group NAME [options]` | Fan out; each member gets its own message and outcome |
| `wait --request ID [--timeout 10m]` | Block until answered, cancelled, or expired |
| `wait --group-send ID [--quorum N]` | Wait for enough answers from a fan-out |
| `inbox [--status S]… [--limit 50]` | This endpoint's mailbox; default everything still pending |
| `receive [--lease 5m]` | Claim the oldest queued message |
| `reply --to-request ID [--outcome O] [--text/--text-file] [--ref …] [--idempotency-key K]` | Answer a request addressed to this endpoint. Outcomes: `completed` (default), `answered`, `refused`, `failed`, `cancelled` |
| `cancel --request ID` | Queued work is removed; delivered work is only asked to stop and stays `cancellation_requested` unless the provider confirms |

`send` flags: `--subject`, `--text` (avoid for anything sensitive — argv is readable by every
process this user runs), `--text-file PATH|-`, `--ref file:/abs/path` or
`media:<instance>/<resource>@pinned|live` (repeatable, up to 16, grants no access), `--attach FILE`
(repeatable, up to 8, default 1 GiB each, `--max-attach-bytes` to lower), `--expires-in 10m`,
`--idempotency-key K` (same key + same content replays; different content is
`idempotency_conflict`), `--notice` (expects no answer; unread notices expire after an hour).

Groups: `group create NAME --member SEL…` (creates or replaces membership), `group add|remove NAME
--member SEL`, `group list`, `group delete NAME`. Groups store endpoint ids, so a group cannot
follow a name to whatever answers to it next.

## Policy

| Command | Purpose |
|---|---|
| `policy show` | This endpoint's gates and budgets |
| `policy set --activate V \| --make-visible V \| --enqueue V \| --team off\|runtime_instance\|space \| …` | Change a gate |
| `policy trust SELECTOR` | Admit a sender, stored as its endpoint id |
| `policy untrust ID` | Withdraw a sender's trust |
| `policy attach allow\|deny` | Whether this endpoint may send files with `--attach` |

Gates: `enqueue` (who may queue), `make_visible` (whose mail `receive`/`inbox` show), `activate`
(who may spend a turn waking the agent), `interrupt`, `pty_nudge` (granted to no provider). A reply
is never rate-limited out of its own conversation. Budgets: `max_inbound_per_minute` (60) and
`max_auto_turns_per_minute` (4), per endpoint and per peer. The default `activate:
replies_and_team` wakes for replies but not for a peer's requests — `replies_and_trusted` wakes for
trusted peers' requests too.

## Peers

| Command | Purpose |
|---|---|
| `peer list` | Every peer: label, `connected`, trust, queued counts, and the bridge's anchor window |
| `peer agents LABEL` | That peer's known agents, each with the exact `agent://LABEL/<id>` selector that queues offline |
| `peer trust LABEL` / `peer untrust LABEL` | Admit or refuse that peer's remote-originated requests |
| `peer connect DEST [-- ssh options]` | One foreground bridge over `ssh -T DEST`, for plain-`ssh` users |
| `peer forget LABEL` | Retire the peer and its proxies; its waiting mail becomes undeliverable |

## Files

| Command | Purpose |
|---|---|
| `ref verify MESSAGE_ID` | Re-check every file a message refers to on this host: length and SHA-256, any size. `receive` verifies inline up to 256 MiB and reports `attachments[].verified` |

## Operations

| Command | Purpose |
|---|---|
| `mcp` | Serve the mailbox as MCP tools over stdio (`agent_mesh_identity`, `_list`, `_send`, `_receive`, `_reply`, `_wait`) |
| `providers` | Every provider adapter, its installed version, what it can do, and why anything is missing |
| `watch --runtime R --instance I [--parent-pid PID] [--reconcile "CMD"] [--poll 1s] [--backoff …] [--max-attempts …] [--once] [--verbose]` | Wake this instance's endpoints when mail arrives. Runtimes spawn and leash it themselves; `--once --verbose` explains one pass |
| `reconcile --from "vivida msg layout"` | Re-derive endpoint addresses from a runtime's layout; only addresses move |
| `readdress --address s3t1w42` | Move one endpoint to a new position after a rearrangement |
| `explain MESSAGE_ID` | Why a message was accepted, refused, or moved — metadata only |
| `sweep` | Return lapsed claims to the queue and retire messages past their deadline |

## Environment

| Variable | Meaning |
|---|---|
| `AGENT_MESH_RUNTIME` / `AGENT_MESH_INSTANCE` / `AGENT_MESH_ADDRESS` | Set by vvmux, Vivido, and Vivida for their panes; `bind` reads them |
| `AGENT_MESH_ENDPOINT` + `AGENT_MESH_TOKEN_FILE` | Authenticate as a bound endpoint (what `vvagent run` exports for its child) |
| `AGENT_MESH_BIN` | Names the executable when it is not on PATH (used by runtimes and `vvssh`) |
| `AGENT_MESH_WATCH` | `off` opts the runtime's watcher out |
| `AGENT_MESH_DB` | Store path override |
| `AGENT_MESH_SYNCHRONOUS` | `FULL` (default) or `NORMAL` durability |
