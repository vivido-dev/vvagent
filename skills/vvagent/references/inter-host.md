# Peers and the SSH bridge

The mesh crosses hosts over SSH and nothing else: no listener, port, daemon, or extra credential.
Whoever can `ssh` to a host as an account can bridge to that account's store, and nobody else can.
Each host keeps its own store; the bridge is store-and-forward, so accepted mail survives the
connection being down and is delivered exactly once when it returns.

## How the bridge runs

`vvssh` starts one mesh lane beside its media lanes when `vvagent` is on PATH (`--no-agent-mesh` and
`AGENT_MESH_WATCH=off` suppress it). The lane runs `vvagent bridge --dial DEST`, which opens its own
SSH exec channel to `vvagent bridge --serve` on the far side. With plain `ssh`,
`vvagent peer connect DEST` runs the same dialler in the foreground.

Behavior to rely on:

- **Silent.** The lane prints nothing to the terminal, ever — including on reconnect. Connection
  state lives in `vvagent peer list`.
- **Never prompts.** Reconnects authenticate only with credentials the session already cached. A
  reconnect needing a fresh one-time code simply does not happen.
- **Retries with backoff** while the session lasts (1 s doubling to 60 s). A far side with no
  `vvagent` on PATH is tried once, then left alone; the interactive session is unaffected.
- **Single-flight per peer.** Two windows `vvssh`'d to one host produce one serving bridge; the
  other stands aside (retrying every ~30 s) and takes over when the serving window closes.
- **Leases, not heartbeats from afar.** A bridge holds a renewable lease per peer. After an unclean
  drop (network death, `kill -9`), the far side's lease lapses after up to 30 s before a reconnect
  is served. Closing a window may likewise take up to those 30 s to clear `connected` on the closing
  side; the far side notices at once.

## Labels and pinning

The peer's label is the SSH destination you dial (`buildbox`, or `user@host` lower-cased). The far
side names you from what the dialler suggests — its host name when it can read one, else
`peer-<8 hex>` (macOS zsh exports neither `/proc` nor `$HOSTNAME`, so Mac peers often get the
fallback name). Labels are display and selector names, never authority.

The first connection under a label pins the far store's `host_id`. A later store presenting a
different `host_id` under the same label is refused (`peer_mismatch`) until `vvagent peer forget`
clears it — a reinstalled host cannot silently inherit the old one's trust and queued mail.

## Trust

Remote-originated requests and notices are refused `not_authorized` until the receiving host trusts
the peer: `vvagent peer trust LABEL`. Replies to your own requests are always admitted. Trust is
granted per peer (or per proxy); attribution *within* a peer is the peer's claim, and no team grant
or `anyone` rule reaches a peer — only explicit trust, where the gate admits it. On top of each
endpoint's own limits, one peer gets at most 60 inbound messages and 4 triggered turns per minute
across *all* local endpoints.

## Selectors across hosts

| Form | While the bridge is up | While it is down |
|---|---|---|
| `@buildbox:builder` (alias) | resolves on that host, sends | `peer_unreachable` immediately |
| `@buildbox:vvmux:dev/f1p2` (address) | resolves on that host, sends | `peer_unreachable` immediately |
| `agent://buildbox/<id>` | sends | **queues**, delivers exactly once on reconnect |
| `s1t2w12f1p2` (positional long form) | resolved host-wide through the bridge anchored on that window | `agent_not_found` |

A bare address like `@buildbox:f1p2` is resolved host-wide on the peer, so two sessions there with
the same shape return `agent_ambiguous` with qualified candidates — the honest answer. `vvagent
peer agents buildbox` lists the agents this store has addressed, each with the offline-safe
`agent://` selector. A second hop (`@a:@b:x`) is refused: no transitive routing.

## Attachments across hosts

`--attach` to a peer copies the file through `file-drop-v1` on the `vvssh` window carrying that
peer's bridge — authenticated, SHA-256-verified before commit, atomic, on Vivid's bulk lane, so it
never competes with the interactive session or the mesh lane. The person at the window sees the
same "Automation is copying NAME (N bytes)" notice a drag shows; nothing is typed.

Rules:

- **Send from the bridge window's instance.** The drop goes through the automation channel of the
  Vivido/Vivida instance whose pane runs that `vvssh`. From another instance it fails
  `file_drop_unavailable` naming the instance and window that holds the bridge. A plain-`ssh`
  bridge has no window and fails the same way; the message without the file still goes.
- **Attachments never queue.** The transfer happens now or the send fails before anything is
  enqueued.
- **One direction, one hop.** Local → remote only (the remote cannot attach files back), and a
  `vvssh` inside a remote `vvmux` pane cannot receive drops. `vvreceive` is Linux-only, so macOS
  and Windows remotes get `file_drop_unavailable`.
- The copy lands in the remote login shell's working directory and outlives the message; cleanup
  belongs to the recipient. The audit trail records counts and bytes only — never names, paths, or
  digests.

## Diagnosing the lane

```sh
vvagent peer list                     # connected, trust, queued counts, anchor window
vvagent peer agents buildbox          # exact selectors for a peer's agents

# Run the lane by hand where stderr is visible:
vvagent bridge --dial buildbox -- ssh -T -o ControlMaster=no -o ControlPath=none buildbox \
  "command -v vvagent >/dev/null 2>&1 && exec vvagent bridge --serve; exec \"\${SHELL:-/bin/sh}\" -lc 'exec vvagent bridge --serve'"
# exit 0 closed · 75 another bridge serves this peer · 69 nothing answered
#      · 74 carrier broke · 1 refused
```

On the far side, `vvagent watch --runtime vvmux --instance NAME --once --verbose` explains why a
message was or was not activated, and `vvagent explain MESSAGE_ID` gives one message's audit trail
(metadata only).
