# `vvagent` for Python

In-process bindings for the agent-mesh mailbox. Bind an endpoint, send, claim, reply and wait
without spawning `vvagent` and parsing its JSON.

```python
import vvagent as mesh

store = mesh.open()                              # $AGENT_MESH_DB, else the XDG state path
me = mesh.authenticate(store)                    # from the inherited endpoint token
reviewer = mesh.resolve(store, me, "reviewer")   # or "p2", or "vvmux:dev/reviewer"

asked = mesh.send(store, me, to=reviewer.endpoint_id, text="please look at the diff")
answer = mesh.wait(store, asked.message_id, timeout=60.0)
if answer.answered:
    print(answer.message.outcome, answer.message.text)
```

Answering, from the other side:

```python
work = mesh.claim(store, me)
if work is not None:
    mesh.respond(store, me, request=work.message_id, outcome=mesh.COMPLETED, text="looks fine")
```

There is no daemon and no broker. Every process opens the same SQLite database directly; SQLite's
transactions are what make concurrent writers safe.

## What it is not

This is deliberately **not** part of `vivid_sdk`. The mesh carries envelopes between agents and
never carries media; Vivid carries media between producers and presenters and knows nothing about
agents. Two packages keep that boundary where it belongs.

## Three properties worth knowing

**A `Caller` is minted by the store.** There is no constructor. A process cannot assert an
identity it does not hold, and the recipient of a message always sees a `from` the store wrote —
`local_user` for a shell, `agent` for a bound endpoint.

**A token never reaches Python.** `bind()` writes it to an owner-only file and returns the path.
Pass `bound.environment()` to the child; a path in the environment is not a secret, and a token in
argv is readable by every process this user runs.

**A reference grants no access.** `FileRef`, `PaneRef` and `MediaRef` are bounded claims about
something outside the mesh. A `MediaRef` says which runtime holds the media and whether you want
it `"pinned"` (as it was when the reference was minted — resolution *fails* once anything has
moved, rather than returning what replaced it) or `"live"` (whatever is there now).

## Errors

Every call raises `vvagent.MeshError`. Branch on `err.code` — `agent_not_found`,
`agent_ambiguous`, `mailbox_full`, `claim_lost`, `not_authorized`, `policy_refused`, and the rest;
the code is contract and the message is for humans. When a selector matched more than one endpoint,
`err.candidates` holds what to retype: ambiguity is never narrowed to one silently.

## The honest limit

The trust boundary is one operating-system account. The endpoint token gives attribution among
cooperating processes; it is not a sandbox against a hostile process running as the same user,
which can read the store directly.

## Building

```sh
maturin develop            # from the repo root
```

or, matching how the tests run here:

```sh
cargo build -p agent-mesh-python
cp target/debug/lib_native.so python/vvagent/_native.abi3.so
PYTHONPATH=python python -m pytest python-tests
```
