"""In-process bindings for the agent-mesh mailbox.

The mesh has had exactly one client since it existed: the ``vvagent`` CLI. A runtime that wanted
to send a message spawned a process and parsed its JSON. This package binds the same SQLite store
directly, so a Python agent can bind an endpoint, send, claim, reply and wait without a subprocess
between it and its mailbox::

    import vvagent as mesh

    store = mesh.open()
    me = mesh.authenticate(store)                    # from the inherited endpoint token
    reviewer = mesh.resolve(store, me, "reviewer")   # or "p2", or "vvmux:dev/reviewer"

    asked = mesh.send(store, me, to=reviewer.endpoint_id, text="please look at the diff")
    answer = mesh.wait(store, asked.message_id, timeout=60.0)
    if answer.message is not None:
        print(answer.message.outcome, answer.message.text)

This is deliberately *not* part of :mod:`vivid_sdk`. The mesh carries messages between agents and
never carries media; Vivid carries media and knows nothing about agents. Two packages keep that
boundary visible.

Three properties this layer preserves, because they are what make the mesh safe:

* A :class:`Caller` is minted only by the store. There is no constructor, so a process cannot
  assert an identity it does not hold.
* An endpoint token never reaches Python. :func:`bind` writes it to an owner-only file and returns
  the *path*; put that path in the child's ``AGENT_MESH_TOKEN_FILE``, never the token in argv.
* A reference is a bounded claim about something outside the mesh, not access to it. Sending a
  :class:`MediaRef` tells a receiver where to ask; it does not hand over a pixel.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple, Union

from . import _native
from ._native import Caller, Store

__all__ = [
    "Bound",
    "Caller",
    "Endpoint",
    "FileRef",
    "Locator",
    "MediaRef",
    "MeshError",
    "Message",
    "PaneRef",
    "Principal",
    "Ref",
    "Resolution",
    "Store",
    "authenticate",
    "bind",
    "cancel",
    "claim",
    "endpoints",
    "inbox",
    "open",
    "resolve",
    "respond",
    "response_for",
    "send",
    "set_state",
    "sweep",
    "unbind",
    "wait",
]

#: Raised by every call in this package. ``code`` is the contract — ``agent_not_found``,
#: ``mailbox_full``, ``not_authorized``, and the rest — while ``message`` is for humans and
#: ``candidates`` carries what to retype when a selector matched more than one endpoint.
MeshError = _native.MeshFailure

# Message kinds. A notice has no response path; a request does and stays pending until answered.
REQUEST = "request"
RESPONSE = "response"
NOTICE = "notice"

# Terminal outcomes. `deferred` is deliberately absent: it is a delivery state, not an outcome.
COMPLETED = "completed"
ANSWERED = "answered"
REFUSED = "refused"
FAILED = "failed"
CANCELLED = "cancelled"


@dataclass(frozen=True)
class Principal:
    """Who sent a message. Always filled in by the store, never accepted from a client."""

    kind: str
    endpoint_id: Optional[str] = None
    incarnation_id: Optional[str] = None


@dataclass(frozen=True)
class FileRef:
    """A path, and optionally what was there when the reference was minted."""

    path: str
    sha256: Optional[str] = None
    bytes: Optional[int] = None

    def _wire(self) -> Dict[str, Any]:
        return {
            "kind": "file",
            "path": self.path,
            "sha256": self.sha256,
            "bytes": self.bytes,
        }


@dataclass(frozen=True)
class PaneRef:
    """Where a pane sits. Local numeric ids only mean something inside their runtime instance,
    which is why ``runtime_instance_id`` is not optional."""

    runtime_instance_id: str
    runtime: str
    workspace: Optional[str] = None
    tab: Optional[str] = None
    pane_id: Optional[int] = None

    def _wire(self) -> Dict[str, Any]:
        return {
            "kind": "pane",
            "runtime_instance_id": self.runtime_instance_id,
            "runtime": self.runtime,
            "workspace": self.workspace,
            "tab": self.tab,
            "pane_id": self.pane_id,
        }


@dataclass(frozen=True)
class MediaRef:
    """Media a runtime is holding, named by an id that runtime minted.

    ``binding`` is not decoration. ``"pinned"`` means "what I was showing when I asked", and
    resolution fails once any revision, generation, or media epoch has moved rather than returning
    what replaced it. ``"live"`` means "whatever is on that surface now". An envelope that did not
    say which it held would leave a reader to guess, and a wrong guess there is a wrong picture
    rather than an error.
    """

    runtime_instance_id: str
    resource_id: str
    binding: str

    def _wire(self) -> Dict[str, Any]:
        return {
            "kind": "media",
            "runtime_instance_id": self.runtime_instance_id,
            "resource_id": self.resource_id,
            "binding": self.binding,
        }


Ref = Union[FileRef, PaneRef, MediaRef]


@dataclass(frozen=True)
class Message:
    """One message as the store holds it."""

    message_id: str
    to: str
    sender: Principal
    kind: str
    conversation_id: str
    state: str
    text: str
    recipient_sequence: int
    created_at_ms: int
    refs: Tuple[Ref, ...] = ()
    reply_to: Optional[str] = None
    outcome: Optional[str] = None
    subject: Optional[str] = None
    expires_at_ms: Optional[int] = None


@dataclass(frozen=True)
class Locator:
    """Where an endpoint sits inside its runtime."""

    runtime: str
    runtime_instance_id: str
    instance_name: Optional[str] = None
    address: Optional[str] = None


@dataclass(frozen=True)
class Endpoint:
    """A durable mailbox slot, online or not."""

    endpoint_id: str
    locator: Locator
    online: bool
    state: str
    state_generation: int
    pending: int
    incarnation_id: Optional[str] = None
    alias: Optional[str] = None
    provider: Optional[str] = None


@dataclass(frozen=True)
class Bound:
    """The result of binding. ``token_file`` is a path to an owner-only file; the token itself is
    never returned, printed, or logged."""

    endpoint_id: str
    incarnation_id: str
    token_file: str
    rebound: bool

    def environment(self) -> Dict[str, str]:
        """The two variables a child process needs to authenticate as this endpoint."""

        return {
            "AGENT_MESH_ENDPOINT": self.endpoint_id,
            "AGENT_MESH_TOKEN_FILE": self.token_file,
        }


@dataclass(frozen=True)
class Resolution:
    """How a :func:`wait` ended.

    ``resolution`` is ``"response"``, ``"cancelled"``, ``"expired"``, ``"undeliverable"`` or
    ``"timeout"``. ``failure`` says why an undeliverable request could not reach its peer host. A
    timeout never mutates the request: a client giving up is not the same as the work stopping, so
    the request is still there to wait on again.
    """

    request: str
    resolution: str
    message: Optional[Message] = None
    state: Optional[str] = None
    failure: Optional[str] = None

    @property
    def answered(self) -> bool:
        return self.message is not None


# -------------------------------------------------------------------------------------------
# Opening and identity
# -------------------------------------------------------------------------------------------


def open(path: Optional[Union[str, "os.PathLike[str]"]] = None) -> Store:
    """Open the mailbox, creating it if this is its first use.

    With no path this is ``$AGENT_MESH_DB``, else ``$XDG_STATE_HOME/vivido/agent-mesh``. There is
    no daemon to start: concurrent processes are safe because SQLite makes them safe.
    """

    return _native.open_store(None if path is None else os.fspath(path))


def authenticate(
    store: Store,
    *,
    endpoint: Optional[str] = None,
    token_file: Optional[Union[str, "os.PathLike[str]"]] = None,
) -> Caller:
    """Identify this process from its inherited endpoint token.

    With no token this is the local user — a real principal with its own durable mailbox, so a
    reply has somewhere to land, but one that cannot claim to be an agent.
    """

    return _native.authenticate(
        store, endpoint, None if token_file is None else os.fspath(token_file)
    )


def bind(
    store: Store,
    *,
    runtime: str,
    instance_id: str,
    alias: Optional[str] = None,
    provider: Optional[str] = None,
    instance_name: Optional[str] = None,
    address: Optional[str] = None,
) -> Bound:
    """Bind an agent endpoint and mint a fresh incarnation for it.

    The same alias in the same runtime instance is the same logical slot, so a restart comes back
    to its own mailbox and pending work. Every bind mints a new incarnation, so a replacement
    process can never acknowledge work its predecessor claimed.
    """

    row = _native.bind(
        store,
        runtime=runtime,
        instance_id=instance_id,
        alias=alias,
        provider=provider,
        instance_name=instance_name,
        address=address,
    )
    return Bound(
        endpoint_id=row["endpoint_id"],
        incarnation_id=row["incarnation_id"],
        token_file=row["token_file"],
        rebound=row["rebound"],
    )


def unbind(store: Store, endpoint: str, incarnation: str) -> None:
    """Release a binding and delete its token file. The mailbox and its pending work survive."""

    _native.unbind(store, endpoint, incarnation)


def set_state(store: Store, endpoint: str, state: str) -> int:
    """Publish what this agent is doing: ``idle``, ``working``, ``blocked``, ``offline``.

    Returns the new state generation, which is monotonic so a stale snapshot can be recognised
    rather than trusted.
    """

    return _native.set_state(store, endpoint, state)


# -------------------------------------------------------------------------------------------
# Addressing
# -------------------------------------------------------------------------------------------


def endpoints(store: Store) -> Tuple[Endpoint, ...]:
    """Every endpoint the store knows, online or not."""

    return tuple(_endpoint(row) for row in _native.list_endpoints(store))


def resolve(store: Store, caller: Caller, selector: str) -> Endpoint:
    """Turn what a person typed into exactly one endpoint.

    Accepts an endpoint id, an alias, a positional address (``p2``, ``s1t2p3``), or a
    runtime-qualified form (``vvmux:dev/reviewer``). More than one match is never silently narrowed
    to one: the caller's own neighbourhood is preferred, and where that does not settle it a
    :data:`MeshError` with code ``agent_ambiguous`` carries the candidates to retype.
    """

    return _endpoint(_native.resolve_selector(store, caller, selector))


# -------------------------------------------------------------------------------------------
# Sending and receiving
# -------------------------------------------------------------------------------------------


def send(
    store: Store,
    caller: Caller,
    *,
    to: str,
    text: str = "",
    kind: str = REQUEST,
    subject: Optional[str] = None,
    refs: Sequence[Ref] = (),
    reply_to: Optional[str] = None,
    outcome: Optional[str] = None,
    expires_in: Optional[float] = None,
    idempotency_key: Optional[str] = None,
) -> Message:
    """Put a message in an endpoint's mailbox.

    ``to`` is an endpoint id — call :func:`resolve` first if you have a name. Without an
    ``idempotency_key`` each call is a new message, so an unkeyed retry is a second request rather
    than an accidental replay; supply one when a retry must be the *same* message.
    """

    return _message(
        _native.send(
            store,
            caller,
            to=to,
            kind=kind,
            text=text,
            idempotency_key=idempotency_key or uuid.uuid4().hex,
            subject=subject,
            refs=[reference._wire() for reference in refs],
            reply_to=reply_to,
            outcome=outcome,
            expires_in_ms=None if expires_in is None else int(expires_in * 1000),
        )
    )


def inbox(
    store: Store,
    endpoint: str,
    *,
    states: Sequence[str] = (),
    limit: int = 64,
) -> Tuple[Message, ...]:
    """Read a mailbox without taking anything out of it."""

    return tuple(
        _message(row) for row in _native.inbox(store, endpoint, list(states), limit)
    )


def claim(store: Store, caller: Caller, *, lease: Optional[float] = None) -> Optional[Message]:
    """Take the oldest queued message under a bounded lease, or ``None`` if there is none.

    The lease belongs to this incarnation. If the process dies the lease lapses and the work goes
    back on the queue; a replacement process cannot acknowledge what its predecessor claimed.
    """

    row = _native.claim(store, caller, None if lease is None else int(lease * 1000))
    return None if row is None else _message(row)


def respond(
    store: Store,
    caller: Caller,
    *,
    request: str,
    outcome: str,
    text: str = "",
    refs: Sequence[Ref] = (),
    idempotency_key: Optional[str] = None,
) -> Message:
    """Answer a claimed or delivered request.

    One transaction: the response lands in the requester's mailbox as the request leaves this one,
    so there is no moment where a request is answered and still pending.
    """

    return _message(
        _native.respond(
            store,
            caller,
            request=request,
            outcome=outcome,
            text=text,
            idempotency_key=idempotency_key or "reply-" + request,
            refs=[reference._wire() for reference in refs],
        )
    )


def response_for(store: Store, request: str) -> Optional[Message]:
    """The answer to a request, if one has arrived."""

    row = _native.response_for(store, request)
    return None if row is None else _message(row)


def cancel(store: Store, caller: Caller, request: str) -> str:
    """Ask for a request to stop, and return the state it reached.

    Queued work is cancelled atomically. Work already claimed or delivered can only be *asked* to
    stop: the store records ``cancellation_requested`` and never manufactures a ``cancelled``
    outcome the responder has not confirmed.
    """

    return _native.cancel(store, caller, request)


def sweep(store: Store) -> Tuple[int, int]:
    """Expire what has aged out and release lapsed claims. Any process may sweep, and correctness
    never depends on one running."""

    return _native.sweep(store)


def wait(
    store: Store,
    request: str,
    *,
    timeout: float,
    poll: float = 0.1,
) -> Resolution:
    """Block until a request is answered, cancelled, expired, or the deadline passes.

    The GIL is released for the wait and the store lock is taken only for each poll, so another
    thread can keep sending while this one waits.
    """

    row = _native.wait(
        store,
        request,
        timeout_ms=int(timeout * 1000),
        poll_ms=int(poll * 1000),
    )
    message = row.get("message")
    return Resolution(
        request=row["request"],
        resolution=row["resolution"],
        message=None if message is None else _message(message),
        state=row.get("state"),
        failure=row.get("failure"),
    )


# -------------------------------------------------------------------------------------------
# Conversion
# -------------------------------------------------------------------------------------------


def _message(row: Mapping[str, Any]) -> Message:
    sender = row["from"]
    return Message(
        message_id=row["message_id"],
        to=row["to"],
        sender=Principal(
            kind=sender["kind"],
            endpoint_id=sender["endpoint_id"],
            incarnation_id=sender["incarnation_id"],
        ),
        kind=row["kind"],
        conversation_id=row["conversation_id"],
        state=row["state"],
        text=row["text"],
        recipient_sequence=row["recipient_sequence"],
        created_at_ms=row["created_at_ms"],
        refs=tuple(_ref(entry) for entry in row["refs"]),
        reply_to=row["reply_to"],
        outcome=row["outcome"],
        subject=row["subject"],
        expires_at_ms=row["expires_at_ms"],
    )


def _endpoint(row: Mapping[str, Any]) -> Endpoint:
    locator = row["locator"]
    return Endpoint(
        endpoint_id=row["endpoint_id"],
        locator=Locator(
            runtime=locator["runtime"],
            runtime_instance_id=locator["runtime_instance_id"],
            instance_name=locator["instance_name"],
            address=locator["address"],
        ),
        online=row["online"],
        state=row["state"],
        state_generation=row["state_generation"],
        pending=row["pending"],
        incarnation_id=row["incarnation_id"],
        alias=row["alias"],
        provider=row["provider"],
    )


def _ref(row: Mapping[str, Any]) -> Ref:
    kind = row["kind"]
    if kind == "file":
        return FileRef(path=row["path"], sha256=row["sha256"], bytes=row["bytes"])
    if kind == "pane":
        return PaneRef(
            runtime_instance_id=row["runtime_instance_id"],
            runtime=row["runtime"],
            workspace=row["workspace"],
            tab=row["tab"],
            pane_id=row["pane_id"],
        )
    if kind == "media":
        return MediaRef(
            runtime_instance_id=row["runtime_instance_id"],
            resource_id=row["resource_id"],
            binding=row["binding"],
        )
    raise MeshError("unknown reference kind: " + repr(kind))
