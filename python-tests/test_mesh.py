"""The mesh, from Python, against a real store.

Every test opens its own SQLite file in a tmp_path, so nothing here touches the developer's own
mailbox and nothing depends on test ordering. Two endpoints are bound in most fixtures rather than
one, because almost every interesting property here is about two parties, and a single-endpoint
test can pass while the isolation it claims to prove is broken.
"""

from __future__ import annotations

import os
import threading
from typing import Iterator, Tuple

import pytest

import vvagent as mesh

INSTANCE = "a" * 32
OTHER_INSTANCE = "b" * 32
TIMEOUT = 5.0


@pytest.fixture()  # type: ignore[untyped-decorator]
def store(tmp_path: object) -> Iterator[mesh.Store]:
    yield mesh.open(os.path.join(str(tmp_path), "mesh.sqlite"))


def bind_agent(
    store: mesh.Store, alias: str, *, instance: str = INSTANCE, address: str | None = None
) -> Tuple[mesh.Bound, mesh.Caller]:
    bound = mesh.bind(
        store, runtime="wrapper", instance_id=instance, alias=alias, address=address
    )
    caller = mesh.authenticate(
        store, endpoint=bound.endpoint_id, token_file=bound.token_file
    )
    return bound, caller


def test_a_request_travels_from_one_agent_to_another(store: mesh.Store) -> None:
    asker, asker_caller = bind_agent(store, "asker")
    doer, doer_caller = bind_agent(store, "doer")

    request = mesh.send(
        store, asker_caller, to=doer.endpoint_id, text="please look at the diff"
    )
    assert request.kind == mesh.REQUEST
    assert request.state == "queued"
    assert request.sender.endpoint_id == asker.endpoint_id

    claimed = mesh.claim(store, doer_caller)
    assert claimed is not None
    assert claimed.message_id == request.message_id
    assert claimed.text == "please look at the diff"

    mesh.respond(
        store,
        doer_caller,
        request=claimed.message_id,
        outcome=mesh.COMPLETED,
        text="looks fine",
    )

    answer = mesh.response_for(store, request.message_id)
    assert answer is not None
    assert answer.outcome == mesh.COMPLETED
    assert answer.text == "looks fine"
    assert answer.to == asker.endpoint_id


def test_wait_returns_the_answer_another_thread_sends(store: mesh.Store) -> None:
    asker, asker_caller = bind_agent(store, "asker")
    doer, doer_caller = bind_agent(store, "doer")
    request = mesh.send(store, asker_caller, to=doer.endpoint_id, text="ping")

    def answer() -> None:
        claimed = mesh.claim(store, doer_caller)
        assert claimed is not None
        mesh.respond(
            store,
            doer_caller,
            request=claimed.message_id,
            outcome=mesh.COMPLETED,
            text="pong",
        )

    # The point of the thread: `wait` must release the GIL, or this reply can never be sent and
    # the test deadlocks rather than failing.
    worker = threading.Thread(target=answer)
    worker.start()
    try:
        resolved = mesh.wait(store, request.message_id, timeout=TIMEOUT, poll=0.01)
    finally:
        worker.join(TIMEOUT)

    assert resolved.resolution == "response"
    assert resolved.answered
    assert resolved.message is not None
    assert resolved.message.text == "pong"


def test_a_timeout_leaves_the_request_alone(store: mesh.Store) -> None:
    _, asker_caller = bind_agent(store, "asker")
    doer, _ = bind_agent(store, "doer")
    request = mesh.send(store, asker_caller, to=doer.endpoint_id, text="unanswered")

    resolved = mesh.wait(store, request.message_id, timeout=0.05, poll=0.01)
    assert resolved.resolution == "timeout"
    assert resolved.message is None
    assert resolved.state == "queued"

    # A client giving up is not the work stopping: the request is still there to wait on again.
    still_there = mesh.inbox(store, doer.endpoint_id)
    assert [message.message_id for message in still_there] == [request.message_id]


def test_two_agents_claim_only_their_own_work(store: mesh.Store) -> None:
    _, asker_caller = bind_agent(store, "asker")
    left, left_caller = bind_agent(store, "left")
    right, right_caller = bind_agent(store, "right")

    for target, text in ((left, "for left"), (right, "for right")):
        mesh.send(store, asker_caller, to=target.endpoint_id, text=text)

    assert (claimed := mesh.claim(store, left_caller)) is not None
    assert claimed.text == "for left"
    assert (claimed := mesh.claim(store, right_caller)) is not None
    assert claimed.text == "for right"
    assert mesh.claim(store, left_caller) is None


def test_rebinding_keeps_the_mailbox_and_retires_the_incarnation(
    store: mesh.Store,
) -> None:
    _, asker_caller = bind_agent(store, "asker")
    first, first_caller = bind_agent(store, "doer")
    held = mesh.send(store, asker_caller, to=first.endpoint_id, text="already claimed")
    waiting = mesh.send(store, asker_caller, to=first.endpoint_id, text="still queued")
    assert mesh.claim(store, first_caller) is not None

    # A restart: same alias, same instance, so the same durable slot comes back with its mailbox.
    second, second_caller = bind_agent(store, "doer")
    assert second.rebound
    assert second.endpoint_id == first.endpoint_id
    assert second.incarnation_id != first.incarnation_id

    # The successor picks up queued work, and does *not* inherit its predecessor's claim: that
    # message stays held until the lease lapses, so two incarnations never both own one request.
    claimed = mesh.claim(store, second_caller)
    assert claimed is not None
    assert claimed.message_id == waiting.message_id

    # And the retired incarnation cannot answer for the one it was holding.
    with pytest.raises(mesh.MeshError) as raised:
        mesh.respond(
            store,
            first_caller,
            request=held.message_id,
            outcome=mesh.COMPLETED,
            text="too late",
        )
    # `claim_lost`, not `not_authorized`: the process is who it says it is, and the thing it lost
    # is the lease. A responder can tell "I was replaced" from "I was never allowed".
    assert raised.value.code == "claim_lost"


def test_an_alias_resolves_and_an_ambiguous_one_refuses(store: mesh.Store) -> None:
    _, inside = bind_agent(store, "asker")
    here, _ = bind_agent(store, "reviewer")
    there, _ = bind_agent(store, "reviewer", instance=OTHER_INSTANCE)

    # Two sessions may both hold a `reviewer`. An agent inside one of them gets its own: the
    # caller's neighbourhood settles it, which is what makes short names usable at all.
    assert mesh.resolve(store, inside, "reviewer").endpoint_id == here.endpoint_id

    # A shell belongs to neither, so nothing settles it — and the answer is the two candidates to
    # retype, never a silent pick between them.
    outside = mesh.authenticate(store)
    with pytest.raises(mesh.MeshError) as raised:
        mesh.resolve(store, outside, "reviewer")
    assert raised.value.code == "agent_ambiguous"
    assert len(raised.value.candidates) == 2
    assert there.endpoint_id != here.endpoint_id


def test_a_media_reference_survives_the_round_trip(store: mesh.Store) -> None:
    _, asker_caller = bind_agent(store, "asker")
    doer, doer_caller = bind_agent(store, "doer")

    reference = mesh.MediaRef(
        runtime_instance_id=INSTANCE, resource_id="surface-7", binding="pinned"
    )
    mesh.send(
        store,
        asker_caller,
        to=doer.endpoint_id,
        text="what do you make of this",
        refs=[reference],
    )

    claimed = mesh.claim(store, doer_caller)
    assert claimed is not None
    assert claimed.refs == (reference,)
    # The binding is the whole point: a receiver must be able to tell "what I was showing" from
    # "what is there now", and it must not have to infer it.
    assert isinstance(claimed.refs[0], mesh.MediaRef)
    assert claimed.refs[0].binding == "pinned"


def test_the_local_user_has_a_mailbox_but_is_not_an_agent(store: mesh.Store) -> None:
    person = mesh.authenticate(store)
    assert person.principal == "local_user"
    assert person.endpoint_id is not None

    doer, doer_caller = bind_agent(store, "doer")
    request = mesh.send(store, person, to=doer.endpoint_id, text="from a shell")

    # A reply reaches the person: having a mailbox is what makes `wait` possible for a shell.
    claimed = mesh.claim(store, doer_caller)
    assert claimed is not None
    mesh.respond(
        store, doer_caller, request=claimed.message_id, outcome=mesh.ANSWERED, text="ok"
    )
    answer = mesh.response_for(store, request.message_id)
    assert answer is not None
    assert answer.to == person.endpoint_id

    # But the recipient can always tell a person from an agent, because the store stamps the
    # principal from the authenticated caller and never from anything the sender supplied.
    assert claimed.sender.kind == "local_user"
    assert claimed.sender.endpoint_id == person.endpoint_id


def test_an_identity_never_carries_its_token(store: mesh.Store) -> None:
    bound, caller = bind_agent(store, "doer")
    token = open(bound.token_file, encoding="utf-8").read().strip()
    assert token

    # The secret exists on disk, owner-only, and reaches Python only as a path.
    assert oct(os.stat(bound.token_file).st_mode & 0o777) == "0o600"
    assert token not in repr(caller)
    assert token not in repr(bound)
    assert not any(token in str(value) for value in vars(bound).values())
    assert caller.endpoint_id == bound.endpoint_id


def test_a_cancelled_request_ends_the_wait(store: mesh.Store) -> None:
    _, asker_caller = bind_agent(store, "asker")
    doer, _ = bind_agent(store, "doer")
    request = mesh.send(store, asker_caller, to=doer.endpoint_id, text="never mind")

    assert mesh.cancel(store, asker_caller, request.message_id) == "cancelled"
    resolved = mesh.wait(store, request.message_id, timeout=TIMEOUT, poll=0.01)
    assert resolved.resolution == "cancelled"
    assert resolved.message is None
