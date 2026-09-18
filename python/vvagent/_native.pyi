"""Type stubs for the private extension.

Everything here returns plain dicts and lists; the typed dataclasses live in ``vvagent``
itself. Nothing in this module is public API — import from ``vvagent``.
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple

class MeshFailure(OSError):
    code: str
    message: str
    candidates: List[str]

class Store:
    @property
    def path(self) -> str: ...

class Caller:
    @property
    def principal(self) -> str: ...
    @property
    def endpoint_id(self) -> Optional[str]: ...
    @property
    def incarnation_id(self) -> Optional[str]: ...
    @property
    def scope(self) -> Optional[str]: ...

def open_store(path: Optional[str] = ...) -> Store: ...
def authenticate(
    store: Store, endpoint: Optional[str] = ..., token_file: Optional[str] = ...
) -> Caller: ...
def bind(
    store: Store,
    *,
    runtime: str,
    instance_id: str,
    alias: Optional[str] = ...,
    provider: Optional[str] = ...,
    instance_name: Optional[str] = ...,
    address: Optional[str] = ...,
) -> Dict[str, Any]: ...
def unbind(store: Store, endpoint: str, incarnation: str) -> None: ...
def set_state(store: Store, endpoint: str, state: str) -> int: ...
def list_endpoints(store: Store) -> List[Dict[str, Any]]: ...
def resolve_selector(store: Store, caller: Caller, selector: str) -> Dict[str, Any]: ...
def send(
    store: Store,
    caller: Caller,
    *,
    to: str,
    kind: str,
    text: str,
    idempotency_key: str,
    subject: Optional[str] = ...,
    refs: Optional[Sequence[Dict[str, Any]]] = ...,
    reply_to: Optional[str] = ...,
    outcome: Optional[str] = ...,
    expires_in_ms: Optional[int] = ...,
) -> Dict[str, Any]: ...
def inbox(
    store: Store, endpoint: str, states: Optional[Sequence[str]] = ..., limit: int = ...
) -> List[Dict[str, Any]]: ...
def claim(
    store: Store, caller: Caller, lease_ms: Optional[int] = ...
) -> Optional[Dict[str, Any]]: ...
def respond(
    store: Store,
    caller: Caller,
    *,
    request: str,
    outcome: str,
    text: str,
    idempotency_key: str,
    refs: Optional[Sequence[Dict[str, Any]]] = ...,
) -> Dict[str, Any]: ...
def response_for(store: Store, request: str) -> Optional[Dict[str, Any]]: ...
def cancel(store: Store, caller: Caller, request: str) -> str: ...
def sweep(store: Store) -> Tuple[int, int]: ...
def wait(
    store: Store, request: str, *, timeout_ms: int, poll_ms: int = ...
) -> Dict[str, Any]: ...
