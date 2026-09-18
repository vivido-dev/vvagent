//! Naming agents on peer hosts (`docs/vvagent-inter-host-plan.md` §5).
//!
//! Three forms, one outcome: the local proxy that stands for the remote agent, whose id is what
//! gets stored, sent to, trusted, or grouped — never the selector.
//!
//! - `agent://buildbox/<id>` and `@buildbox:<id>` name one exact remote endpoint. They need no
//!   connection, so mail to them queues while the peer is away.
//! - `@buildbox:<selector>` is an alias or address in buildbox's own tree. Only buildbox can say
//!   what that names *now*, so it is asked, through the bridge, and the question fails as
//!   `peer_unreachable` when no bridge is connected. Resolving against a remembered copy of the
//!   remote directory would be resolving a position against a stale layout.
//! - `s1t2w12f1p2` is the positional long form: whatever is at `f1p2` on the host that window 12's
//!   bridge is connected to. Window 12 is found from the live bridge lease, never from anything
//!   stored, and `f1p2` is resolved by that host, host-wide.

use std::time::{Duration, Instant};

use agent_mesh_core::{
    Endpoint, ErrorCode, MeshError, Opaque, PeerLabel, RemoteSelector, Result, RuntimeKind,
    time::now_ms,
};
use agent_mesh_store::{Caller, Peer, RESOLUTION_TIMEOUT_MS, Store};

/// The proxy a remote selector names, or `None` when the selector names nothing remote and local
/// resolution should proceed.
pub fn resolve(store: &mut Store, selector: &str, caller: &Caller) -> Result<Option<Endpoint>> {
    let Some(remote) = RemoteSelector::parse(selector)? else {
        return Ok(None);
    };
    let (peer, endpoint_id, display) = match remote {
        RemoteSelector::Exact { peer, endpoint_id } => (known(store, &peer)?, endpoint_id, None),
        RemoteSelector::Named { peer, selector } => {
            let peer = known(store, &peer)?;
            let (id, display) = ask(store, &peer, &selector)?;
            (peer, id, display)
        }
        RemoteSelector::Through { window, rest } => {
            let peers = through_window(store, window, caller)?;
            let peer = match peers.as_slice() {
                // `w12f1p2` is also a legal alias: with no bridge on window 12, it is local.
                [] => return Ok(None),
                [peer] => peer.clone(),
                several => {
                    return Err(MeshError::new(
                        ErrorCode::AgentAmbiguous,
                        format!("several connected peers are anchored on a window {window}"),
                    )
                    .with_candidates(
                        several
                            .iter()
                            .map(|peer| format!("@{}:{rest}", peer.label))
                            .collect(),
                    ));
                }
            };
            let (id, display) = ask(store, &peer, &rest.to_string())?;
            (peer, id, display)
        }
    };
    let proxy = store.ensure_proxy(&peer.peer_id, &endpoint_id, display.as_deref())?;
    store.endpoint(&proxy).map(Some)
}

fn known(store: &Store, label: &PeerLabel) -> Result<Peer> {
    store.peer(label).map_err(|err| match err.code {
        ErrorCode::NotFound => MeshError::new(
            ErrorCode::AgentNotFound,
            format!("no peer host is called `{label}`; see `vvagent peer list`"),
        ),
        _ => err,
    })
}

/// Ask the peer what `selector` names on its host, through whichever bridge holds its lease.
fn ask(store: &mut Store, peer: &Peer, selector: &str) -> Result<(Opaque, Option<String>)> {
    let request = store.request_resolution(&peer.peer_id, selector)?;
    let deadline = Instant::now() + Duration::from_millis(RESOLUTION_TIMEOUT_MS as u64);
    loop {
        if let Some(answer) = store.take_resolution(request)? {
            return answer.map_err(|err| retypeable(err, &peer.label));
        }
        if Instant::now() >= deadline {
            return Err(MeshError::new(
                ErrorCode::PeerUnreachable,
                format!("`{}` did not answer in time", peer.label),
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The peer names its candidates as its own local selectors; say them as this host would type them.
fn retypeable(err: MeshError, label: &PeerLabel) -> MeshError {
    let candidates = err
        .candidates
        .iter()
        .map(|name| match name.strip_prefix("agent://local/") {
            Some(id) => format!("agent://{label}/{id}"),
            None => format!("@{label}:{name}"),
        })
        .collect();
    MeshError::new(err.code, err.message).with_candidates(candidates)
}

/// Connected peers whose bridge was launched from window `window`.
///
/// A window id is unique within one runtime instance, so a caller inside a Vivido or Vivida window
/// looks only at its own instance's windows; anyone else looks at every instance and must find
/// exactly one.
fn through_window(store: &Store, window: u32, caller: &Caller) -> Result<Vec<Peer>> {
    let own = caller
        .principal
        .endpoint_id
        .as_ref()
        .and_then(|id| store.endpoint(id).ok())
        .filter(|endpoint| {
            matches!(
                endpoint.locator.kind,
                RuntimeKind::Vivido | RuntimeKind::Vivida
            )
        })
        .map(|endpoint| (endpoint.locator.kind, endpoint.locator.instance_name));
    let now = now_ms();
    Ok(store
        .list_peers()?
        .into_iter()
        .filter(|peer| {
            let Some(anchor) = peer
                .lease
                .as_ref()
                .filter(|lease| lease.is_live(now))
                .and_then(|lease| lease.anchor.as_ref())
            else {
                return false;
            };
            anchor.window == window
                && own.as_ref().is_none_or(|(kind, instance)| {
                    anchor.runtime == *kind && instance.as_deref() == Some(anchor.instance.as_str())
                })
        })
        .collect())
}
