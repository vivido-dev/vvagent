//! Store-level proofs for inter-host milestone IH1: peers, leases, and proxies.
//!
//! Each test name is one claim `docs/vvagent-inter-host-plan.md` §4 makes.

use agent_mesh_core::time::now_ms;
use agent_mesh_core::{
    Address, Alias, Capabilities, Capability, Draft, ErrorCode, Kind, Locator, Opaque, Outcome,
    PeerLabel, PrincipalKind, RuntimeKind, State,
};
use agent_mesh_store::{Binding, Bound, Caller, LeaseAnchor, Store};

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "agent-mesh-ih1-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        Self(base)
    }

    fn store(&self) -> Store {
        Store::open(self.0.join("state").join("mesh.sqlite")).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const INST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MINUTE: i64 = 60_000;

fn label(value: &str) -> PeerLabel {
    PeerLabel::parse(value).unwrap()
}

fn bind(store: &mut Store, alias: &str) -> Bound {
    store
        .bind(&Binding {
            alias: Some(Alias::parse(alias).unwrap()),
            provider: Some("fake".into()),
            locator: Locator {
                kind: RuntimeKind::Vvmux,
                runtime_instance_id: Opaque::parse(INST).unwrap(),
                instance_name: Some("dev".into()),
                address: Some(Address::parse("f1p1").unwrap()),
            },
        })
        .unwrap()
}

fn caller(store: &Store, bound: &Bound) -> Caller {
    store
        .authenticate(&bound.endpoint_id, &bound.token)
        .unwrap()
}

fn draft(to: &Opaque, kind: Kind, key: &str) -> Draft {
    Draft {
        to: to.clone(),
        kind,
        reply_to: None,
        outcome: None,
        subject: None,
        text: format!("body {key}"),
        refs: Vec::new(),
        idempotency_key: key.into(),
        expires_in_ms: None,
    }
}

/// A connected peer: pinned, leased to `owner`, with one proxy for `remote`.
fn connected(store: &mut Store, name: &str, owner: &Opaque, remote: &Opaque) -> (Opaque, Opaque) {
    let peer = store.pin_peer(&label(name), &Opaque::generate()).unwrap();
    assert!(
        store
            .acquire_peer_lease(&peer.peer_id, owner, None, MINUTE, now_ms())
            .unwrap()
    );
    let proxy = store
        .ensure_proxy(&peer.peer_id, remote, Some("vvmux:dev/f1p2 (builder)"))
        .unwrap();
    (peer.peer_id, proxy)
}

#[test]
fn a_store_has_one_host_id_that_survives_reopening() {
    let scratch = Scratch::new("host-id");
    let first = scratch.store().host_id().unwrap();
    assert_eq!(scratch.store().host_id().unwrap(), first);
    let elsewhere = Scratch::new("host-id-2");
    assert_ne!(elsewhere.store().host_id().unwrap(), first);
}

#[test]
fn a_label_is_pinned_to_the_store_that_first_answered() {
    let scratch = Scratch::new("pin");
    let mut store = scratch.store();
    let buildbox = Opaque::generate();

    let pinned = store.pin_peer(&label("buildbox"), &buildbox).unwrap();
    assert_eq!(
        store
            .pin_peer(&label("buildbox"), &buildbox)
            .unwrap()
            .peer_id,
        pinned.peer_id,
        "the same store under the same label is the same peer"
    );

    let substitute = store.pin_peer(&label("buildbox"), &Opaque::generate());
    assert_eq!(substitute.unwrap_err().code, ErrorCode::PeerMismatch);
    let second_name = store.pin_peer(&label("bb"), &buildbox);
    assert_eq!(second_name.unwrap_err().code, ErrorCode::PeerMismatch);
    let own = store.host_id().unwrap();
    assert_eq!(
        store.pin_peer(&label("me"), &own).unwrap_err().code,
        ErrorCode::InvalidRequest
    );

    // Forgetting frees the label for a different store, as a new peer.
    store.retire_peer(&label("buildbox")).unwrap();
    let reinstalled = store
        .pin_peer(&label("buildbox"), &Opaque::generate())
        .unwrap();
    assert_ne!(reinstalled.peer_id, pinned.peer_id);
    assert_eq!(store.list_peers().unwrap().len(), 1);
}

#[test]
fn a_proxy_is_never_a_local_endpoint_and_nothing_local_can_become_one() {
    let scratch = Scratch::new("proxy-local");
    let mut store = scratch.store();
    let local = bind(&mut store, "builder");
    let (peer, proxy) = connected(
        &mut store,
        "buildbox",
        &Opaque::generate(),
        &Opaque::generate(),
    );

    // Local listing — and therefore every alias and address resolution — never sees a proxy.
    let listed: Vec<_> = store
        .list_endpoints()
        .unwrap()
        .into_iter()
        .map(|endpoint| endpoint.endpoint_id)
        .collect();
    assert_eq!(listed, vec![local.endpoint_id.clone()]);
    assert_eq!(store.list_proxies(&peer).unwrap().len(), 1);
    let record = store.endpoint(&proxy).unwrap();
    assert_eq!(record.locator.kind, RuntimeKind::Peer);
    assert!(record.alias.is_none() && record.locator.address.is_none());

    // No token exists for a proxy, and no process may bind as a peer.
    assert!(store.authenticate(&proxy, "anything").is_err());
    let refused = store.bind(&Binding {
        alias: None,
        provider: None,
        locator: Locator {
            kind: RuntimeKind::Peer,
            runtime_instance_id: peer.clone(),
            instance_name: None,
            address: None,
        },
    });
    assert_eq!(refused.unwrap_err().code, ErrorCode::InvalidRequest);

    // The same remote id on the same peer is the same proxy.
    let remote = store.proxy(&proxy).unwrap().remote_endpoint_id;
    assert_eq!(store.ensure_proxy(&peer, &remote, None).unwrap(), proxy);
}

#[test]
fn remote_originated_work_needs_trust_and_a_peer_is_never_a_teammate() {
    let scratch = Scratch::new("peer-policy");
    let mut store = scratch.store();
    let local = bind(&mut store, "builder");
    let owner = Opaque::generate();
    let (_, proxy) = connected(&mut store, "buildbox", &owner, &Opaque::generate());
    let remote = store.proxy_caller(&proxy, &owner).unwrap();
    assert_eq!(remote.principal.kind, PrincipalKind::Peer);

    let refused = store.send(&remote, &draft(&local.endpoint_id, Kind::Request, "r1"));
    assert_eq!(refused.unwrap_err().code, ErrorCode::PolicyRefused);

    store.set_peer_trust(&label("buildbox"), true).unwrap();
    let accepted = store
        .send(&remote, &draft(&local.endpoint_id, Kind::Request, "r1"))
        .unwrap();
    assert_eq!(accepted.from.kind, PrincipalKind::Peer);
    assert_eq!(accepted.from.endpoint_id.as_ref(), Some(&proxy));

    // Trusted means visible; it does not mean it may spend the agent's turns by default.
    let me = caller(&store, &local);
    assert_eq!(
        store.claim(&me, None).unwrap().unwrap().message_id,
        accepted.message_id
    );
    store
        .respond(
            &me,
            &accepted.message_id,
            Outcome::Completed,
            "done",
            vec![],
            "a1",
        )
        .unwrap();
    store
        .set_capabilities(
            &local.endpoint_id,
            &Capabilities {
                provider: Some("fake".into()),
                native_session: Some("thread".into()),
                granted: vec![Capability::ExternalTurnStart, Capability::StructuredPull],
                ..Capabilities::default()
            },
        )
        .unwrap();
    store
        .send(&remote, &draft(&local.endpoint_id, Kind::Request, "r2"))
        .unwrap();
    let wake = store
        .activatable(&Opaque::parse(INST).unwrap(), now_ms(), 0, 3)
        .unwrap();
    assert_eq!(wake.len(), 1, "the activatable agent is considered");
    assert!(
        !wake[0].decision.allowed,
        "and a trusted peer still does not wake it under the default policy"
    );
}

#[test]
fn a_reply_from_a_peer_is_admitted_without_trust() {
    let scratch = Scratch::new("peer-reply");
    let mut store = scratch.store();
    let local = bind(&mut store, "asker");
    let owner = Opaque::generate();
    let (_, proxy) = connected(&mut store, "buildbox", &owner, &Opaque::generate());

    // The local agent asks; the bridge takes the request off the proxy's queue as outbound mail.
    let asker = caller(&store, &local);
    let request = store
        .send(&asker, &draft(&proxy, Kind::Request, "q1"))
        .unwrap();
    let bridge = store.proxy_caller(&proxy, &owner).unwrap();
    let outbound = store.claim(&bridge, None).unwrap().unwrap();
    assert_eq!(outbound.message_id, request.message_id);

    // The peer's answer comes back through the same proxy, untrusted peer or not.
    let answer = store
        .respond(
            &bridge,
            &request.message_id,
            Outcome::Completed,
            "built",
            vec![],
            "origin-1",
        )
        .unwrap();
    assert_eq!(answer.to_endpoint, local.endpoint_id);
    let seen = store.response_for(&request.message_id).unwrap().unwrap();
    assert_eq!(seen.text, "built");
    assert_eq!(
        store.message(&request.message_id).unwrap().state,
        State::Consumed
    );
}

#[test]
fn only_the_live_lease_holder_acts_for_a_peer() {
    let scratch = Scratch::new("lease");
    let mut store = scratch.store();
    let local = bind(&mut store, "asker");
    let first = Opaque::generate();
    let second = Opaque::generate();
    let (peer, proxy) = connected(&mut store, "buildbox", &first, &Opaque::generate());
    let anchor = LeaseAnchor {
        runtime: RuntimeKind::Vivida,
        instance: "main".into(),
        window: 12,
    };

    // A second window connected to the same host stands aside while the first is live.
    assert!(
        !store
            .acquire_peer_lease(&peer, &second, Some(&anchor), MINUTE, now_ms())
            .unwrap()
    );
    assert_eq!(
        store.proxy_caller(&proxy, &second).unwrap_err().code,
        ErrorCode::ClaimLost
    );

    // The first bridge takes a message in flight, then its lease lapses.
    let asker = caller(&store, &local);
    let request = store
        .send(&asker, &draft(&proxy, Kind::Request, "q1"))
        .unwrap();
    let old = store.proxy_caller(&proxy, &first).unwrap();
    assert!(store.claim(&old, None).unwrap().is_some());
    assert!(
        store
            .acquire_peer_lease(&peer, &first, None, MINUTE, now_ms() - 2 * MINUTE)
            .unwrap(),
        "renewal by the holder, with a clock that makes it already lapsed"
    );

    // The successor takes over: the in-flight claim returns to the queue for it to resend, and
    // nothing the old bridge still holds works any more.
    assert!(
        store
            .acquire_peer_lease(&peer, &second, Some(&anchor), MINUTE, now_ms())
            .unwrap()
    );
    assert_eq!(
        store.message(&request.message_id).unwrap().state,
        State::Queued
    );
    assert_eq!(
        store.claim(&old, None).unwrap_err().code,
        ErrorCode::ClaimLost
    );
    let respond = store.respond(
        &old,
        &request.message_id,
        Outcome::Completed,
        "x",
        vec![],
        "k",
    );
    assert_eq!(respond.unwrap_err().code, ErrorCode::ClaimLost);
    let peer_record = store.peer_by_id(&peer).unwrap();
    assert_eq!(peer_record.lease.unwrap().anchor, Some(anchor));

    let new = store.proxy_caller(&proxy, &second).unwrap();
    assert_eq!(
        store.claim(&new, None).unwrap().unwrap().message_id,
        request.message_id
    );

    // Releasing requeues the holder's claims and takes the proxies offline; a stranger's release
    // changes nothing.
    store.release_peer_lease(&peer, &first).unwrap();
    assert_eq!(
        store.message(&request.message_id).unwrap().state,
        State::Claimed
    );
    store.release_peer_lease(&peer, &second).unwrap();
    assert_eq!(
        store.message(&request.message_id).unwrap().state,
        State::Queued
    );
    assert!(!store.endpoint(&proxy).unwrap().online);
    assert!(store.peer_by_id(&peer).unwrap().lease.is_none());
}

#[test]
fn a_peer_cannot_route_through_this_host_to_another_peer() {
    let scratch = Scratch::new("no-transit");
    let mut store = scratch.store();
    let owner = Opaque::generate();
    let (_, first) = connected(&mut store, "one", &owner, &Opaque::generate());
    let (_, second) = connected(&mut store, "two", &owner, &Opaque::generate());
    store.set_peer_trust(&label("one"), true).unwrap();

    let from_one = store.proxy_caller(&first, &owner).unwrap();
    let relayed = store.send(&from_one, &draft(&second, Kind::Request, "hop"));
    assert_eq!(relayed.unwrap_err().code, ErrorCode::NotAuthorized);
}

#[test]
fn forgetting_a_peer_fails_what_waits_on_it_and_leaves_claimed_work_with_its_agent() {
    let scratch = Scratch::new("retire");
    let mut store = scratch.store();
    let local = bind(&mut store, "asker");
    let owner = Opaque::generate();
    let (_, proxy) = connected(&mut store, "buildbox", &owner, &Opaque::generate());
    store.set_peer_trust(&label("buildbox"), true).unwrap();

    let asker = caller(&store, &local);
    let outbound = store
        .send(&asker, &draft(&proxy, Kind::Request, "q1"))
        .unwrap();
    let remote = store.proxy_caller(&proxy, &owner).unwrap();
    let in_hand = store
        .send(&remote, &draft(&local.endpoint_id, Kind::Request, "r1"))
        .unwrap();
    let unread = store
        .send(&remote, &draft(&local.endpoint_id, Kind::Request, "r2"))
        .unwrap();
    assert_eq!(
        store.claim(&asker, None).unwrap().unwrap().message_id,
        in_hand.message_id
    );

    let retired = store.retire_peer(&label("buildbox")).unwrap();
    assert_eq!(retired.proxies, 1);
    assert_eq!(retired.undeliverable, 1);
    assert_eq!(retired.withdrawn, 1);

    for id in [&outbound.message_id, &unread.message_id] {
        let failed = store.message(id).unwrap();
        assert_eq!(failed.state, State::Undeliverable);
        assert_eq!(failed.failure.as_deref(), Some("peer_retired"));
    }
    assert_eq!(store.endpoint(&proxy).unwrap().pending, 0);
    assert_eq!(
        store.endpoint(&local.endpoint_id).unwrap().pending,
        1,
        "only the claimed request still holds the agent's capacity"
    );

    // Claimed work stays with its agent, but can no longer be answered, and nothing new goes out.
    assert_eq!(
        store.message(&in_hand.message_id).unwrap().state,
        State::Claimed
    );
    let answer = store.respond(
        &asker,
        &in_hand.message_id,
        Outcome::Completed,
        "x",
        vec![],
        "a",
    );
    assert_eq!(answer.unwrap_err().code, ErrorCode::PeerRetired);
    let late = store.send(&asker, &draft(&proxy, Kind::Request, "q2"));
    assert_eq!(late.unwrap_err().code, ErrorCode::PeerRetired);
    assert_eq!(
        store.proxy_caller(&proxy, &owner).unwrap_err().code,
        ErrorCode::PeerRetired
    );
    assert!(store.list_peers().unwrap().is_empty());
}

/// The owner-scoped regression root `AGENTS.md` requires: two peers whose remote agents share an
/// id, a display, and therefore everything a careless key might use, stay independent through send,
/// lease changes, retirement and reconnection.
#[test]
fn two_peers_whose_remote_endpoints_share_an_id_stay_independent() {
    let scratch = Scratch::new("two-peers");
    let mut store = scratch.store();
    let local = bind(&mut store, "asker");
    let same_remote = Opaque::generate();
    let one_owner = Opaque::generate();
    let two_owner = Opaque::generate();
    let (one, one_proxy) = connected(&mut store, "one", &one_owner, &same_remote);
    let (two, two_proxy) = connected(&mut store, "two", &two_owner, &same_remote);
    assert_ne!(one_proxy, two_proxy);

    let asker = caller(&store, &local);
    let to_one = store
        .send(&asker, &draft(&one_proxy, Kind::Request, "q1"))
        .unwrap();
    let to_two = store
        .send(&asker, &draft(&two_proxy, Kind::Request, "q2"))
        .unwrap();

    // Each bridge sees only its own peer's outbox, and cannot act for the other.
    let bridge_two = store.proxy_caller(&two_proxy, &two_owner).unwrap();
    assert_eq!(
        store.claim(&bridge_two, None).unwrap().unwrap().message_id,
        to_two.message_id
    );
    assert!(store.claim(&bridge_two, None).unwrap().is_none());
    assert!(store.proxy_caller(&one_proxy, &two_owner).is_err());

    // Releasing one peer's lease leaves the other's claims and proxies alone.
    store.release_peer_lease(&one, &one_owner).unwrap();
    assert_eq!(
        store.message(&to_two.message_id).unwrap().state,
        State::Claimed
    );
    assert!(store.endpoint(&two_proxy).unwrap().online);

    // Forgetting one fails only its mail.
    store.retire_peer(&label("one")).unwrap();
    assert_eq!(
        store.message(&to_one.message_id).unwrap().state,
        State::Undeliverable
    );
    assert_eq!(
        store.message(&to_two.message_id).unwrap().state,
        State::Claimed
    );
    store
        .respond(
            &bridge_two,
            &to_two.message_id,
            Outcome::Completed,
            "ok",
            vec![],
            "o2",
        )
        .unwrap();
    assert!(store.response_for(&to_two.message_id).unwrap().is_some());

    // Reconnecting under the old label is a new peer with new proxies; the old one never returns.
    let again = store.pin_peer(&label("one"), &Opaque::generate()).unwrap();
    assert_ne!(again.peer_id, one);
    let fresh = store
        .ensure_proxy(&again.peer_id, &same_remote, None)
        .unwrap();
    assert_ne!(fresh, one_proxy);
    assert_ne!(fresh, two_proxy);
    assert_eq!(store.list_proxies(&two).unwrap().len(), 1);
}

fn delivery(origin_endpoint: &Opaque, to: &Opaque, kind: Kind) -> agent_mesh_core::bridge::Deliver {
    agent_mesh_core::bridge::Deliver {
        origin_message_id: Opaque::generate(),
        origin_endpoint_id: origin_endpoint.clone(),
        to_endpoint_id: to.clone(),
        kind,
        reply_to_origin: None,
        outcome: None,
        subject: None,
        text: "from afar".into(),
        refs: Vec::new(),
        remaining_lifetime_ms: None,
    }
}

#[test]
fn one_peer_has_one_inbound_budget_across_every_local_agent() {
    use agent_mesh_core::PEER_MAX_INBOUND_PER_MINUTE;
    let scratch = Scratch::new("peer-budget");
    let mut store = scratch.store();
    let first = bind(&mut store, "first");
    let second = bind(&mut store, "second");
    let owner = Opaque::generate();
    let (peer, _) = connected(&mut store, "buildbox", &owner, &Opaque::generate());
    store.set_peer_trust(&label("buildbox"), true).unwrap();
    let remote_agent = Opaque::generate();

    // Spread across two agents, each well inside its own per-endpoint limit.
    for index in 0..PEER_MAX_INBOUND_PER_MINUTE {
        let to = if index % 2 == 0 { &first } else { &second };
        store
            .ingest(
                &peer,
                &owner,
                &delivery(&remote_agent, &to.endpoint_id, Kind::Request),
            )
            .unwrap();
    }
    let over = store.ingest(
        &peer,
        &owner,
        &delivery(&remote_agent, &first.endpoint_id, Kind::Request),
    );
    assert_eq!(over.unwrap_err().code, ErrorCode::RateLimited);

    // A replay of something already accepted is not new mail, and is accepted again.
    let replay = delivery(&remote_agent, &second.endpoint_id, Kind::Notice);
    let other = Opaque::generate();
    let (fresh_peer, _) = connected(&mut store, "other", &other, &Opaque::generate());
    store.set_peer_trust(&label("other"), true).unwrap();
    let landed = store.ingest(&fresh_peer, &other, &replay).unwrap();
    assert_eq!(
        store
            .ingest(&fresh_peer, &other, &replay)
            .unwrap()
            .message_id,
        landed.message_id
    );
}

#[test]
fn one_peer_has_one_turn_budget_across_every_local_agent() {
    use agent_mesh_core::{DeliveryMode, PEER_MAX_AUTO_TURNS_PER_MINUTE, Rule};
    let scratch = Scratch::new("peer-turns");
    let mut store = scratch.store();
    let owner = Opaque::generate();
    let (peer, _) = connected(&mut store, "buildbox", &owner, &Opaque::generate());
    store.set_peer_trust(&label("buildbox"), true).unwrap();
    let remote_agent = Opaque::generate();

    let mut sender = None;
    for index in 0..PEER_MAX_AUTO_TURNS_PER_MINUTE {
        let local = bind(&mut store, &format!("agent{index}"));
        let message = store
            .ingest(
                &peer,
                &owner,
                &delivery(&remote_agent, &local.endpoint_id, Kind::Request),
            )
            .unwrap();
        assert!(
            store
                .peer_activation_budget_left(&message.from, now_ms())
                .unwrap()
        );
        store
            .record_activation(
                &message.message_id,
                &local.endpoint_id,
                DeliveryMode::ActivateAndPull,
                Rule::Trusted,
                "started",
            )
            .unwrap();
        sender = Some(message.from);
    }
    let sender = sender.unwrap();
    assert!(
        !store
            .peer_activation_budget_left(&sender, now_ms())
            .unwrap(),
        "four turns on four different agents exhaust the one peer budget"
    );
    let local = bind(&mut store, "local-only");
    let me = caller(&store, &local);
    let local_sender = store
        .send(&me, &draft(&local.endpoint_id, Kind::Notice, "n"))
        .unwrap()
        .from;
    assert!(
        store
            .peer_activation_budget_left(&local_sender, now_ms())
            .unwrap(),
        "local mail has no peer budget"
    );
}

#[test]
fn a_reference_says_which_host_its_file_is_on() {
    use agent_mesh_core::Ref;
    use agent_mesh_core::bridge::{RefHost, WireRef};
    let scratch = Scratch::new("ref-host");
    let mut store = scratch.store();
    let local = bind(&mut store, "reader");
    let owner = Opaque::generate();
    let (peer, _) = connected(&mut store, "buildbox", &owner, &Opaque::generate());
    store.set_peer_trust(&label("buildbox"), true).unwrap();

    let file = |path: &str| Ref::File {
        path: path.into(),
        sha256: None,
        bytes: None,
        host: None,
    };
    #[cfg(unix)]
    let (peer_path, staged_path, result_path) = (
        "C:\\build\\out.log",
        "/tmp/staged.bin",
        "/home/u/result.txt",
    );
    #[cfg(windows)]
    let (peer_path, staged_path, result_path) = (
        "/build/out.log",
        "C:\\tmp\\staged.bin",
        "C:\\home\\u\\result.txt",
    );
    let mut deliver = delivery(&Opaque::generate(), &local.endpoint_id, Kind::Request);
    deliver.refs = vec![
        WireRef {
            on: RefHost::Sender,
            reference: file(peer_path),
        },
        WireRef {
            on: RefHost::Recipient,
            reference: file(staged_path),
        },
    ];
    let landed = store.ingest(&peer, &owner, &deliver).unwrap();
    assert_eq!(
        landed.refs,
        vec![
            Ref::File {
                path: peer_path.into(),
                sha256: None,
                bytes: None,
                host: Some(peer.clone()),
            },
            file(staged_path),
        ],
        "a foreign path on the peer is kept, and marked as the peer's"
    );

    // A path the peer says is on *this* host is held to this host's rules when it lands.
    #[cfg(unix)]
    {
        let mut wrong = delivery(&Opaque::generate(), &local.endpoint_id, Kind::Request);
        wrong.refs = vec![WireRef {
            on: RefHost::Recipient,
            reference: file("C:\\not\\here"),
        }];
        assert_eq!(
            store.ingest(&peer, &owner, &wrong).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }

    // Going back out, the peer's own file is `on: recipient` again, and a local one `on: sender`.
    let me = caller(&store, &local);
    let proxy = store
        .ensure_proxy(&peer, &Opaque::generate(), None)
        .unwrap();
    let mut reply = draft(&proxy, Kind::Request, "out");
    reply.refs = vec![landed.refs[0].clone(), file(result_path)];
    let queued = store.send(&me, &reply).unwrap();
    let outbound = store
        .outbound(&store.proxy(&proxy).unwrap(), &queued, now_ms())
        .unwrap();
    assert_eq!(outbound.refs[0].on, RefHost::Recipient);
    assert_eq!(outbound.refs[1].on, RefHost::Sender);
    assert!(
        outbound
            .refs
            .iter()
            .all(|wire| matches!(wire.reference, Ref::File { host: None, .. })),
        "which host a reference is about travels as `on`, never as a store's own peer id"
    );
}

#[test]
fn a_question_for_a_peer_needs_a_connected_bridge_and_only_that_peer_answers_it() {
    let scratch = Scratch::new("resolution");
    let mut store = scratch.store();
    let owner = Opaque::generate();
    let (peer, _) = connected(&mut store, "buildbox", &owner, &Opaque::generate());
    let (other, _) = connected(
        &mut store,
        "other",
        &Opaque::generate(),
        &Opaque::generate(),
    );

    let asked = store.request_resolution(&peer, "builder").unwrap();
    assert_eq!(
        store.pending_resolutions(&peer).unwrap(),
        vec![(asked, "builder".to_owned())]
    );
    assert!(store.pending_resolutions(&other).unwrap().is_empty());
    assert_eq!(store.take_resolution(asked).unwrap(), None, "no answer yet");

    // Another peer cannot answer a question it was not asked.
    let forged = Opaque::generate();
    assert!(
        !store
            .answer_resolution(&other, asked, Ok((forged, None)))
            .unwrap()
    );
    let remote = Opaque::generate();
    assert!(
        store
            .answer_resolution(
                &peer,
                asked,
                Ok((remote.clone(), Some("vvmux:dev/builder".into())))
            )
            .unwrap()
    );
    assert!(
        !store
            .answer_resolution(&peer, asked, Ok((Opaque::generate(), None)))
            .unwrap(),
        "and it is answered once"
    );
    assert_eq!(
        store.take_resolution(asked).unwrap(),
        Some(Ok((remote, Some("vvmux:dev/builder".into()))))
    );
    assert_eq!(
        store.take_resolution(asked).unwrap(),
        None,
        "reading it removed it"
    );

    // An ambiguity keeps its candidates.
    let ambiguous = store.request_resolution(&peer, "f1p2").unwrap();
    let err = MeshErrorShape::ambiguous();
    store
        .answer_resolution(&peer, ambiguous, Err(err.clone()))
        .unwrap();
    let answer = store
        .take_resolution(ambiguous)
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(answer.code, ErrorCode::AgentAmbiguous);
    assert_eq!(answer.candidates, err.candidates);

    // Without a live bridge, nothing can say what a name means now.
    store.release_peer_lease(&peer, &owner).unwrap();
    assert_eq!(
        store.request_resolution(&peer, "builder").unwrap_err().code,
        ErrorCode::PeerUnreachable
    );
    assert!(store.request_resolution(&other, "").is_err());
    assert!(store.request_resolution(&other, "a\nb").is_err());
}

struct MeshErrorShape;

impl MeshErrorShape {
    fn ambiguous() -> agent_mesh_core::MeshError {
        agent_mesh_core::MeshError::new(ErrorCode::AgentAmbiguous, "several")
            .with_candidates(vec!["vvmux:dev/f1p2".into(), "vvmux:ci/f1p2".into()])
    }
}

#[test]
fn questions_waiting_for_one_peer_are_bounded() {
    let scratch = Scratch::new("resolution-bound");
    let mut store = scratch.store();
    let (peer, _) = connected(
        &mut store,
        "buildbox",
        &Opaque::generate(),
        &Opaque::generate(),
    );
    for index in 0..64 {
        store
            .request_resolution(&peer, &format!("agent{index}"))
            .unwrap();
    }
    assert_eq!(
        store
            .request_resolution(&peer, "one-more")
            .unwrap_err()
            .code,
        ErrorCode::RateLimited
    );
}
