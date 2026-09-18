//! Store-level proofs for M1.
//!
//! Each test name is one claim `docs/agent-mesh-plan-final.md` makes. A claim with no test here is
//! not established.

use agent_mesh_core::{
    Address, Admit, Alias, Draft, Kind, Locator, MAX_PENDING_COUNT, Opaque, Outcome, Policy,
    PrincipalKind, RESERVED_COUNT, Ref, RuntimeKind, State,
};
use agent_mesh_store::{Binding, Bound, Caller, Store};

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "agent-mesh-m1-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        Self(base)
    }

    fn db(&self) -> std::path::PathBuf {
        self.0.join("state").join("mesh.sqlite")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn locator(instance: &str, pane: Option<u64>) -> Locator {
    Locator {
        kind: RuntimeKind::Vvmux,
        runtime_instance_id: Opaque::parse(instance).unwrap(),
        instance_name: Some(format!("inst-{}", &instance[..4])),
        address: pane.map(|index| Address::parse(&format!("f1p{index}")).unwrap()),
    }
}

const INST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn bind(store: &mut Store, alias: &str, instance: &str, pane: Option<u64>) -> Bound {
    store
        .bind(&Binding {
            alias: Some(Alias::parse(alias).unwrap()),
            provider: Some("fake".into()),
            locator: locator(instance, pane),
        })
        .unwrap()
}

fn caller(store: &Store, bound: &Bound) -> Caller {
    store
        .authenticate(&bound.endpoint_id, &bound.token)
        .unwrap()
}

/// Lift the per-minute ceiling so a test about *capacity* is not stopped by a test about *rate*.
fn unlimited_rate(store: &mut Store, endpoint: &Opaque) {
    let policy = Policy {
        max_inbound_per_minute: u32::MAX,
        ..store.policy(endpoint).unwrap()
    };
    store.set_policy(endpoint, &policy).unwrap();
}

fn request(to: &Opaque, text: &str, key: &str) -> Draft {
    Draft {
        to: to.clone(),
        kind: Kind::Request,
        reply_to: None,
        outcome: None,
        subject: Some("subject".into()),
        text: text.into(),
        refs: Vec::new(),
        idempotency_key: key.into(),
        expires_in_ms: None,
    }
}

#[test]
fn visibility_leaves_refused_mail_queued_without_hiding_authorized_mail() {
    let scratch = Scratch::new("visibility");
    let mut store = Store::open(scratch.db()).unwrap();
    let target = bind(&mut store, "target", INST_A, Some(1));
    let outsider = bind(&mut store, "outsider", INST_B, Some(1));
    let teammate = bind(&mut store, "teammate", INST_A, Some(2));
    let blocked = store
        .send(
            &caller(&store, &outsider),
            &request(&target.endpoint_id, "hidden", "blocked"),
        )
        .unwrap();
    let visible = store
        .send(
            &caller(&store, &teammate),
            &request(&target.endpoint_id, "visible", "visible"),
        )
        .unwrap();
    let target_caller = caller(&store, &target);
    assert_eq!(store.inbox(&target.endpoint_id, &[], 100).unwrap().len(), 1);
    assert_eq!(
        store
            .claim(&target_caller, None)
            .unwrap()
            .unwrap()
            .message_id,
        visible.message_id
    );
    assert!(store.claim(&target_caller, None).unwrap().is_none());
    assert_eq!(
        store.message(&blocked.message_id).unwrap().state,
        State::Queued
    );
    let mut policy = store.policy(&target.endpoint_id).unwrap();
    policy.trusted.push(outsider.endpoint_id);
    store.set_policy(&target.endpoint_id, &policy).unwrap();
    assert_eq!(
        store
            .claim(&target_caller, None)
            .unwrap()
            .unwrap()
            .message_id,
        blocked.message_id
    );
}

#[test]
fn notices_are_consumed_once_and_cannot_be_answered() {
    let scratch = Scratch::new("notice");
    let mut store = Store::open(scratch.db()).unwrap();
    let target = bind(&mut store, "target", INST_A, Some(1));
    let mut draft = request(&target.endpoint_id, "for information", "notice");
    draft.kind = Kind::Notice;
    let sent = store.send(&Caller::local_user(), &draft).unwrap();
    let receiver = caller(&store, &target);
    assert_eq!(
        store.claim(&receiver, None).unwrap().unwrap().state,
        State::Consumed
    );
    assert_eq!(store.endpoint(&target.endpoint_id).unwrap().pending, 0);
    assert!(store.claim(&receiver, None).unwrap().is_none());
    assert!(
        store
            .respond(
                &receiver,
                &sent.message_id,
                Outcome::Answered,
                "no",
                vec![],
                "reply"
            )
            .is_err()
    );
}

#[test]
fn interruption_confirmation_is_scoped_to_the_exact_owner_and_incarnation() {
    let scratch = Scratch::new("interrupt");
    let mut store = Store::open(scratch.db()).unwrap();
    let a = bind(&mut store, "target", INST_A, Some(1));
    let b = bind(&mut store, "target", INST_B, Some(1));
    let mut requests = Vec::new();
    for (key, target) in [("a", &a), ("b", &b)] {
        let message = store
            .send(
                &Caller::local_user(),
                &request(&target.endpoint_id, key, key),
            )
            .unwrap();
        store.claim(&caller(&store, target), None).unwrap().unwrap();
        store
            .cancel(&Caller::local_user(), &message.message_id)
            .unwrap();
        assert!(
            store
                .interrupt_target(&message.message_id)
                .unwrap()
                .is_none(),
            "interrupt is disabled by default"
        );
        let mut policy = store.policy(&target.endpoint_id).unwrap();
        policy.interrupt = true;
        store.set_policy(&target.endpoint_id, &policy).unwrap();
        assert_eq!(
            store.interrupt_target(&message.message_id).unwrap(),
            Some(target.incarnation_id.clone())
        );
        requests.push(message);
    }
    // A rebind during provider I/O makes the captured confirmation stale.
    bind(&mut store, "target", INST_A, Some(1));
    assert_ne!(
        store
            .confirm_interrupt(&requests[0].message_id, &a.incarnation_id)
            .unwrap(),
        State::Cancelled
    );
    assert_eq!(
        store.message(&requests[1].message_id).unwrap().state,
        State::CancellationRequested
    );
    assert_eq!(
        store
            .confirm_interrupt(&requests[1].message_id, &b.incarnation_id)
            .unwrap(),
        State::Cancelled
    );
    assert_eq!(store.endpoint(&b.endpoint_id).unwrap().pending, 0);
    assert_eq!(store.endpoint(&a.endpoint_id).unwrap().pending, 1);
}

// --- identity -------------------------------------------------------------------------------

#[test]
fn rebinding_the_same_alias_and_instance_keeps_the_endpoint_and_mints_a_new_incarnation() {
    let scratch = Scratch::new("rebind");
    let mut store = Store::open(scratch.db()).unwrap();

    let first = bind(&mut store, "reviewer", INST_A, Some(1));
    store
        .unbind(&first.endpoint_id, &first.incarnation_id)
        .unwrap();
    let second = bind(&mut store, "reviewer", INST_A, Some(1));

    assert_eq!(
        first.endpoint_id, second.endpoint_id,
        "the durable slot survives a restart, which is what keeps a mailbox reachable"
    );
    assert_ne!(
        first.incarnation_id, second.incarnation_id,
        "a replacement process never inherits its predecessor's identity"
    );
    assert!(second.rebound);
}

#[test]
fn a_superseded_incarnations_token_stops_working() {
    let scratch = Scratch::new("token");
    let mut store = Store::open(scratch.db()).unwrap();

    let first = bind(&mut store, "reviewer", INST_A, None);
    assert!(store.authenticate(&first.endpoint_id, &first.token).is_ok());

    let second = bind(&mut store, "reviewer", INST_A, None);
    assert!(
        store
            .authenticate(&first.endpoint_id, &first.token)
            .is_err(),
        "the old token must not authenticate after a rebind"
    );
    assert!(
        store
            .authenticate(&second.endpoint_id, &second.token)
            .is_ok()
    );
}

/// The owner-scoped regression the root `AGENTS.md` mandates: two owners deliberately reusing the
/// same local numeric ID, proving the unrelated owner stays intact.
#[test]
fn two_endpoints_reusing_the_same_pane_id_are_completely_independent() {
    let scratch = Scratch::new("panes");
    let mut store = Store::open(scratch.db()).unwrap();

    // Both runtimes call their pane 1, so both addresses read `f1p1`. Only
    // `runtime_instance_id` tells them apart — which is exactly why an address is never identity.
    let mine = bind(&mut store, "reviewer", INST_A, Some(1));
    let theirs = bind(&mut store, "reviewer", INST_B, Some(1));
    assert_ne!(mine.endpoint_id, theirs.endpoint_id);
    assert_eq!(
        store.endpoint(&mine.endpoint_id).unwrap().locator.address,
        store.endpoint(&theirs.endpoint_id).unwrap().locator.address,
        "the same address in two instances is two different endpoints"
    );

    let sender = Caller::local_user();
    store
        .send(&sender, &request(&mine.endpoint_id, "for mine", "k1"))
        .unwrap();
    store
        .send(&sender, &request(&theirs.endpoint_id, "for theirs", "k2"))
        .unwrap();

    // Tear one down completely.
    store
        .unbind(&mine.endpoint_id, &mine.incarnation_id)
        .unwrap();

    let survivor = store.endpoint(&theirs.endpoint_id).unwrap();
    assert!(survivor.online, "an unrelated owner must be untouched");
    assert_eq!(survivor.pending, 1);
    let inbox = store.inbox(&theirs.endpoint_id, &[], 10).unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].text, "for theirs");

    // And the torn-down owner keeps its own mail, since a mailbox outlives a binding.
    let orphan = store.inbox(&mine.endpoint_id, &[], 10).unwrap();
    assert_eq!(orphan.len(), 1);
    assert_eq!(orphan[0].text, "for mine");
}

// --- sending --------------------------------------------------------------------------------

#[test]
fn the_store_authors_identity_and_a_caller_cannot_forge_it() {
    let scratch = Scratch::new("identity");
    let mut store = Store::open(scratch.db()).unwrap();
    let alice = bind(&mut store, "alice", INST_A, None);
    let bob = bind(&mut store, "bob", INST_A, None);

    let sent = store
        .send(
            &caller(&store, &alice),
            &request(&bob.endpoint_id, "hi", "k1"),
        )
        .unwrap();

    assert_eq!(sent.from.kind, PrincipalKind::Agent);
    assert_eq!(sent.from.endpoint_id.as_ref(), Some(&alice.endpoint_id));
    assert_eq!(
        sent.from.incarnation_id.as_ref(),
        Some(&alice.incarnation_id)
    );
    assert_eq!(sent.recipient_sequence, 1);

    // A shell with no token is a distinct principal, not a nameless agent.
    let sent = store
        .send(
            &Caller::local_user(),
            &request(&bob.endpoint_id, "hi", "k2"),
        )
        .unwrap();
    assert_eq!(sent.from.kind, PrincipalKind::LocalUser);
    assert!(sent.from.endpoint_id.is_none());
}

#[test]
fn identical_retry_replays_and_a_changed_body_conflicts() {
    let scratch = Scratch::new("idem");
    let mut store = Store::open(scratch.db()).unwrap();
    let bob = bind(&mut store, "bob", INST_A, None);
    let sender = Caller::local_user();

    let first = store
        .send(&sender, &request(&bob.endpoint_id, "review", "k1"))
        .unwrap();
    let replay = store
        .send(&sender, &request(&bob.endpoint_id, "review", "k1"))
        .unwrap();
    assert_eq!(first.message_id, replay.message_id);
    assert_eq!(store.endpoint(&bob.endpoint_id).unwrap().pending, 1);

    let err = store
        .send(&sender, &request(&bob.endpoint_id, "DIFFERENT", "k1"))
        .unwrap_err();
    assert_eq!(err.code, agent_mesh_core::ErrorCode::IdempotencyConflict);
    assert_eq!(
        store.endpoint(&bob.endpoint_id).unwrap().pending,
        1,
        "a conflict charges nothing"
    );
}

#[test]
fn a_full_mailbox_rejects_and_never_evicts_accepted_work() {
    let scratch = Scratch::new("full");
    let mut store = Store::open(scratch.db()).unwrap();
    let bob = bind(&mut store, "bob", INST_A, None);
    let sender = Caller::local_user();
    // The quota is what is under test here. At the default 60 a minute the rate limit would stop
    // this long before the mailbox filled — which is the intended shape of the two limits, and the
    // reason this test has to lift one of them to reach the other.
    unlimited_rate(&mut store, &bob.endpoint_id);

    for index in 0..MAX_PENDING_COUNT {
        store
            .send(
                &sender,
                &request(&bob.endpoint_id, "x", &format!("k{index}")),
            )
            .expect("within capacity");
    }
    let before: Vec<i64> = store
        .inbox(&bob.endpoint_id, &[], 1000)
        .unwrap()
        .iter()
        .map(|m| m.recipient_sequence)
        .collect();

    let err = store
        .send(&sender, &request(&bob.endpoint_id, "x", "overflow"))
        .unwrap_err();
    assert_eq!(err.code, agent_mesh_core::ErrorCode::MailboxFull);

    let after: Vec<i64> = store
        .inbox(&bob.endpoint_id, &[], 1000)
        .unwrap()
        .iter()
        .map(|m| m.recipient_sequence)
        .collect();
    assert_eq!(before, after, "accepted work is never evicted to make room");
}

#[test]
fn the_reserve_keeps_completion_traffic_flowing_when_requests_are_full() {
    let scratch = Scratch::new("reserve");
    let mut store = Store::open(scratch.db()).unwrap();
    let alice = bind(&mut store, "alice", INST_A, None);
    let helper = bind(&mut store, "helper", INST_A, None);
    let alice_caller = caller(&store, &alice);
    let helper_caller = caller(&store, &helper);
    let sender = Caller::local_user();
    unlimited_rate(&mut store, &alice.endpoint_id);

    for index in 0..MAX_PENDING_COUNT {
        store
            .send(
                &sender,
                &request(&alice.endpoint_id, "x", &format!("k{index}")),
            )
            .unwrap();
    }
    assert!(
        store
            .send(&sender, &request(&alice.endpoint_id, "x", "more"))
            .is_err()
    );

    // A response may reach into the reserve, so a request flood cannot starve answers.
    for index in 0..RESERVED_COUNT {
        let original = store
            .send(
                &alice_caller,
                &request(&helper.endpoint_id, "please", &format!("ask-{index}")),
            )
            .unwrap();
        let response = Draft {
            to: alice.endpoint_id.clone(),
            kind: Kind::Response,
            reply_to: Some(original.message_id),
            outcome: Some(Outcome::Completed),
            subject: None,
            text: "done".into(),
            refs: Vec::new(),
            idempotency_key: format!("r{index}"),
            expires_in_ms: None,
        };
        store
            .send(&helper_caller, &response)
            .expect("the reserve admits responses");
    }
    assert_eq!(
        store.endpoint(&alice.endpoint_id).unwrap().pending,
        MAX_PENDING_COUNT + RESERVED_COUNT
    );
}

// --- policy ---------------------------------------------------------------------------------

#[test]
fn the_enqueue_gate_refuses_a_stranger_but_still_admits_a_reply() {
    let scratch = Scratch::new("policy");
    let mut store = Store::open(scratch.db()).unwrap();
    let alice = bind(&mut store, "alice", INST_A, None);
    let stranger = bind(&mut store, "stranger", INST_B, None);

    // Alice closes her mailbox to everyone but replies and same-instance teammates.
    store
        .set_policy(
            &alice.endpoint_id,
            &Policy {
                enqueue: Admit::RepliesAndTeam,
                ..Policy::default()
            },
        )
        .unwrap();

    let stranger_caller = caller(&store, &stranger);
    let err = store
        .send(
            &stranger_caller,
            &request(&alice.endpoint_id, "unsolicited", "k1"),
        )
        .unwrap_err();
    assert_eq!(err.code, agent_mesh_core::ErrorCode::PolicyRefused);

    // But once Alice asks the stranger something, the answer gets through.
    let alice_caller = caller(&store, &alice);
    let asked = store
        .send(
            &alice_caller,
            &request(&stranger.endpoint_id, "please review", "k2"),
        )
        .unwrap();
    let answer = store
        .respond(
            &stranger_caller,
            &asked.message_id,
            Outcome::Completed,
            "here you go",
            Vec::new(),
            "reply-1",
        )
        .unwrap();
    assert_eq!(answer.to_endpoint, alice.endpoint_id);
    assert_eq!(answer.outcome, Some(Outcome::Completed));
}

// --- claims and replies ---------------------------------------------------------------------

#[test]
fn a_claim_lease_expires_and_a_stale_incarnation_cannot_answer() {
    let scratch = Scratch::new("claim");
    let mut store = Store::open(scratch.db()).unwrap();
    let bob = bind(&mut store, "bob", INST_A, None);
    let sender = store.ensure_local_user().unwrap();
    let sent = store
        .send(&sender, &request(&bob.endpoint_id, "work", "k1"))
        .unwrap();

    let first = caller(&store, &bob);
    let claimed = store.claim(&first, Some(1)).unwrap().expect("queued work");
    assert_eq!(claimed.message_id, sent.message_id);

    // The lease lapses; a sweep puts it back.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let (reclaimed, _) = store.sweep(agent_mesh_core::time::now_ms()).unwrap();
    assert_eq!(reclaimed, 1);

    // A new incarnation takes it. The old one is gone and cannot answer.
    let second_bind = bind(&mut store, "bob", INST_A, None);
    let second = caller(&store, &second_bind);
    let retaken = store.claim(&second, None).unwrap().expect("redelivered");
    assert_eq!(
        retaken.message_id, sent.message_id,
        "same message, not a new one"
    );

    let stale = store.respond(
        &first,
        &sent.message_id,
        Outcome::Completed,
        "too late",
        Vec::new(),
        "r1",
    );
    assert!(stale.is_err(), "a superseded incarnation must not answer");

    store
        .respond(
            &second,
            &sent.message_id,
            Outcome::Completed,
            "done",
            Vec::new(),
            "r2",
        )
        .unwrap();
    assert_eq!(store.endpoint(&second_bind.endpoint_id).unwrap().pending, 0);
}

#[test]
fn responding_retires_the_request_and_a_second_response_is_refused() {
    let scratch = Scratch::new("respond");
    let mut store = Store::open(scratch.db()).unwrap();
    let alice = bind(&mut store, "alice", INST_A, None);
    let bob = bind(&mut store, "bob", INST_A, None);

    let alice_caller = caller(&store, &alice);
    let bob_caller = caller(&store, &bob);
    let asked = store
        .send(&alice_caller, &request(&bob.endpoint_id, "question", "k1"))
        .unwrap();

    let answer = store
        .respond(
            &bob_caller,
            &asked.message_id,
            Outcome::Completed,
            "answer",
            Vec::new(),
            "r1",
        )
        .unwrap();
    assert_eq!(answer.reply_to.as_ref(), Some(&asked.message_id));
    assert_eq!(
        answer.conversation_id, asked.conversation_id,
        "a response joins its request's conversation"
    );
    assert_eq!(
        store.message(&asked.message_id).unwrap().state,
        State::Consumed
    );

    let again = store.respond(
        &bob_caller,
        &asked.message_id,
        Outcome::Completed,
        "again",
        Vec::new(),
        "r2",
    );
    assert_eq!(
        again.unwrap_err().code,
        agent_mesh_core::ErrorCode::AlreadyResponded
    );

    // The sender can find its answer by request id, never by screen state.
    let found = store.response_for(&asked.message_id).unwrap().unwrap();
    assert_eq!(found.message_id, answer.message_id);
    assert_eq!(found.outcome, Some(Outcome::Completed));
}

#[test]
fn cancelling_queued_work_removes_it_but_claimed_work_is_only_asked() {
    let scratch = Scratch::new("cancel");
    let mut store = Store::open(scratch.db()).unwrap();
    let alice = bind(&mut store, "alice", INST_A, None);
    let bob = bind(&mut store, "bob", INST_A, None);
    let alice_caller = caller(&store, &alice);
    let bob_caller = caller(&store, &bob);

    let queued = store
        .send(&alice_caller, &request(&bob.endpoint_id, "one", "k1"))
        .unwrap();
    assert_eq!(
        store.cancel(&alice_caller, &queued.message_id).unwrap(),
        State::Cancelled,
        "queued work can simply be removed"
    );

    let claimed = store
        .send(&alice_caller, &request(&bob.endpoint_id, "two", "k2"))
        .unwrap();
    store.claim(&bob_caller, None).unwrap().unwrap();
    assert_eq!(
        store.cancel(&alice_caller, &claimed.message_id).unwrap(),
        State::CancellationRequested,
        "work already in an agent's hands can only be asked to stop"
    );

    // Only the sender may cancel.
    assert!(store.cancel(&bob_caller, &claimed.message_id).is_err());
}

#[test]
fn expiry_retires_a_request_and_frees_its_capacity() {
    let scratch = Scratch::new("expiry");
    let mut store = Store::open(scratch.db()).unwrap();
    let bob = bind(&mut store, "bob", INST_A, None);
    let sender = Caller::local_user();

    let mut draft = request(&bob.endpoint_id, "short-lived", "k1");
    draft.expires_in_ms = Some(1);
    let sent = store.send(&sender, &draft).unwrap();
    assert_eq!(store.endpoint(&bob.endpoint_id).unwrap().pending, 1);

    std::thread::sleep(std::time::Duration::from_millis(20));
    let (_, expired) = store.sweep(agent_mesh_core::time::now_ms()).unwrap();
    assert_eq!(expired, 1);
    assert_eq!(
        store.message(&sent.message_id).unwrap().state,
        State::Expired
    );
    assert_eq!(
        store.endpoint(&bob.endpoint_id).unwrap().pending,
        0,
        "an expired request stops occupying capacity"
    );
}

// --- audit ----------------------------------------------------------------------------------

#[test]
fn the_audit_trail_records_metadata_and_never_the_body() {
    let scratch = Scratch::new("audit");
    let mut store = Store::open(scratch.db()).unwrap();
    let bob = bind(&mut store, "bob", INST_A, None);
    let secret = "the launch code is hunter2";
    let sent = store
        .send(
            &Caller::local_user(),
            &request(&bob.endpoint_id, secret, "k1"),
        )
        .unwrap();

    let rows = store.audit_for(&sent.message_id).unwrap();
    assert!(!rows.is_empty());
    assert_eq!(rows[0].operation, "send");
    assert_eq!(rows[0].result, "accepted");
    assert_eq!(rows[0].rule.as_deref(), Some("anyone"));
    assert!(rows[0].bytes > 0, "size is metadata; content is not");

    let rendered = format!("{rows:?}");
    assert!(
        !rendered.contains("hunter2"),
        "a message body must never enter the audit trail"
    );
}

// --- references -----------------------------------------------------------------------------

#[test]
fn references_survive_a_round_trip_and_grant_nothing() {
    let scratch = Scratch::new("refs");
    let mut store = Store::open(scratch.db()).unwrap();
    let bob = bind(&mut store, "bob", INST_A, None);

    // Deliberately a path that does not exist: a reference is a claim, not a capability, so the
    // store must neither require the file nor go looking for it.
    let absent = scratch.0.join("never-created.patch");
    assert!(!absent.exists());

    let mut draft = request(&bob.endpoint_id, "see attached", "k1");
    draft.refs = vec![Ref::File {
        path: absent.display().to_string(),
        sha256: None,
        bytes: Some(42),
        host: None,
    }];
    let sent = store.send(&Caller::local_user(), &draft).unwrap();
    let read_back = store.message(&sent.message_id).unwrap();
    assert_eq!(read_back.refs, draft.refs, "a reference survives verbatim");
    assert!(
        !absent.exists(),
        "the store must never create or open what a reference names"
    );
}

// --- durability -----------------------------------------------------------------------------

#[test]
fn a_mailbox_survives_closing_and_reopening_the_store() {
    let scratch = Scratch::new("durable");
    let db = scratch.db();
    let (endpoint, sequence) = {
        let mut store = Store::open(&db).unwrap();
        let bob = bind(&mut store, "bob", INST_A, None);
        let sent = store
            .send(
                &Caller::local_user(),
                &request(&bob.endpoint_id, "persist", "k1"),
            )
            .unwrap();
        (bob.endpoint_id, sent.recipient_sequence)
    };

    let store = Store::open(&db).unwrap();
    let inbox = store.inbox(&endpoint, &[State::Queued], 10).unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].recipient_sequence, sequence);
    assert_eq!(inbox[0].text, "persist");
}

#[test]
fn the_local_user_gets_a_mailbox_but_never_becomes_an_agent() {
    let scratch = Scratch::new("localuser");
    let mut store = Store::open(scratch.db()).unwrap();
    let bob = bind(&mut store, "bob", INST_A, None);

    let me = store.ensure_local_user().unwrap();
    assert_eq!(
        me.principal.kind,
        PrincipalKind::LocalUser,
        "a mailbox does not promote a shell to an agent"
    );
    let mailbox = me
        .principal
        .endpoint_id
        .clone()
        .expect("a place for replies");

    // The same shell, later, is the same mailbox.
    let again = store.ensure_local_user().unwrap();
    assert_eq!(again.principal.endpoint_id, Some(mailbox.clone()));

    // A person can ask a question and be answered.
    let asked = store
        .send(&me, &request(&bob.endpoint_id, "is it safe?", "k1"))
        .unwrap();
    let bob_caller = caller(&store, &bob);
    store
        .respond(
            &bob_caller,
            &asked.message_id,
            Outcome::Completed,
            "yes",
            Vec::new(),
            "r1",
        )
        .unwrap();
    let answer = store.response_for(&asked.message_id).unwrap().unwrap();
    assert_eq!(answer.to_endpoint, mailbox);
    assert_eq!(answer.outcome, Some(Outcome::Completed));
}

#[test]
fn the_local_user_is_not_a_teammate_of_any_runtime_instance() {
    let scratch = Scratch::new("notteam");
    let mut store = Store::open(scratch.db()).unwrap();
    let bob = bind(&mut store, "bob", INST_A, None);
    store
        .set_policy(
            &bob.endpoint_id,
            &Policy {
                enqueue: Admit::RepliesAndTeam,
                ..Policy::default()
            },
        )
        .unwrap();

    let me = store.ensure_local_user().unwrap();
    let err = store
        .send(&me, &request(&bob.endpoint_id, "unsolicited", "k1"))
        .unwrap_err();
    assert_eq!(
        err.code,
        agent_mesh_core::ErrorCode::PolicyRefused,
        "the reserved local-user scope must not match a runtime instance"
    );
}
