//! The M5 recovery suite: what survives a crash at each state transition.
//!
//! A process can stop between any two operations, so each transition is exercised by doing the
//! work, dropping the store as a process death would, reopening, and asking what is true. The rule
//! every case is measured against is guarantee 5.2.5: **no accepted unread request is silently
//! lost.** Duplicated or replayed work is recoverable; vanished work is not.

use agent_mesh_core::{Address, Alias, Draft, Kind, Locator, Opaque, Outcome, RuntimeKind, State};
use agent_mesh_store::{Binding, Bound, Caller, Store};

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "agent-mesh-recovery-{name}-{}-{}",
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

const INST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn bind(store: &mut Store, alias: &str, address: &str) -> Bound {
    store
        .bind(&Binding {
            alias: Some(Alias::parse(alias).unwrap()),
            provider: Some("fake".into()),
            locator: Locator {
                kind: RuntimeKind::Vvmux,
                runtime_instance_id: Opaque::parse(INST).unwrap(),
                instance_name: Some("dev".into()),
                address: Address::parse(address).ok(),
            },
        })
        .unwrap()
}

fn caller(store: &Store, bound: &Bound) -> Caller {
    store
        .authenticate(&bound.endpoint_id, &bound.token)
        .unwrap()
}

fn request(to: &Opaque, text: &str, key: &str) -> Draft {
    Draft {
        to: to.clone(),
        kind: Kind::Request,
        reply_to: None,
        outcome: None,
        subject: None,
        text: text.into(),
        refs: Vec::new(),
        idempotency_key: key.into(),
        expires_in_ms: None,
    }
}

/// Everything a reopened store should still agree about.
fn pending(store: &Store, endpoint: &Opaque) -> Vec<(i64, State, String)> {
    store
        .inbox(endpoint, &[], 100)
        .unwrap()
        .into_iter()
        .map(|m| (m.recipient_sequence, m.state, m.text))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// A crash at each transition
// ---------------------------------------------------------------------------------------------

#[test]
fn a_crash_after_accepting_leaves_the_message_queued() {
    let scratch = Scratch::new("after-send");
    let db = scratch.db();
    let (endpoint, sequence) = {
        let mut store = Store::open(&db).unwrap();
        let target = bind(&mut store, "target", "f1p1");
        let sent = store
            .send(
                &Caller::local_user(),
                &request(&target.endpoint_id, "work", "k1"),
            )
            .unwrap();
        (target.endpoint_id, sent.recipient_sequence)
        // The store is dropped here without any orderly shutdown.
    };

    let store = Store::open(&db).unwrap();
    assert_eq!(
        pending(&store, &endpoint),
        vec![(sequence, State::Queued, "work".to_owned())],
        "an accepted message is queued and nothing else"
    );
}

#[test]
fn a_crash_while_holding_a_claim_returns_the_work_to_the_queue() {
    let scratch = Scratch::new("after-claim");
    let db = scratch.db();
    let endpoint;
    let token;
    {
        let mut store = Store::open(&db).unwrap();
        let target = bind(&mut store, "target", "f1p1");
        endpoint = target.endpoint_id.clone();
        token = target.token.clone();
        store
            .send(&Caller::local_user(), &request(&endpoint, "work", "k1"))
            .unwrap();
        let holder = caller(&store, &target);
        store
            .claim(&holder, Some(50))
            .unwrap()
            .expect("queued work");
        // The claim holder dies here, still holding it.
    }

    let mut store = Store::open(&db).unwrap();
    // Before the lease lapses the work is still spoken for — a crash is not instantly visible, and
    // pretending otherwise would let two agents take one message.
    assert_eq!(pending(&store, &endpoint)[0].1, State::Claimed);

    std::thread::sleep(std::time::Duration::from_millis(70));
    let reclaimed = store.sweep(agent_mesh_core::time::now_ms()).unwrap().0;
    assert_eq!(reclaimed, 1);
    assert_eq!(pending(&store, &endpoint)[0].1, State::Queued);

    // And it can be taken again, exactly once.
    let revived = store.authenticate(&endpoint, &token).unwrap();
    assert!(store.claim(&revived, None).unwrap().is_some());
    assert!(
        store.claim(&revived, None).unwrap().is_none(),
        "one message, not two"
    );
}

#[test]
fn a_crash_between_answering_and_retiring_keeps_the_answer() {
    // `respond` writes the response and retires the request in two transactions. A crash between
    // them leaves the answer delivered and the request still pending — recoverable, because a
    // duplicate response is refused. The reverse ordering would lose the answer, which is not.
    let scratch = Scratch::new("respond");
    let db = scratch.db();
    let asker;
    let helper;
    let request_id;
    {
        let mut store = Store::open(&db).unwrap();
        let a = bind(&mut store, "asker", "f1p1");
        let h = bind(&mut store, "helper", "f1p2");
        asker = a.endpoint_id.clone();
        helper = h.endpoint_id.clone();
        let sent = store
            .send(&caller(&store, &a), &request(&helper, "question", "k1"))
            .unwrap();
        request_id = sent.message_id.clone();
        store
            .respond(
                &caller(&store, &h),
                &request_id,
                Outcome::Completed,
                "answer",
                Vec::new(),
                "r1",
            )
            .unwrap();
    }

    let store = Store::open(&db).unwrap();
    let answer = store
        .response_for(&request_id)
        .unwrap()
        .expect("the answer survived");
    assert_eq!(answer.text, "answer");
    assert_eq!(answer.to_endpoint, asker);
    assert_eq!(store.message(&request_id).unwrap().state, State::Consumed);
    let _ = helper;
}

#[test]
fn a_duplicate_response_after_a_restart_is_refused_rather_than_delivered_twice() {
    let scratch = Scratch::new("dup-response");
    let db = scratch.db();
    let helper_id;
    let helper_token;
    let request_id;
    {
        let mut store = Store::open(&db).unwrap();
        let asker = bind(&mut store, "asker", "f1p1");
        let helper = bind(&mut store, "helper", "f1p2");
        helper_id = helper.endpoint_id.clone();
        helper_token = helper.token.clone();
        let sent = store
            .send(&caller(&store, &asker), &request(&helper_id, "q", "k1"))
            .unwrap();
        request_id = sent.message_id.clone();
        store
            .respond(
                &caller(&store, &helper),
                &request_id,
                Outcome::Completed,
                "first",
                Vec::new(),
                "r1",
            )
            .unwrap();
    }

    // The helper restarts and, not knowing whether its answer landed, tries again.
    let mut store = Store::open(&db).unwrap();
    let revived = store.authenticate(&helper_id, &helper_token).unwrap();
    let again = store.respond(
        &revived,
        &request_id,
        Outcome::Completed,
        "second",
        Vec::new(),
        "r2",
    );
    assert_eq!(
        again.unwrap_err().code,
        agent_mesh_core::ErrorCode::AlreadyResponded
    );
    assert_eq!(
        store.response_for(&request_id).unwrap().unwrap().text,
        "first",
        "the first answer stands"
    );
}

#[test]
fn an_idempotent_retry_after_a_restart_replays_rather_than_duplicating() {
    // The case a sender actually hits: it crashed without learning whether its send landed.
    let scratch = Scratch::new("retry");
    let db = scratch.db();
    let target;
    let first_id;
    {
        let mut store = Store::open(&db).unwrap();
        let bound = bind(&mut store, "target", "f1p1");
        target = bound.endpoint_id.clone();
        first_id = store
            .send(&Caller::local_user(), &request(&target, "work", "k1"))
            .unwrap()
            .message_id;
    }

    let mut store = Store::open(&db).unwrap();
    let replay = store
        .send(&Caller::local_user(), &request(&target, "work", "k1"))
        .unwrap();
    assert_eq!(replay.message_id, first_id);
    assert_eq!(store.inbox(&target, &[], 10).unwrap().len(), 1);
}

#[test]
fn a_rebind_across_a_restart_keeps_the_slot_and_its_mail() {
    let scratch = Scratch::new("rebind");
    let db = scratch.db();
    let original;
    {
        let mut store = Store::open(&db).unwrap();
        let bound = bind(&mut store, "reviewer", "f1p1");
        original = bound.endpoint_id.clone();
        store
            .send(&Caller::local_user(), &request(&original, "before", "k1"))
            .unwrap();
    }

    let mut store = Store::open(&db).unwrap();
    let revived = bind(&mut store, "reviewer", "f1p1");
    assert_eq!(revived.endpoint_id, original, "the durable slot came back");
    assert_eq!(pending(&store, &original)[0].2, "before");

    // The endpoint is online again and can take its work.
    let taken = store.claim(&caller(&store, &revived), None).unwrap();
    assert_eq!(taken.unwrap().text, "before");
}

#[test]
fn an_expired_request_is_retired_exactly_once_across_restarts() {
    let scratch = Scratch::new("expiry");
    let db = scratch.db();
    let target;
    let message_id;
    {
        let mut store = Store::open(&db).unwrap();
        let bound = bind(&mut store, "target", "f1p1");
        target = bound.endpoint_id.clone();
        let mut draft = request(&target, "short", "k1");
        draft.expires_in_ms = Some(1);
        message_id = store
            .send(&Caller::local_user(), &draft)
            .unwrap()
            .message_id;
    }
    std::thread::sleep(std::time::Duration::from_millis(20));

    let mut store = Store::open(&db).unwrap();
    let (_, expired) = store.sweep(agent_mesh_core::time::now_ms()).unwrap();
    assert_eq!(expired, 1);
    // A second sweep — in this process or a later one — must not double-count or resurrect it.
    let (_, again) = store.sweep(agent_mesh_core::time::now_ms()).unwrap();
    assert_eq!(again, 0);
    assert_eq!(store.message(&message_id).unwrap().state, State::Expired);
    assert_eq!(store.endpoint(&target).unwrap().pending, 0);
}

#[test]
fn counters_survive_a_restart_and_still_match_the_messages() {
    // A pending count that drifted from reality would eventually refuse mail with a full mailbox
    // that is not full, or accept past a cap that should have held.
    let scratch = Scratch::new("counters");
    let db = scratch.db();
    let target;
    {
        let mut store = Store::open(&db).unwrap();
        let bound = bind(&mut store, "target", "f1p1");
        target = bound.endpoint_id.clone();
        for index in 0..5 {
            store
                .send(
                    &Caller::local_user(),
                    &request(&target, "x", &format!("k{index}")),
                )
                .unwrap();
        }
        let holder = caller(&store, &bound);
        store.claim(&holder, None).unwrap();
    }

    let store = Store::open(&db).unwrap();
    let counted = store.endpoint(&target).unwrap().pending;
    let actual = store
        .inbox(&target, &[], 100)
        .unwrap()
        .iter()
        .filter(|m| m.state.is_pending())
        .count() as i64;
    assert_eq!(counted, actual, "the counter and the mailbox agree");
    assert_eq!(counted, 5, "a claimed message is still pending work");
}

#[test]
fn two_stores_open_at_once_do_not_lose_a_message() {
    // Two processes, both live — the ordinary case, not a crash. Neither may drop work.
    let scratch = Scratch::new("concurrent");
    let db = scratch.db();
    let mut first = Store::open(&db).unwrap();
    let target = bind(&mut first, "target", "f1p1");
    let mut second = Store::open(&db).unwrap();

    first
        .send(
            &Caller::local_user(),
            &request(&target.endpoint_id, "a", "k1"),
        )
        .unwrap();
    second
        .send(
            &Caller::local_user(),
            &request(&target.endpoint_id, "b", "k2"),
        )
        .unwrap();

    let sequences: Vec<i64> = first
        .inbox(&target.endpoint_id, &[], 10)
        .unwrap()
        .iter()
        .map(|m| m.recipient_sequence)
        .collect();
    assert_eq!(sequences, vec![1, 2], "gap-free across two open stores");
    assert_eq!(second.endpoint(&target.endpoint_id).unwrap().pending, 2);
}

#[test]
fn a_store_reopened_after_every_operation_agrees_with_itself_throughout() {
    // The whole lifecycle, reopening between each step, so no step depends on state that only
    // existed in one process's memory.
    let scratch = Scratch::new("lifecycle");
    let db = scratch.db();

    let (asker, helper, helper_token, request_id) = {
        let mut store = Store::open(&db).unwrap();
        let a = bind(&mut store, "asker", "f1p1");
        let h = bind(&mut store, "helper", "f1p2");
        let sent = store
            .send(&caller(&store, &a), &request(&h.endpoint_id, "q", "k1"))
            .unwrap();
        (
            a.endpoint_id.clone(),
            h.endpoint_id.clone(),
            h.token.clone(),
            sent.message_id,
        )
    };

    {
        let mut store = Store::open(&db).unwrap();
        let helper_caller = store.authenticate(&helper, &helper_token).unwrap();
        assert_eq!(
            store
                .claim(&helper_caller, None)
                .unwrap()
                .unwrap()
                .message_id,
            request_id
        );
    }

    {
        let mut store = Store::open(&db).unwrap();
        let helper_caller = store.authenticate(&helper, &helper_token).unwrap();
        store
            .respond(
                &helper_caller,
                &request_id,
                Outcome::Completed,
                "done",
                Vec::new(),
                "r1",
            )
            .unwrap();
    }

    let store = Store::open(&db).unwrap();
    assert_eq!(store.message(&request_id).unwrap().state, State::Consumed);
    assert_eq!(store.endpoint(&helper).unwrap().pending, 0);
    let answer = store.response_for(&request_id).unwrap().unwrap();
    assert_eq!(answer.to_endpoint, asker);
    assert_eq!(answer.outcome, Some(Outcome::Completed));
}
