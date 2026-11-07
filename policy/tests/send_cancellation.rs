use core::ffi::c_void;
use hyperv_policy::{
    engine::{Action, Engine, Finish, Submission, allocate_record},
    packet::Packet,
};
use hyperv_protocol::{Verdict, connection_header_len};
use std::{
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[path = "../../driver/src/send_guard.rs"]
mod send_guard;
use send_guard::with_send_guard;

#[derive(Default)]
struct Guard {
    locked: AtomicBool,
    cancelled: AtomicBool,
    attempts: AtomicUsize,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn hv_send_guard_lock(value: *mut c_void) -> u32 {
    let guard = unsafe { &*value.cast::<Guard>() };
    guard.attempts.fetch_add(1, Ordering::SeqCst);
    while guard
        .locked
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        thread::yield_now();
    }
    u32::from(guard.cancelled.load(Ordering::Relaxed))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn hv_send_guard_unlock(value: *mut c_void) {
    let guard = unsafe { &*value.cast::<Guard>() };
    guard.locked.store(false, Ordering::Release);
}

fn guard_ptr(guard: &Guard) -> *mut c_void {
    ptr::from_ref(guard).cast_mut().cast()
}

#[test]
fn cancellation_during_capture_prevents_pending_publication() {
    let mut engine = Engine::new();
    assert!(engine.attach(101));
    assert!(engine.restart(101));
    engine.connect();
    let mut packet = Packet::EMPTY;
    packet.connection.protocol = 17;
    packet.flow.protocol = 17;
    packet.cacheable = true;
    packet.payload_len = 100;
    packet.ip_len = 100;
    let nbl = 42;
    let cancel = 0xabc;
    let guard = Guard::default();
    let handle = guard_ptr(&guard);
    assert_eq!(
        with_send_guard(handle, |cancelled| {
            assert!(!cancelled);
            engine.preflight(101, &packet, nbl, 100)
        }),
        Ok(true)
    );

    // The cancel handler runs after preflight but before pending publication.
    unsafe { hv_send_guard_lock(handle) };
    guard.cancelled.store(true, Ordering::Relaxed);
    unsafe { hv_send_guard_unlock(handle) };
    assert_eq!(engine.cancel(101, cancel), None);
    let mut record = allocate_record(connection_header_len(&packet.connection) + 100);
    let result = with_send_guard(handle, |cancelled| {
        if cancelled {
            Submission::Finish(Action {
                nbl,
                finish: Finish::Cancel,
            })
        } else {
            engine.submit(101, packet, nbl, Some(cancel), 101, record.take())
        }
    });
    assert_eq!(
        result,
        Submission::Finish(Action {
            nbl,
            finish: Finish::Cancel,
        })
    );
    assert_eq!(engine.pending_count(), 0);
    assert!(
        record.is_some(),
        "cancelled record must be freed after unlocking"
    );

    // A later callback with the same cancel ID has a fresh guard.
    let next_guard = Guard::default();
    let next = with_send_guard(guard_ptr(&next_guard), |cancelled| {
        assert!(!cancelled);
        engine.submit(101, packet, 43, Some(cancel), 102, record.take())
    });
    let Submission::Pending(id) = next else {
        panic!("new send should be published");
    };
    assert_eq!(
        engine.verdict(id, Verdict::Accept, 103).unwrap(),
        Action {
            nbl: 43,
            finish: Finish::Allow,
        }
    );
}

#[test]
fn publication_guard_serializes_a_concurrent_cancel() {
    let guard = Guard::default();
    let address = guard_ptr(&guard) as usize;
    let published = AtomicBool::new(false);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    thread::scope(|scope| {
        let published = &published;
        scope.spawn(move || {
            with_send_guard(address as *mut c_void, |cancelled| {
                assert!(!cancelled);
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                published.store(true, Ordering::SeqCst);
            });
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let cancelled = &guard.cancelled;
        scope.spawn(move || {
            unsafe { hv_send_guard_lock(address as *mut c_void) };
            assert!(published.load(Ordering::SeqCst));
            cancelled.store(true, Ordering::Relaxed);
            unsafe { hv_send_guard_unlock(address as *mut c_void) };
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while guard.attempts.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            thread::yield_now();
        }
        let attempted = guard.attempts.load(Ordering::SeqCst) >= 2;
        let still_locked = guard.locked.load(Ordering::SeqCst);
        let cancelled_early = guard.cancelled.load(Ordering::SeqCst);
        release_tx.send(()).unwrap();
        assert!(attempted && still_locked && !cancelled_early);
    });
    assert!(guard.cancelled.load(Ordering::SeqCst));
    assert!(!with_send_guard(ptr::null_mut(), |cancelled| cancelled));
}
