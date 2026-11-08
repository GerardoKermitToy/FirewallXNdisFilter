//! Host-only OS fakes. Every IRP/list/stack uses generated WDK storage; the
//! dispatch, queue, worker and session algorithms are the production functions.
#![allow(non_snake_case)]
use super::*;
use std::{boxed::Box, cell::RefCell, collections::VecDeque, sync::Mutex, vec::Vec};
static SERIAL: Mutex<()> = Mutex::new(());
#[derive(Default)]
struct Fake {
    completions: Vec<(usize, i32, usize)>,
    data: VecDeque<u8>,
    references: i32,
    mutex: bool,
    reject_rundown: bool,
    stop_on_rundown_acquire: bool,
    cancel_insert: bool,
    worker: IO_WORKITEM_ROUTINE,
    connects: u32,
    disconnects: u32,
    waits: u32,
    reinits: u32,
}
thread_local! { static FAKE: RefCell<Fake> = RefCell::new(Fake::default()); }
fn state<R>(f: impl FnOnce(&mut Fake) -> R) -> R {
    FAKE.with(|s| f(&mut s.borrow_mut()))
}
unsafe fn reset() {
    unsafe {
        state(|s| *s = Fake::default());
        list_init(addr_of_mut!(READ_IRPS));
        CLIENT = null_mut();
        READ_CLIENT = null_mut();
        CLASSIFICATION_CLOSED = false;
        READ_WORK_ITEM.store(1usize as PIO_WORKITEM, Ordering::Release);
        STOPPING.store(0, Ordering::SeqCst);
        READ_PENDING.store(0, Ordering::SeqCst);
        READ_READY.store(0, Ordering::SeqCst);
        READ_ONLINE.store(0, Ordering::SeqCst);
        READ_SCHEDULED.store(0, Ordering::SeqCst);
    }
}
struct Request {
    irp: Box<IRP>,
    _stack: Box<IO_STACK_LOCATION>,
    output: Vec<u8>,
}
impl Request {
    fn new(major: u32, file: usize, length: usize) -> Self {
        unsafe {
            let mut irp: Box<IRP> = Box::new(zeroed());
            let mut stack: Box<IO_STACK_LOCATION> = Box::new(zeroed());
            stack.MajorFunction = major as u8;
            stack.FileObject = file as PFILE_OBJECT;
            stack.Parameters.Read.Length = length as u32;
            irp.Tail
                .Overlay
                .__bindgen_anon_2
                .__bindgen_anon_1
                .CurrentStackLocation = &mut *stack;
            let mut output = std::vec![0xa5; length];
            if length != 0 {
                irp.AssociatedIrp.SystemBuffer = output.as_mut_ptr().cast();
            }
            Self {
                irp,
                _stack: stack,
                output,
            }
        }
    }
    fn run(&mut self) -> i32 {
        unsafe { dispatch(null_mut(), &mut *self.irp) }
    }
}
fn open(file: usize) {
    let mut r = Request::new(IRP_MJ_CREATE, file, 0);
    assert_eq!(r.run(), 0);
    state(|s| s.completions.clear());
}
fn run_worker() {
    let callback = state(|s| s.worker.take()).expect("queued worker");
    unsafe { callback(null_mut(), null_mut()) };
}
fn produce(bytes: &[u8]) {
    state(|s| s.data.extend(bytes));
    READ_READY.store(1, Ordering::SeqCst);
}

pub(crate) mod calls {
    use super::*;
    pub unsafe fn ExAcquireFastMutex(_: PFAST_MUTEX) {
        state(|s| {
            assert!(!s.mutex);
            s.mutex = true;
        });
    }
    pub unsafe fn ExReleaseFastMutex(_: PFAST_MUTEX) {
        state(|s| {
            assert!(s.mutex);
            s.mutex = false;
        });
    }
    pub unsafe fn ExAcquireRundownProtection(_: PEX_RUNDOWN_REF) -> u8 {
        state(|s| {
            if s.reject_rundown {
                0
            } else {
                s.references += 1;
                if s.stop_on_rundown_acquire {
                    STOPPING.store(1, Ordering::SeqCst);
                }
                1
            }
        })
    }
    pub unsafe fn ExReleaseRundownProtection(_: PEX_RUNDOWN_REF) {
        state(|s| {
            assert!(s.references > 0);
            s.references -= 1;
        });
    }
    pub unsafe fn ExWaitForRundownProtectionRelease(_: PEX_RUNDOWN_REF) {
        state(|s| s.waits += 1);
    }
    pub unsafe fn ExReInitializeRundownProtection(_: PEX_RUNDOWN_REF) {
        state(|s| s.reinits += 1);
    }
    pub unsafe fn IofCompleteRequest(irp: PIRP, _: i8) {
        unsafe {
            state(|s| {
                assert!(!s.mutex, "completion under IoMutex");
                s.completions.push((
                    irp as usize,
                    (*irp).IoStatus.__bindgen_anon_1.Status,
                    (*irp).IoStatus.Information as usize,
                ));
            });
        }
    }
    pub unsafe fn IoCsqInsertIrpEx(
        csq: PIO_CSQ,
        irp: PIRP,
        _: PIO_CSQ_IRP_CONTEXT,
        context: PVOID,
    ) -> i32 {
        unsafe {
            assert!(!state(|s| s.mutex), "CSQ insertion under IoMutex");
            if state(|s| s.cancel_insert) {
                read_cancelled(csq, irp);
                return 0;
            }
            read_insert(csq, irp, context)
        }
    }
    pub unsafe fn IoCsqRemoveNextIrp(csq: PIO_CSQ, context: PVOID) -> PIRP {
        unsafe {
            let irp = read_peek(csq, null_mut(), context);
            if !irp.is_null() {
                read_remove(csq, irp);
            }
            irp
        }
    }
    pub unsafe fn IoQueueWorkItem(
        item: PIO_WORKITEM,
        callback: IO_WORKITEM_ROUTINE,
        _: WORK_QUEUE_TYPE,
        _: PVOID,
    ) {
        state(|s| {
            assert!(!item.is_null());
            assert!(s.references > 0, "work item queued without rundown");
            assert!(s.worker.is_none());
            s.worker = callback;
        });
    }
    pub unsafe fn FwxRead(out: *mut u8, length: u32) -> u32 {
        unsafe {
            let n = state(|s| {
                assert!(s.mutex);
                let n = s.data.len().min(length as usize);
                for i in 0..n {
                    *out.add(i) = s.data.pop_front().unwrap();
                }
                n
            });
            if state(|s| s.data.is_empty()) {
                READ_READY.store(0, Ordering::SeqCst);
            }
            n as u32
        }
    }
    pub unsafe fn FwxWrite(_: *const u8, length: u32) -> i32 {
        if length == 0 {
            FWX_WDK_STATUS_INVALID_PARAMETER
        } else {
            0
        }
    }
    pub unsafe fn FwxConnect() {
        state(|s| s.connects += 1);
        READ_ONLINE.store(1, Ordering::SeqCst);
    }
    pub unsafe fn FwxDisconnect() {
        state(|s| {
            assert!(s.waits > 0);
            s.disconnects += 1;
        });
        READ_ONLINE.store(0, Ordering::SeqCst);
        READ_READY.store(0, Ordering::SeqCst);
    }
}

#[test]
fn exclusive_device_create_cleanup_reopens_rundown_once() {
    let _lock = SERIAL.lock().unwrap();
    unsafe {
        reset();
    }
    open(1);
    let mut second = Request::new(IRP_MJ_CREATE, 2, 0);
    assert_eq!(second.run(), FWX_WDK_STATUS_SHARING_VIOLATION);
    let mut cleanup = Request::new(IRP_MJ_CLEANUP, 1, 0);
    assert_eq!(cleanup.run(), 0);
    assert_eq!(cleanup.run(), 0);
    state(|s| {
        assert_eq!(s.waits, 1);
        assert_eq!(s.disconnects, 1);
    });
    open(2);
    state(|s| {
        assert_eq!(s.connects, 2);
        assert_eq!(s.reinits, 1);
    });
}
#[test]
fn zero_length_read_finishes_but_empty_nonzero_read_waits() {
    let _lock = SERIAL.lock().unwrap();
    unsafe {
        reset();
    }
    open(1);
    let mut zero = Request::new(IRP_MJ_READ, 1, 0);
    assert_eq!(zero.run(), 0);
    let mut read = Request::new(IRP_MJ_READ, 1, 16);
    assert_eq!(read.run(), FWX_WDK_STATUS_PENDING);
    state(|s| {
        assert_eq!(s.references, 1);
        assert_eq!(s.completions.len(), 1);
        assert!(s.worker.is_none());
    });
    unsafe {
        cancel_reads(1usize as PFILE_OBJECT);
    }
    state(|s| {
        assert_eq!(s.references, 0);
        assert_eq!(s.completions.last().unwrap().1, FWX_WDK_STATUS_CANCELLED);
    });
}
#[test]
fn ready_worker_copies_then_completes_outside_locks_and_releases_refs() {
    let _lock = SERIAL.lock().unwrap();
    unsafe {
        reset();
    }
    open(1);
    produce(b"packet-record");
    let mut read = Request::new(IRP_MJ_READ, 1, 64);
    assert_eq!(read.run(), FWX_WDK_STATUS_PENDING);
    assert_eq!(state(|s| s.references), 2);
    run_worker();
    assert_eq!(&read.output[..13], b"packet-record");
    state(|s| {
        assert_eq!(s.references, 0);
        assert_eq!(s.completions.len(), 1);
        assert_eq!(s.completions[0].2, 13);
    });
}
#[test]
fn stale_readiness_requeues_without_successful_empty_completion() {
    let _lock = SERIAL.lock().unwrap();
    unsafe {
        reset();
    }
    open(1);
    READ_READY.store(1, Ordering::SeqCst);
    let mut read = Request::new(IRP_MJ_READ, 1, 8);
    assert_eq!(read.run(), FWX_WDK_STATUS_PENDING);
    run_worker();
    state(|s| {
        assert_eq!(s.references, 1);
        assert!(s.completions.is_empty());
    });
    produce(b"data");
    unsafe {
        schedule_read();
    }
    run_worker();
    assert_eq!(&read.output[..4], b"data");
    assert_eq!(state(|s| s.references), 0);
}
#[test]
fn already_cancelled_insert_completes_inline_exactly_once() {
    let _lock = SERIAL.lock().unwrap();
    unsafe {
        reset();
    }
    open(1);
    state(|s| s.cancel_insert = true);
    let mut read = Request::new(IRP_MJ_READ, 1, 16);
    assert_eq!(read.run(), FWX_WDK_STATUS_PENDING);
    state(|s| {
        assert_eq!(s.references, 0);
        assert_eq!(s.completions.len(), 1);
        assert_eq!(s.completions[0].1, FWX_WDK_STATUS_CANCELLED);
    });
}
#[test]
fn rejected_insert_after_pending_mark_completes_and_returns_pending() {
    let _lock = SERIAL.lock().unwrap();
    unsafe { reset() };
    open(1);
    // An open handle may submit a read after the session has shut down.
    READ_ONLINE.store(0, Ordering::SeqCst);
    let mut read = Request::new(IRP_MJ_READ, 1, 16);
    assert_eq!(read.run(), FWX_WDK_STATUS_PENDING);
    assert_ne!(read._stack.Control & SL_PENDING_RETURNED as u8, 0);
    state(|s| {
        assert_eq!(s.references, 0);
        assert_eq!(s.completions.len(), 1);
        assert_eq!(s.completions[0].1, FWX_WDK_STATUS_DEVICE_NOT_CONNECTED);
        assert_eq!(s.completions[0].2, 0);
        assert!(s.worker.is_none());
    });
}

#[test]
fn work_item_scheduling_respects_publication_and_rundown() {
    let _lock = SERIAL.lock().unwrap();
    unsafe { reset() };
    READ_PENDING.store(1, Ordering::SeqCst);
    READ_WORK_ITEM.store(null_mut(), Ordering::Release);
    unsafe { schedule_read() };
    state(|s| {
        assert_eq!(s.references, 0);
        assert!(s.worker.is_none());
    });
    READ_WORK_ITEM.store(1usize as PIO_WORKITEM, Ordering::Release);
    state(|s| s.stop_on_rundown_acquire = true);
    unsafe { schedule_read() };
    state(|s| {
        assert_eq!(s.references, 0);
        assert!(s.worker.is_none());
    });
}

#[test]
fn cleanup_cancels_all_reads_and_closed_session_rejects_new_irps() {
    let _lock = SERIAL.lock().unwrap();
    unsafe {
        reset();
    }
    open(1);
    let mut a = Request::new(IRP_MJ_READ, 1, 8);
    let mut b = Request::new(IRP_MJ_READ, 1, 8);
    assert_eq!(a.run(), FWX_WDK_STATUS_PENDING);
    assert_eq!(b.run(), FWX_WDK_STATUS_PENDING);
    let mut cleanup = Request::new(IRP_MJ_CLEANUP, 1, 0);
    assert_eq!(cleanup.run(), 0);
    assert_eq!(state(|s| s.references), 0);
    assert_eq!(
        Request::new(IRP_MJ_READ, 1, 8).run(),
        FWX_WDK_STATUS_DEVICE_NOT_CONNECTED
    );
    state(|s| {
        assert_eq!(
            s.completions
                .iter()
                .filter(|x| x.1 == FWX_WDK_STATUS_CANCELLED)
                .count(),
            2
        )
    });
}
#[test]
fn null_output_and_rundown_failure_do_not_queue_or_leak() {
    let _lock = SERIAL.lock().unwrap();
    unsafe {
        reset();
    }
    open(1);
    let mut read = Request::new(IRP_MJ_READ, 1, 8);
    read.irp.AssociatedIrp.SystemBuffer = null_mut();
    assert_eq!(read.run(), FWX_WDK_STATUS_INVALID_PARAMETER);
    state(|s| s.reject_rundown = true);
    assert_eq!(
        Request::new(IRP_MJ_READ, 1, 8).run(),
        FWX_WDK_STATUS_DEVICE_NOT_CONNECTED
    );
    assert_eq!(state(|s| s.references), 0);
}
#[test]
fn ioctl_uses_production_codec_and_shutdown_cancels_pending_reads() {
    let _lock = SERIAL.lock().unwrap();
    unsafe {
        reset();
    }
    open(1);
    let mut query = Request::new(IRP_MJ_DEVICE_CONTROL, 1, 4);
    query._stack.Parameters.DeviceIoControl.IoControlCode = firewallx_protocol::IOCTL_VERSION;
    query._stack.Parameters.DeviceIoControl.InputBufferLength = 0;
    query._stack.Parameters.DeviceIoControl.OutputBufferLength = 4;
    assert_eq!(query.run(), 0);
    assert_eq!(query.output, [0, 3, 3, 0]);
    let mut read = Request::new(IRP_MJ_READ, 1, 4);
    assert_eq!(read.run(), FWX_WDK_STATUS_PENDING);
    let mut shutdown = Request::new(IRP_MJ_DEVICE_CONTROL, 1, 0);
    shutdown._stack.Parameters.DeviceIoControl.IoControlCode = firewallx_protocol::IOCTL_SHUTDOWN;
    assert_eq!(shutdown.run(), 0);
    assert_eq!(shutdown.run(), 0);
    state(|s| {
        assert_eq!(s.references, 0);
        assert_eq!(s.disconnects, 1);
    });
}
