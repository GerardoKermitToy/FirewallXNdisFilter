//! Buffered control device and cancel-safe pending reads. IRPs are never borrowed
//! after successful CSQ insertion or completion (both can finish synchronously).
use super::*;
#[cfg(not(test))]
use crate as policy;
#[cfg(not(test))]
use crate::wdk as api;
#[cfg(test)]
#[path = "native_device_tests.rs"]
pub(super) mod tests;
use crate::device_control::FwxDeviceControl;
use firewallx_protocol::{IOCTL_ADAPTER_INFO, IOCTL_SHUTDOWN};
#[cfg(test)]
use tests::calls as api;
#[cfg(test)]
use tests::calls as policy;

unsafe fn stack(irp: PIRP) -> PIO_STACK_LOCATION {
    unsafe {
        (*irp)
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation
    }
}
unsafe fn irp_link(irp: PIRP) -> *mut LIST_ENTRY {
    unsafe { addr_of_mut!((*irp).Tail.Overlay.__bindgen_anon_2.ListEntry) }
}
const IRP_LINK_OFFSET: usize =
    offset_of!(IRP, Tail) + offset_of!(_IRP__bindgen_ty_4__bindgen_ty_1, __bindgen_anon_2);
unsafe fn complete_read(irp: PIRP, status: i32, bytes: u32) {
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = status;
        (*irp).IoStatus.Information = bytes as u64;
        api::IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
        api::ExReleaseRundownProtection(addr_of_mut!(READ_RUNDOWN));
    }
}
unsafe extern "C" fn read_insert(_: PIO_CSQ, irp: PIRP, _: PVOID) -> i32 {
    unsafe {
        if is_stopping()
            || READ_CLIENT != (*stack(irp)).FileObject
            || READ_ONLINE.load(Ordering::SeqCst) == 0
        {
            return FWX_WDK_STATUS_DEVICE_NOT_CONNECTED;
        }
        list_insert_tail(addr_of_mut!(READ_IRPS), irp_link(irp));
        READ_PENDING.store(1, Ordering::SeqCst);
        FWX_WDK_STATUS_SUCCESS
    }
}
unsafe extern "C" fn read_remove(_: PIO_CSQ, irp: PIRP) {
    unsafe {
        list_remove(irp_link(irp));
        READ_PENDING.store(
            i32::from(!list_empty(addr_of!(READ_IRPS))),
            Ordering::SeqCst,
        );
    }
}
unsafe extern "C" fn read_peek(_: PIO_CSQ, irp: PIRP, context: PVOID) -> PIRP {
    unsafe {
        let head = addr_of_mut!(READ_IRPS);
        let mut entry = if irp.is_null() {
            (*head).Flink
        } else {
            (*irp_link(irp)).Flink
        };
        while entry != head {
            let next = entry.cast::<u8>().sub(IRP_LINK_OFFSET).cast::<IRP>();
            if context.is_null() || (*stack(next)).FileObject.cast::<core::ffi::c_void>() == context
            {
                return next;
            }
            entry = (*entry).Flink;
        }
        null_mut()
    }
}
unsafe extern "C" fn read_acquire(_: PIO_CSQ, irql: PKIRQL) {
    unsafe {
        *irql = spin_lock(addr_of_mut!(READ_LOCK));
    }
}
unsafe extern "C" fn read_release(_: PIO_CSQ, irql: KIRQL) {
    unsafe {
        spin_unlock(addr_of_mut!(READ_LOCK), irql);
    }
}
unsafe extern "C" fn read_cancelled(_: PIO_CSQ, irp: PIRP) {
    unsafe {
        complete_read(irp, FWX_WDK_STATUS_CANCELLED, 0);
    }
}
unsafe fn set_read_client(file: PFILE_OBJECT) {
    unsafe {
        let irql = spin_lock(addr_of_mut!(READ_LOCK));
        READ_CLIENT = file;
        spin_unlock(addr_of_mut!(READ_LOCK), irql);
    }
}
pub(super) unsafe fn cancel_reads(file: PFILE_OBJECT) {
    unsafe {
        loop {
            let irp = api::IoCsqRemoveNextIrp(addr_of_mut!(READ_CSQ), file.cast());
            if irp.is_null() {
                break;
            }
            complete_read(irp, FWX_WDK_STATUS_CANCELLED, 0);
        }
    }
}
pub(super) unsafe fn schedule_read() {
    unsafe {
        if is_stopping()
            || READ_PENDING.load(Ordering::SeqCst) == 0
            || (READ_READY.load(Ordering::SeqCst) == 0 && READ_ONLINE.load(Ordering::SeqCst) != 0)
        {
            return;
        }
        if api::ExAcquireRundownProtection(addr_of_mut!(READ_RUNDOWN)) == 0 {
            return;
        }
        // The device can be published before initialization stores the item.
        // The atomic publishes it safely; rundown keeps it alive through queueing.
        let work_item = READ_WORK_ITEM.load(Ordering::Acquire);
        if !is_stopping()
            && !work_item.is_null()
            && READ_SCHEDULED
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            api::IoQueueWorkItem(work_item, Some(read_worker), DelayedWorkQueue, null_mut());
        } else {
            api::ExReleaseRundownProtection(addr_of_mut!(READ_RUNDOWN));
        }
    }
}
unsafe extern "C" fn read_worker(_: PDEVICE_OBJECT, _: PVOID) {
    unsafe {
        loop {
            if is_stopping()
                || (READ_READY.load(Ordering::SeqCst) == 0
                    && READ_ONLINE.load(Ordering::SeqCst) != 0)
            {
                break;
            }
            let irp = api::IoCsqRemoveNextIrp(addr_of_mut!(READ_CSQ), null_mut());
            if irp.is_null() {
                break;
            }
            let mut status = FWX_WDK_STATUS_SUCCESS;
            let mut bytes = 0;
            api::ExAcquireFastMutex(addr_of_mut!(IO_MUTEX));
            if is_stopping()
                || READ_ONLINE.load(Ordering::SeqCst) == 0
                || CLIENT != (*stack(irp)).FileObject
            {
                status = FWX_WDK_STATUS_CANCELLED;
            } else {
                bytes = policy::FwxRead(
                    (*irp).AssociatedIrp.SystemBuffer.cast(),
                    (*stack(irp)).Parameters.Read.Length,
                );
            }
            api::ExReleaseFastMutex(addr_of_mut!(IO_MUTEX));
            if !nt_success(status) || bytes != 0 {
                complete_read(irp, status, bytes);
            } else {
                status = api::IoCsqInsertIrpEx(addr_of_mut!(READ_CSQ), irp, null_mut(), null_mut());
                if !nt_success(status) {
                    complete_read(irp, status, 0);
                }
                break;
            }
        }
        READ_SCHEDULED.store(0, Ordering::SeqCst);
        schedule_read();
        api::ExReleaseRundownProtection(addr_of_mut!(READ_RUNDOWN));
    }
}

unsafe extern "C" fn dispatch(_: PDEVICE_OBJECT, irp: PIRP) -> i32 {
    unsafe {
        let stack = stack(irp);
        let mut status = FWX_WDK_STATUS_SUCCESS;
        let mut transferred: usize = 0;
        let mut queue_read = false;
        let mut cancel = false;
        api::ExAcquireFastMutex(addr_of_mut!(IO_MUTEX));
        match (*stack).MajorFunction as u32 {
            IRP_MJ_CREATE => {
                if is_stopping() {
                    status = FWX_WDK_STATUS_DELETE_PENDING;
                } else if !CLIENT.is_null() {
                    status = FWX_WDK_STATUS_SHARING_VIOLATION;
                } else {
                    CLIENT = (*stack).FileObject;
                    set_read_client(CLIENT);
                    open_classification_session();
                }
            }
            IRP_MJ_CLEANUP => {
                if CLIENT == (*stack).FileObject {
                    set_read_client(null_mut());
                    close_classification_session();
                    CLIENT = null_mut();
                }
                cancel = true;
            }
            IRP_MJ_CLOSE => (),
            major => {
                if is_stopping() || CLIENT != (*stack).FileObject {
                    status = FWX_WDK_STATUS_DEVICE_NOT_CONNECTED;
                } else {
                    match major {
                        IRP_MJ_READ => {
                            let len = (*stack).Parameters.Read.Length;
                            if len != 0 && (*irp).AssociatedIrp.SystemBuffer.is_null() {
                                status = FWX_WDK_STATUS_INVALID_PARAMETER;
                            } else if len != 0 {
                                if api::ExAcquireRundownProtection(addr_of_mut!(READ_RUNDOWN)) == 0
                                {
                                    status = FWX_WDK_STATUS_DEVICE_NOT_CONNECTED;
                                } else {
                                    queue_read = true;
                                }
                            }
                        }
                        IRP_MJ_WRITE => {
                            status = policy::FwxWrite(
                                (*irp).AssociatedIrp.SystemBuffer.cast(),
                                (*stack).Parameters.Write.Length,
                            );
                            if nt_success(status) {
                                transferred = (*stack).Parameters.Write.Length as usize;
                            }
                            if READ_ONLINE.load(Ordering::SeqCst) == 0 {
                                cancel = true;
                            }
                        }
                        IRP_MJ_DEVICE_CONTROL => {
                            let request = (*stack).Parameters.DeviceIoControl;
                            let mut bytes = 0;
                            status = FwxDeviceControl(
                                request.IoControlCode,
                                request.InputBufferLength,
                                (*irp).AssociatedIrp.SystemBuffer.cast(),
                                request.OutputBufferLength,
                                FILTERED_DEVICE_COUNT.load(Ordering::SeqCst) as u64,
                                &mut bytes,
                            );
                            transferred = bytes as usize;
                            if nt_success(status) {
                                if request.IoControlCode == IOCTL_SHUTDOWN {
                                    close_classification_session();
                                    cancel = true;
                                } else if request.IoControlCode == IOCTL_ADAPTER_INFO {
                                    status = ndis::query_adapter_info(
                                        (*irp).AssociatedIrp.SystemBuffer.cast(),
                                        request.OutputBufferLength,
                                        &mut transferred,
                                    );
                                }
                            }
                        }
                        _ => status = FWX_WDK_STATUS_INVALID_DEVICE_REQUEST,
                    }
                }
            }
        }
        api::ExReleaseFastMutex(addr_of_mut!(IO_MUTEX));
        if cancel {
            cancel_reads((*stack).FileObject);
        }
        if queue_read {
            (*stack).Control |= SL_PENDING_RETURNED as u8;
            status = api::IoCsqInsertIrpEx(addr_of_mut!(READ_CSQ), irp, null_mut(), null_mut());
            if !nt_success(status) {
                complete_read(irp, status, 0);
                return FWX_WDK_STATUS_PENDING;
            }
            schedule_read();
            return FWX_WDK_STATUS_PENDING;
        }
        (*irp).IoStatus.__bindgen_anon_1.Status = status;
        (*irp).IoStatus.Information = transferred as u64;
        api::IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
        status
    }
}

#[cfg(not(test))]
pub(super) unsafe fn initialize_io() -> i32 {
    unsafe {
        // Exact ExInitializeFastMutex macro, using generated storage layout.
        IO_MUTEX.Count = 1;
        IO_MUTEX.Owner = null_mut();
        IO_MUTEX.Contention = 0;
        KeInitializeEvent(addr_of_mut!(IO_MUTEX.Event), SynchronizationEvent, 0);
        KeInitializeSpinLock(addr_of_mut!(POLICY_LOCK));
        KeInitializeSpinLock(addr_of_mut!(ADAPTER_INFO_LOCK));
        KeInitializeSpinLock(addr_of_mut!(READ_LOCK));
        list_init(addr_of_mut!(ADAPTERS));
        list_init(addr_of_mut!(READ_IRPS));
        ExInitializeRundownProtection(addr_of_mut!(CLASSIFICATION_RUNDOWN));
        ExInitializeRundownProtection(addr_of_mut!(READ_RUNDOWN));
        ExInitializeRundownProtection(addr_of_mut!(CACHE_RUNDOWN));
        KeInitializeTimer(addr_of_mut!(PENDING_TIMER));
        KeInitializeDpc(addr_of_mut!(PENDING_DPC), Some(pending_dpc), null_mut());
        KeInitializeTimer(addr_of_mut!(CACHE_TIMER));
        KeInitializeDpc(addr_of_mut!(CACHE_DPC), Some(cache_dpc), null_mut());
        IoCsqInitializeEx(
            addr_of_mut!(READ_CSQ),
            Some(read_insert),
            Some(read_remove),
            Some(read_peek),
            Some(read_acquire),
            Some(read_release),
            Some(read_cancelled),
        )
    }
}

static mut DEVICE_NAME: UNICODE_STRING = wide!("\\Device\\FirewallXNdisFilter");
static mut LINK_NAME: UNICODE_STRING = wide!("\\DosDevices\\FirewallXNdisFilter");
#[unsafe(no_mangle)]
#[cfg(not(test))]
unsafe extern "C" fn fwx_initialize(driver: PDRIVER_OBJECT, registry: PUNICODE_STRING) -> i32 {
    unsafe {
        let mut status = initialize_io();
        if !nt_success(status) {
            return status;
        }
        registry::read_configuration(registry);
        // Start the machine-wide address inventory before NDIS can admit any
        // packet callbacks. A failed worker start cannot provide the required
        // local-address exemption, so fail driver initialization instead.
        status = crate::native_local_address::start();
        if !nt_success(status) {
            return status;
        }
        (*driver).DriverUnload = Some(unload);
        let mut dispatch_table: [PDRIVER_DISPATCH; IRP_MJ_MAXIMUM_FUNCTION as usize + 1] =
            [None; IRP_MJ_MAXIMUM_FUNCTION as usize + 1];
        for major in [
            IRP_MJ_CREATE,
            IRP_MJ_CLEANUP,
            IRP_MJ_CLOSE,
            IRP_MJ_READ,
            IRP_MJ_WRITE,
            IRP_MJ_DEVICE_CONTROL,
        ] {
            dispatch_table[major as usize] = Some(dispatch);
        }
        let mut sddl = wide!("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        FILTER_NDIS_VERSION = ndis::ndis_version(NdisGetVersion());
        let mut characteristics: NDIS_FILTER_DRIVER_CHARACTERISTICS = zeroed();
        if !ndis::configure_characteristics(&mut characteristics, FILTER_NDIS_VERSION) {
            status = FWX_WDK_NDIS_BAD_VERSION;
        } else {
            status = NdisFRegisterFilterDriver(
                driver,
                driver.cast(),
                &mut characteristics,
                addr_of_mut!(DRIVER_HANDLE),
            );
            if status == FWX_WDK_NDIS_SUCCESS {
                let mut attributes: NDIS_DEVICE_OBJECT_ATTRIBUTES = zeroed();
                attributes.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES as u8;
                attributes.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1 as u8;
                attributes.Header.Size = FWX_WDK_DEVICE_ATTRIBUTES_SIZE as u16;
                attributes.DeviceName = addr_of_mut!(DEVICE_NAME);
                attributes.SymbolicName = addr_of_mut!(LINK_NAME);
                attributes.MajorFunctions = dispatch_table.as_mut_ptr();
                attributes.DefaultSDDLString = &mut sddl;
                status = NdisRegisterDeviceEx(
                    DRIVER_HANDLE,
                    &mut attributes,
                    addr_of_mut!(CONTROL_DEVICE),
                    addr_of_mut!(DEVICE_HANDLE),
                );
            }
        }
        if status != FWX_WDK_NDIS_SUCCESS {
            unload(driver);
            return status;
        }
        let read_work_item = IoAllocateWorkItem(CONTROL_DEVICE);
        READ_WORK_ITEM.store(read_work_item, Ordering::Release);
        CACHE_WORK_ITEM = IoAllocateWorkItem(CONTROL_DEVICE);
        (*CONTROL_DEVICE).Flags |= DO_BUFFERED_IO;
        schedule_read();
        (*CONTROL_DEVICE).Flags &= !DO_DEVICE_INITIALIZING;
        registry::signal_driver_ready();
        FWX_WDK_STATUS_SUCCESS
    }
}
#[cfg(not(test))]
unsafe extern "C" fn unload(_: PDRIVER_OBJECT) {
    unsafe {
        if !READY_EVENT.is_null() {
            KeClearEvent(READY_EVENT);
        }
        api::ExAcquireFastMutex(addr_of_mut!(IO_MUTEX));
        STOPPING.store(1, Ordering::SeqCst);
        set_read_client(null_mut());
        close_classification_session();
        CLIENT = null_mut();
        api::ExReleaseFastMutex(addr_of_mut!(IO_MUTEX));
        cancel_reads(null_mut());
        KeCancelTimer(addr_of_mut!(PENDING_TIMER));
        KeCancelTimer(addr_of_mut!(CACHE_TIMER));
        KeFlushQueuedDpcs();
        ExWaitForRundownProtectionRelease(addr_of_mut!(READ_RUNDOWN));
        ExWaitForRundownProtectionRelease(addr_of_mut!(CACHE_RUNDOWN));
        let read_work_item = READ_WORK_ITEM.swap(null_mut(), Ordering::AcqRel);
        if !read_work_item.is_null() {
            IoFreeWorkItem(read_work_item);
        }
        if !CACHE_WORK_ITEM.is_null() {
            IoFreeWorkItem(CACHE_WORK_ITEM);
            CACHE_WORK_ITEM = null_mut();
        }
        if !DRIVER_HANDLE.is_null() {
            NdisFDeregisterFilterDriver(DRIVER_HANDLE);
            DRIVER_HANDLE = null_mut();
        }
        // NDIS admission is closed and its callbacks have drained. Cancel
        // NETIO notifications and join the inventory worker before unload.
        crate::native_local_address::stop();
        if !DEVICE_HANDLE.is_null() {
            NdisDeregisterDeviceEx(DEVICE_HANDLE);
            DEVICE_HANDLE = null_mut();
        }
        CONTROL_DEVICE = null_mut();
        if !READY_EVENT.is_null() {
            ObfDereferenceObject(READY_EVENT.cast());
            READY_EVENT = null_mut();
        }
        if !READY_EVENT_HANDLE.is_null() {
            let _ = ZwClose(READY_EVENT_HANDLE);
            READY_EVENT_HANDLE = null_mut();
        }
    }
}
