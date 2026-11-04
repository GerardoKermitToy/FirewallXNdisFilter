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
use crate::device_control::HvDeviceControl;
use hyperv_protocol::{IOCTL_ADAPTER_INFO, IOCTL_SHUTDOWN};
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
            return HV_WDK_STATUS_DEVICE_NOT_CONNECTED;
        }
        list_insert_tail(addr_of_mut!(READ_IRPS), irp_link(irp));
        READ_PENDING.store(1, Ordering::SeqCst);
        HV_WDK_STATUS_SUCCESS
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
        complete_read(irp, HV_WDK_STATUS_CANCELLED, 0);
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
            complete_read(irp, HV_WDK_STATUS_CANCELLED, 0);
        }
    }
}
pub(super) unsafe fn schedule_read() {
    unsafe {
        if is_stopping()
            || READ_WORK_ITEM.is_null()
            || READ_PENDING.load(Ordering::SeqCst) == 0
            || (READ_READY.load(Ordering::SeqCst) == 0 && READ_ONLINE.load(Ordering::SeqCst) != 0)
        {
            return;
        }
        if api::ExAcquireRundownProtection(addr_of_mut!(READ_RUNDOWN)) == 0 {
            return;
        }
        if READ_SCHEDULED
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            api::IoQueueWorkItem(
                READ_WORK_ITEM,
                Some(read_worker),
                DelayedWorkQueue,
                null_mut(),
            );
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
            let mut status = HV_WDK_STATUS_SUCCESS;
            let mut bytes = 0;
            api::ExAcquireFastMutex(addr_of_mut!(IO_MUTEX));
            if is_stopping()
                || READ_ONLINE.load(Ordering::SeqCst) == 0
                || CLIENT != (*stack(irp)).FileObject
            {
                status = HV_WDK_STATUS_CANCELLED;
            } else {
                bytes = policy::HvRead(
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
        let mut status = HV_WDK_STATUS_SUCCESS;
        let mut transferred: usize = 0;
        let mut queue_read = false;
        let mut cancel = false;
        api::ExAcquireFastMutex(addr_of_mut!(IO_MUTEX));
        match (*stack).MajorFunction as u32 {
            IRP_MJ_CREATE => {
                if is_stopping() {
                    status = HV_WDK_STATUS_DELETE_PENDING;
                } else if !CLIENT.is_null() {
                    status = HV_WDK_STATUS_SHARING_VIOLATION;
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
                    status = HV_WDK_STATUS_DEVICE_NOT_CONNECTED;
                } else {
                    match major {
                        IRP_MJ_READ => {
                            let len = (*stack).Parameters.Read.Length;
                            if len != 0 && (*irp).AssociatedIrp.SystemBuffer.is_null() {
                                status = HV_WDK_STATUS_INVALID_PARAMETER;
                            } else if len != 0 {
                                if api::ExAcquireRundownProtection(addr_of_mut!(READ_RUNDOWN)) == 0
                                {
                                    status = HV_WDK_STATUS_DEVICE_NOT_CONNECTED;
                                } else {
                                    queue_read = true;
                                }
                            }
                        }
                        IRP_MJ_WRITE => {
                            status = policy::HvWrite(
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
                            status = HvDeviceControl(
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
                        _ => status = HV_WDK_STATUS_INVALID_DEVICE_REQUEST,
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
                return status;
            }
            schedule_read();
            return HV_WDK_STATUS_PENDING;
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

const DEVICE_CLASS: GUID = GUID {
    Data1: 0x874bec2c,
    Data2: 0x0e77,
    Data3: 0x4ed4,
    Data4: [0xa3, 0x76, 0x14, 0x60, 0x6b, 0xe3, 0xc8, 0x64],
};
static mut DEVICE_NAME: UNICODE_STRING = wide!("\\Device\\HyperVXNdisFilter");
static mut LINK_NAME: UNICODE_STRING = wide!("\\DosDevices\\HyperVXNdisFilter");
unsafe extern "C" {
    fn HvWfpInitialize(driver: *mut core::ffi::c_void) -> i32;
    fn HvWfpStop();
    fn HvWfpUninitialize();
}

#[unsafe(no_mangle)]
#[cfg(not(test))]
unsafe extern "C" fn hv_initialize(driver: PDRIVER_OBJECT, registry: PUNICODE_STRING) -> i32 {
    unsafe {
        let mut status = initialize_io();
        if !nt_success(status) {
            return status;
        }
        STANDALONE_WFP = registry::read_configuration(registry);
        status = HvWfpInitialize(driver.cast());
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
        if STANDALONE_WFP {
            for (major, callback) in dispatch_table.iter().enumerate() {
                if callback.is_some() {
                    (*driver).MajorFunction[major] = *callback;
                }
            }
            status = WdmlibIoCreateDeviceSecure(
                driver,
                0,
                addr_of_mut!(DEVICE_NAME),
                FILE_DEVICE_UNKNOWN,
                FILE_DEVICE_SECURE_OPEN,
                0,
                &sddl,
                &DEVICE_CLASS,
                addr_of_mut!(CONTROL_DEVICE),
            );
        } else {
            FILTER_NDIS_VERSION = ndis::ndis_version(NdisGetVersion());
            let mut characteristics: NDIS_FILTER_DRIVER_CHARACTERISTICS = zeroed();
            if !ndis::configure_characteristics(&mut characteristics, FILTER_NDIS_VERSION) {
                status = HV_WDK_NDIS_BAD_VERSION;
            } else {
                status = NdisFRegisterFilterDriver(
                    driver,
                    driver.cast(),
                    &mut characteristics,
                    addr_of_mut!(DRIVER_HANDLE),
                );
                if status == HV_WDK_NDIS_SUCCESS {
                    let mut attributes: NDIS_DEVICE_OBJECT_ATTRIBUTES = zeroed();
                    attributes.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES as u8;
                    attributes.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1 as u8;
                    attributes.Header.Size = HV_WDK_DEVICE_ATTRIBUTES_SIZE as u16;
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
        }
        if !nt_success(status) || (!STANDALONE_WFP && status != HV_WDK_NDIS_SUCCESS) {
            unload(driver);
            return status;
        }
        READ_WORK_ITEM = IoAllocateWorkItem(CONTROL_DEVICE);
        CACHE_WORK_ITEM = IoAllocateWorkItem(CONTROL_DEVICE);
        if READ_WORK_ITEM.is_null() || CACHE_WORK_ITEM.is_null() {
            status = HV_WDK_STATUS_INSUFFICIENT_RESOURCES;
        } else {
            (*CONTROL_DEVICE).Flags |= DO_BUFFERED_IO;
            if STANDALONE_WFP {
                status = IoCreateSymbolicLink(addr_of_mut!(LINK_NAME), addr_of_mut!(DEVICE_NAME));
                if nt_success(status) {
                    STANDALONE_LINK_CREATED = true;
                }
            }
            if nt_success(status) {
                schedule_read();
                (*CONTROL_DEVICE).Flags &= !DO_DEVICE_INITIALIZING;
                registry::signal_driver_ready();
                return HV_WDK_STATUS_SUCCESS;
            }
        }
        unload(driver);
        status
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
        if !READ_WORK_ITEM.is_null() {
            IoFreeWorkItem(READ_WORK_ITEM);
            READ_WORK_ITEM = null_mut();
        }
        if !CACHE_WORK_ITEM.is_null() {
            IoFreeWorkItem(CACHE_WORK_ITEM);
            CACHE_WORK_ITEM = null_mut();
        }
        HvWfpStop();
        if !DRIVER_HANDLE.is_null() {
            NdisFDeregisterFilterDriver(DRIVER_HANDLE);
            DRIVER_HANDLE = null_mut();
        }
        HvWfpUninitialize();
        if STANDALONE_WFP {
            if STANDALONE_LINK_CREATED {
                let _ = IoDeleteSymbolicLink(addr_of_mut!(LINK_NAME));
                STANDALONE_LINK_CREATED = false;
            }
            if !CONTROL_DEVICE.is_null() {
                IoDeleteDevice(CONTROL_DEVICE);
            }
        } else if !DEVICE_HANDLE.is_null() {
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
