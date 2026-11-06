//! PASSIVE-level registry admission and protected readiness notification.
use super::*;

fn object_attributes(
    name: PUNICODE_STRING,
    root: HANDLE,
    flags: u32,
    descriptor: PVOID,
) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root,
        ObjectName: name,
        Attributes: flags,
        SecurityDescriptor: descriptor,
        SecurityQualityOfService: null_mut(),
    }
}
unsafe fn read_dword(key: HANDLE, mut name: UNICODE_STRING, fallback: u32) -> u32 {
    unsafe {
        // Native header is u32-aligned; variable tail is explicitly byte-decoded.
        let mut buffer = [0u32; (size_of::<KEY_VALUE_PARTIAL_INFORMATION>() + 4).div_ceil(4)];
        let mut returned = 0;
        let status = ZwQueryValueKey(
            key,
            &mut name,
            KeyValuePartialInformation,
            buffer.as_mut_ptr().cast(),
            size_of_val(&buffer) as u32,
            &mut returned,
        );
        let info = buffer.as_ptr().cast::<KEY_VALUE_PARTIAL_INFORMATION>();
        if nt_success(status) && (*info).Type == REG_DWORD && (*info).DataLength == 4 {
            let p = addr_of!((*info).Data).cast::<u8>();
            u32::from_le_bytes([*p, *p.add(1), *p.add(2), *p.add(3)])
        } else {
            fallback
        }
    }
}

pub(super) unsafe fn target_adapter(p: PNDIS_FILTER_ATTACH_PARAMETERS, guid: *mut GUID) -> bool {
    unsafe {
        let mut path = wide!("\\Registry\\Machine\\SOFTWARE\\HyperVXNdisFilter\\Lwf");
        let mut name = wide!("TargetAdapters");
        let mut attributes = object_attributes(
            &mut path,
            null_mut(),
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            null_mut(),
        );
        let mut key = null_mut();
        if !nt_success(ZwOpenKey(&mut key, KEY_READ, &mut attributes)) {
            return false;
        }
        let mut matched = false;
        let prefix = offset_of!(KEY_VALUE_PARTIAL_INFORMATION, Data) as u32;
        if read_dword(key, wide!("ConfigVersion"), 0) == 3
            && read_dword(key, wide!("AllowBindings"), 0) == 1
        {
            for _ in 0..3 {
                let mut needed = 0;
                let mut returned = 0;
                let status = ZwQueryValueKey(
                    key,
                    &mut name,
                    KeyValuePartialInformation,
                    null_mut(),
                    0,
                    &mut needed,
                );
                if (status != HV_WDK_STATUS_BUFFER_TOO_SMALL
                    && status != HV_WDK_STATUS_BUFFER_OVERFLOW)
                    || needed < prefix + 4
                {
                    break;
                }
                let info = pool_allocation(ExAllocatePool2(
                    HV_WDK_POOL_FLAG_NON_PAGED as u64,
                    needed as u64,
                    TAG,
                ))
                .cast::<KEY_VALUE_PARTIAL_INFORMATION>();
                let status = ZwQueryValueKey(
                    key,
                    &mut name,
                    KeyValuePartialInformation,
                    info.cast(),
                    needed,
                    &mut returned,
                );
                if status == HV_WDK_STATUS_BUFFER_TOO_SMALL
                    || status == HV_WDK_STATUS_BUFFER_OVERFLOW
                {
                    ExFreePoolWithTag(info.cast(), TAG);
                    continue;
                }
                if nt_success(status)
                    && returned >= prefix
                    && returned <= needed
                    && (*info).Type == REG_BINARY
                    && (*info).DataLength <= returned - prefix
                    && read_dword(key, wide!("ConfigVersion"), 0) == 3
                    && read_dword(key, wide!("AllowBindings"), 0) == 1
                {
                    let mut actual: GUID = zeroed();
                    if nt_success(ConvertInterfaceLuidToGuid(
                        addr_of!((*p).BaseMiniportNetLuid),
                        &mut actual,
                    )) {
                        matched = crate::target_config::HvTargetAdapterMatch(
                            addr_of!((*info).Data).cast(),
                            (*info).DataLength,
                            addr_of!(actual).cast(),
                            (*p).BaseMiniportNetLuid.Value,
                        ) != 0;
                        if matched {
                            *guid = actual;
                        }
                    }
                }
                ExFreePoolWithTag(info.cast(), TAG);
                break;
            }
        }
        let _ = ZwClose(key);
        matched
    }
}

pub(super) unsafe fn read_configuration(registry: PUNICODE_STRING) -> bool {
    unsafe {
        let mut attributes = object_attributes(
            registry,
            null_mut(),
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            null_mut(),
        );
        let mut service = null_mut();
        let mut parameters = null_mut();
        if !nt_success(ZwOpenKey(&mut service, KEY_READ, &mut attributes)) {
            return false;
        }
        let mut name = wide!("Parameters");
        attributes = object_attributes(
            &mut name,
            service,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            null_mut(),
        );
        let mut standalone = false;
        if nt_success(ZwOpenKey(&mut parameters, KEY_READ, &mut attributes)) {
            crate::HvConfigure(
                read_dword(parameters, wide!("DecisionTimeoutMs"), DEFAULT_TIMEOUT_MS),
                read_dword(parameters, wide!("CacheTtlMs"), 60000),
                read_dword(parameters, wide!("FailClosed"), DEFAULT_FAIL_CLOSED),
            );
            standalone = read_dword(parameters, wide!("StandaloneWfp"), 0) == 1;
            let _ = ZwClose(parameters);
        }
        let _ = ZwClose(service);
        standalone
    }
}

unsafe extern "C" {
    // SeExports is an imported data pointer, not a callable import thunk.
    #[link_name = "__imp_SeExports"]
    static SE_EXPORTS_IMPORT: *const PSE_EXPORTS;
    #[link_name = "__imp_ExEventObjectType"]
    static EVENT_OBJECT_TYPE_IMPORT: *const *mut POBJECT_TYPE;
}

#[repr(C)]
struct ReadyAcl {
    header: ACL,
    aces: [u8; 2 * (size_of::<ACCESS_ALLOWED_ACE>() + HV_WDK_SECURITY_MAX_SID_SIZE as usize)],
}
pub(super) unsafe fn signal_driver_ready() {
    unsafe {
        let status = create_ready_event();
        if !nt_success(status) {
            // BaseNamedObjects can be absent at boot: best effort, never disable LWF.
            DbgPrintEx(
                DPFLTR_IHVNETWORK_ID as u32,
                DPFLTR_WARNING_LEVEL,
                c"HyperVXNdisFilter: driver-ready event unavailable: 0x%08lX\n".as_ptr(),
                status as u32,
            );
        }
    }
}
unsafe fn create_ready_event() -> i32 {
    unsafe {
        let mut descriptor: SECURITY_DESCRIPTOR = zeroed();
        let mut acl: ReadyAcl = zeroed();
        let mut status = RtlCreateSecurityDescriptor(
            addr_of_mut!(descriptor).cast(),
            SECURITY_DESCRIPTOR_REVISION,
        );
        if !nt_success(status) {
            return status;
        }
        status = RtlCreateAcl(&mut acl.header, size_of::<ReadyAcl>() as u32, ACL_REVISION);
        if !nt_success(status) {
            return status;
        }
        status = RtlAddAccessAllowedAce(
            &mut acl.header,
            ACL_REVISION,
            EVENT_ALL_ACCESS,
            (**SE_EXPORTS_IMPORT).SeLocalSystemSid,
        );
        if !nt_success(status) {
            return status;
        }
        status = RtlAddAccessAllowedAce(
            &mut acl.header,
            ACL_REVISION,
            EVENT_ALL_ACCESS,
            (**SE_EXPORTS_IMPORT).SeAliasAdminsSid,
        );
        if !nt_success(status) {
            return status;
        }
        status =
            RtlSetDaclSecurityDescriptor(addr_of_mut!(descriptor).cast(), 1, &mut acl.header, 0);
        if !nt_success(status) {
            return status;
        }
        descriptor.Control |= SE_DACL_PROTECTED as u16;
        let mut name = wide!("\\BaseNamedObjects\\HyperVXNdisFilter.DriverReady");
        let mut attributes = object_attributes(
            &mut name,
            null_mut(),
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
            addr_of_mut!(descriptor).cast(),
        );
        status = ZwCreateEvent(
            addr_of_mut!(READY_EVENT_HANDLE),
            EVENT_MODIFY_STATE | SYNCHRONIZE,
            &mut attributes,
            NotificationEvent,
            0,
        );
        if !nt_success(status) {
            return status;
        }
        status = ObReferenceObjectByHandle(
            READY_EVENT_HANDLE,
            EVENT_MODIFY_STATE,
            **EVENT_OBJECT_TYPE_IMPORT,
            KernelMode as i8,
            addr_of_mut!(READY_EVENT).cast(),
            null_mut(),
        );
        if !nt_success(status) {
            let _ = ZwClose(READY_EVENT_HANDLE);
            READY_EVENT_HANDLE = null_mut();
            return status;
        }
        KeSetEvent(READY_EVENT, IO_NO_INCREMENT as i32, 0);
        HV_WDK_STATUS_SUCCESS
    }
}
use core::mem::size_of_val;
