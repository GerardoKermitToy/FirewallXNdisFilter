//! Attached-module diagnostics. Native code owns WDK lifetimes and locks; this
//! module owns fixed-width storage and explicit schema-1 byte encoding.
use core::{
    mem::{align_of, offset_of, size_of},
    ptr, slice,
};
use hyperv_protocol as wire;

#[repr(C)]
pub struct AdapterInfo {
    pub(crate) module_id: u64,
    pub(crate) interface_index: u32,
    pub(crate) filter_interface_index: u32,
    pub(crate) lower_interface_index: u32,
    pub(crate) flags: u32,
    pub(crate) interface_luid: u64,
    pub(crate) filter_interface_luid: u64,
    pub(crate) lower_interface_luid: u64,
    pub(crate) interface_guid: [u8; 16],
    pub(crate) media_type: u32,
    pub(crate) physical_medium: u32,
    pub(crate) media_connect_state: u32,
    pub(crate) media_duplex_state: u32,
    pub(crate) xmit_link_speed: u64,
    pub(crate) rcv_link_speed: u64,
    pub(crate) mtu: u32,
    pub(crate) mac_options: u32,
    pub(crate) supported_packet_filters: u32,
    pub(crate) max_multicast_list_size: u32,
    pub(crate) max_xmit_link_speed: u64,
    pub(crate) max_rcv_link_speed: u64,
    pub(crate) lookahead_size: u32,
    pub(crate) access_type: u32,
    pub(crate) connection_type: u32,
    pub(crate) supported_statistics: u32,
    pub(crate) data_back_fill_size: u32,
    pub(crate) context_back_fill_size: u32,
    pub(crate) restart_flags: u32,
    pub(crate) attach_flags: u32,
    pub(crate) connector_present: u32,
    pub(crate) mac_address_length: u32,
    pub(crate) mac_address: [u8; wire::ADAPTER_INFO_MAC_CAPACITY],
    pub(crate) instance_name_length: u32,
    pub(crate) base_name_length: u32,
    pub(crate) filter_module_name_length: u32,
    pub(crate) auto_negotiation_flags: u32,
    pub(crate) pause_reason: u32,
    pub(crate) pause_flags: u32,
    pub(crate) instance_name: [u16; wire::ADAPTER_INFO_NAME_CAPACITY],
    pub(crate) base_name: [u16; wire::ADAPTER_INFO_NAME_CAPACITY],
    pub(crate) filter_module_name: [u16; wire::ADAPTER_INFO_NAME_CAPACITY],
}
const _: () = {
    assert!(size_of::<AdapterInfo>() == 1760);
    assert!(align_of::<AdapterInfo>() == 8);
    assert!(offset_of!(AdapterInfo, interface_guid) == 48);
    assert!(offset_of!(AdapterInfo, mac_address) == 168);
    assert!(offset_of!(AdapterInfo, instance_name) == 224);
    assert!(offset_of!(AdapterInfo, base_name) == 736);
    assert!(offset_of!(AdapterInfo, filter_module_name) == 1248);
};

#[repr(C)]
pub enum AdapterInfoAction {
    TooSmall,
    CountOverflow,
    HeaderOnly,
    GrowStaging,
    Encode,
}

fn snapshot_size(count: u32) -> u32 {
    count
        .checked_mul(wire::ADAPTER_INFO_ENTRY_SIZE as u32)
        .and_then(|n| n.checked_add(wire::ADAPTER_INFO_HEADER_SIZE as u32))
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn HvAdapterInfoSize(count: u32) -> u32 {
    snapshot_size(count)
}

/// # Safety
/// `required` points to writable native storage, protected by the diagnostic lock.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvPlanAdapterInfo(
    count: u64,
    capacity: u32,
    staged: u64,
    required: *mut u32,
) -> AdapterInfoAction {
    if capacity < wire::ADAPTER_INFO_HEADER_SIZE as u32 {
        return AdapterInfoAction::TooSmall;
    }
    if count > wire::ADAPTER_INFO_MAX_ADAPTERS as u64 {
        return AdapterInfoAction::CountOverflow;
    }
    let size = snapshot_size(count as u32);
    unsafe {
        required.write(size);
    }
    if capacity < size {
        AdapterInfoAction::HeaderOnly
    } else if staged < count {
        AdapterInfoAction::GrowStaging
    } else {
        AdapterInfoAction::Encode
    }
}

/// # Safety
/// `info` is exclusive, aligned native AdapterInfo storage under the diagnostic lock.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvClearGeneralAttributes(info: *mut AdapterInfo) {
    let a = unsafe { &mut *info };
    a.flags &= !wire::ADAPTER_GENERAL_VALID;
    a.mtu = 0;
    a.max_xmit_link_speed = 0;
    a.max_rcv_link_speed = 0;
    a.lookahead_size = 0;
    a.mac_options = 0;
    a.supported_packet_filters = 0;
    a.max_multicast_list_size = 0;
    a.access_type = 0;
    a.restart_flags = 0;
    a.connection_type = 0;
    a.supported_statistics = 0;
    a.data_back_fill_size = 0;
    a.context_back_fill_size = 0;
}

/// # Safety
/// `out` holds NAME_CAPACITY writable u16s, `flags` is writable, and a non-null
/// `source` holds `length` readable u16s. Input/output do not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvCopyAdapterName(
    out: *mut u16,
    source: *const u16,
    length: u32,
    flags: *mut u32,
    truncated_flag: u32,
) -> u32 {
    let out = unsafe { slice::from_raw_parts_mut(out, wire::ADAPTER_INFO_NAME_CAPACITY) };
    out.fill(0);
    if source.is_null() {
        return 0;
    }
    let source = unsafe { slice::from_raw_parts(source, length as usize) };
    let mut copied = 0;
    while copied < source.len() && copied < out.len() - 1 && source[copied] != 0 {
        out[copied] = source[copied];
        copied += 1;
    }
    if copied < source.len() && source[copied] != 0 {
        unsafe {
            *flags |= truncated_flag;
        }
        if copied != 0 && (0xd800..=0xdbff).contains(&out[copied - 1]) {
            copied -= 1;
            out[copied] = 0;
        }
    }
    copied as u32
}

/// # Safety
/// `out` holds four writable bytes; no alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvInfoWrite32(out: *mut u8, value: u32) {
    unsafe {
        ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), out, 4);
    }
}
/// # Safety
/// `out` holds eight writable bytes; no alignment is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvInfoWrite64(out: *mut u8, value: u64) {
    unsafe {
        ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), out, 8);
    }
}

fn write32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn write64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// # Safety
/// `out` holds ADAPTER_INFO_HEADER_SIZE writable bytes. Counts are one consistent
/// diagnostic-lock observation; encoding does not acquire any lock or allocate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvEncodeAdapterInfoHeader(out: *mut u8, count: u32, running: u32) {
    let out = unsafe { slice::from_raw_parts_mut(out, wire::ADAPTER_INFO_HEADER_SIZE) };
    write32(out, 0, wire::ADAPTER_INFO_VERSION);
    write32(out, 4, wire::ADAPTER_INFO_ENTRY_SIZE as u32);
    write32(out, 8, count);
    write32(out, 12, running);
}

/// # Safety
/// `out` holds ADAPTER_INFO_ENTRY_SIZE writable bytes; `info` is a valid aligned
/// immutable snapshot, disjoint from output. Native code retains its lifetime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvEncodeAdapterInfo(out: *mut u8, info: *const AdapterInfo) {
    let out = unsafe { slice::from_raw_parts_mut(out, wire::ADAPTER_INFO_ENTRY_SIZE) };
    let a = unsafe { &*info };
    write64(out, 0, a.module_id);
    write32(out, 8, a.interface_index);
    write32(out, 12, a.filter_interface_index);
    write32(out, 16, a.lower_interface_index);
    write32(out, 20, a.flags);
    write64(out, 24, a.interface_luid);
    write64(out, 32, a.filter_interface_luid);
    write64(out, 40, a.lower_interface_luid);
    out[48..64].copy_from_slice(&a.interface_guid);
    write32(out, 64, a.media_type);
    write32(out, 68, a.physical_medium);
    write32(out, 72, a.media_connect_state);
    write32(out, 76, a.media_duplex_state);
    write64(out, 80, a.xmit_link_speed);
    write64(out, 88, a.rcv_link_speed);
    write32(out, 96, a.mtu);
    write32(out, 100, a.mac_options);
    write32(out, 104, a.supported_packet_filters);
    write32(out, 108, a.max_multicast_list_size);
    write64(out, 112, a.max_xmit_link_speed);
    write64(out, 120, a.max_rcv_link_speed);
    write32(out, 128, a.lookahead_size);
    write32(out, 132, a.access_type);
    write32(out, 136, a.connection_type);
    write32(out, 140, a.supported_statistics);
    write32(out, 144, a.data_back_fill_size);
    write32(out, 148, a.context_back_fill_size);
    write32(out, 152, a.restart_flags);
    write32(out, 156, a.attach_flags);
    write32(out, 160, a.connector_present);
    write32(out, 164, a.mac_address_length);
    out[168..200].copy_from_slice(&a.mac_address);
    write32(out, 200, a.instance_name_length);
    write32(out, 204, a.base_name_length);
    write32(out, 208, a.filter_module_name_length);
    write32(out, 212, a.auto_negotiation_flags);
    write32(out, 216, a.pause_reason);
    write32(out, 220, a.pause_flags);
    for (offset, name) in [
        (224, &a.instance_name),
        (736, &a.base_name),
        (1248, &a.filter_module_name),
    ] {
        for (pair, value) in out[offset..offset + 2 * wire::ADAPTER_INFO_NAME_CAPACITY]
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .zip(name)
        {
            pair.copy_from_slice(&value.to_le_bytes());
        }
    }
}
