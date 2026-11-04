//! Kernel attach admission checks on the explicit registry blob. Registry reads
//! and the NETIO GUID/LUID round trip stay at the native WDK boundary.
use core::slice;

const ENTRY_SIZE: usize = 24;

fn read_luid(entry: &[u8]) -> u64 {
    u64::from_le_bytes(entry[16..24].try_into().unwrap())
}

fn matches(data: &[u8], guid: &[u8], luid: u64) -> bool {
    if data.len() < 4 || luid == 0 {
        return false;
    }
    let count = u32::from_le_bytes(data[..4].try_into().unwrap());
    let Some(size) = count
        .checked_mul(ENTRY_SIZE as u32)
        .and_then(|n| n.checked_add(4))
    else {
        return false;
    };
    if count == 0 || size as usize != data.len() {
        return false;
    }
    let entries = &data[4..];
    let mut found = false;
    for (i, entry) in entries.as_chunks::<ENTRY_SIZE>().0.iter().enumerate() {
        let value = read_luid(entry);
        if value == 0 || entry[..16].iter().all(|byte| *byte == 0) {
            return false;
        }
        for previous in entries[..i * ENTRY_SIZE].as_chunks::<ENTRY_SIZE>().0 {
            if previous[..16] == entry[..16] || read_luid(previous) == value {
                return false;
            }
        }
        found |= entry[..16] == *guid && value == luid;
    }
    found
}

/// # Safety
/// Non-null `data` is readable for `length` bytes; non-null `guid` holds the
/// native round-tripped Windows GUID's 16 bytes. Neither pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvTargetAdapterMatch(
    data: *const u8,
    length: u32,
    guid: *const u8,
    luid: u64,
) -> u32 {
    if data.is_null() || guid.is_null() {
        return 0;
    }
    let data = unsafe { slice::from_raw_parts(data, length as usize) };
    let guid = unsafe { slice::from_raw_parts(guid, 16) };
    matches(data, guid, luid) as u32
}
