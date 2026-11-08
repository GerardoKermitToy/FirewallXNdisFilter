extern crate alloc;

#[path = "../../driver/src/packet_snapshot.rs"]
mod packet_snapshot;

use firewallx_policy::packet::SNAPSHOT;
use packet_snapshot::{ParserScratch, Snapshot, SnapshotError};

fn view(bytes: &[u8], storage: *mut u8, split: bool) -> Snapshot {
    let copied = bytes.len().min(SNAPSHOT);
    let data = if !split {
        bytes.as_ptr()
    } else if storage.is_null() {
        core::ptr::null()
    } else {
        // SAFETY: ParserScratch supplies at least SNAPSHOT writable bytes.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), storage, copied) };
        storage
    };
    Snapshot {
        data,
        copied: if data.is_null() { 0 } else { copied as u32 },
        trusted: if data.is_null() { 0 } else { copied as u32 },
        frame_len: bytes.len() as u32,
        offload: 1,
    }
}

#[test]
fn contiguous_prefixes_never_allocate_or_copy() {
    let mut scratch = ParserScratch::default();
    for length in [1, 14, 319, 320, 321, 1500, 65535] {
        let bytes = vec![0xa5; length];
        let result = scratch
            .read(
                |storage| {
                    assert!(storage.is_null());
                    view(&bytes, storage, false)
                },
                |_| panic!("contiguous input must not allocate parser scratch"),
            )
            .unwrap();
        assert_eq!(result.data, bytes.as_ptr());
        assert_eq!(result.copied as usize, length.min(SNAPSHOT));
        assert_eq!(result.trusted, result.copied);
        assert_eq!(result.frame_len as usize, length);
        assert_eq!(result.offload, 1);
    }
}

#[test]
fn split_and_contiguous_nbs_reuse_one_lazy_scratch() {
    let mut scratch = ParserScratch::default();
    let mut allocations = 0;
    let mut probes = 0;
    let mut saved_storage: *mut u8 = core::ptr::null_mut();
    for (index, split) in [false, true, true, false, true].into_iter().enumerate() {
        let bytes = vec![index as u8; 1500];
        let result = scratch
            .read(
                |storage| {
                    probes += 1;
                    if !storage.is_null() {
                        if saved_storage.is_null() {
                            saved_storage = storage;
                        }
                        assert_eq!(storage, saved_storage);
                    }
                    view(&bytes, storage, split)
                },
                |length| {
                    allocations += 1;
                    assert_eq!(length, SNAPSHOT);
                    vec![0; length]
                },
            )
            .unwrap();
        assert_eq!(
            result.data,
            if split { saved_storage } else { bytes.as_ptr() }
        );
        // SAFETY: the input and scratch are alive; consume before the next read.
        let captured = unsafe { core::slice::from_raw_parts(result.data, result.copied as usize) };
        assert_eq!(captured, &bytes[..SNAPSHOT]);
    }
    assert_eq!(allocations, 1);
    assert_eq!(probes, 6); // Only the first split NB needs a storage-free retry.
}

#[test]
fn failed_mapping_retry_remains_malformed_and_reuses_existing_scratch() {
    let mut scratch = ParserScratch::default();
    let mut probes = 0;
    let result = scratch.read(
        |_| {
            probes += 1;
            Snapshot {
                frame_len: 1500,
                ..Snapshot::default()
            }
        },
        |length| vec![0; length],
    );
    assert!(matches!(result, Err(SnapshotError::Malformed)));
    assert_eq!(probes, 2);
    let result = scratch.read(
        |storage| {
            probes += 1;
            assert!(!storage.is_null());
            Snapshot {
                frame_len: 1500,
                ..Snapshot::default()
            }
        },
        |_| panic!("existing scratch must not be allocated again"),
    );
    assert!(matches!(result, Err(SnapshotError::Malformed)));
    assert_eq!(probes, 3);
}

#[test]
fn invalid_lengths_are_rejected_without_exposing_unbounded_storage() {
    let mut scratch = ParserScratch::default();
    assert!(matches!(
        scratch.read(
            |_| Snapshot::default(),
            |_| panic!("empty NB must not allocate")
        ),
        Err(SnapshotError::Malformed)
    ));
    let bytes = vec![0xa5; SNAPSHOT + 1];
    assert!(matches!(
        scratch.read(
            |_| Snapshot {
                data: bytes.as_ptr(),
                copied: (SNAPSHOT + 1) as u32,
                frame_len: bytes.len() as u32,
                ..Snapshot::default()
            },
            |_| panic!("malformed view must not allocate"),
        ),
        Err(SnapshotError::Malformed)
    ));
    assert!(matches!(
        scratch.read(
            |storage| view(&bytes, storage, true),
            |_| vec![0; SNAPSHOT - 1]
        ),
        Err(SnapshotError::Resource)
    ));
}
