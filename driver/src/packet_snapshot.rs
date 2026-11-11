use alloc::vec::Vec;
use firewallx_policy::packet::SNAPSHOT;
use likely_stable::unlikely;

#[derive(Default)]
pub struct Snapshot {
    pub data: *const u8,
    pub copied: u32,
    pub trusted: u32,
    pub frame_len: u32,
    pub offload: u32,
}
#[derive(Debug, PartialEq, Eq)]
pub enum SnapshotError {
    Resource,
    Malformed,
}
#[derive(Default)]
pub struct ParserScratch {
    bytes: Option<Vec<u8>>,
}
impl ParserScratch {
    // The common parser always needs at most the fixed-size prefix.
    pub fn read(
        &mut self,
        snapshot: impl FnMut(*mut u8) -> Snapshot,
        allocate: impl FnOnce(usize) -> Vec<u8>,
    ) -> Result<Snapshot, SnapshotError> {
        self.read_with_limit(SNAPSHOT, snapshot, allocate)
    }

    // Borrow a contiguous prefix when possible; otherwise reuse nonpaged
    // scratch. Returned pointers expire before the next read or publication.
    pub fn read_with_limit(
        &mut self,
        limit: usize,
        mut snapshot: impl FnMut(*mut u8) -> Snapshot,
        allocate: impl FnOnce(usize) -> Vec<u8>,
    ) -> Result<Snapshot, SnapshotError> {
        let storage = self
            .bytes
            .as_mut()
            .filter(|bytes| bytes.len() >= limit)
            .map_or(core::ptr::null_mut(), |bytes| bytes.as_mut_ptr());
        let mut view = snapshot(storage);
        if view.data.is_null() && view.frame_len != 0 && storage.is_null() {
            let mut bytes = allocate(limit);
            if unlikely(bytes.len() < limit) {
                return Err(SnapshotError::Resource);
            }
            view = snapshot(bytes.as_mut_ptr());
            self.bytes = Some(bytes);
        }
        if unlikely(view.data.is_null() || view.copied as usize > limit) {
            return Err(SnapshotError::Malformed);
        }
        Ok(view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::cell::Cell;

    #[test]
    fn grows_scratch_for_a_larger_fragmented_prefix_and_reuses_it() {
        let mut scratch = ParserScratch::default();
        let data: Vec<u8> = (0..16).collect();
        let allocations = Cell::new(0);
        for (limit, expected_calls, expected_allocations) in [(4, 2, 1), (12, 2, 2), (8, 1, 2)] {
            let calls = Cell::new(0);
            let view = scratch
                .read_with_limit(
                    limit,
                    |storage| {
                        calls.set(calls.get() + 1);
                        let mut view = Snapshot {
                            frame_len: data.len() as u32,
                            ..Snapshot::default()
                        };
                        if !storage.is_null() {
                            // SAFETY: read supplies at least `limit` bytes.
                            unsafe {
                                core::ptr::copy_nonoverlapping(data.as_ptr(), storage, limit)
                            };
                            view.data = storage;
                            view.copied = limit as u32;
                            view.trusted = limit as u32;
                        }
                        view
                    },
                    |size| {
                        allocations.set(allocations.get() + 1);
                        vec![0; size]
                    },
                )
                .unwrap();
            assert_eq!(calls.get(), expected_calls);
            assert_eq!(allocations.get(), expected_allocations);
            // SAFETY: this view remains valid until the next scratch read.
            let prefix = unsafe { core::slice::from_raw_parts(view.data, view.copied as usize) };
            assert_eq!(prefix, &data[..limit]);
        }
    }

    #[test]
    fn contiguous_prefix_does_not_allocate_and_invalid_reads_fail() {
        let mut scratch = ParserScratch::default();
        let data = [1, 2, 3, 4];
        let view = scratch
            .read_with_limit(
                data.len(),
                |_| Snapshot {
                    data: data.as_ptr(),
                    copied: data.len() as u32,
                    trusted: data.len() as u32,
                    frame_len: data.len() as u32,
                    offload: 0,
                },
                |_| panic!("contiguous data must not allocate"),
            )
            .unwrap();
        assert_eq!(view.data, data.as_ptr());
        assert_eq!(view.offload, 0);

        assert!(matches!(
            scratch.read_with_limit(
                4,
                |_| Snapshot {
                    frame_len: 4,
                    ..Snapshot::default()
                },
                |_| vec![0; 3],
            ),
            Err(SnapshotError::Resource)
        ));
        assert!(matches!(
            scratch.read_with_limit(
                4,
                |_| Snapshot {
                    data: data.as_ptr(),
                    copied: 5,
                    ..Snapshot::default()
                },
                |_| vec![],
            ),
            Err(SnapshotError::Malformed)
        ));
        assert!(matches!(
            scratch.read_with_limit(
                4,
                |_| Snapshot {
                    frame_len: 4,
                    ..Snapshot::default()
                },
                |size| vec![0; size],
            ),
            Err(SnapshotError::Malformed)
        ));
    }
}
