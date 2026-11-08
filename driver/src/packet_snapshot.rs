use alloc::vec::Vec;
use firewallx_policy::packet::SNAPSHOT;

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
    // Read only the fixed parser prefix. Once allocated, scratch is reused for
    // the remaining NBs; contiguous data can still be returned without copying.
    // Returned pointers must be consumed before the next read or NBL publication.
    pub fn read(
        &mut self,
        mut snapshot: impl FnMut(*mut u8) -> Snapshot,
        allocate: impl FnOnce(usize) -> Vec<u8>,
    ) -> Result<Snapshot, SnapshotError> {
        let storage = self
            .bytes
            .as_mut()
            .map_or(core::ptr::null_mut(), |bytes| bytes.as_mut_ptr());
        let mut view = snapshot(storage);
        if view.data.is_null() && view.frame_len != 0 && self.bytes.is_none() {
            let mut bytes = allocate(SNAPSHOT);
            if bytes.len() < SNAPSHOT {
                return Err(SnapshotError::Resource);
            }
            view = snapshot(bytes.as_mut_ptr());
            self.bytes = Some(bytes);
        }
        if view.data.is_null() || view.copied as usize > SNAPSHOT {
            return Err(SnapshotError::Malformed);
        }
        Ok(view)
    }
}
