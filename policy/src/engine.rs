use crate::{
    bandwidth::{BandwidthGroup, BandwidthStore},
    cache::{CacheAllocator, CachePlan, CacheWork, Caches, Decision},
    packet::Packet,
    storage::{Handle, List},
};
use alloc::vec::Vec;
use core::fmt::{self, Write};
use hyperv_protocol::{
    BANDWIDTH_HEADER, BandwidthEntry, MAX_LOG_RECORD, MAX_PAYLOAD, MAX_RECORD, Verdict,
    bandwidth_entry_len, bandwidth_record_len, connection_header_len, encode_bandwidth_entry,
    encode_bandwidth_header, encode_connection_header, encode_log,
};

use likely_stable::{likely, unlikely};

pub use crate::bandwidth::{BandwidthPlan, BandwidthWork, DeferredBandwidth};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finish {
    Allow,
    Drop,
    Cancel,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action {
    pub nbl: usize,
    pub finish: Finish,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submission {
    Pending(u64),
    Finish(Action),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerdictError {
    NotFound,
    // The cache changed while its storage was being prepared outside PolicyLock.
    RetryCache,
}

struct Interface {
    interface_index: u32,
    running: bool,
    ndis_attached: bool,
    forwarding: bool,
    dirty: bool,
    candidate: bool,
    pending: usize,
    caches: Caches,
}
impl Interface {
    fn idle_forward(&self) -> bool {
        self.forwarding
            && !self.ndis_attached
            && !self.dirty
            && !self.candidate
            && self.pending == 0
            && self.caches.bytes() == 0
    }
}
#[derive(Clone, Copy)]
struct Pending {
    id: u64,
    nbl: usize,
    cancel: Option<usize>,
    deadline: u64,
    interface_index: u32,
    invalidated: bool,
    event: Option<Handle<Event>>,
    packet: Packet,
}
struct Event {
    read: usize,
    pending: Option<Handle<Pending>>,
    data: Vec<u8>,
}

// Records and metadata have no aggregate byte quota; the per-record payload
// limit remains part of the wire contract.
pub fn allocate_record(len: usize) -> Option<Vec<u8>> {
    if unlikely(len > MAX_RECORD) {
        return None;
    }
    allocate_event(len)
}
fn allocate_event(len: usize) -> Option<Vec<u8>> {
    core::alloc::Layout::array::<u8>(len).ok()?;
    Some(alloc::vec![0; len])
}
#[derive(Default)]
struct BandwidthReportGroup {
    count: usize,
    data: Option<Vec<u8>>,
    offset: usize,
}

pub struct BandwidthTable {
    store: BandwidthStore,
    epoch: u64,
}
impl Default for BandwidthTable {
    fn default() -> Self {
        Self::new()
    }
}
impl BandwidthTable {
    pub fn new() -> Self {
        Self {
            store: BandwidthStore::new(),
            epoch: 0,
        }
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    fn group_record(group: BandwidthGroup, count: usize) -> Option<Vec<u8>> {
        let len = bandwidth_record_len(group.ipv6, count)?;
        let mut data = allocate_event(len)?;
        encode_bandwidth_header(
            &mut data,
            group.interface_index,
            group.ipv6,
            group.protocol,
            count,
        )
        .expect("valid bandwidth event layout");
        Some(data)
    }
    fn encode_counter(
        data: &mut [u8],
        offset: &mut usize,
        ipv6: bool,
        connection: &hyperv_protocol::Connection,
        tx: u64,
        rx: u64,
    ) -> bool {
        let Some(end) = offset.checked_add(bandwidth_entry_len(ipv6)) else {
            return false;
        };
        let Some(output) = data.get_mut(*offset..end) else {
            return false;
        };
        let entry = BandwidthEntry {
            local_ip: connection.local_ip,
            local_port: connection.local_port,
            remote_ip: connection.remote_ip,
            remote_port: connection.remote_port,
            transmitted_bytes: tx,
            received_bytes: rx,
        };
        encode_bandwidth_entry(output, ipv6, &entry).expect("valid bandwidth entry layout");
        *offset = end;
        true
    }
    // One or two groups need no per-entry index or sorting. Count before
    // encoding so a mixed snapshot never allocates a speculative full record.
    fn report_small_groups(&mut self, submit: &mut impl FnMut(Vec<u8>) -> bool) -> bool {
        let Some(mut first) = self.store.first_group() else {
            return false;
        };
        let mut second = None;
        let (mut first_count, mut second_count) = (0usize, 0usize);
        if !self.store.visit_report_while(&mut |group, _, _, _| {
            let count = if group == first {
                &mut first_count
            } else if second.is_none() || second == Some(group) {
                second = Some(group);
                &mut second_count
            } else {
                return false;
            };
            let Some(next) = count.checked_add(1) else {
                return false;
            };
            *count = next;
            true
        }) {
            return false;
        }
        if let Some(mut other) = second
            && other < first
        {
            core::mem::swap(&mut first, &mut other);
            core::mem::swap(&mut first_count, &mut second_count);
            second = Some(other);
        }
        let Some(mut first_data) = Self::group_record(first, first_count) else {
            return false;
        };
        let mut second_data = if let Some(group) = second {
            let Some(data) = Self::group_record(group, second_count) else {
                return false;
            };
            Some(data)
        } else {
            None
        };
        let (mut first_offset, mut second_offset) = (BANDWIDTH_HEADER, BANDWIDTH_HEADER);
        if !self
            .store
            .visit_report_while(&mut |group, connection, tx, rx| {
                if group == first {
                    Self::encode_counter(
                        &mut first_data,
                        &mut first_offset,
                        first.ipv6,
                        connection,
                        tx,
                        rx,
                    )
                } else if let (Some(other), Some(data)) = (second, second_data.as_mut()) {
                    group == other
                        && Self::encode_counter(
                            data,
                            &mut second_offset,
                            other.ipv6,
                            connection,
                            tx,
                            rx,
                        )
                } else {
                    false
                }
            })
            || first_offset != first_data.len()
            || second_data
                .as_ref()
                .is_some_and(|data| second_offset != data.len())
        {
            return false;
        }
        if submit(first_data) {
            let second_queued = match second_data {
                Some(data) => submit(data),
                None => true,
            };
            if second_queued {
                self.store = BandwidthStore::new();
            } else {
                self.store.retain_after(first);
            }
        }
        true
    }
    // Reporting and any detached-bank consolidation run outside PolicyLock in
    // the driver path. A failed consolidation leaves all deltas retryable.
    pub fn report(&mut self, mut submit: impl FnMut(Vec<u8>) -> bool) {
        if !self.store.consolidate() {
            return;
        }
        if self.report_small_groups(&mut submit) {
            return;
        }

        let mut groups = Vec::<(BandwidthGroup, BandwidthReportGroup)>::new();
        if !self.store.visit_report_while(&mut |group, _, _, _| {
            let index = match groups.binary_search_by_key(&group, |entry| entry.0) {
                Ok(index) => index,
                Err(index) => {
                    groups.insert(index, (group, BandwidthReportGroup::default()));
                    index
                }
            };
            let report = &mut groups[index].1;
            let Some(count) = report.count.checked_add(1) else {
                return false;
            };
            report.count = count;
            true
        }) {
            return;
        }
        let mut valid = true;
        for (group, report) in &mut groups {
            if valid {
                report.data = Self::group_record(*group, report.count);
                report.offset = BANDWIDTH_HEADER;
                valid = report.data.is_some();
            }
        }
        if !self
            .store
            .visit_report_while(&mut |group, connection, tx, rx| {
                let Ok(index) = groups.binary_search_by_key(&group, |entry| entry.0) else {
                    return false;
                };
                let report = &mut groups[index].1;
                let Some(data) = report.data.as_mut() else {
                    return true;
                };
                Self::encode_counter(data, &mut report.offset, group.ipv6, connection, tx, rx)
            })
            || groups.iter().any(|(_, report)| {
                report
                    .data
                    .as_ref()
                    .is_some_and(|data| report.offset != data.len())
            })
        {
            return;
        }

        let mut last = None;
        let mut complete = true;
        for (group, report) in groups {
            let Some(data) = report.data else {
                complete = false;
                break;
            };
            if !submit(data) {
                complete = false;
                break;
            }
            last = Some(group);
        }
        if complete {
            self.store = BandwidthStore::new();
        } else if let Some(group) = last {
            self.store.retain_after(group);
        }
    }
}

// Opaque ownership returned to the driver for destruction outside PolicyLock.
pub struct RetiredStorage {
    _events: List<Event>,
    _bandwidth: BandwidthStore,
}
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    pub received: u64,
    pub allowed: u64,
    pub dropped: u64,
    pub queued: u64,
    pub cache_hits: u64,
    pub cache_allocation_failures: u64,
    pub timeouts: u64,
    pub overflow: u64,
    pub cancelled: u64,
    pub invalidated: u64,
    pub malformed: u64,
    pub non_ip: u64,
}
impl Stats {
    const EMPTY: Self = Self {
        received: 0,
        allowed: 0,
        dropped: 0,
        queued: 0,
        cache_hits: 0,
        cache_allocation_failures: 0,
        timeouts: 0,
        overflow: 0,
        cancelled: 0,
        invalidated: 0,
        malformed: 0,
        non_ip: 0,
    };
}

// Each metadata allocation is fixed-size; there is no item-count ceiling or
// growing-array relocation under PolicyLock. Packet capture and cache table
// allocation/initialization/retirement still happen OUTSIDE that lock.
pub struct Engine {
    pending: List<Pending>,
    pending_count: usize,
    interfaces: List<Interface>,
    idle_forward: u32,
    cache_candidate_count: usize,
    cache_allocator: CacheAllocator,
    events: List<Event>,
    retired_events: List<Event>,
    bandwidth: BandwidthStore,
    retry_bandwidth: BandwidthStore,
    retired_bandwidth: BandwidthStore,
    bandwidth_count: usize,
    bandwidth_epoch: u64,
    queued_bytes: usize,
    next_id: u64,
    online: bool,
    fail_closed: bool,
    timeout: u64,
    cache_ttl: u64,
    stats: Stats,
}
impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}
impl Engine {
    pub const fn new() -> Self {
        Self::with_cache_allocator(CacheAllocator::GLOBAL)
    }
    pub const fn with_cache_allocator(allocator: CacheAllocator) -> Self {
        Self {
            pending: List::new(),
            pending_count: 0,
            interfaces: List::new(),
            idle_forward: 0,
            cache_candidate_count: 0,
            cache_allocator: allocator,
            events: List::new(),
            retired_events: List::new(),
            bandwidth: BandwidthStore::new(),
            retry_bandwidth: BandwidthStore::new(),
            retired_bandwidth: BandwidthStore::new(),
            bandwidth_count: 0,
            bandwidth_epoch: 0,
            queued_bytes: 0,
            next_id: 1,
            online: false,
            fail_closed: true,
            timeout: 8000,
            cache_ttl: 60000,
            stats: Stats::EMPTY,
        }
    }
    pub fn configure(&mut self, timeout: u32, cache_ttl: u32, fail_closed: bool) {
        self.timeout = u64::from(timeout.clamp(100, 60000));
        self.cache_ttl = u64::from(cache_ttl.clamp(1000, 300000));
        self.fail_closed = fail_closed;
    }
    pub fn fallback(&self) -> Finish {
        if self.fail_closed {
            Finish::Drop
        } else {
            Finish::Allow
        }
    }
    pub fn stats(&self) -> Stats {
        self.stats
    }
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }
    pub fn is_online(&self) -> bool {
        self.online
    }
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }
    pub fn cache_candidates(&self) -> usize {
        self.cache_candidate_count
    }
    fn update_cache_candidates(&mut self, handle: Handle<Interface>) {
        // SAFETY: callers just found this live interface under exclusive access.
        let interface = unsafe { self.interfaces.get_mut(handle) };
        let candidate = !interface.dirty && interface.caches.has_entries();
        if candidate != interface.candidate {
            if candidate {
                self.cache_candidate_count += 1;
            } else {
                self.cache_candidate_count -= 1;
            }
            interface.candidate = candidate;
        }
    }
    fn clear_events(&mut self) {
        for event in self.events.iter() {
            if let Some(handle) = event.pending {
                // SAFETY: detach every event back-reference before retiring the
                // chain. Only the one partially read, already claimed request
                // can be inactive here; unread claims are removed immediately.
                let pending = unsafe { self.pending.get_mut(handle) };
                pending.event = None;
                if pending.id == 0 {
                    unsafe { self.pending.remove(handle) };
                }
            }
        }
        self.retired_events.append(&mut self.events);
        self.queued_bytes = 0;
    }
    pub fn take_retired_storage(&mut self) -> Option<RetiredStorage> {
        if !self.retired_events.is_empty() {
            return Some(RetiredStorage {
                _events: core::mem::replace(&mut self.retired_events, List::new()),
                _bandwidth: BandwidthStore::new(),
            });
        }
        self.retired_bandwidth
            .has_storage()
            .then(|| RetiredStorage {
                _events: List::new(),
                _bandwidth: core::mem::replace(&mut self.retired_bandwidth, BandwidthStore::new()),
            })
    }
    fn has_room(&self, len: usize) -> bool {
        self.queued_bytes.checked_add(len).is_some()
    }
    fn push_event(
        &mut self,
        data: Vec<u8>,
        pending: Option<Handle<Pending>>,
    ) -> Option<Handle<Event>> {
        let queued_bytes = self.queued_bytes.checked_add(data.len())?;
        let handle = self
            .events
            .try_push_back(Event {
                read: 0,
                pending,
                data,
            })
            .ok()?;
        self.queued_bytes = queued_bytes;
        Some(handle)
    }
    fn pop_event(&mut self) {
        if let Some(event) = self.events.pop_front() {
            self.queued_bytes -= event.data.len();
            if let Some(handle) = event.pending {
                // SAFETY: a pending node is retained until BOTH its event has
                // left the queue and its NBL has been claimed. No event
                // handle escapes; there is exactly one event per pending node.
                let pending = unsafe { self.pending.get_mut(handle) };
                pending.event = None;
                if pending.id == 0 {
                    unsafe { self.pending.remove(handle) };
                }
            }
        }
    }
    pub fn connect(&mut self) {
        self.bandwidth_epoch = self.bandwidth_epoch.wrapping_add(1);
        self.online = true;
        self.clear_events();
        self.clear_cache();
        self.clear_bandwidth();
        self.log(3, "HyperVXNdisFilter: shared NDIS/IPFORWARD verdicts and traffic data; full IP packets, interface index, no PID, redirects, UpdateV4/V6 or synthetic END");
    }
    // Complete actions using take_due() after dropping the lock.
    pub fn disconnect(&mut self) {
        self.bandwidth_epoch = self.bandwidth_epoch.wrapping_add(1);
        self.online = false;
        self.stats = Stats::EMPTY;
        self.clear_events();
        self.clear_cache();
        self.clear_bandwidth();
        let idle = core::mem::take(&mut self.idle_forward);
        if idle != 0 {
            self.reap_idle_forward(idle);
        }
    }
    pub fn attach(&mut self, interface_index: u32) -> bool {
        if interface_index == 0 {
            return false;
        }
        if let Some(interface) = self
            .interfaces
            .iter_mut()
            .find(|s| s.interface_index == interface_index)
        {
            if interface.ndis_attached {
                return false;
            }
            interface.ndis_attached = true;
            interface.running = false;
            return true;
        }
        self.interfaces
            .try_push_back(Interface {
                interface_index,
                running: false,
                ndis_attached: true,
                forwarding: false,
                dirty: false,
                candidate: false,
                pending: 0,
                caches: Caches::new(self.cache_allocator),
            })
            .is_ok()
    }
    // WFP observes any source interface. Reuse the same policy/cache row; no
    // NETIO inventory, network-lifecycle callback or parallel flow store exists.
    pub fn ensure_forward(&mut self, interface_index: u32) -> bool {
        if interface_index == 0 {
            return false;
        }
        if let Some(interface) = self
            .interfaces
            .iter_mut()
            .find(|s| s.interface_index == interface_index)
        {
            interface.forwarding = true;
            return true;
        }
        if self.idle_forward != 0
            && let Some(interface) = self
                .interfaces
                .iter_mut()
                .find(|s| s.interface_index == self.idle_forward && s.idle_forward())
        {
            interface.interface_index = interface_index;
            self.idle_forward = interface_index;
            return true;
        }
        self.interfaces
            .try_push_back(Interface {
                interface_index,
                running: false,
                ndis_attached: false,
                forwarding: true,
                dirty: false,
                candidate: false,
                pending: 0,
                caches: Caches::new(self.cache_allocator),
            })
            .is_ok()
    }
    // Keep at most one idle forward-only row for the next packet. It holds no
    // cache or pending decision and is released on disconnect or replacement.
    pub fn reap_idle_forward(&mut self, interface_index: u32) -> bool {
        let Some(handle) = self
            .interfaces
            .find(|interface| interface.interface_index == interface_index)
        else {
            return false;
        };
        self.reap_idle_forward_handle(handle)
    }
    fn reap_idle_forward_handle(&mut self, handle: Handle<Interface>) -> bool {
        // SAFETY: callers obtained this live handle under exclusive access.
        let interface = unsafe { self.interfaces.get(handle) };
        if !interface.idle_forward() {
            return false;
        }
        let index = interface.interface_index;
        if self.online {
            if self.idle_forward == index {
                return true;
            }
            let previous = core::mem::replace(&mut self.idle_forward, index);
            if previous != 0
                && let Some(old) = self.interfaces.find(|interface| {
                    interface.interface_index == previous && interface.idle_forward()
                })
            {
                // SAFETY: this old row was just found and owns no cache storage.
                unsafe { self.interfaces.remove(old) };
            }
        } else {
            if self.idle_forward == index {
                self.idle_forward = 0;
            }
            // SAFETY: this row owns no cache storage or valid pending decision.
            unsafe { self.interfaces.remove(handle) };
        }
        true
    }
    // Driver shutdown only, never an interface-change notification. Release
    // forward-only rows using the same unlocked cache reclamation as NDIS.
    pub fn stop_forward(&mut self) {
        self.idle_forward = 0;
        while let Some(handle) = self.interfaces.find(|s| s.forwarding) {
            let index = unsafe { self.interfaces.get(handle) }.interface_index;
            self.invalidate(index, false);
            let interface = unsafe { self.interfaces.get_mut(handle) };
            interface.forwarding = false;
            if !interface.ndis_attached {
                interface.interface_index = 0;
                if !interface.dirty {
                    unsafe { self.interfaces.remove(handle) };
                }
            }
        }
    }
    pub fn restart(&mut self, interface_index: u32) -> bool {
        if let Some(interface) = self.interfaces.iter_mut().find(|s| {
            s.interface_index == interface_index && interface_index != 0 && s.ndis_attached
        }) {
            interface.running = true;
            true
        } else {
            false
        }
    }
    pub fn invalidate(&mut self, interface_index: u32, pause: bool) {
        if let Some(interface) = self
            .interfaces
            .iter_mut()
            .find(|s| s.interface_index == interface_index && interface_index != 0)
        {
            interface.dirty = interface.caches.bytes() != 0;
            interface.pending = 0;
            if interface.candidate {
                interface.candidate = false;
                self.cache_candidate_count -= 1;
            }
            if pause {
                interface.running = false;
            }
            // A restart or reuse of the same index must not revive these IDs.
            for pending in self.pending.iter_mut() {
                if pending.id != 0 && pending.interface_index == interface_index {
                    pending.invalidated = true;
                }
            }
        }
    }
    pub fn detach(&mut self, interface_index: u32) {
        self.invalidate(interface_index, true);
        if let Some(handle) = self
            .interfaces
            .find(|s| s.interface_index == interface_index && interface_index != 0)
        {
            // SAFETY: handle was found in this list, with exclusive engine access.
            let interface = unsafe { self.interfaces.get_mut(handle) };
            interface.ndis_attached = false;
            if !interface.forwarding {
                interface.interface_index = 0;
                if !interface.dirty {
                    unsafe { self.interfaces.remove(handle) };
                }
            }
        }
        self.reap_idle_forward(interface_index);
    }
    fn running(&self, interface_index: u32) -> bool {
        self.interfaces
            .iter()
            .any(|s| s.interface_index == interface_index && (s.running || s.forwarding))
    }
    // Immediately disable all old tables; retire one bank at a time outside the
    // driver lock rather than returning a large per-interface array on its stack.
    pub fn clear_cache(&mut self) {
        self.cache_candidate_count = 0;
        for interface in self.interfaces.iter_mut() {
            interface.candidate = false;
            interface.dirty = interface.caches.bytes() != 0;
        }
    }
    pub fn take_retired_caches(&mut self) -> Option<Caches> {
        let handle = self.interfaces.find(|c| c.dirty)?;
        // SAFETY: found in this exclusively borrowed list; removal only happens
        // after moving out the cache allocations, which the caller frees unlocked.
        let interface = unsafe { self.interfaces.get_mut(handle) };
        interface.dirty = false;
        let index = interface.interface_index;
        let retired = interface.caches.clear();
        if index == 0 {
            unsafe { self.interfaces.remove(handle) };
        } else {
            self.reap_idle_forward(index);
        }
        Some(retired)
    }
    pub fn cache_cleanup_limit(&self) -> u32 {
        self.interfaces
            .iter()
            .filter(|s| s.candidate)
            .map(|s| s.interface_index)
            .max()
            .unwrap_or(0)
    }
    // A scalar cursor survives unlocked ranges without holding node pointers or
    // allocating a snapshot. The initial upper bound makes each pass finite even
    // if interfaces attach concurrently. Reused indices cannot revive old caches.
    pub fn next_cache_candidate(&self, after: u32, through: u32) -> Option<(u32, usize)> {
        self.interfaces
            .iter()
            .filter(|s| s.candidate && s.interface_index > after && s.interface_index <= through)
            .min_by_key(|s| s.interface_index)
            .map(|s| (s.interface_index, s.caches.cleanup_slots()))
    }
    pub fn cache_cleanup_slots(&self, interface_index: u32) -> usize {
        self.interfaces
            .iter()
            .find(|s| s.interface_index == interface_index && s.candidate)
            .map_or(0, |s| s.caches.cleanup_slots())
    }
    pub fn clean_range_with_work(
        &mut self,
        interface_index: u32,
        start: usize,
        now: u64,
        work: &mut CacheWork,
    ) -> bool {
        let Some(handle) = self
            .interfaces
            .find(|s| s.interface_index == interface_index && s.candidate)
        else {
            return false;
        };
        // SAFETY: this handle was just found; no mutation can remove it here.
        unsafe { self.interfaces.get_mut(handle) }
            .caches
            .maintain_range(start, now, work);
        self.update_cache_candidates(handle);
        let active = unsafe { self.interfaces.get(handle) }.candidate;
        if !active {
            self.reap_idle_forward(interface_index);
        }
        active
    }
    // Host helper. The kernel worker uses ranges to release PolicyLock between
    // batches while completing every candidate bank in the same cleanup run.
    pub fn clean(&mut self, now: u64) {
        while let Some(retired) = self.take_retired_caches() {
            drop(retired);
        }
        let limit = self.cache_cleanup_limit();
        let mut after = 0;
        while let Some((index, _)) = self.next_cache_candidate(after, limit) {
            after = index;
            let handle = self
                .interfaces
                .find(|s| s.interface_index == index)
                .unwrap();
            let mut work = CacheWork::empty();
            // SAFETY: found in this list; the bank stays live throughout this call.
            unsafe { self.interfaces.get_mut(handle) }
                .caches
                .maintain(now, &mut work);
            self.update_cache_candidates(handle);
            self.reap_idle_forward(index);
        }
    }
    fn cache_eligible(packet: &Packet) -> bool {
        packet.cacheable
            && likely(matches!(packet.connection.protocol, 6 | 17))
            && packet.flow.protocol == packet.connection.protocol
            && packet.flow.ipv6 == packet.connection.ipv6
    }
    fn cache_bank(&self, interface_index: u32, packet: &Packet) -> Option<Handle<Interface>> {
        if !Self::cache_eligible(packet) {
            return None;
        }
        self.interfaces.find(|interface| {
            interface.interface_index == interface_index
                && (interface.running || interface.forwarding)
                && !interface.dirty
        })
    }
    pub fn cache_plan(&self, id: u64, verdict: Verdict, now: u64) -> Option<CachePlan> {
        if !verdict.permanent() || !self.online {
            return None;
        }
        let pending = self
            .pending
            .iter()
            .find(|p| p.id == id && id != 0 && !p.invalidated && p.deadline > now)?;
        let bank = self.cache_bank(pending.interface_index, &pending.packet)?;
        // SAFETY: cache_bank returned a live handle in this borrowed list.
        unsafe { self.interfaces.get(bank) }
            .caches
            .plan(&pending.packet.connection)
    }
    fn cache_counts(&self) -> (usize, usize) {
        self.interfaces
            .iter()
            .filter(|c| !c.dirty)
            .fold((0, 0), |(v4, v6), c| {
                let counts = c.caches.counts();
                (v4 + counts.0, v6 + counts.1)
            })
    }
    fn cache_bytes(&self) -> usize {
        self.interfaces.iter().map(|c| c.caches.bytes()).sum()
    }
    // Call only while the controller session is online.
    fn account(
        &mut self,
        interface_index: u32,
        packet: &Packet,
        allow: bool,
        work: &mut BandwidthWork,
    ) {
        if allow {
            self.stats.allowed = self.stats.allowed.saturating_add(1);
            if likely(matches!(packet.connection.protocol, 6 | 17)) {
                self.bandwidth_add_with_work(interface_index, packet, work);
            }
        } else {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
        }
    }
    pub fn non_ip(&mut self) {
        if self.online {
            self.stats.received = self.stats.received.saturating_add(1);
            self.stats.non_ip = self.stats.non_ip.saturating_add(1);
            self.stats.allowed = self.stats.allowed.saturating_add(1);
        }
    }
    pub fn malformed(&mut self) {
        if self.online {
            self.stats.received = self.stats.received.saturating_add(1);
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            self.stats.dropped = self.stats.dropped.saturating_add(1);
        }
    }
    pub fn resource_drop(&mut self) {
        if self.online {
            self.stats.received = self.stats.received.saturating_add(1);
            self.stats.overflow = self.stats.overflow.saturating_add(1);
            self.stats.dropped = self.stats.dropped.saturating_add(1);
        }
    }
    fn event_room(&self, packet: &Packet) -> bool {
        self.has_room(connection_header_len(&packet.connection) + packet.payload_len as usize)
            && self.next_id != u64::MAX
    }
    // Read-only allocation hint: this cannot refresh idle expiry or admit traffic.
    pub fn wants_event(&self, interface_index: u32, packet: &Packet, now: u64) -> bool {
        self.running(interface_index)
            && self.online
            && self.cache_bank(interface_index, packet).is_none_or(|bank| {
                // SAFETY: the handle belongs to this borrowed interface list.
                unsafe { self.interfaces.get(bank) }
                    .caches
                    .get(&packet.connection, now)
                    .is_none()
            })
            && self.event_room(packet)
    }
    fn immediate(
        &mut self,
        interface_index: u32,
        packet: &Packet,
        nbl: usize,
        now: u64,
        work: &mut BandwidthWork,
    ) -> (Option<Action>, Option<Handle<Interface>>) {
        let interface = self
            .interfaces
            .find(|interface| interface.interface_index == interface_index);
        let active = interface.is_some_and(|handle| {
            // SAFETY: the handle was just found in this live list.
            let interface = unsafe { self.interfaces.get(handle) };
            interface.running || interface.forwarding
        });
        if !self.online {
            return (
                Some(Action {
                    nbl,
                    finish: if active {
                        self.fallback()
                    } else {
                        Finish::Drop
                    },
                }),
                interface,
            );
        }
        let allow = if !active {
            false
        } else {
            let handle = interface.expect("active interface has a live handle");
            // SAFETY: the live handle remains valid throughout this locked call.
            let bank = unsafe { self.interfaces.get_mut(handle) };
            if bank.dirty || !Self::cache_eligible(packet) {
                return (None, interface);
            }
            let Some(allow) = bank.caches.apply(&packet.connection, now, self.cache_ttl) else {
                return (None, interface);
            };
            self.stats.cache_hits = self.stats.cache_hits.saturating_add(1);
            allow
        };
        self.stats.received = self.stats.received.saturating_add(1);
        self.account(interface_index, packet, allow, work);
        (
            Some(Action {
                nbl,
                finish: if allow { Finish::Allow } else { Finish::Drop },
            }),
            interface,
        )
    }
    // The driver returns cache hits here: one lookup, no packet capture or second
    // policy-lock acquisition. Only misses proceed to the unlocked event copy.
    pub fn preflight(
        &mut self,
        interface_index: u32,
        packet: &Packet,
        nbl: usize,
        now: u64,
    ) -> Result<bool, Action> {
        let mut work = BandwidthWork::prepare(self.bandwidth_plan());
        self.preflight_with_work(interface_index, packet, nbl, now, &mut work)
    }
    pub fn preflight_with_work(
        &mut self,
        interface_index: u32,
        packet: &Packet,
        nbl: usize,
        now: u64,
        work: &mut BandwidthWork,
    ) -> Result<bool, Action> {
        if let (Some(action), _) = self.immediate(interface_index, packet, nbl, now, work) {
            Err(action)
        } else {
            Ok(self.event_room(packet))
        }
    }
    fn overflow(
        &mut self,
        interface_index: u32,
        packet: &Packet,
        nbl: usize,
        work: &mut BandwidthWork,
    ) -> Submission {
        self.stats.overflow = self.stats.overflow.saturating_add(1);
        let finish = self.fallback();
        self.account(interface_index, packet, finish == Finish::Allow, work);
        Submission::Finish(Action { nbl, finish })
    }
    pub fn submit(
        &mut self,
        interface_index: u32,
        packet: Packet,
        nbl: usize,
        cancel: Option<usize>,
        now: u64,
        record: Option<Vec<u8>>,
    ) -> Submission {
        let mut work = BandwidthWork::prepare(self.bandwidth_plan());
        self.submit_with_work(interface_index, packet, nbl, cancel, now, record, &mut work)
    }
    // Re-establish forward-only membership atomically with publication. The
    // row can be reaped while a classifier captures bytes outside PolicyLock.
    pub fn submit_forward_with_work(
        &mut self,
        interface_index: u32,
        packet: Packet,
        nbl: usize,
        now: u64,
        record: Option<Vec<u8>>,
        work: &mut BandwidthWork,
    ) -> Submission {
        if !self.online {
            // The controller may disconnect while this classifier captures the
            // packet. Retire its now-idle row without collecting traffic stats.
            self.reap_idle_forward(interface_index);
            return Submission::Finish(Action {
                nbl,
                finish: self.fallback(),
            });
        }
        if !self.ensure_forward(interface_index) {
            self.resource_drop();
            return Submission::Finish(Action {
                nbl,
                finish: Finish::Drop,
            });
        }
        let result = self.submit_with_work(interface_index, packet, nbl, None, now, record, work);
        if matches!(result, Submission::Finish(_)) {
            self.reap_idle_forward(interface_index);
        }
        result
    }
    #[allow(clippy::too_many_arguments)]
    pub fn submit_with_work(
        &mut self,
        interface_index: u32,
        packet: Packet,
        nbl: usize,
        cancel: Option<usize>,
        now: u64,
        record: Option<Vec<u8>>,
        work: &mut BandwidthWork,
    ) -> Submission {
        let (action, interface) = self.immediate(interface_index, &packet, nbl, now, work);
        if let Some(action) = action {
            return Submission::Finish(action);
        }
        self.stats.received = self.stats.received.saturating_add(1);
        let payload_len = packet.payload_len as usize;
        let expected = connection_header_len(&packet.connection) + payload_len;
        if unlikely(
            payload_len > MAX_PAYLOAD || record.as_ref().is_some_and(|data| data.len() != expected),
        ) {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            self.account(interface_index, &packet, false, work);
            return Submission::Finish(Action {
                nbl,
                finish: Finish::Drop,
            });
        }
        if unlikely(!self.has_room(expected) || self.next_id == u64::MAX || record.is_none()) {
            return self.overflow(interface_index, &packet, nbl, work);
        }
        let id = self.next_id;
        let mut data = record.unwrap_or_default();
        if unlikely(
            encode_connection_header(
                &mut data,
                id,
                interface_index,
                &packet.connection,
                payload_len,
            )
            .is_err(),
        ) {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            self.account(interface_index, &packet, false, work);
            return Submission::Finish(Action {
                nbl,
                finish: Finish::Drop,
            });
        }
        let Some(interface) = interface else {
            self.account(interface_index, &packet, false, work);
            return Submission::Finish(Action {
                nbl,
                finish: Finish::Drop,
            });
        };
        let Some(interface_pending) = (unsafe { self.interfaces.get(interface) })
            .pending
            .checked_add(1)
        else {
            return self.overflow(interface_index, &packet, nbl, work);
        };
        let Ok(handle) = self.pending.try_push_back(Pending {
            id,
            nbl,
            cancel,
            deadline: now.saturating_add(self.timeout),
            interface_index,
            invalidated: false,
            event: None,
            packet,
        }) else {
            return self.overflow(interface_index, &packet, nbl, work);
        };
        let Some(event) = self.push_event(data, Some(handle)) else {
            // SAFETY: the event was not published, so only this new handle exists.
            unsafe { self.pending.remove(handle) };
            return self.overflow(interface_index, &packet, nbl, work);
        };
        // SAFETY: both nodes are live and no handles escape the locked engine.
        unsafe { self.pending.get_mut(handle) }.event = Some(event);
        unsafe { self.interfaces.get_mut(interface) }.pending = interface_pending;
        self.next_id += 1;
        self.pending_count += 1;
        self.stats.queued = self.stats.queued.saturating_add(1);
        Submission::Pending(id)
    }
    fn claim(
        &mut self,
        handle: Handle<Pending>,
        finish: Finish,
        bandwidth: &mut BandwidthWork,
    ) -> Action {
        // SAFETY: callers found a live, active node under exclusive engine access.
        let pending = unsafe { self.pending.get_mut(handle) };
        let p = *pending;
        pending.id = 0;
        let retain = if let Some(event) = p.event {
            // SAFETY: a pending event handle stays live until pop_event clears
            // it. Unread stale events can be unlinked in O(1), avoiding repeated
            // scans of claimed nodes when a large timeout/cancel batch drains.
            if unsafe { self.events.get(event) }.read == 0 {
                let event = unsafe { self.events.remove(event) };
                self.queued_bytes -= event.data.len();
                false
            } else {
                true // Finish a partial frame before freeing its pending node.
            }
        } else {
            false
        };
        if !retain {
            unsafe { self.pending.remove(handle) };
        }
        self.pending_count -= 1;
        let interface = self
            .interfaces
            .find(|interface| interface.interface_index == p.interface_index);
        if !p.invalidated
            && let Some(interface) = interface
        {
            // SAFETY: this handle was found in the live interface list above.
            let interface = unsafe { self.interfaces.get_mut(interface) };
            interface.pending = interface.pending.saturating_sub(1);
        }
        if self.online {
            self.account(
                p.interface_index,
                &p.packet,
                finish == Finish::Allow,
                bandwidth,
            );
        }
        if let Some(interface) = interface {
            self.reap_idle_forward_handle(interface);
        }
        Action { nbl: p.nbl, finish }
    }
    pub fn verdict(&mut self, id: u64, verdict: Verdict, now: u64) -> Result<Action, VerdictError> {
        loop {
            while let Some(retired) = self.take_retired_caches() {
                drop(retired);
            }
            let mut work = CacheWork::prepare(self.cache_plan(id, verdict, now));
            let mut bandwidth = BandwidthWork::prepare(self.bandwidth_plan());
            match self.verdict_with_work(id, verdict, now, &mut work, &mut bandwidth) {
                Err(VerdictError::RetryCache) => continue,
                result => return result,
            }
        }
    }
    pub fn verdict_with_work(
        &mut self,
        id: u64,
        verdict: Verdict,
        now: u64,
        work: &mut CacheWork,
        bandwidth: &mut BandwidthWork,
    ) -> Result<Action, VerdictError> {
        let handle = self
            .pending
            .find(|p| p.id == id && id != 0)
            .ok_or(VerdictError::NotFound)?;
        // SAFETY: the handle was found in this list and no node is removed here.
        let p = *unsafe { self.pending.get(handle) };
        if p.deadline <= now || !self.online || p.invalidated {
            return Err(VerdictError::NotFound);
        }
        if verdict.permanent()
            && Self::cache_eligible(&p.packet)
            && let Some(bank) = self.interfaces.find(|interface| {
                interface.interface_index == p.interface_index
                    && (interface.running || interface.forwarding)
            })
        {
            // SAFETY: the handle was just found and remains live under PolicyLock.
            let interface = unsafe { self.interfaces.get_mut(bank) };
            if interface.dirty {
                // Old storage must be detached and freed before installing the
                // new decision; the pending ID remains live for the retry.
                return Err(VerdictError::RetryCache);
            }
            let inserted = interface.caches.insert(
                &p.packet.connection,
                Decision {
                    allow: verdict.allows(),
                    expires: now.saturating_add(self.cache_ttl),
                },
                now,
                work,
            );
            let retry = !inserted
                && interface
                    .caches
                    .plan(&p.packet.connection)
                    .is_some_and(|plan| work.needs_preparation(plan));
            self.update_cache_candidates(bank);
            if retry {
                return Err(VerdictError::RetryCache);
            }
            if unlikely(!inserted) {
                self.stats.cache_allocation_failures =
                    self.stats.cache_allocation_failures.saturating_add(1);
            }
        }
        Ok(self.claim(
            handle,
            if verdict.allows() {
                Finish::Allow
            } else {
                Finish::Drop
            },
            bandwidth,
        ))
    }
    // One owned nbl at a time, never an unbounded array on the kernel stack.
    pub fn take_due(&mut self, now: u64) -> Option<Action> {
        let mut work = BandwidthWork::prepare(self.bandwidth_plan());
        self.take_due_with_work(now, &mut work)
    }
    pub fn take_due_with_work(&mut self, now: u64, work: &mut BandwidthWork) -> Option<Action> {
        if self.pending_count == 0 {
            return None;
        }
        let handle = self
            .pending
            .find(|p| p.id != 0 && (p.invalidated || !self.online || p.deadline <= now))?;
        // SAFETY: the handle was just found under exclusive engine access.
        let p = *unsafe { self.pending.get(handle) };
        let finish = if p.invalidated {
            if self.online {
                self.stats.invalidated = self.stats.invalidated.saturating_add(1);
            }
            Finish::Drop
        } else if !self.online {
            self.fallback()
        } else {
            self.stats.timeouts = self.stats.timeouts.saturating_add(1);
            self.fallback()
        };
        Some(self.claim(handle, finish, work))
    }
    pub fn cancel(&mut self, interface_index: u32, cancel: usize) -> Option<Action> {
        let handle = self.pending.find(|p| {
            p.id != 0 && p.interface_index == interface_index && p.cancel == Some(cancel)
        })?;
        if self.online {
            self.stats.cancelled = self.stats.cancelled.saturating_add(1);
        }
        // Cancellation never admits bytes and cannot consume bandwidth storage.
        Some(self.claim(handle, Finish::Cancel, &mut BandwidthWork::empty()))
    }
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let mut written = 0;
        while written < out.len() {
            let Some(event) = self.events.front() else {
                break;
            };
            let stale = event.read == 0
                && event.pending.is_some_and(|handle| {
                    // SAFETY: queued events retain their pending node even after claim.
                    unsafe { self.pending.get(handle) }.id == 0
                });
            if stale {
                self.pop_event();
                continue;
            }
            let event = self.events.front_mut().unwrap();
            let n = (event.data.len() - event.read).min(out.len() - written);
            out[written..written + n].copy_from_slice(&event.data[event.read..event.read + n]);
            event.read += n;
            written += n;
            if event.read == event.data.len() {
                self.pop_event();
            }
        }
        written
    }
    pub fn log(&mut self, severity: u8, message: &str) {
        if !self.online {
            return;
        }
        let mut bytes = [0; MAX_LOG_RECORD];
        let Ok(len) = encode_log(&mut bytes, severity, message) else {
            return;
        };
        if !self.has_room(len) {
            return;
        }
        if let Some(mut data) = allocate_record(len) {
            data.copy_from_slice(&bytes[..len]);
            let _ = self.push_event(data, None);
        }
    }
    pub fn log_args(&mut self, severity: u8, message: fmt::Arguments<'_>) {
        if !self.online {
            return;
        }
        let mut text = Text {
            bytes: [0; 400],
            len: 0,
        };
        if text.write_fmt(message).is_ok() {
            self.log(severity, text.as_str());
        }
    }
    fn clear_bandwidth(&mut self) {
        self.retired_bandwidth.append(&mut self.bandwidth);
        self.retired_bandwidth.append(&mut self.retry_bandwidth);
        self.bandwidth_count = 0;
    }
    // Read-only capacity hint. The driver prepares these allocations unlocked,
    // then rechecks the hint before invoking a single accounting operation.
    pub fn bandwidth_plan(&self) -> Option<BandwidthPlan> {
        self.online.then(|| self.bandwidth.plan()).flatten()
    }
    // The synchronous slow path retries only the accounting operation, never
    // the packet decision. A session reset invalidates its captured epoch.
    pub fn complete_bandwidth(
        &mut self,
        deferred: &DeferredBandwidth,
        work: &mut BandwidthWork,
    ) -> Option<BandwidthPlan> {
        if !self.online || self.bandwidth_epoch != deferred.epoch {
            return None;
        }
        match self.bandwidth.try_add(
            deferred.interface_index,
            &deferred.connection,
            deferred.bytes,
            work,
        ) {
            Ok(Some(added)) => self.bandwidth_count += usize::from(added),
            Ok(None) => self.stats.overflow = self.stats.overflow.saturating_add(1),
            Err(plan) => return Some(plan),
        }
        None
    }
    #[cfg(test)]
    fn bandwidth_add(&mut self, interface_index: u32, p: &Packet) {
        let mut work = BandwidthWork::prepare(self.bandwidth_plan());
        self.bandwidth_add_with_work(interface_index, p, &mut work);
    }
    fn bandwidth_add_with_work(
        &mut self,
        interface_index: u32,
        p: &Packet,
        work: &mut BandwidthWork,
    ) {
        match self
            .bandwidth
            .try_add(interface_index, &p.connection, p.ip_len, work)
        {
            Ok(Some(added)) => self.bandwidth_count += usize::from(added),
            Err(plan) if work.defer_missing => {
                debug_assert!(work.deferred.is_none());
                work.deferred = Some(DeferredBandwidth {
                    interface_index,
                    connection: p.connection,
                    bytes: p.ip_len,
                    epoch: self.bandwidth_epoch,
                    plan,
                });
            }
            Ok(None) | Err(_) => self.stats.overflow = self.stats.overflow.saturating_add(1),
        }
    }
    pub fn begin_bandwidth(&mut self, table: &mut BandwidthTable) -> bool {
        if (self.bandwidth_count == 0 && self.retry_bandwidth.is_empty())
            || table.store.has_storage()
        {
            return false;
        }
        // Move only ownership headers. Pages/entries/index buffers never move.
        core::mem::swap(&mut self.bandwidth, &mut table.store);
        table.store.append(&mut self.retry_bandwidth);
        table.epoch = self.bandwidth_epoch;
        self.bandwidth_count = 0;
        true
    }
    pub fn queue_bandwidth(&mut self, epoch: u64, data: Vec<u8>) -> Result<(), Vec<u8>> {
        if !self.online || epoch != self.bandwidth_epoch || !self.has_room(data.len()) {
            return Err(data);
        }
        let queued_bytes = self.queued_bytes + data.len();
        match self.events.try_push_back(Event {
            read: 0,
            pending: None,
            data,
        }) {
            Ok(_) => {
                self.queued_bytes = queued_bytes;
                Ok(())
            }
            Err(event) => Err(event.data),
        }
    }
    pub fn finish_bandwidth(&mut self, table: &mut BandwidthTable) -> bool {
        if !self.online || table.epoch != self.bandwidth_epoch {
            return false;
        }
        // Keep unqueued deltas as whole retry banks, without a bulk locked
        // merge. The next detached report combines duplicate keys unlocked.
        if !table.store.is_empty() {
            self.retry_bandwidth.append(&mut table.store);
        }
        self.bandwidth_count = self.bandwidth.len() + self.retry_bandwidth.len();
        true
    }
    // Offline policy tests use the same detached-table path as the kernel bridge.
    pub fn bandwidth(&mut self) {
        let mut table = BandwidthTable::new();
        if !self.begin_bandwidth(&mut table) {
            return;
        }
        let epoch = table.epoch();
        table.report(|data| match self.queue_bandwidth(epoch, data) {
            Ok(()) => true,
            Err(data) => {
                drop(data);
                false
            }
        });
        let _ = self.finish_bandwidth(&mut table);
    }
    pub fn memory_stats(&mut self) {
        let mut text = Text {
            bytes: [0; 400],
            len: 0,
        };
        let s = self.stats;
        let metadata = self.pending.bytes()
            + self.events.bytes()
            + self.interfaces.bytes()
            + self.bandwidth.bytes()
            + self.retry_bandwidth.bytes();
        let _ = write!(
            text,
            "HyperVXNdisFilter: fixed_bytes={} metadata_bytes={} event_bytes={} pending={} events={} bandwidth={} cached_v4={} cached_v6={} cache_bytes={} cache_alloc_fail={} rx={} allow={} drop={} queued={} cache_hits={} timeout={} overflow={} cancel={} invalidated={} malformed={} non_ip={}",
            core::mem::size_of::<Self>(),
            metadata,
            self.queued_bytes,
            self.pending_count(),
            self.events.len(),
            self.bandwidth_count,
            self.cache_counts().0,
            self.cache_counts().1,
            self.cache_bytes(),
            s.cache_allocation_failures,
            s.received,
            s.allowed,
            s.dropped,
            s.queued,
            s.cache_hits,
            s.timeouts,
            s.overflow,
            s.cancelled,
            s.invalidated,
            s.malformed,
            s.non_ip
        );
        self.log(3, text.as_str());
    }
}
struct Text {
    bytes: [u8; 400],
    len: usize,
}
impl Text {
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("statistics formatting error")
    }
}
impl Write for Text {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.bytes.len() - self.len);
        self.bytes[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        if n == s.len() {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::packet::NdisPath;
    use hyperv_protocol::Direction;
    use std::{boxed::Box, vec};
    fn engine() -> Box<Engine> {
        let mut e = default_engine();
        e.configure(2000, 60000, false); // Explicit fail-open/short deadline for these fixtures.
        e
    }
    fn default_engine() -> Box<Engine> {
        let mut e = Box::new(Engine::new());
        assert!(e.attach(101));
        assert!(e.restart(101));
        e.connect();
        e
    }
    fn packet() -> Packet {
        let mut p = Packet::EMPTY;
        p.cacheable = true;
        p.flow.protocol = 17;
        p.connection.protocol = 17;
        p.ip_len = 100;
        p.payload_len = 100;
        p
    }
    fn cache_packet(ipv6: bool, protocol: u8, source_port: u16) -> Packet {
        let mut p = packet();
        p.flow.ipv6 = ipv6;
        p.connection.ipv6 = ipv6;
        p.flow.protocol = protocol;
        p.connection.protocol = protocol;
        p.flow.source[0] = 10;
        p.flow.destination[0] = 20;
        p.flow.source_port = source_port;
        p.flow.destination_port = 443;
        p.orient(NdisPath::Receive);
        p
    }
    fn record(p: &Packet) -> Option<Vec<u8>> {
        allocate_record(connection_header_len(&p.connection) + p.payload_len as usize)
    }
    fn complete_deferred(e: &mut Engine, work: &mut BandwidthWork) -> bool {
        let Some(deferred) = work.take_deferred() else {
            return false;
        };
        let mut plan = deferred.plan();
        loop {
            let mut prepared = BandwidthWork::prepare(Some(plan));
            match e.complete_bandwidth(&deferred, &mut prepared) {
                Some(next) => plan = next,
                None => return true,
            }
        }
    }
    fn submit(e: &mut Engine, interface_index: u32, t: usize) -> u64 {
        let p = packet();
        match e.submit(interface_index, p, t, None, 100, record(&p)) {
            Submission::Pending(id) => id,
            _ => panic!("expected pending"),
        }
    }
    #[test]
    fn forward_only_rows_remain_bounded_and_reuse_the_idle_row() {
        let mut e = Engine::new();
        e.connect();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let p = packet();
        let mut first_row = core::ptr::null();
        for index in 1..=1000 {
            let mut work = BandwidthWork::prepare(e.bandwidth_plan());
            let Submission::Pending(id) =
                e.submit_forward_with_work(index, p, index as usize, 100, record(&p), &mut work)
            else {
                panic!("expected pending forward packet");
            };
            drop(work);
            assert_eq!(
                e.verdict(id, Verdict::Drop, 101).unwrap().nbl,
                index as usize
            );
            assert_eq!(e.interfaces.len(), 1);
            let row = e.interfaces.front().unwrap() as *const Interface;
            if index == 1 {
                first_row = row;
            } else {
                assert_eq!(row, first_row);
            }
        }
        let address = e.interfaces.front().unwrap() as *const Interface;
        let mut work = BandwidthWork::prepare(e.bandwidth_plan());
        let Submission::Pending(id) =
            e.submit_forward_with_work(1000, p, 1001, 102, record(&p), &mut work)
        else {
            panic!("expected pending forward packet");
        };
        e.verdict(id, Verdict::Drop, 103).unwrap();
        assert_eq!(e.interfaces.front().unwrap() as *const Interface, address);
        e.disconnect();
        assert!(e.interfaces.is_empty());
    }

    #[test]
    fn forward_rows_survive_pending_and_live_cache_until_expiry() {
        let mut e = Engine::new();
        e.connect();
        let p = packet();
        let mut work = BandwidthWork::prepare(e.bandwidth_plan());
        let Submission::Pending(first) =
            e.submit_forward_with_work(7, p, 1, 100, record(&p), &mut work)
        else {
            panic!("expected first pending packet");
        };
        let Submission::Pending(second) =
            e.submit_forward_with_work(7, p, 2, 100, record(&p), &mut work)
        else {
            panic!("expected second pending packet");
        };
        drop(work);
        assert!(!e.reap_idle_forward(7));
        e.verdict(first, Verdict::Drop, 101).unwrap();
        assert_eq!(e.interfaces.len(), 1);
        e.verdict(second, Verdict::PermanentAccept, 101).unwrap();
        assert_eq!(e.interfaces.len(), 1);
        assert!(!e.reap_idle_forward(7));
        e.clean(60101);
        assert_eq!(e.interfaces.len(), 1);
        e.disconnect();
        assert!(e.interfaces.is_empty());
    }

    #[test]
    fn forwarding_rechecks_membership_after_unlocked_packet_capture() {
        let mut e = Engine::new();
        e.connect();
        let p = packet();
        let mut work = BandwidthWork::prepare(e.bandwidth_plan());
        let Submission::Pending(first) =
            e.submit_forward_with_work(7, p, 1, 100, record(&p), &mut work)
        else {
            panic!("expected first pending packet");
        };
        assert!(e.preflight_with_work(7, &p, 2, 100, &mut work).unwrap());
        e.verdict(first, Verdict::Drop, 101).unwrap();
        assert!(e.ensure_forward(8));
        assert!(e.reap_idle_forward(8));
        assert!(
            e.interfaces
                .iter()
                .all(|interface| interface.interface_index != 7)
        );
        let Submission::Pending(second) =
            e.submit_forward_with_work(7, p, 2, 102, record(&p), &mut work)
        else {
            panic!("forward membership must be restored before publication");
        };
        assert_eq!(e.verdict(second, Verdict::Accept, 103).unwrap().nbl, 2);
        assert_eq!(e.interfaces.len(), 1);
        e.configure(8000, 60000, false);
        assert!(e.ensure_forward(7));
        assert!(e.preflight_with_work(7, &p, 3, 104, &mut work).unwrap());
        e.disconnect();
        assert_eq!(
            e.submit_forward_with_work(7, p, 3, 104, record(&p), &mut work),
            Submission::Finish(Action {
                nbl: 3,
                finish: Finish::Allow,
            })
        );
        assert!(e.interfaces.is_empty());
    }

    #[test]
    fn disconnected_forward_after_capture_does_not_account_for_fallback() {
        for fail_closed in [false, true] {
            let mut e = Engine::new();
            e.configure(8000, 60000, fail_closed);
            e.connect();
            let p = packet();
            let mut work = BandwidthWork::defer_missing();
            assert!(e.ensure_forward(7));
            assert!(e.preflight_with_work(7, &p, 1, 100, &mut work).unwrap());
            e.disconnect();
            let finish = if fail_closed {
                Finish::Drop
            } else {
                Finish::Allow
            };
            assert_eq!(
                e.submit_forward_with_work(7, p, 1, 101, record(&p), &mut work),
                Submission::Finish(Action { nbl: 1, finish })
            );
            assert_eq!(e.stats, Stats::EMPTY);
            assert_eq!(e.bandwidth_count, 0);
            assert!(work.take_deferred().is_none());
            assert!(e.interfaces.is_empty());
        }
    }

    #[test]
    fn traffic_statistics_stop_offline_and_restart_with_a_new_session() {
        for fail_closed in [false, true] {
            let mut e = Engine::new();
            e.configure(8000, 60000, fail_closed);
            assert!(e.attach(101));
            assert!(e.restart(101));
            let p = packet();
            let fallback = if fail_closed {
                Finish::Drop
            } else {
                Finish::Allow
            };
            assert_eq!(
                e.preflight(101, &p, 1, 100),
                Err(Action {
                    nbl: 1,
                    finish: fallback,
                })
            );
            e.non_ip();
            e.malformed();
            e.resource_drop();
            assert_eq!(e.stats(), Stats::EMPTY);
            assert!(!e.bandwidth.has_storage());

            e.connect();
            e.read(&mut [0; MAX_LOG_RECORD]);
            let first = submit(&mut e, 101, 2);
            e.verdict(first, Verdict::Accept, 101).unwrap();
            assert_eq!(e.stats().received, 1);
            assert_eq!(e.stats().allowed, 1);
            assert_eq!(e.bandwidth_count, 1);
            e.non_ip();
            e.malformed();
            e.resource_drop();
            assert_eq!(e.stats().received, 4);
            assert_eq!(e.stats().allowed, 2);
            assert_eq!(e.stats().dropped, 2);
            assert_eq!(e.stats().non_ip, 1);
            assert_eq!(e.stats().malformed, 1);
            assert_eq!(e.stats().overflow, 1);
            assert!(matches!(
                e.submit(101, p, 3, Some(7), 102, record(&p)),
                Submission::Pending(_)
            ));
            let _second = submit(&mut e, 101, 4);
            e.invalidate(101, false);
            e.disconnect();
            assert_eq!(e.stats(), Stats::EMPTY);
            assert!(!e.bandwidth.has_storage());
            assert!(e.retired_bandwidth.has_storage());
            assert_eq!(e.cancel(101, 7).unwrap().finish, Finish::Cancel);
            assert_eq!(e.take_due(103).unwrap().finish, Finish::Drop);
            e.non_ip();
            e.malformed();
            e.resource_drop();
            assert_eq!(e.stats(), Stats::EMPTY);
            while let Some(retired) = e.take_retired_storage() {
                drop(retired);
            }
            assert!(!e.retired_bandwidth.has_storage());

            e.connect();
            e.read(&mut [0; MAX_LOG_RECORD]);
            let next = submit(&mut e, 101, 5);
            e.verdict(next, Verdict::Accept, 101).unwrap();
            assert_eq!(e.stats().received, 1);
            assert_eq!(e.stats().allowed, 1);
            e.bandwidth();
            assert_eq!(bandwidth_rows(&mut e), [(101, 17, false, 0, 100, 0)]);
        }
    }

    #[test]
    fn invalidated_forward_claim_does_not_change_new_pending_count() {
        let mut e = Engine::new();
        e.connect();
        let p = packet();
        let mut work = BandwidthWork::prepare(e.bandwidth_plan());
        let Submission::Pending(old) =
            e.submit_forward_with_work(7, p, 1, 100, record(&p), &mut work)
        else {
            panic!("expected old packet");
        };
        e.invalidate(7, false);
        let Submission::Pending(new) =
            e.submit_forward_with_work(7, p, 2, 101, record(&p), &mut work)
        else {
            panic!("expected new packet");
        };
        assert!(e.verdict(old, Verdict::Accept, 102).is_err());
        assert_eq!(e.take_due_with_work(102, &mut work).unwrap().nbl, 1);
        assert!(!e.reap_idle_forward(7));
        assert_eq!(e.verdict(new, Verdict::Accept, 103).unwrap().nbl, 2);
        assert_eq!(e.interfaces.len(), 1);
        e.disconnect();
        assert!(e.interfaces.is_empty());
    }

    #[test]
    fn replacing_idle_forward_row_preserves_pending_and_attached_rows() {
        let mut e = Engine::new();
        e.connect();
        let p = packet();
        let mut work = BandwidthWork::prepare(e.bandwidth_plan());
        let Submission::Pending(first) =
            e.submit_forward_with_work(1, p, 1, 100, record(&p), &mut work)
        else {
            panic!("expected pending packet");
        };
        e.verdict(first, Verdict::Drop, 101).unwrap();
        let Submission::Pending(still_pending) =
            e.submit_forward_with_work(1, p, 2, 102, record(&p), &mut work)
        else {
            panic!("expected pending packet");
        };
        let Submission::Pending(other) =
            e.submit_forward_with_work(2, p, 3, 102, record(&p), &mut work)
        else {
            panic!("expected pending packet");
        };
        e.verdict(other, Verdict::Drop, 103).unwrap();
        assert_eq!(e.interfaces.len(), 2);
        e.verdict(still_pending, Verdict::Drop, 103).unwrap();
        assert_eq!(e.interfaces.len(), 1);
        assert!(e.attach(1));
        assert!(e.ensure_forward(2));
        assert!(e.reap_idle_forward(2));
        assert_eq!(e.interfaces.len(), 2);
        assert!(
            e.interfaces
                .iter()
                .any(|interface| interface.interface_index == 1 && interface.ndis_attached)
        );
        e.disconnect();
        assert_eq!(e.interfaces.len(), 1);
    }

    #[test]
    fn forwarding_reap_never_removes_an_attached_ndis_row() {
        let mut e = default_engine();
        assert!(e.ensure_forward(101));
        assert!(!e.reap_idle_forward(101));
        assert!(e.preflight(101, &packet(), 1, 100).unwrap());
    }

    #[test]
    fn pending_events_grow_past_old_counts_and_preserve_every_id_and_packet() {
        const COUNT: usize = 4097;
        let mut e = default_engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut ids = Vec::new();
        for nbl in 1..=COUNT {
            let mut p = packet();
            p.flow.source_port = nbl as u16;
            p.orient(NdisPath::Receive);
            let Submission::Pending(id) = e.submit(101, p, nbl, None, 100, record(&p)) else {
                panic!("small packets must not hit a fixed item limit");
            };
            ids.push(id);
        }
        assert_eq!(e.pending_count(), COUNT);
        assert_eq!(e.events.len(), COUNT);
        assert_eq!(e.stats().overflow, 0);
        let mut bytes = Vec::new();
        let mut chunk = [0; 65536];
        loop {
            let n = e.read(&mut chunk);
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..n]);
        }
        let size = connection_header_len(&packet().connection) + 100;
        assert_eq!(bytes.len(), COUNT * size);
        for (i, event) in bytes.chunks_exact(size).enumerate() {
            assert_eq!(event[0], 1);
            assert_eq!(u64::from_le_bytes(event[5..13].try_into().unwrap()), ids[i]);
            assert_eq!(u32::from_le_bytes(event[13..17].try_into().unwrap()), 101);
            assert_eq!(
                u16::from_le_bytes(event[27..29].try_into().unwrap()),
                (i + 1) as u16
            );
            assert_eq!(u32::from_le_bytes(event[32..36].try_into().unwrap()), 100);
            assert!(event[36..].iter().all(|byte| *byte == 0));
        }
        for &i in &[COUNT - 1, 1, 2048] {
            assert_eq!(e.verdict(ids[i], Verdict::Drop, 101).unwrap().nbl, i + 1);
            assert!(e.verdict(ids[i], Verdict::PermanentAccept, 102).is_err());
        }
        let mut expired = 0;
        while let Some(action) = e.take_due(8100) {
            assert_eq!(action.finish, Finish::Drop);
            expired += 1;
        }
        assert_eq!(expired, COUNT - 3);
        assert_eq!(e.pending_count(), 0);
        assert!(e.pending.is_empty());
        assert!(e.events.is_empty());
        assert_eq!(e.stats().dropped, COUNT as u64);
    }

    #[test]
    fn large_unread_drains_unlink_nodes_but_finish_the_one_partial_frame() {
        const COUNT: usize = 4097;
        for mode in 0..4 {
            let mut e = default_engine();
            e.read(&mut [0; MAX_LOG_RECORD]);
            let mut p = packet();
            p.orient(NdisPath::Send);
            let mut prefix = [0; 3];
            for nbl in 0..COUNT {
                assert!(matches!(
                    e.submit(101, p, nbl, Some(42), 100, record(&p)),
                    Submission::Pending(_)
                ));
                if nbl == 0 {
                    assert_eq!(e.read(&mut prefix), 3);
                }
            }
            if mode == 2 {
                e.disconnect();
            }
            if mode == 3 {
                e.invalidate(101, true);
            }
            let mut seen = vec![false; COUNT];
            loop {
                let action = if mode == 1 {
                    e.cancel(101, 42)
                } else {
                    e.take_due(8100)
                };
                let Some(action) = action else { break };
                assert!(!seen[action.nbl]);
                seen[action.nbl] = true;
                assert_eq!(
                    action.finish,
                    if mode == 1 {
                        Finish::Cancel
                    } else {
                        Finish::Drop
                    }
                );
            }
            assert!(seen.into_iter().all(|seen| seen));
            assert_eq!(e.pending_count(), 0);
            assert_eq!(e.events.len(), usize::from(mode != 2));
            assert_eq!(e.pending.len(), usize::from(mode != 2));
            let mut tail = [0; 256];
            let n = e.read(&mut tail);
            assert_eq!(n, if mode == 2 { 0 } else { 133 });
            assert_eq!(prefix[0], 1);
            assert!(e.events.is_empty());
            assert!(e.pending.is_empty());
            assert_eq!(e.queued_bytes, 0);
        }
    }

    #[test]
    fn bandwidth_and_report_events_grow_without_splitting_groups() {
        const COUNT: usize = 1025;
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        for port in 1..=COUNT {
            let mut p = packet();
            p.flow.source_port = port as u16;
            p.flow.ipv6 = port % 2 == 0;
            p.connection.ipv6 = p.flow.ipv6;
            p.orient(NdisPath::Receive);
            let Submission::Pending(id) = e.submit(101, p, port, None, 100, record(&p)) else {
                panic!("expected a distinct tuple");
            };
            assert_eq!(
                e.read(&mut [0; 256]),
                connection_header_len(&p.connection) + 100
            );
            e.verdict(id, Verdict::Accept, 101).unwrap();
        }
        assert_eq!(e.bandwidth_count, COUNT);
        e.bandwidth();
        assert_eq!(e.bandwidth_count, 0);
        assert_eq!(e.events.len(), 2);
        let mut bytes = vec![0; COUNT * 66];
        let n = e.read(&mut bytes);
        let mut offset = 0;
        let mut records = 0;
        let mut seen = vec![false; COUNT];
        while offset < n {
            let event = &bytes[offset..];
            let size = 5 + u32::from_le_bytes(event[1..5].try_into().unwrap()) as usize;
            assert!(matches!(event[0], 5 | 6));
            let ipv6 = event[0] == 6;
            let count = u32::from_le_bytes(event[10..14].try_into().unwrap()) as usize;
            assert_eq!(count, if ipv6 { COUNT / 2 } else { COUNT.div_ceil(2) });
            assert_eq!(u32::from_le_bytes(event[6..10].try_into().unwrap()), 101);
            assert_eq!(event[5], 17);
            let entry_size = bandwidth_entry_len(ipv6);
            let address_size = if ipv6 { 16 } else { 4 };
            assert_eq!(size, BANDWIDTH_HEADER + count * entry_size);
            for entry in event[BANDWIDTH_HEADER..size].chunks_exact(entry_size) {
                let port =
                    u16::from_le_bytes(entry[address_size..address_size + 2].try_into().unwrap())
                        as usize;
                assert!((1..=COUNT).contains(&port));
                assert_eq!(port.is_multiple_of(2), ipv6);
                assert!(!seen[port - 1]);
                seen[port - 1] = true;
                assert_eq!(
                    u64::from_le_bytes(entry[entry_size - 16..entry_size - 8].try_into().unwrap()),
                    100
                );
                assert_eq!(
                    u64::from_le_bytes(entry[entry_size - 8..].try_into().unwrap()),
                    0
                );
            }
            offset += size;
            records += 1;
        }
        assert_eq!(offset, n);
        assert_eq!(records, 2);
        assert!(seen.into_iter().all(|seen| seen));
        assert!(e.events.is_empty());
    }

    #[test]
    fn bandwidth_table_reports_after_detach() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        for port in 1..=3 {
            let mut p = packet();
            p.connection.local_port = port;
            e.bandwidth_add(101, &p);
        }
        let mut table = BandwidthTable::new();
        assert!(e.begin_bandwidth(&mut table));
        assert_eq!(e.bandwidth_count, 0);
        let epoch = table.epoch();
        table.report(|data| match e.queue_bandwidth(epoch, data) {
            Ok(()) => true,
            Err(data) => {
                drop(data);
                false
            }
        });
        assert!(e.finish_bandwidth(&mut table));
        assert_eq!(e.bandwidth_count, 0);
        assert_eq!(e.events.len(), 1);
        let mut out = [0; 128];
        assert_eq!(
            e.read(&mut out),
            BANDWIDTH_HEADER + 3 * bandwidth_entry_len(false)
        );
    }

    fn bandwidth_rows(e: &mut Engine) -> Vec<(u32, u8, bool, u16, u64, u64)> {
        let mut out = vec![0; 4096];
        let len = e.read(&mut out);
        let mut offset = 0;
        let mut rows = Vec::new();
        while offset < len {
            let data = &out[offset..len];
            assert!(matches!(data[0], 5 | 6));
            let ipv6 = data[0] == 6;
            let record_len = 5 + u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
            let index = u32::from_le_bytes(data[6..10].try_into().unwrap());
            let count = u32::from_le_bytes(data[10..14].try_into().unwrap()) as usize;
            let size = bandwidth_entry_len(ipv6);
            assert_eq!(record_len, BANDWIDTH_HEADER + count * size);
            let address_size = if ipv6 { 16 } else { 4 };
            for entry in data[BANDWIDTH_HEADER..record_len].chunks_exact(size) {
                rows.push((
                    index,
                    data[5],
                    ipv6,
                    u16::from_le_bytes(entry[address_size..address_size + 2].try_into().unwrap()),
                    u64::from_le_bytes(entry[size - 16..size - 8].try_into().unwrap()),
                    u64::from_le_bytes(entry[size - 8..].try_into().unwrap()),
                ));
            }
            offset += record_len;
        }
        assert_eq!(offset, len);
        rows.sort_unstable();
        rows
    }

    #[test]
    fn matching_group_edges_do_not_hide_interleaved_counters() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut tcp = packet();
        tcp.connection.protocol = 6;
        tcp.connection.local_port = 11;
        let mut udp = packet();
        udp.connection.local_port = 22;
        let mut other_tcp = tcp;
        other_tcp.connection.local_port = 33;
        e.bandwidth_add(101, &tcp);
        e.bandwidth_add(101, &udp);
        e.bandwidth_add(101, &other_tcp);

        e.bandwidth();
        assert_eq!(
            bandwidth_rows(&mut e),
            [
                (101, 6, false, 11, 100, 0),
                (101, 6, false, 33, 100, 0),
                (101, 17, false, 22, 100, 0),
            ]
        );
        assert_eq!(e.bandwidth_count, 0);
    }

    #[test]
    fn rejected_single_group_keeps_all_counters_for_retry() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        e.bandwidth_add(101, &packet());
        let mut table = BandwidthTable::new();
        assert!(e.begin_bandwidth(&mut table));
        let before = table.store.bytes();
        table.report(|_| false);
        assert_eq!(table.store.bytes(), before);
        assert_eq!(table.store.len(), 1);
        assert!(e.finish_bandwidth(&mut table));
        e.bandwidth();
        assert_eq!(bandwidth_rows(&mut e), [(101, 17, false, 0, 100, 0)]);
    }

    #[test]
    fn reversed_two_groups_preserve_unqueued_counters() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut udp = packet();
        udp.connection.local_port = 11;
        let mut tcp = packet();
        tcp.connection.protocol = 6;
        tcp.connection.local_port = 22;
        let mut other_udp = udp;
        other_udp.connection.local_port = 33;
        e.bandwidth_add(101, &udp);
        e.bandwidth_add(101, &tcp);
        e.bandwidth_add(101, &other_udp);

        let mut table = BandwidthTable::new();
        assert!(e.begin_bandwidth(&mut table));
        let epoch = table.epoch();
        let mut groups = 0;
        table.report(|data| {
            groups += 1;
            groups == 1 && e.queue_bandwidth(epoch, data).is_ok()
        });
        assert_eq!(groups, 2);
        assert!(e.finish_bandwidth(&mut table));
        assert_eq!(bandwidth_rows(&mut e), [(101, 6, false, 22, 100, 0)]);
        e.bandwidth();
        assert_eq!(
            bandwidth_rows(&mut e),
            [(101, 17, false, 11, 100, 0), (101, 17, false, 33, 100, 0)]
        );
    }

    #[test]
    fn partial_three_group_report_keeps_every_unqueued_delta() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        for n in 0..9 {
            let mut p = packet();
            p.connection.local_port = n + 1;
            p.connection.protocol = if n % 3 == 2 { 17 } else { 6 };
            p.connection.ipv6 = n % 3 == 1;
            e.bandwidth_add(101, &p);
        }
        let mut table = BandwidthTable::new();
        assert!(e.begin_bandwidth(&mut table));
        let epoch = table.epoch();
        let mut groups = 0;
        table.report(|data| {
            groups += 1;
            groups == 1 && e.queue_bandwidth(epoch, data).is_ok()
        });
        assert_eq!(groups, 2);
        assert!(e.finish_bandwidth(&mut table));
        assert_eq!(
            bandwidth_rows(&mut e),
            [
                (101, 6, false, 1, 100, 0),
                (101, 6, false, 4, 100, 0),
                (101, 6, false, 7, 100, 0)
            ]
        );
        e.bandwidth();
        assert_eq!(
            bandwidth_rows(&mut e),
            [
                (101, 6, true, 2, 100, 0),
                (101, 6, true, 5, 100, 0),
                (101, 6, true, 8, 100, 0),
                (101, 17, false, 3, 100, 0),
                (101, 17, false, 6, 100, 0),
                (101, 17, false, 9, 100, 0),
            ]
        );
        assert_eq!(e.bandwidth_count, 0);
    }

    #[test]
    fn partial_bandwidth_report_retains_deltas_and_merges_concurrent_full_keys() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut tcp = packet();
        tcp.connection.protocol = 6;
        tcp.connection.local_port = 11;
        let mut udp = packet();
        udp.connection.local_port = 22;
        e.bandwidth_add(101, &tcp);
        e.bandwidth_add(101, &udp);
        let mut table = BandwidthTable::new();
        assert!(e.begin_bandwidth(&mut table));

        tcp.ip_len = 7;
        e.bandwidth_add(101, &tcp);
        udp.connection.direction = Direction::Inbound;
        udp.ip_len = 13;
        e.bandwidth_add(101, &udp);
        let mut new_udp = udp;
        new_udp.connection.local_port = 33;
        new_udp.ip_len = 19;
        e.bandwidth_add(101, &new_udp);

        let epoch = table.epoch();
        let mut groups = 0;
        table.report(|data| {
            groups += 1;
            if groups == 2 {
                return false;
            }
            e.queue_bandwidth(epoch, data).unwrap();
            true
        });
        assert_eq!(groups, 2);
        assert!(e.finish_bandwidth(&mut table));
        assert_eq!(bandwidth_rows(&mut e), [(101, 6, false, 11, 100, 0)]);
        // The retry bank can contain the same UDP key as new live traffic. It
        // must become one entry, not two rows or a lost/duplicated delta.
        e.bandwidth();
        assert_eq!(
            bandwidth_rows(&mut e),
            [
                (101, 6, false, 11, 7, 0),
                (101, 17, false, 22, 100, 13),
                (101, 17, false, 33, 0, 19),
            ]
        );
        assert_eq!(e.bandwidth_count, 0);
        e.bandwidth();
        assert!(!e.has_events());
    }

    #[test]
    fn partial_report_reclaims_sent_storage_before_retry() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut tcp = packet();
        tcp.connection.protocol = 6;
        for n in 0..512u32 {
            tcp.connection.remote_ip[..4].copy_from_slice(&n.to_le_bytes());
            e.bandwidth_add(101, &tcp);
        }
        let udp = packet();
        e.bandwidth_add(101, &udp);
        let before = e.bandwidth.bytes();
        let mut table = BandwidthTable::new();
        assert!(e.begin_bandwidth(&mut table));
        let epoch = table.epoch();
        let mut groups = 0;
        table.report(|data| {
            groups += 1;
            groups == 1 && e.queue_bandwidth(epoch, data).is_ok()
        });
        assert_eq!(groups, 2);
        assert!(e.finish_bandwidth(&mut table));
        assert_eq!(e.bandwidth_count, 1);
        assert!(e.retry_bandwidth.bytes() < before / 4);
        let mut output = vec![0; 20_000];
        assert!(e.read(&mut output) > 0);
        e.bandwidth();
        assert_eq!(bandwidth_rows(&mut e), [(101, 17, false, 0, 100, 0)]);
        assert_eq!(e.bandwidth_count, 0);
    }

    #[test]
    fn unused_prepared_bandwidth_work_does_not_publish_an_empty_bank() {
        let mut e = engine();
        let p = packet();
        let mut work = BandwidthWork::prepare(e.bandwidth_plan());
        assert!(e.preflight_with_work(101, &p, 1, 100, &mut work).unwrap());
        drop(work);
        assert_eq!(e.bandwidth_count, 0);
        assert!(!e.bandwidth.has_storage());
        e.bandwidth();
        assert!(!e.bandwidth.has_storage());
    }

    #[test]
    fn bandwidth_preparation_occurs_only_after_actual_accounting_needs_it() {
        let mut e = engine();
        let p = packet();
        e.configure(2000, 60000, true);
        let mut bandwidth = BandwidthWork::defer_missing();
        assert!(
            e.preflight_with_work(101, &p, 1, 100, &mut bandwidth)
                .unwrap()
        );
        assert!(!complete_deferred(&mut e, &mut bandwidth));
        let Submission::Pending(id) =
            e.submit_with_work(101, p, 1, None, 100, record(&p), &mut bandwidth)
        else {
            panic!("expected pending packet");
        };
        assert!(!complete_deferred(&mut e, &mut bandwidth));
        assert!(!e.bandwidth.has_storage());
        let mut cache = CacheWork::prepare(e.cache_plan(id, Verdict::PermanentAccept, 101));
        assert_eq!(
            e.verdict_with_work(
                id,
                Verdict::PermanentAccept,
                101,
                &mut cache,
                &mut bandwidth
            )
            .unwrap()
            .finish,
            Finish::Allow
        );
        assert_eq!(e.bandwidth_count, 0);
        assert!(complete_deferred(&mut e, &mut bandwidth));
        assert_eq!(e.bandwidth_count, 1);
        assert_eq!(
            e.preflight_with_work(101, &p, 2, 102, &mut bandwidth)
                .unwrap_err()
                .finish,
            Finish::Allow
        );
        assert!(!complete_deferred(&mut e, &mut bandwidth));
        e.bandwidth();
        assert_eq!(e.bandwidth_count, 0);
        assert_eq!(
            e.preflight_with_work(101, &p, 3, 103, &mut bandwidth)
                .unwrap_err()
                .finish,
            Finish::Allow
        );
        assert!(complete_deferred(&mut e, &mut bandwidth));
        assert_eq!(e.bandwidth_count, 1);
    }

    #[test]
    fn deferred_bandwidth_covers_fail_open_timeout_and_capture_failure() {
        let mut e = engine();
        let p = packet();
        let mut bandwidth = BandwidthWork::defer_missing();
        assert_eq!(
            e.submit_with_work(101, p, 1, None, 100, None, &mut bandwidth),
            Submission::Finish(Action {
                nbl: 1,
                finish: Finish::Allow
            })
        );
        assert!(complete_deferred(&mut e, &mut bandwidth));
        assert_eq!(e.bandwidth_count, 1);
        e.bandwidth();
        assert_eq!(e.bandwidth_count, 0);
        let Submission::Pending(_) =
            e.submit_with_work(101, p, 2, None, 100, record(&p), &mut bandwidth)
        else {
            panic!("expected pending packet");
        };
        assert!(!complete_deferred(&mut e, &mut bandwidth));
        assert!(e.take_due_with_work(2099, &mut bandwidth).is_none());
        assert_eq!(
            e.take_due_with_work(2100, &mut bandwidth).unwrap().finish,
            Finish::Allow
        );
        assert!(complete_deferred(&mut e, &mut bandwidth));
        assert_eq!(e.bandwidth_count, 1);
    }

    #[test]
    fn fail_open_accounts_when_pending_publication_fails() {
        for fail_event in [false, true] {
            let mut e = engine();
            e.events.fail_allocations = fail_event;
            e.pending.fail_allocations = !fail_event;
            let p = packet();
            let mut bandwidth = BandwidthWork::defer_missing();
            assert_eq!(
                e.submit_with_work(101, p, 1, None, 100, record(&p), &mut bandwidth),
                Submission::Finish(Action {
                    nbl: 1,
                    finish: Finish::Allow
                })
            );
            assert!(complete_deferred(&mut e, &mut bandwidth));
            assert_eq!(e.bandwidth_count, 1);
            assert_eq!(e.pending_count, 0);
        }
    }

    #[test]
    fn deferred_bandwidth_does_not_cross_a_session_reset() {
        let mut e = engine();
        let p = packet();
        let mut bandwidth = BandwidthWork::defer_missing();
        assert!(matches!(
            e.submit_with_work(101, p, 1, None, 100, None, &mut bandwidth),
            Submission::Finish(Action {
                finish: Finish::Allow,
                ..
            })
        ));
        e.disconnect();
        e.connect();
        assert!(complete_deferred(&mut e, &mut bandwidth));
        assert_eq!(e.bandwidth_count, 0);
        assert!(!e.bandwidth.has_storage());
    }

    #[test]
    fn concurrent_deferred_same_key_accounts_each_packet_once() {
        let mut e = engine();
        let p = packet();
        let mut first = BandwidthWork::defer_missing();
        let mut second = BandwidthWork::defer_missing();
        for work in [&mut first, &mut second] {
            assert!(matches!(
                e.submit_with_work(101, p, 1, None, 100, None, work),
                Submission::Finish(Action {
                    finish: Finish::Allow,
                    ..
                })
            ));
        }
        assert!(complete_deferred(&mut e, &mut first));
        assert!(complete_deferred(&mut e, &mut second));
        assert_eq!(e.bandwidth_count, 1);
        e.read(&mut [0; MAX_LOG_RECORD]);
        e.bandwidth();
        assert_eq!(bandwidth_rows(&mut e), [(101, 17, false, 0, 200, 0)]);
    }

    #[test]
    fn bandwidth_queue_rejection_keeps_every_delta_for_a_later_report() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let p = packet();
        e.bandwidth_add(101, &p);
        e.events.fail_allocations = true;
        e.bandwidth();
        assert!(!e.has_events());
        assert_eq!(e.bandwidth_count, 1);
        e.bandwidth(); // Repeated failure must neither lose nor duplicate deltas.
        assert_eq!(e.bandwidth_count, 1);
        e.events.fail_allocations = false;
        e.bandwidth();
        assert_eq!(bandwidth_rows(&mut e), [(101, 17, false, 0, 100, 0)]);
        assert_eq!(e.bandwidth_count, 0);
    }

    #[test]
    fn detached_bandwidth_cannot_cross_a_controller_session_reset() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut p = packet();
        e.bandwidth_add(101, &p);
        let mut table = BandwidthTable::new();
        assert!(e.begin_bandwidth(&mut table));
        let old_epoch = table.epoch();
        e.disconnect();
        e.connect();
        e.read(&mut [0; MAX_LOG_RECORD]);
        p.ip_len = 17;
        e.bandwidth_add(101, &p);
        let mut attempted = false;
        table.report(|data| {
            attempted = true;
            assert!(e.queue_bandwidth(old_epoch, data).is_err());
            false
        });
        assert!(attempted);
        assert!(!e.finish_bandwidth(&mut table));
        e.bandwidth();
        assert_eq!(bandwidth_rows(&mut e), [(101, 17, false, 0, 17, 0)]);
    }

    #[test]
    fn bandwidth_queues_the_entire_large_group_without_count_caps_or_splitting() {
        const COUNT: usize = 40000;
        for ipv6 in [false, true] {
            let mut e = engine();
            e.read(&mut [0; MAX_LOG_RECORD]);
            for port in 1..=COUNT {
                let mut p = packet();
                p.connection.ipv6 = ipv6;
                p.connection.local_port = port as u16;
                e.bandwidth_add(101, &p);
            }
            assert_eq!(e.bandwidth_count, COUNT);
            e.bandwidth();
            assert_eq!(e.bandwidth_count, 0);
            assert_eq!(e.events.len(), 1);
            // Successfully queued reports release their detached nodes after
            // serialization, so no large list is retired under the policy lock.
            assert!(!e.retired_bandwidth.has_storage());
            while let Some(retired) = e.take_retired_storage() {
                drop(retired);
            }
            let len = bandwidth_record_len(ipv6, COUNT).unwrap();
            assert!(len > MAX_RECORD);
            let mut out = vec![0; len];
            assert_eq!(e.read(&mut out), len);
            assert_eq!(out[0], if ipv6 { 6 } else { 5 });
            assert_eq!(
                u32::from_le_bytes(out[1..5].try_into().unwrap()) as usize,
                len - 5
            );
            assert_eq!(out[5], 17);
            assert_eq!(u32::from_le_bytes(out[6..10].try_into().unwrap()), 101);
            assert_eq!(
                u32::from_le_bytes(out[10..14].try_into().unwrap()) as usize,
                COUNT
            );
            let entry_size = bandwidth_entry_len(ipv6);
            let address_size = if ipv6 { 16 } else { 4 };
            let mut seen = vec![false; COUNT];
            for entry in out[BANDWIDTH_HEADER..].chunks_exact(entry_size) {
                let port =
                    u16::from_le_bytes(entry[address_size..address_size + 2].try_into().unwrap())
                        as usize;
                assert!((1..=COUNT).contains(&port));
                assert!(!seen[port - 1]);
                seen[port - 1] = true;
                assert_eq!(
                    u64::from_le_bytes(entry[entry_size - 16..entry_size - 8].try_into().unwrap()),
                    100
                );
                assert_eq!(
                    u64::from_le_bytes(entry[entry_size - 8..].try_into().unwrap()),
                    0
                );
            }
            assert!(seen.into_iter().all(|seen| seen));
            e.bandwidth();
            assert!(!e.has_events());
        }
    }

    #[test]
    fn metadata_allocation_failure_uses_fallback_without_publishing_or_losing_a_token() {
        for fail_closed in [false, true] {
            for fail_pending in [false, true] {
                let mut e = default_engine();
                e.configure(8000, 60000, fail_closed);
                e.read(&mut [0; MAX_LOG_RECORD]);
                e.pending.fail_allocations = fail_pending;
                e.events.fail_allocations = !fail_pending;
                let p = packet();
                assert_eq!(
                    e.submit(101, p, 7, None, 100, record(&p)),
                    Submission::Finish(Action {
                        nbl: 7,
                        finish: if fail_closed {
                            Finish::Drop
                        } else {
                            Finish::Allow
                        },
                    })
                );
                assert_eq!(e.pending_count(), 0);
                assert!(e.pending.is_empty());
                assert!(!e.has_events());
                assert_eq!(e.queued_bytes, 0);
                assert_eq!(e.stats().overflow, 1);
                assert!(e.take_due(u64::MAX).is_none());
                e.pending.fail_allocations = false;
                e.events.fail_allocations = false;
                let id = submit(&mut e, 101, 8);
                assert_eq!(id, 1);
                assert_eq!(e.verdict(id, Verdict::Drop, 101).unwrap().nbl, 8);
                e.read(&mut [0; 256]);
                assert!(e.pending.is_empty());
            }
        }
    }

    #[test]
    fn bandwidth_separates_interfaces_protocols_and_families_but_not_directions() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        // 101 and 357 also exercise identical low hash bits for the same tuple.
        for index in [357, u32::MAX] {
            assert!(e.attach(index));
            assert!(e.restart(index));
        }
        let mut expected = Vec::new();
        for (ordinal, interface_index) in [101, 357, u32::MAX].into_iter().enumerate() {
            for protocol in [6, 17] {
                for ipv6 in [false, true] {
                    let tx = ((ordinal as u64 + 1) << 32) + 123;
                    let rx = tx + 456;
                    for (direction, bytes) in [(Direction::Outbound, tx), (Direction::Inbound, rx)]
                    {
                        let mut p = packet();
                        p.connection.protocol = protocol;
                        p.flow.protocol = protocol;
                        p.connection.ipv6 = ipv6;
                        p.flow.ipv6 = ipv6;
                        p.connection.direction = direction;
                        p.ip_len = bytes;
                        let Submission::Pending(id) =
                            e.submit(interface_index, p, 1, None, 100, record(&p))
                        else {
                            panic!("expected an uncached packet");
                        };
                        assert_eq!(
                            e.verdict(id, Verdict::Accept, 101).unwrap().finish,
                            Finish::Allow
                        );
                    }
                    expected.push((interface_index, protocol, ipv6, tx, rx));
                }
            }
        }
        assert_eq!(e.bandwidth_count, expected.len());
        e.bandwidth();
        assert_eq!(e.bandwidth_count, 0);
        let mut out = vec![0; expected.len() * 66];
        let n = e.read(&mut out);
        let mut offset = 0;
        let mut seen = vec![false; expected.len()];
        while offset < n {
            let event = &out[offset..];
            let ipv6 = event[0] == 6;
            assert!(matches!(event[0], 5 | 6));
            let len = if ipv6 { 66 } else { 42 };
            assert_eq!(
                u32::from_le_bytes(event[1..5].try_into().unwrap()) as usize,
                len - 5
            );
            assert_eq!(u32::from_le_bytes(event[10..14].try_into().unwrap()), 1);
            let index = u32::from_le_bytes(event[6..10].try_into().unwrap());
            let i = expected
                .iter()
                .position(|&(iface, protocol, family, _, _)| {
                    (iface, protocol, family) == (index, event[5], ipv6)
                })
                .expect("unexpected bandwidth key");
            assert!(!seen[i]);
            seen[i] = true;
            assert_eq!(
                u64::from_le_bytes(event[len - 16..len - 8].try_into().unwrap()),
                expected[i].3
            );
            assert_eq!(
                u64::from_le_bytes(event[len - 8..len].try_into().unwrap()),
                expected[i].4
            );
            offset += len;
        }
        assert_eq!(offset, n);
        assert!(seen.into_iter().all(|seen| seen));
        e.bandwidth();
        assert!(!e.has_events());
        // Successfully queued reports reset only their deltas.
        let mut p = packet();
        p.ip_len = 33;
        let Submission::Pending(id) = e.submit(357, p, 1, None, 100, record(&p)) else {
            panic!()
        };
        e.verdict(id, Verdict::Accept, 101).unwrap();
        e.bandwidth();
        assert_eq!(e.read(&mut out), 42);
        assert_eq!(u32::from_le_bytes(out[6..10].try_into().unwrap()), 357);
        assert_eq!(u64::from_le_bytes(out[26..34].try_into().unwrap()), 33);
        assert_eq!(u64::from_le_bytes(out[34..42].try_into().unwrap()), 0);
    }

    #[test]
    fn bandwidth_keeps_the_interface_on_cached_allows_and_fail_open_fallbacks() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        assert!(e.attach(357));
        assert!(e.restart(357));
        for interface_index in [101, 357] {
            let id = submit(&mut e, interface_index, 1);
            e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
            let mut p = packet();
            p.connection.direction = Direction::Inbound;
            p.ip_len = 75;
            assert_eq!(
                e.preflight(interface_index, &p, 2, 102).unwrap_err().finish,
                Finish::Allow
            );
            p.connection.direction = Direction::Outbound;
            p.cacheable = false;
            p.ip_len = 125;
            assert_eq!(
                e.submit(interface_index, p, 3, None, 103, None),
                Submission::Finish(Action {
                    nbl: 3,
                    finish: Finish::Allow
                })
            );
            p.ip_len = 150;
            assert!(matches!(
                e.submit(interface_index, p, 4, None, 104, record(&p)),
                Submission::Pending(_)
            ));
            assert_eq!(
                e.take_due(2104),
                Some(Action {
                    nbl: 4,
                    finish: Finish::Allow
                })
            );
        }
        assert_eq!(e.stats().cache_hits, 2);
        assert_eq!(e.stats().overflow, 2);
        assert_eq!(e.stats().timeouts, 2);
        assert_eq!(e.bandwidth_count, 2);
        e.bandwidth();
        let mut out = [0; 128];
        assert_eq!(e.read(&mut out), 84);
        let mut indices = [0; 2];
        for (i, event) in out[..84].as_chunks::<42>().0.iter().enumerate() {
            indices[i] = u32::from_le_bytes(event[6..10].try_into().unwrap());
            assert_eq!(u64::from_le_bytes(event[26..34].try_into().unwrap()), 375);
            assert_eq!(u64::from_le_bytes(event[34..42].try_into().unwrap()), 75);
        }
        indices.sort_unstable();
        assert_eq!(indices, [101, 357]);
    }

    #[test]
    fn bandwidth_oom_does_not_change_a_verdict_or_cached_allow() {
        let mut e = engine();
        let id = submit(&mut e, 101, 1);
        e.bandwidth.fail_allocations = true;
        assert_eq!(
            e.verdict(id, Verdict::PermanentAccept, 101).unwrap().finish,
            Finish::Allow
        );
        assert_eq!(
            e.preflight(101, &packet(), 2, 102),
            Err(Action {
                nbl: 2,
                finish: Finish::Allow
            })
        );
        assert_eq!(e.stats().overflow, 2);
        assert_eq!(e.stats().cache_hits, 1);
        assert!(e.bandwidth_count == 0);
        e.bandwidth.fail_allocations = false;
        assert!(e.preflight(101, &packet(), 3, 103).is_err());
        assert_eq!(e.bandwidth_count, 1);
    }

    #[test]
    fn interface_oom_rejects_only_that_attach_and_cleanup_covers_more_than_one_word() {
        let mut e = Box::new(Engine::new());
        e.interfaces.fail_allocations = true;
        assert!(!e.attach(101));
        assert!(!e.restart(101));
        assert!(e.interfaces.is_empty());
        e.interfaces.fail_allocations = false;
        e.connect();
        e.read(&mut [0; MAX_LOG_RECORD]);
        for index in (1..=129).chain([u32::MAX]) {
            assert!(e.attach(index));
            assert!(e.restart(index));
            let id = submit(&mut e, index, index as usize);
            e.verdict(id, Verdict::PermanentDrop, 101).unwrap();
        }
        assert_eq!(e.cache_candidates(), 130);
        let limit = e.cache_cleanup_limit();
        assert_eq!(limit, u32::MAX);
        let mut after = 0;
        let mut visited = 0;
        while let Some((index, slots)) = e.next_cache_candidate(after, limit) {
            after = index;
            for start in (0..slots).step_by(crate::cache::CLEANUP_SLOTS_PER_BATCH) {
                let mut work = CacheWork::empty();
                e.clean_range_with_work(index, start, 60101, &mut work);
            }
            visited += 1;
        }
        assert_eq!(visited, 130);
        assert_eq!(e.cache_candidates(), 0);
        assert_eq!(e.cache_bytes(), 0);
        assert!(e.next_cache_candidate(after, limit).is_none());
        for index in (1..=129).chain([u32::MAX]) {
            e.detach(index);
        }
        assert!(e.interfaces.is_empty());
        e.read(&mut [0; 256]);
        assert!(e.pending.is_empty());
    }

    #[test]
    fn cleared_event_and_bandwidth_chains_retire_without_bulk_locked_destruction() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        for port in 1..=2049 {
            let mut p = packet();
            p.flow.source_port = port;
            p.orient(NdisPath::Receive);
            let Submission::Pending(id) = e.submit(101, p, port as usize, None, 100, record(&p))
            else {
                panic!();
            };
            e.read(&mut [0; 256]);
            e.verdict(id, Verdict::Accept, 101).unwrap();
            e.log(3, "queued diagnostic");
        }
        assert_eq!(e.bandwidth_count, 2049);
        e.disconnect();
        assert!(!e.has_events());
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.bandwidth_count, 0);
        assert!(!e.retired_events.is_empty());
        assert!(e.retired_bandwidth.has_storage());
        // A second reset appends to the retired chain rather than destroying it.
        e.connect();
        e.disconnect();
        assert_eq!(e.retired_events.len(), 2);
        let mut banks = 0;
        while let Some(storage) = e.take_retired_storage() {
            drop(storage); // Driver performs the same drop after hv_unlock().
            banks += 1;
        }
        assert!(banks > 1);
        assert!(e.retired_events.is_empty());
        assert!(!e.retired_bandwidth.has_storage());
        assert!(core::mem::size_of::<RetiredStorage>() < 128);
    }

    #[test]
    fn default_pending_deadline_is_eight_seconds_and_drops_unanswered_packets() {
        let mut e = default_engine();
        let id = submit(&mut e, 101, 1);
        assert!(e.take_due(2100).is_none());
        assert!(e.take_due(8099).is_none());
        assert!(e.verdict(id, Verdict::PermanentAccept, 8100).is_err());
        assert!(e.cache_plan(id, Verdict::PermanentAccept, 8100).is_none());
        assert_eq!(
            e.take_due(8100),
            Some(Action {
                nbl: 1,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.cache_counts(), (0, 0));
        assert_eq!(e.stats().timeouts, 1);
    }

    #[test]
    fn default_fallback_drops_ip_traffic_without_a_controller() {
        let mut e = Box::new(Engine::new());
        assert_eq!(e.fallback(), Finish::Drop);
        assert!(e.attach(101));
        assert!(e.restart(101));
        for ipv6 in [false, true] {
            for protocol in [1, 6, 17, 58] {
                for path in [NdisPath::Send, NdisPath::Receive] {
                    let mut p = packet();
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    p.orient(path);
                    assert!(!e.wants_event(101, &p, 100));
                    assert_eq!(
                        e.preflight(101, &p, 1, 100),
                        Err(Action {
                            nbl: 1,
                            finish: Finish::Drop
                        })
                    );
                    assert_eq!(
                        e.submit(101, p, 2, None, 100, None),
                        Submission::Finish(Action {
                            nbl: 2,
                            finish: Finish::Drop
                        })
                    );
                }
            }
        }
        assert_eq!(e.pending_count(), 0);
        assert!(!e.has_events());
        assert_eq!(e.stats().allowed, 0);
    }

    #[test]
    fn default_disconnect_drops_pending_and_clears_prior_allow_cache() {
        let mut e = default_engine();
        let id = submit(&mut e, 101, 1);
        e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
        assert_eq!(
            e.preflight(101, &packet(), 1, 102),
            Err(Action {
                nbl: 1,
                finish: Finish::Allow
            })
        );
        let mut p = packet();
        p.flow.source_port = 12345;
        p.orient(NdisPath::Receive);
        let Submission::Pending(pending) = e.submit(101, p, 2, None, 102, record(&p)) else {
            panic!()
        };
        e.disconnect();
        assert_eq!(e.cache_counts(), (0, 0));
        assert!(!e.has_events());
        assert!(e.verdict(pending, Verdict::PermanentAccept, 103).is_err());
        assert_eq!(
            e.take_due(103),
            Some(Action {
                nbl: 2,
                finish: Finish::Drop
            })
        );
        assert_eq!(
            e.submit(101, packet(), 3, None, 103, None),
            Submission::Finish(Action {
                nbl: 3,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.pending_count(), 0);
        e.connect();
        assert!(e.wants_event(101, &packet(), 104));
    }

    #[test]
    fn default_capture_failure_drops_but_queue_grows_past_16_mib() {
        let mut e = default_engine();
        assert_eq!(
            e.submit(101, packet(), 999, None, 100, None),
            Submission::Finish(Action {
                nbl: 999,
                finish: Finish::Drop
            })
        );
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut p = packet();
        p.payload_len = MAX_PAYLOAD as u32;
        const COUNT: usize = 32;
        for nbl in 1..=COUNT {
            assert!(matches!(
                e.submit(101, p, nbl, None, 100, record(&p)),
                Submission::Pending(_)
            ));
        }
        assert!(e.queued_bytes > 16 * 1024 * 1024);
        assert_eq!(e.pending_count(), COUNT);
        let mut count = 0;
        while let Some(action) = e.take_due(8100) {
            assert_eq!(action.finish, Finish::Drop);
            count += 1;
        }
        assert_eq!(count, COUNT);
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.queued_bytes, 0);
        assert_eq!(e.stats().overflow, 1);
        assert_eq!(e.stats().allowed, 0);
        assert_eq!(e.stats().dropped, COUNT as u64 + 1);
    }

    #[test]
    fn default_fail_closed_applies_timely_userspace_verdicts() {
        for verdict in [
            Verdict::Accept,
            Verdict::PermanentAccept,
            Verdict::Block,
            Verdict::PermanentBlock,
            Verdict::Drop,
            Verdict::PermanentDrop,
        ] {
            let mut e = default_engine();
            assert_eq!(e.fallback(), Finish::Drop);
            let id = submit(&mut e, 101, 1);
            assert_eq!(
                e.verdict(id, verdict, 8099),
                Ok(Action {
                    nbl: 1,
                    finish: if verdict.allows() {
                        Finish::Allow
                    } else {
                        Finish::Drop
                    },
                })
            );
            assert_eq!(e.pending_count(), 0);
            if verdict.permanent() {
                assert_eq!(
                    e.preflight(101, &packet(), 2, 8100),
                    Err(Action {
                        nbl: 2,
                        finish: if verdict.allows() {
                            Finish::Allow
                        } else {
                            Finish::Drop
                        },
                    })
                );
            } else {
                assert!(e.wants_event(101, &packet(), 8100));
            }
        }
    }

    #[test]
    fn fail_open_requires_an_explicit_configuration_override() {
        let mut e = default_engine();
        assert_eq!(e.fallback(), Finish::Drop);
        e.configure(8000, 60000, false);
        assert_eq!(e.fallback(), Finish::Allow);
        let id = submit(&mut e, 101, 1);
        assert_eq!(
            e.take_due(8100),
            Some(Action {
                nbl: 1,
                finish: Finish::Allow
            })
        );
        assert!(e.verdict(id, Verdict::PermanentAccept, 8100).is_err());
        submit(&mut e, 101, 2);
        e.disconnect();
        assert_eq!(
            e.take_due(101),
            Some(Action {
                nbl: 2,
                finish: Finish::Allow
            })
        );
        assert_eq!(
            e.submit(101, packet(), 3, None, 102, None),
            Submission::Finish(Action {
                nbl: 3,
                finish: Finish::Allow
            })
        );
        assert_eq!(e.cache_counts(), (0, 0));
    }

    #[test]
    fn one_cleanup_run_scans_all_interfaces_protocols_and_families() {
        let mut e = engine();
        assert!(e.attach(102));
        assert!(e.restart(102));
        for interface_index in [101, 102] {
            for protocol in [6, 17] {
                for ipv6 in [false, true] {
                    for port in 0..1025 {
                        let mut p = packet();
                        p.flow.protocol = protocol;
                        p.connection.protocol = protocol;
                        p.flow.ipv6 = ipv6;
                        p.connection.ipv6 = ipv6;
                        p.flow.source_port = port;
                        p.orient(NdisPath::Receive);
                        let Submission::Pending(id) =
                            e.submit(interface_index, p, 1, None, 100, record(&p))
                        else {
                            panic!()
                        };
                        e.verdict(id, Verdict::PermanentDrop, 101).unwrap();
                        e.read(&mut [0; 512]);
                    }
                }
            }
        }
        assert_eq!(e.cache_candidates(), 2);
        let mut batches = 0;
        let limit = e.cache_cleanup_limit();
        let mut after = 0;
        while let Some((index, slots)) = e.next_cache_candidate(after, limit) {
            after = index;
            assert_eq!(slots, e.cache_cleanup_slots(index));
            assert!(slots > crate::cache::CLEANUP_SLOTS_PER_BATCH);
            for start in (0..slots).step_by(crate::cache::CLEANUP_SLOTS_PER_BATCH) {
                let mut work = CacheWork::empty();
                let active = e.clean_range_with_work(index, start, 60101, &mut work);
                drop(work);
                batches += 1;
                if !active {
                    break;
                }
            }
        }
        assert!(batches > 2);
        assert_eq!(e.cache_candidates(), 0);
        assert_eq!(e.cache_counts(), (0, 0));
        assert_eq!(e.cache_bytes(), 0);
        assert_eq!(e.cache_cleanup_slots(u32::MAX), 0);
        assert!(!e.clean_range_with_work(u32::MAX, 0, 60101, &mut CacheWork::empty()));
    }

    #[test]
    fn pending_candidates_follow_verdict_timeout_cancel_and_invalidation() {
        let mut e = engine();
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.cache_candidates(), 0);
        assert!(e.take_due(u64::MAX).is_none());
        let first = submit(&mut e, 101, 1);
        let second = submit(&mut e, 101, 2);
        assert_eq!(e.pending_count(), 2);
        e.verdict(first, Verdict::Accept, 101).unwrap();
        assert_eq!(e.pending_count(), 1);
        assert!(e.verdict(first, Verdict::Accept, 101).is_err());
        assert!(e.take_due(2099).is_none());
        assert_eq!(e.take_due(2100).unwrap().nbl, 2);
        assert_eq!(e.pending_count(), 0);
        assert!(e.verdict(second, Verdict::Accept, 2100).is_err());
        assert!(e.take_due(u64::MAX).is_none());
        let p = packet();
        assert!(matches!(
            e.submit(101, p, 3, Some(42), 100, record(&p)),
            Submission::Pending(_)
        ));
        assert_eq!(e.cancel(101, 42).unwrap().finish, Finish::Cancel);
        assert_eq!(e.pending_count(), 0);
        submit(&mut e, 101, 4);
        assert!(e.cancel(101, 42).is_none());
        assert_eq!(e.pending_count(), 1);
        e.invalidate(101, true);
        assert_eq!(e.take_due(101).unwrap().finish, Finish::Drop);
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.cache_candidates(), 0);
    }

    #[test]
    fn cache_candidates_track_nonempty_interfaces_and_expiry() {
        let mut e = engine();
        e.configure(2000, 1000, false);
        assert!(e.attach(102));
        assert!(e.restart(102));
        for interface_index in [101, 102] {
            let id = submit(&mut e, interface_index, interface_index as usize);
            e.verdict(id, Verdict::PermanentDrop, 101).unwrap();
        }
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.cache_candidates(), 2);
        e.invalidate(101, true);
        assert_eq!(e.cache_candidates(), 1);
        e.clean(1101);
        assert_eq!(e.cache_candidates(), 0);
        assert_eq!(e.cache_counts(), (0, 0));
        assert_eq!(e.cache_bytes(), 0);
        e.clean(u64::MAX);
        assert_eq!(e.cache_candidates(), 0);
    }

    #[test]
    fn pending_timeout_does_not_sweep_cache_entries() {
        let mut e = engine();
        e.configure(2000, 1000, false);
        let k = 101;
        let id = submit(&mut e, k, 1);
        e.verdict(id, Verdict::PermanentDrop, 101).unwrap();
        let mut p = packet();
        p.flow.source_port = 123;
        p.orient(NdisPath::Receive);
        let other = k;
        assert!(matches!(
            e.submit(other, p, 2, None, 100, record(&p)),
            Submission::Pending(_)
        ));
        assert_eq!(e.take_due(3000).unwrap().nbl, 2);
        assert!(e.take_due(3000).is_none());
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.cache_counts(), (1, 0));
        assert_ne!(e.cache_candidates(), 0);
        for _ in 0..4 {
            e.clean(3000);
        }
        assert_eq!(e.cache_candidates(), 0);
    }

    #[test]
    fn missing_cache_preparation_retries_and_session_reset_disables_candidates() {
        let mut e = engine();
        let k = 101;
        let id = submit(&mut e, k, 1);
        let mut bandwidth = BandwidthWork::prepare(e.bandwidth_plan());
        assert_eq!(
            e.verdict_with_work(
                id,
                Verdict::PermanentAccept,
                101,
                &mut CacheWork::empty(),
                &mut bandwidth,
            ),
            Err(VerdictError::RetryCache)
        );
        assert_eq!(e.pending_count(), 1);
        assert_eq!(e.cache_candidates(), 0);
        assert_eq!(e.stats().cache_allocation_failures, 0);
        e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
        assert_ne!(e.cache_candidates(), 0);
        e.clear_cache();
        assert_eq!(e.cache_candidates(), 0);
        let id = submit(&mut e, k, 3);
        e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
        assert_ne!(e.cache_candidates(), 0);
        e.disconnect();
        assert_eq!(e.cache_candidates(), 0);
        e.connect();
        assert_eq!(e.cache_candidates(), 0);
    }

    #[test]
    fn new_forward_verdict_waits_for_paused_interface_cache_retirement() {
        for ipv6 in [false, true] {
            for protocol in [6, 17] {
                for verdict in [
                    Verdict::PermanentAccept,
                    Verdict::PermanentBlock,
                    Verdict::PermanentDrop,
                ] {
                    let mut e = engine();
                    assert!(e.ensure_forward(101));
                    let old = cache_packet(ipv6, protocol, 1000);
                    let Submission::Pending(id) = e.submit(101, old, 1, None, 100, record(&old))
                    else {
                        panic!("expected old pending packet");
                    };
                    e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
                    e.invalidate(101, true);

                    let new = cache_packet(ipv6, protocol, 2000);
                    let mut bandwidth = BandwidthWork::prepare(e.bandwidth_plan());
                    let Submission::Pending(id) =
                        e.submit_forward_with_work(101, new, 2, 102, record(&new), &mut bandwidth)
                    else {
                        panic!("new forward packet must be pending");
                    };
                    let mut work = CacheWork::prepare(e.cache_plan(id, verdict, 103));
                    assert_eq!(
                        e.verdict_with_work(id, verdict, 103, &mut work, &mut bandwidth),
                        Err(VerdictError::RetryCache)
                    );
                    assert_eq!(e.pending_count(), 1);
                    assert_eq!(e.stats().cache_allocation_failures, 0);
                    drop(work);

                    drop(e.take_retired_caches().expect("old cache must be retired"));
                    let mut work = CacheWork::prepare(e.cache_plan(id, verdict, 104));
                    let action = e
                        .verdict_with_work(id, verdict, 104, &mut work, &mut bandwidth)
                        .unwrap();
                    let finish = if verdict.allows() {
                        Finish::Allow
                    } else {
                        Finish::Drop
                    };
                    assert_eq!(action, Action { nbl: 2, finish });
                    assert_eq!(e.pending_count(), 0);
                    assert_eq!(
                        e.preflight(101, &new, 3, 105),
                        Err(Action { nbl: 3, finish })
                    );
                }
            }
        }
    }

    #[test]
    fn verdict_replans_when_expiry_cleanup_retires_the_table() {
        for ipv6 in [false, true] {
            for protocol in [6, 17] {
                for verdict in [
                    Verdict::PermanentAccept,
                    Verdict::PermanentBlock,
                    Verdict::PermanentDrop,
                ] {
                    let mut e = engine();
                    e.configure(8000, 1000, true);
                    let old = cache_packet(ipv6, protocol, 1000);
                    let Submission::Pending(id) = e.submit(101, old, 1, None, 100, record(&old))
                    else {
                        panic!("expected old pending packet");
                    };
                    e.verdict(id, Verdict::PermanentAccept, 101).unwrap();

                    let new = cache_packet(ipv6, protocol, 2000);
                    let Submission::Pending(id) = e.submit(101, new, 2, None, 10099, record(&new))
                    else {
                        panic!("new packet must be pending");
                    };
                    // There is room when the verdict is planned. The normal
                    // expiry worker can retire that table before it is applied.
                    let plan = e.cache_plan(id, verdict, 10100);
                    assert!(plan.is_none());
                    let mut work = CacheWork::prepare(plan);
                    e.clean(10101);
                    let mut bandwidth = BandwidthWork::prepare(e.bandwidth_plan());
                    assert_eq!(
                        e.verdict_with_work(id, verdict, 10102, &mut work, &mut bandwidth),
                        Err(VerdictError::RetryCache)
                    );
                    assert_eq!(e.pending_count(), 1);
                    assert_eq!(e.stats().cache_allocation_failures, 0);
                    drop(work);

                    let mut work = CacheWork::prepare(e.cache_plan(id, verdict, 10103));
                    let action = e
                        .verdict_with_work(id, verdict, 10103, &mut work, &mut bandwidth)
                        .unwrap();
                    let finish = if verdict.allows() {
                        Finish::Allow
                    } else {
                        Finish::Drop
                    };
                    assert_eq!(action, Action { nbl: 2, finish });
                    assert_eq!(e.pending_count(), 0);
                    assert_eq!(
                        e.preflight(101, &new, 3, 10104),
                        Err(Action { nbl: 3, finish })
                    );
                }
            }
        }
    }

    #[test]
    fn retry_rechecks_cancellation_invalidation_and_deadline() {
        for scenario in 0..3 {
            let mut e = engine();
            let p = cache_packet(false, 17, 2000);
            let Submission::Pending(id) = e.submit(101, p, 1, Some(44), 100, record(&p)) else {
                panic!("expected pending packet");
            };
            let mut bandwidth = BandwidthWork::prepare(e.bandwidth_plan());
            assert_eq!(
                e.verdict_with_work(
                    id,
                    Verdict::PermanentAccept,
                    101,
                    &mut CacheWork::empty(),
                    &mut bandwidth,
                ),
                Err(VerdictError::RetryCache)
            );
            assert_eq!(e.pending_count(), 1);
            let now = match scenario {
                0 => {
                    assert_eq!(e.cancel(101, 44).unwrap().finish, Finish::Cancel);
                    102
                }
                1 => {
                    e.invalidate(101, true);
                    assert!(e.restart(101));
                    102
                }
                _ => 2100,
            };
            let mut work = CacheWork::prepare(e.cache_plan(id, Verdict::PermanentAccept, now));
            assert_eq!(
                e.verdict_with_work(id, Verdict::PermanentAccept, now, &mut work, &mut bandwidth,),
                Err(VerdictError::NotFound)
            );
            if scenario != 0 {
                assert!(e.take_due(now).is_some());
            }
            assert_eq!(e.pending_count(), 0);
            assert_eq!(e.cache_candidates(), 0);
        }
    }

    #[test]
    fn connection_indices_follow_each_interface_across_paths_and_slot_reuse() {
        let mut e = engine();
        e.read(&mut [0; 512]);
        assert!(e.attach(0x12345678));
        assert!(e.restart(0x12345678));
        let mut previous_id = 0;
        for interface_index in [101, 0x12345678, 101, 0x87654321, 0x12345678] {
            if interface_index == 0x87654321 {
                e.detach(101);
                assert!(e.attach(interface_index));
                assert!(e.restart(interface_index));
            }
            for ipv6 in [false, true] {
                for path in [NdisPath::Send, NdisPath::Receive] {
                    let mut p = packet();
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.orient(path);
                    let nbl = interface_index as usize;
                    let Submission::Pending(id) =
                        e.submit(interface_index, p, nbl, None, 100, record(&p))
                    else {
                        panic!("each interface must produce its own event");
                    };
                    assert!(id > previous_id);
                    previous_id = id;
                    let mut bytes = [0; 256];
                    let n = e.read(&mut bytes);
                    assert_eq!(
                        n,
                        connection_header_len(&p.connection) + p.payload_len as usize
                    );
                    assert_eq!(bytes[0], if ipv6 { 2 } else { 1 });
                    assert_eq!(u64::from_le_bytes(bytes[5..13].try_into().unwrap()), id);
                    assert_eq!(
                        u32::from_le_bytes(bytes[13..17].try_into().unwrap()),
                        interface_index
                    );
                    assert_eq!(bytes[17], path.direction() as u8);
                    assert_eq!(e.verdict(id, Verdict::Accept, 101).unwrap().nbl, nbl);
                }
            }
        }
    }

    #[test]
    fn permanent_cache_isolates_interface_protocol_and_family_not_direction_or_l2() {
        let mut e = engine();
        assert!(e.attach(102));
        assert!(e.restart(102));
        for interface_index in [101, 102] {
            for ipv6 in [false, true] {
                for protocol in [6, 17] {
                    let mut p = packet();
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.flow.source[0] = 10;
                    p.flow.destination[0] = 20;
                    p.flow.source_port = 12345;
                    p.flow.destination_port = 443;
                    p.orient(NdisPath::Receive);
                    let allow = (interface_index == 101) ^ ipv6 ^ (protocol == 6);
                    let Submission::Pending(id) =
                        e.submit(interface_index, p, 11, None, 100, record(&p))
                    else {
                        panic!(
                            "other interface/protocol/family entries must not answer this tuple"
                        );
                    };
                    e.verdict(
                        id,
                        if allow {
                            Verdict::PermanentAccept
                        } else {
                            Verdict::PermanentDrop
                        },
                        101,
                    )
                    .unwrap();
                }
            }
        }
        assert_eq!(e.cache_counts(), (4, 4));
        for interface_index in [101, 102] {
            for ipv6 in [false, true] {
                for protocol in [6, 17] {
                    for path in [NdisPath::Receive, NdisPath::Send] {
                        let mut p = packet();
                        p.flow.protocol = protocol;
                        p.connection.protocol = protocol;
                        p.flow.ipv6 = ipv6;
                        p.connection.ipv6 = ipv6;
                        p.flow.source[0] = 10;
                        p.flow.destination[0] = 20;
                        p.flow.source_port = 12345;
                        p.flow.destination_port = 443;
                        // A different Ethernet/VLAN snapshot never partitions a verdict.
                        p.flow.l2 = [42; 22];
                        p.flow.l2_len = 18;
                        if path == NdisPath::Send {
                            core::mem::swap(&mut p.flow.source, &mut p.flow.destination);
                            core::mem::swap(&mut p.flow.source_port, &mut p.flow.destination_port);
                        }
                        p.orient(path);
                        let allow = (interface_index == 101) ^ ipv6 ^ (protocol == 6);
                        assert_eq!(
                            e.preflight(interface_index, &p, 12, 102),
                            Err(Action {
                                nbl: 12,
                                finish: if allow { Finish::Allow } else { Finish::Drop },
                            })
                        );
                    }
                }
            }
        }
        assert_eq!(e.cache_counts(), (4, 4));
    }

    #[test]
    fn temporary_verdict_never_caches_and_duplicate_rejected() {
        let mut e = engine();
        let k = 101;
        let id = submit(&mut e, k, 1);
        assert_eq!(
            e.verdict(id, Verdict::Accept, 101).unwrap().finish,
            Finish::Allow
        );
        assert_eq!(
            e.verdict(id, Verdict::Drop, 102),
            Err(VerdictError::NotFound)
        );
        let _ = submit(&mut e, k, 2);
    }
    #[test]
    fn timeout_and_disconnect_are_bounded_and_clear_cache() {
        let mut e = engine();
        let k = 101;
        let id = submit(&mut e, k, 1);
        assert!(e.take_due(2099).is_none());
        assert_eq!(e.take_due(2100).unwrap().finish, Finish::Allow);
        assert_eq!(
            e.verdict(id, Verdict::Accept, 2100),
            Err(VerdictError::NotFound)
        );
        let _ = submit(&mut e, k, 2);
        e.disconnect();
        assert_eq!(e.take_due(101).unwrap().nbl, 2);
        assert_eq!(e.pending_count(), 0);
        e.configure(2000, 60000, true);
        e.connect();
        let _ = submit(&mut e, k, 3);
        e.disconnect();
        assert_eq!(e.take_due(102).unwrap().finish, Finish::Drop);
    }
    #[test]
    fn pause_cancels_existing_ids_without_generations_and_restart_accepts_new_ids() {
        let mut e = engine();
        let old = submit(&mut e, 101, 1);
        e.invalidate(101, true);
        assert!(e.cache_plan(old, Verdict::PermanentAccept, 101).is_none());
        assert_eq!(
            e.verdict(old, Verdict::PermanentAccept, 101),
            Err(VerdictError::NotFound)
        );
        assert_eq!(
            e.preflight(101, &packet(), 9, 101),
            Err(Action {
                nbl: 9,
                finish: Finish::Drop
            })
        );
        assert!(e.restart(101));
        let new = submit(&mut e, 101, 2);
        assert_ne!(old, new);
        // Even restart-before-drain cannot resurrect the old ID on the same index.
        assert!(e.verdict(old, Verdict::PermanentAccept, 101).is_err());
        assert_eq!(
            e.take_due(101),
            Some(Action {
                nbl: 1,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.pending_count(), 1);
        assert_eq!(e.verdict(new, Verdict::Accept, 101).unwrap().nbl, 2);
        assert_eq!(e.cache_counts(), (0, 0));
    }

    #[test]
    fn cancellation_and_event_slot_reuse_do_not_expose_stale_ids() {
        let mut e = engine();
        let p = packet();
        let Submission::Pending(old) = e.submit(101, p, 1, Some(42), 100, record(&p)) else {
            panic!()
        };
        assert_eq!(e.cancel(101, 42).unwrap().finish, Finish::Cancel);
        let new = submit(&mut e, 101, 2);
        assert_ne!(old, new);
        assert!(e.verdict(old, Verdict::PermanentAccept, 101).is_err());
        let mut b = [0; 2048];
        let n = e.read(&mut b);
        let mut i = 0;
        let mut seen = 0;
        while i < n {
            let len = u32::from_le_bytes(b[i + 1..i + 5].try_into().unwrap()) as usize;
            if matches!(b[i], 1 | 2) {
                assert_eq!(
                    u64::from_le_bytes(b[i + 5..i + 13].try_into().unwrap()),
                    new
                );
                seen += 1;
            }
            i += 5 + len;
        }
        assert_eq!(seen, 1);
    }

    #[test]
    fn cancel_send_is_interface_scoped_and_does_not_claim_receive_ownership() {
        let mut e = engine();
        assert!(e.attach(102));
        assert!(e.restart(102));
        let mut p = packet();
        p.orient(NdisPath::Receive);
        assert!(matches!(
            e.submit(101, p, 1, None, 100, record(&p)),
            Submission::Pending(_)
        ));
        p.orient(NdisPath::Send);
        assert!(matches!(
            e.submit(101, p, 2, Some(0), 100, record(&p)),
            Submission::Pending(_)
        ));
        assert!(matches!(
            e.submit(102, p, 3, Some(0), 100, record(&p)),
            Submission::Pending(_)
        ));
        assert_eq!(e.cancel(101, 0).unwrap().nbl, 2);
        assert!(e.cancel(101, 0).is_none());
        assert_eq!(e.pending_count(), 2);
        assert_eq!(e.cancel(102, 0).unwrap().nbl, 3);
        assert_eq!(e.pending_count(), 1);
        e.disconnect();
        assert_eq!(e.take_due(101).unwrap().nbl, 1);
    }

    #[test]
    fn partial_reads_remain_a_valid_stream_after_timeout() {
        let mut e = engine();
        let k = 101;
        let _ = submit(&mut e, k, 1);
        let mut b = [0; 2048];
        let n = e.read(&mut b);
        assert!(n > 40);
        let id = submit(&mut e, k, 2);
        let mut prefix = [0; 3];
        assert_eq!(e.read(&mut prefix), 3);
        e.take_due(2100);
        let n = e.read(&mut b);
        assert_eq!(prefix[0], 1);
        assert_eq!(n, 133);
        assert_eq!(u64::from_le_bytes(b[2..10].try_into().unwrap()), id);
    }
    #[test]
    fn queue_accounting_overflow_falls_back_without_losing_owned_token() {
        for fail_closed in [false, true] {
            let mut e = engine();
            e.read(&mut [0; MAX_LOG_RECORD]);
            e.configure(2000, 60000, fail_closed);
            let p = packet();
            e.queued_bytes = usize::MAX;
            assert!(!e.wants_event(101, &p, 100));
            assert_eq!(
                e.submit(101, p, 999, None, 100, record(&p)),
                Submission::Finish(Action {
                    nbl: 999,
                    finish: e.fallback()
                })
            );
            assert_eq!(e.queued_bytes, usize::MAX);
            assert_eq!(e.pending_count(), 0);
            assert!(e.events.is_empty());
            assert_eq!(e.stats().overflow, 1);
            e.queued_bytes = 0;
        }
    }

    #[test]
    fn maximum_packets_survive_chunked_reads_and_timeout_without_truncation() {
        for ipv6 in [false, true] {
            let mut e = engine();
            assert!(e.read(&mut [0; MAX_LOG_RECORD]) > 0);
            let k = 101;
            let mut p = packet();
            p.connection.ipv6 = ipv6;
            p.payload_len = MAX_PAYLOAD as u32;
            p.ip_len = u64::from(p.payload_len);
            p.cacheable = false;
            let prefix = connection_header_len(&p.connection);
            let mut data = record(&p).unwrap();
            for (i, byte) in data[prefix..].iter_mut().enumerate() {
                *byte = (i % 251) as u8;
            }
            let Submission::Pending(id) = e.submit(k, p, 7, None, 100, Some(data)) else {
                panic!("expected full-packet event");
            };
            assert_eq!(e.queued_bytes, prefix + MAX_PAYLOAD);
            let mut chunk = vec![0; 65536];
            let mut received = Vec::new();
            assert_eq!(e.read(&mut chunk), chunk.len());
            received.extend_from_slice(&chunk);
            assert_eq!(e.take_due(2100).unwrap().nbl, 7);
            loop {
                let n = e.read(&mut chunk);
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..n]);
            }
            assert_eq!(received.len(), prefix + MAX_PAYLOAD);
            assert_eq!(u64::from_le_bytes(received[5..13].try_into().unwrap()), id);
            assert_eq!(
                u32::from_le_bytes(received[13..17].try_into().unwrap()),
                101
            );
            assert_eq!(received[17], 0);
            assert_eq!(
                u32::from_le_bytes(received[prefix - 4..prefix].try_into().unwrap()) as usize,
                MAX_PAYLOAD
            );
            assert!(
                received[prefix..]
                    .iter()
                    .enumerate()
                    .all(|(i, b)| *b == (i % 251) as u8)
            );
            assert_eq!(e.queued_bytes, 0);
            assert!(e.events.is_empty());
            assert_eq!(e.pending_count(), 0);
        }
    }
    #[test]
    fn unread_expired_full_packet_releases_its_queue_bytes() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let k = 101;
        let mut p = packet();
        p.payload_len = 70000;
        let _ = e.submit(k, p, 9, None, 100, record(&p));
        assert!(e.queued_bytes > 65536);
        assert_eq!(e.take_due(2100).unwrap().nbl, 9);
        assert_eq!(e.read(&mut [0; 16]), 0);
        assert_eq!(e.queued_bytes, 0);
        assert!(e.events.is_empty());
    }
    #[test]
    fn event_queue_exceeds_16_mib_and_disconnect_retires_all_records() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut p = packet();
        p.payload_len = MAX_PAYLOAD as u32;
        p.cacheable = false;
        let size = connection_header_len(&p.connection) + MAX_PAYLOAD;
        const COUNT: usize = 32;
        for nbl in 1..=COUNT {
            assert!(e.wants_event(101, &p, 100));
            assert!(matches!(
                e.submit(101, p, nbl, None, 100, record(&p)),
                Submission::Pending(_)
            ));
        }
        assert!(e.wants_event(101, &p, 100));
        assert_eq!(e.queued_bytes, COUNT * size);
        assert!(e.queued_bytes > 16 * 1024 * 1024);
        assert_eq!(e.stats().overflow, 0);
        e.disconnect();
        assert_eq!(e.queued_bytes, 0);
        assert!(e.events.is_empty());
        let retired = e.take_retired_storage().unwrap();
        assert_eq!(retired._events.len(), COUNT);
        drop(retired);
        let mut released = 0;
        while e.take_due(101).is_some() {
            released += 1;
        }
        assert_eq!(released, COUNT);
    }
    #[test]
    fn read_above_64_kib_coalesces_complete_records_without_truncation() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut p = packet();
        p.payload_len = MAX_PAYLOAD as u32;
        let size = connection_header_len(&p.connection) + MAX_PAYLOAD;
        let mut ids = Vec::new();
        for nbl in 1..=2 {
            let Submission::Pending(id) = e.submit(101, p, nbl, None, 100, record(&p)) else {
                panic!("full packet must be queued");
            };
            ids.push(id);
        }
        let mut out = vec![0; 2 * size];
        assert_eq!(e.read(&mut out), out.len());
        for (frame, id) in out.chunks_exact(size).zip(ids) {
            assert_eq!(u64::from_le_bytes(frame[5..13].try_into().unwrap()), id);
            assert_eq!(
                u32::from_le_bytes(frame[32..36].try_into().unwrap()),
                MAX_PAYLOAD as u32
            );
            assert_eq!(
                e.verdict(id, Verdict::Accept, 101).unwrap().finish,
                Finish::Allow
            );
        }
        assert_eq!(e.queued_bytes, 0);
        assert_eq!(e.pending_count(), 0);
    }
    #[test]
    fn bandwidth_preserves_a_batch_above_u32_max() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut p = packet();
        p.ip_len = u64::from(u32::MAX) + 123;
        e.bandwidth_add(101, &p);
        e.bandwidth();
        let mut out = [0; 128];
        let len = e.read(&mut out);
        assert_eq!(out[0], 5);
        assert_eq!(
            u64::from_le_bytes(out[len - 16..len - 8].try_into().unwrap()),
            p.ip_len
        );
        assert_eq!(u64::from_le_bytes(out[len - 8..len].try_into().unwrap()), 0);
    }

    #[test]
    fn missing_capture_uses_fallback_without_publishing_a_short_packet() {
        for fail_closed in [false, true] {
            let mut e = engine();
            e.read(&mut [0; MAX_LOG_RECORD]);
            e.configure(2000, 60000, fail_closed);
            let k = 101;
            assert_eq!(
                e.submit(k, packet(), 77, None, 100, None),
                Submission::Finish(Action {
                    nbl: 77,
                    finish: if fail_closed {
                        Finish::Drop
                    } else {
                        Finish::Allow
                    },
                })
            );
            assert_eq!(e.pending_count(), 0);
            assert_eq!(e.queued_bytes, 0);
            assert_eq!(e.stats().overflow, 1);
            assert_eq!(e.stats().malformed, 0);
        }
    }
    #[test]
    fn truncated_capture_is_dropped_not_encoded_as_a_complete_packet() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let k = 101;
        let p = packet();
        let mut data = record(&p).unwrap();
        data.pop();
        assert_eq!(
            e.submit(k, p, 88, None, 100, Some(data)),
            Submission::Finish(Action {
                nbl: 88,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.queued_bytes, 0);
        assert_eq!(e.stats().malformed, 1);
    }
    #[test]
    fn allocation_preflight_does_not_bypass_disconnect_or_invalidation() {
        let mut e = engine();
        let k = 101;
        let p = packet();
        assert!(e.wants_event(k, &p, 100));
        let data = record(&p);
        e.disconnect();
        assert_eq!(
            e.submit(k, p, 1, None, 100, data),
            Submission::Finish(Action {
                nbl: 1,
                finish: Finish::Allow
            })
        );
        assert_eq!(e.queued_bytes, 0);
        e.connect();
        e.read(&mut [0; MAX_LOG_RECORD]);
        assert!(e.wants_event(k, &p, 100));
        let data = record(&p);
        e.invalidate(101, true);
        assert_eq!(
            e.submit(k, p, 2, None, 100, data),
            Submission::Finish(Action {
                nbl: 2,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.queued_bytes, 0);
        assert_eq!(e.pending_count(), 0);
    }
    #[test]
    fn read_readiness_tracks_partial_reads_and_disconnect() {
        let mut engine = Box::new(Engine::new());
        assert!(!engine.is_online() && !engine.has_events());
        engine.connect();
        assert!(engine.is_online() && engine.has_events());
        assert_eq!(engine.read(&mut []), 0);
        assert!(engine.has_events());
        assert_eq!(engine.read(&mut [0; 1]), 1);
        assert!(engine.has_events());
        while engine.read(&mut [0; 512]) != 0 {}
        assert!(!engine.has_events() && engine.is_online());
        engine.log(3, "queued");
        assert!(engine.has_events());
        engine.disconnect();
        assert!(!engine.has_events() && !engine.is_online());
        engine.log(3, "offline");
        assert!(!engine.has_events());
    }
    #[test]
    fn pending_metadata_does_not_contain_packet_sized_arrays() {
        assert!(core::mem::size_of::<Packet>() < 256);
        assert!(core::mem::size_of::<Pending>() < 512);
        assert!(core::mem::size_of::<Engine>() < 512 * 1024);
        assert!(allocate_record(MAX_RECORD + 1).is_none());
    }
    #[test]
    fn uncacheable_fragments_always_request_even_permanent() {
        let mut e = engine();
        let k = 101;
        let mut p = packet();
        p.cacheable = false;
        let Submission::Pending(id) = e.submit(k, p, 1, None, 0, record(&p)) else {
            panic!()
        };
        e.verdict(id, Verdict::PermanentAccept, 1).unwrap();
        assert!(matches!(
            e.submit(k, p, 2, None, 2, record(&p)),
            Submission::Pending(_)
        ));
    }
    #[test]
    fn permanent_accept_ttl_refreshes_on_matching_inbound_and_outbound_packets() {
        for protocol in [6, 17] {
            for ipv6 in [false, true] {
                let mut e = engine();
                e.configure(2000, 1000, false);
                let mut guest = [0; 16];
                let mut peer = [0; 16];
                if ipv6 {
                    guest = [0x11; 16];
                    peer = [0x22; 16];
                } else {
                    guest[..4].copy_from_slice(&[10, 0, 0, 2]);
                    peer[..4].copy_from_slice(&[192, 0, 2, 1]);
                }
                let mut outbound = packet();
                outbound.flow.protocol = protocol;
                outbound.connection.protocol = protocol;
                outbound.flow.ipv6 = ipv6;
                outbound.connection.ipv6 = ipv6;
                outbound.flow.source = guest;
                outbound.flow.destination = peer;
                outbound.flow.source_port = 40000;
                outbound.flow.destination_port = 443;
                // Host receive is guest outbound.
                outbound.orient(NdisPath::Receive);

                let mut inbound = outbound;
                inbound.flow.source = peer;
                inbound.flow.destination = guest;
                inbound.flow.source_port = 443;
                inbound.flow.destination_port = 40000;
                // Host send is guest inbound and must normalize to the same tuple.
                inbound.orient(NdisPath::Send);

                let k = 101;
                let Submission::Pending(id) =
                    e.submit(k, outbound, 1, None, 100, record(&outbound))
                else {
                    panic!("expected initial decision");
                };
                e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
                e.read(&mut [0; 512]);

                for (nbl, p, now) in [
                    (2, inbound, 1100),
                    (3, outbound, 2099),
                    (4, inbound, 3098),
                    (5, outbound, 4097),
                ] {
                    assert!(!e.wants_event(k, &p, now));
                    let action = e.preflight(k, &p, nbl, now).unwrap_err();
                    assert_eq!(
                        action,
                        Action {
                            nbl,
                            finish: Finish::Allow,
                        }
                    );
                }
                assert_eq!(e.stats().cache_hits, 4);
                assert!(e.wants_event(k, &inbound, 5097));
            }
        }
    }

    #[test]
    fn permanent_accept_tcp_udp_ttl_tracks_last_cache_hit() {
        for protocol in [6, 17] {
            for ipv6 in [false, true] {
                for path in [NdisPath::Send, NdisPath::Receive] {
                    let mut e = engine();
                    e.configure(2000, 1000, false);
                    let mut p = packet();
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.orient(path);
                    let k = 101;
                    let Submission::Pending(id) = e.submit(k, p, 1, None, 100, record(&p)) else {
                        panic!("expected initial decision");
                    };
                    e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
                    e.read(&mut [0; 512]);
                    for (nbl, now) in [(2, 1100), (3, 2099), (4, 3098)] {
                        e.clean(now);
                        assert!(!e.wants_event(k, &p, now));
                        assert_eq!(
                            e.submit(k, p, nbl, None, now, None),
                            Submission::Finish(Action {
                                nbl,
                                finish: Finish::Allow
                            })
                        );
                    }
                    assert_eq!(e.stats().cache_hits, 3);
                    assert_eq!(e.stats().queued, 1);
                    assert_eq!(e.pending_count(), 0);
                    assert!(!e.has_events());
                    assert!(!e.wants_event(k, &p, 4097));
                    e.clean(4098);
                    assert!(e.wants_event(k, &p, 4098));
                    assert!(matches!(
                        e.submit(k, p, 5, None, 4098, record(&p)),
                        Submission::Pending(_)
                    ));
                }
            }
        }
    }
    #[test]
    fn preflight_and_uncacheable_packets_do_not_refresh_accept_ttl() {
        let mut e = engine();
        e.configure(2000, 1000, false);
        let p = packet();
        let k = 101;
        let Submission::Pending(id) = e.submit(k, p, 1, None, 100, record(&p)) else {
            panic!();
        };
        e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
        assert!(!e.wants_event(k, &p, 1100));
        assert_eq!(e.stats().cache_hits, 0);
        let mut uncacheable = p;
        uncacheable.cacheable = false;
        assert!(e.wants_event(k, &uncacheable, 1100));
        let Submission::Pending(id) = e.submit(k, uncacheable, 2, None, 1100, record(&uncacheable))
        else {
            panic!("uncacheable traffic must still request a verdict");
        };
        e.verdict(id, Verdict::PermanentAccept, 1100).unwrap();
        assert_eq!(e.stats().cache_hits, 0);
        assert!(e.wants_event(k, &p, 1101));
        assert!(matches!(
            e.submit(k, p, 3, None, 1101, record(&p)),
            Submission::Pending(_)
        ));
    }
    #[test]
    fn cache_activity_refreshes_only_matching_tuple_interface_protocol_and_family() {
        let mut e = engine();
        e.configure(2000, 1000, false);
        assert!(e.attach(102));
        assert!(e.restart(102));
        let p = packet();
        for variant in 0..7 {
            e.clear_cache();
            let mut other = p;
            let interface_index = if variant == 0 { 102 } else { 101 };
            match variant {
                0 => {}
                1 => other.flow.source_port = 1234,
                2 => other.flow.destination_port = 53,
                3 => other.flow.source = [1; 16],
                4 => other.flow.destination = [2; 16],
                5 => {
                    other.flow.protocol = 6;
                    other.connection.protocol = 6;
                }
                6 => {
                    other.flow.ipv6 = true;
                    other.connection.ipv6 = true;
                }
                _ => unreachable!(),
            }
            other.orient(NdisPath::Receive);
            for (index, packet) in [(101, p), (interface_index, other)] {
                let Submission::Pending(id) =
                    e.submit(index, packet, 1, None, 100, record(&packet))
                else {
                    panic!()
                };
                e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
            }
            e.read(&mut [0; 512]);
            assert_eq!(
                e.submit(101, p, 2, None, 1100, None),
                Submission::Finish(Action {
                    nbl: 2,
                    finish: Finish::Allow
                })
            );
            e.clean(1101);
            assert!(!e.wants_event(101, &p, 1101));
            assert!(e.wants_event(interface_index, &other, 1101));
        }
    }

    #[test]
    fn expired_accept_is_not_revived_by_new_traffic() {
        for sweep in [false, true] {
            let mut e = engine();
            e.configure(2000, 1000, false);
            let p = packet();
            let k = 101;
            let Submission::Pending(id) = e.submit(k, p, 1, None, 100, record(&p)) else {
                panic!();
            };
            e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
            if sweep {
                e.clean(1101);
            }
            assert!(e.wants_event(k, &p, 1101));
            let Submission::Pending(id) = e.submit(k, p, 2, None, 1101, record(&p)) else {
                panic!("expired cache entry must require a new verdict");
            };
            assert_eq!(e.stats().cache_hits, 0);
            e.verdict(id, Verdict::PermanentAccept, 1102).unwrap();
            assert!(!e.wants_event(k, &p, 2101));
            assert!(e.wants_event(k, &p, 2102));
        }
    }
    #[test]
    fn accept_ttl_refresh_saturates_instead_of_wrapping() {
        let mut e = engine();
        e.configure(2000, 1000, false);
        let p = packet();
        let k = 101;
        let now = u64::MAX - 1500;
        let Submission::Pending(id) = e.submit(k, p, 1, None, now, record(&p)) else {
            panic!();
        };
        e.verdict(id, Verdict::PermanentAccept, now + 1).unwrap();
        assert!(matches!(
            e.submit(k, p, 2, None, u64::MAX - 600, None),
            Submission::Finish(Action {
                finish: Finish::Allow,
                ..
            })
        ));
        assert!(!e.wants_event(k, &p, u64::MAX - 1));
        assert!(e.wants_event(k, &p, u64::MAX));
    }
    #[test]
    fn ttl_expiry_requires_a_new_decision() {
        for verdict in [Verdict::PermanentBlock, Verdict::PermanentDrop] {
            for protocol in [6, 17] {
                let mut e = engine();
                let mut p = packet();
                p.flow.protocol = protocol;
                p.connection.protocol = protocol;
                let k = 101;
                let Submission::Pending(id) = e.submit(k, p, 1, None, 100, record(&p)) else {
                    panic!();
                };
                e.verdict(id, verdict, 101).unwrap();
                assert!(matches!(
                    e.submit(k, p, 2, None, 60100, None),
                    Submission::Finish(Action {
                        finish: Finish::Drop,
                        ..
                    })
                ));
                assert!(matches!(
                    e.submit(k, p, 3, None, 60101, record(&p)),
                    Submission::Pending(_)
                ));
            }
        }
    }
    #[test]
    fn invalidation_clears_only_that_interface_bank_and_reclaims_all_four_caches() {
        let mut e = engine();
        assert!(e.attach(102));
        assert!(e.restart(102));
        for interface_index in [101, 102] {
            for protocol in [6, 17] {
                for ipv6 in [false, true] {
                    let mut p = packet();
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    let Submission::Pending(id) =
                        e.submit(interface_index, p, 1, None, 100, record(&p))
                    else {
                        panic!()
                    };
                    e.verdict(
                        id,
                        if interface_index == 101 {
                            Verdict::PermanentAccept
                        } else {
                            Verdict::PermanentDrop
                        },
                        101,
                    )
                    .unwrap();
                }
            }
        }
        assert_eq!(e.cache_counts(), (4, 4));
        e.invalidate(101, false);
        assert_eq!(e.preflight(101, &packet(), 2, 102), Ok(true));
        assert_eq!(
            e.preflight(102, &packet(), 3, 102),
            Err(Action {
                nbl: 3,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.cache_counts(), (2, 2));
        let retired = e.take_retired_caches().unwrap();
        assert_eq!(retired.counts(), (2, 2));
        assert!(retired.bytes() > 0);
        drop(retired);
        assert!(e.take_retired_caches().is_none());
        assert_eq!(e.preflight(101, &packet(), 4, 102), Ok(true));
        assert_eq!(
            e.preflight(102, &packet(), 5, 102),
            Err(Action {
                nbl: 5,
                finish: Finish::Drop
            })
        );
    }

    #[test]
    fn only_tcp_udp_can_create_or_consume_permanent_cache() {
        for ipv6 in [false, true] {
            for protocol in [0, 1, 2, 47, 50, 58, 255] {
                for verdict in [
                    Verdict::PermanentAccept,
                    Verdict::PermanentBlock,
                    Verdict::PermanentDrop,
                ] {
                    let mut e = engine();
                    let mut p = packet();
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    // Deliberately set cacheable: the engine enforces TCP/UDP too.
                    let k = 101;
                    let Submission::Pending(id) = e.submit(k, p, 1, None, 100, record(&p)) else {
                        panic!();
                    };
                    assert!(e.cache_plan(id, verdict, 101).is_none());
                    e.verdict(id, verdict, 101).unwrap();
                    assert_eq!(e.cache_counts(), (0, 0));
                    assert_eq!(e.cache_bytes(), 0);
                    assert_eq!(e.preflight(k, &p, 2, 102), Ok(true));
                    assert!(matches!(
                        e.submit(k, p, 2, None, 102, record(&p)),
                        Submission::Pending(_)
                    ));
                    assert_eq!(e.stats().cache_hits, 0);
                }
            }
        }
    }
    #[test]
    fn dynamic_cache_keeps_more_than_1024_verdicts_per_protocol_and_family() {
        let mut e = engine();
        e.read(&mut [0; 512]);
        for protocol in [6, 17] {
            for ipv6 in [false, true] {
                for n in 0..1536u32 {
                    let mut p = packet();
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.flow.source[..4].copy_from_slice(&n.to_le_bytes());
                    p.orient(NdisPath::Receive);
                    let Submission::Pending(id) = e.submit(101, p, 1, None, 100, record(&p)) else {
                        panic!()
                    };
                    e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
                    e.read(&mut [0; 256]);
                }
            }
        }
        assert_eq!(e.cache_counts(), (3072, 3072));
        for protocol in [6, 17] {
            for ipv6 in [false, true] {
                for n in 0..1536u32 {
                    let mut p = packet();
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.flow.source[..4].copy_from_slice(&n.to_le_bytes());
                    p.orient(NdisPath::Receive);
                    assert_eq!(
                        e.preflight(101, &p, 2, 102),
                        Err(Action {
                            nbl: 2,
                            finish: Finish::Allow
                        })
                    );
                }
            }
        }
        assert_eq!(e.stats().cache_hits, 6144);
        assert_eq!(e.stats().received, 12288);
        assert_eq!(e.stats().cache_allocation_failures, 0);
    }

    #[test]
    fn reused_interface_index_starts_with_empty_caches() {
        let mut e = engine();
        let k = 101;
        let id = submit(&mut e, k, 1);
        e.verdict(id, Verdict::PermanentDrop, 101).unwrap();
        e.invalidate(101, false);
        let k = 101;
        let id = submit(&mut e, k, 2);
        e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
        assert_eq!(
            e.preflight(k, &packet(), 3, 102),
            Err(Action {
                nbl: 3,
                finish: Finish::Allow
            })
        );
        e.detach(101);
        assert!(e.attach(101));
        assert!(e.restart(101));
        let k = 101;
        assert_eq!(e.preflight(k, &packet(), 4, 102), Ok(true));
        e.clear_cache();
        e.clean(102);
        assert_eq!(e.cache_bytes(), 0);
    }
    #[test]
    fn cache_ignores_ethernet_but_separates_protocol_and_interface() {
        let mut e = engine();
        let id = submit(&mut e, 101, 1);
        e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
        let mut p = packet();
        p.flow.l2 = [42; 22];
        p.flow.l2_len = 14;
        assert_eq!(
            e.preflight(101, &p, 2, 102),
            Err(Action {
                nbl: 2,
                finish: Finish::Allow
            })
        );
        p.flow.protocol = 6;
        p.connection.protocol = 6;
        assert_eq!(e.preflight(101, &p, 3, 102), Ok(true));
        let Submission::Pending(id) = e.submit(101, p, 3, None, 102, record(&p)) else {
            panic!()
        };
        e.verdict(id, Verdict::PermanentDrop, 103).unwrap();
        assert_eq!(
            e.preflight(101, &p, 4, 104),
            Err(Action {
                nbl: 4,
                finish: Finish::Drop
            })
        );
        assert_eq!(
            e.preflight(101, &packet(), 5, 104),
            Err(Action {
                nbl: 5,
                finish: Finish::Allow
            })
        );
        assert!(e.attach(102));
        assert!(e.restart(102));
        assert_eq!(e.preflight(102, &p, 6, 104), Ok(true));
    }

    #[test]
    fn bandwidth_combines_guest_normalized_tx_and_rx() {
        let mut e = engine();
        let k = 101;
        let tx = packet();
        let mut rx = tx;
        rx.orient(NdisPath::Send);
        rx.ip_len = 75;
        let Submission::Pending(id) = e.submit(k, tx, 1, None, 100, record(&tx)) else {
            panic!()
        };
        e.verdict(id, Verdict::Accept, 101).unwrap();
        let inbound = k;
        let Submission::Pending(id) = e.submit(inbound, rx, 2, None, 102, record(&rx)) else {
            panic!()
        };
        e.verdict(id, Verdict::Accept, 103).unwrap();
        e.bandwidth();
        let mut b = [0; 2048];
        let n = e.read(&mut b);
        let mut i = 0;
        let mut seen = 0;
        while i < n {
            let len = u32::from_le_bytes(b[i + 1..i + 5].try_into().unwrap()) as usize;
            if b[i] == 5 {
                assert_eq!(
                    u64::from_le_bytes(b[i + 26..i + 34].try_into().unwrap()),
                    100
                );
                assert_eq!(
                    u64::from_le_bytes(b[i + 34..i + 42].try_into().unwrap()),
                    75
                );
                seen += 1;
            }
            i += 5 + len;
        }
        assert_eq!(seen, 1);
    }
    #[test]
    fn bandwidth_counts_admitted_bytes_and_reports_the_interface_index() {
        let mut e = engine();
        let k = 101;
        let id = submit(&mut e, k, 1);
        e.verdict(id, Verdict::Accept, 101).unwrap();
        e.bandwidth();
        let mut b = [0; 2048];
        let n = e.read(&mut b);
        let mut i = 0;
        let mut seen = false;
        while i < n {
            let len = u32::from_le_bytes(b[i + 1..i + 5].try_into().unwrap()) as usize;
            if b[i] == 5 {
                assert_eq!(len, 37);
                assert_eq!(u32::from_le_bytes(b[i + 6..i + 10].try_into().unwrap()), k);
                seen = true;
                assert_eq!(
                    u64::from_le_bytes(b[i + 26..i + 34].try_into().unwrap()),
                    100
                );
            }
            i += 5 + len;
        }
        assert!(seen);
    }

    #[test]
    fn interface_indices_are_unique_nonzero_and_have_no_slot_count_limit() {
        let mut e = Box::new(Engine::new());
        assert!(!e.attach(0));
        assert!(!e.restart(0));
        for index in (1..=129).chain([u32::MAX]) {
            assert!(e.attach(index));
            assert!(e.restart(index));
            assert!(!e.attach(index));
        }
        assert_eq!(e.interfaces.len(), 130);
        assert!(e.attach(1000));
        e.detach(1);
        assert!(e.attach(1));
        assert!(e.restart(1));
        e.detach(1000);
        assert!(!e.restart(1000));
    }

    #[test]
    fn reused_index_does_not_revive_pending_ids_or_invalidate_other_interfaces() {
        let mut e = engine();
        assert!(e.attach(102));
        assert!(e.restart(102));
        let old = submit(&mut e, 101, 1);
        let other = submit(&mut e, 102, 2);
        let mut work = CacheWork::prepare(e.cache_plan(old, Verdict::PermanentAccept, 101));
        e.detach(101);
        assert!(e.attach(101));
        assert!(e.restart(101));
        let new = submit(&mut e, 101, 3);
        assert!(
            e.verdict_with_work(
                old,
                Verdict::PermanentAccept,
                101,
                &mut work,
                &mut BandwidthWork::empty()
            )
            .is_err()
        );
        assert_eq!(e.cache_counts(), (0, 0));
        assert_eq!(
            e.take_due(101),
            Some(Action {
                nbl: 1,
                finish: Finish::Drop
            })
        );
        assert!(e.take_due(101).is_none());
        assert_eq!(
            e.verdict(other, Verdict::PermanentDrop, 101).unwrap().nbl,
            2
        );
        assert_eq!(
            e.verdict(new, Verdict::PermanentAccept, 101).unwrap().nbl,
            3
        );
        assert_eq!(e.stats().invalidated, 1);
        assert_eq!(e.cache_counts(), (2, 0));
    }
}
