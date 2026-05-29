// Put this above your WasmEngine implementation

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
}

// The 4-Tuple that uniquely identifies a TCP connection
// (Src IP, Src Port, Dst IP, Dst Port)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) struct FlowKey(pub u32, pub u16, pub u32, pub u16);


pub (crate) struct ConnectionNode {
    key: FlowKey, // Needed so we can remove it from the BTreeMap on timeout
    pub(crate) state: TcpState,
    pub(crate) snd_nxt: u32,
    pub(crate) rcv_nxt: u32,
    last_active_tsc: u64,

    // Doubly Linked List links (Indices into the arena, not pointers!)
    prev: Option<usize>,
    next: Option<usize>,
}

pub(crate) struct ConnectionPool {
    map: BTreeMap<FlowKey, usize>,
    arena: Vec<ConnectionNode>,

    // The active Doubly Linked List
    head: Option<usize>, // Oldest connections (Timeouts)
    tail: Option<usize>, // Newest / Recently Active connections

    // A list of empty slots in the arena to reuse memory without allocating
    free_head: Option<usize>,
}

impl ConnectionPool {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            arena: Vec::with_capacity(capacity),
            head: None,
            tail: None,
            free_head: None,
        }
    }

    /// O(1) Unlink a node from its current position in the linked list
    fn unlink(&mut self, index: usize) {
        let prev = self.arena[index].prev;
        let next = self.arena[index].next;

        if let Some(p) = prev { self.arena[p].next = next; } else { self.head = next; }
        if let Some(n) = next { self.arena[n].prev = prev; } else { self.tail = prev; }

        self.arena[index].prev = None;
        self.arena[index].next = None;
    }

    /// O(1) Push a node to the tail of the linked list (Mark as newest)
    fn push_tail(&mut self, index: usize) {
        self.arena[index].prev = self.tail;
        self.arena[index].next = None;

        if let Some(t) = self.tail { self.arena[t].next = Some(index); }
        self.tail = Some(index);
        if self.head.is_none() { self.head = Some(index); }
    }

    /// O(log N) Insert a brand new connection
    pub fn insert(&mut self, key: FlowKey, state: TcpState, snd_nxt: u32, rcv_nxt: u32, tsc: u64) {
        let index = if let Some(free_idx) = self.free_head {
            // Reuse an empty slot
            self.free_head = self.arena[free_idx].next;
            self.arena[free_idx] = ConnectionNode { key, state, snd_nxt, rcv_nxt, last_active_tsc: tsc, prev: None, next: None };
            free_idx
        } else {
            // Allocate a new slot
            let new_idx = self.arena.len();
            self.arena.push(ConnectionNode { key, state, snd_nxt, rcv_nxt, last_active_tsc: tsc, prev: None, next: None });
            new_idx
        };

        self.map.insert(key, index);
        self.push_tail(index);
    }

    /// O(1) Get a mutable reference without modifying the linked list or timestamp
    pub fn get_mut(&mut self, key: &FlowKey) -> Option<&mut ConnectionNode> {
        if let Some(&index) = self.map.get(key) {
            Some(&mut self.arena[index])
        } else {
            None
        }
    }

    /// O(log N) Get a connection and instantly move it to the tail
    pub fn get_mut_and_touch(&mut self, key: &FlowKey, current_tsc: u64) -> Option<&mut ConnectionNode> {
        if let Some(&index) = self.map.get(key) {
            self.unlink(index);
            self.push_tail(index);
            self.arena[index].last_active_tsc = current_tsc;
            Some(&mut self.arena[index])
        } else {
            None
        }
    }

    /// O(log N) Completely remove a connection
    pub fn remove(&mut self, key: &FlowKey) {
        if let Some(index) = self.map.remove(key) {
            self.unlink(index);
            // Push to free list so the memory can be reused
            self.arena[index].next = self.free_head;
            self.free_head = Some(index);
        }
    }

    /// O(1) Check the oldest connections. Returns keys that need a FIN sent.
    pub fn scavenge_timeouts(&mut self, current_tsc: u64, timeout_cycles: u64) -> Vec<FlowKey> {
        let mut timed_out_keys = Vec::new();

        while let Some(oldest_idx) = self.head {
            if current_tsc.saturating_sub(self.arena[oldest_idx].last_active_tsc) > timeout_cycles {
                // It timed out! 
                let key = self.arena[oldest_idx].key;

                let state = self.arena[oldest_idx].state;
                if state == TcpState::Established
                    || state == TcpState::SynReceived
                    || state == TcpState::FinWait1
                {
                    // Let the tick handler own the state transition (polite close or Guillotine).
                    // Bump the timestamp so this connection gets a fresh window before the
                    // next scavenge fires again.
                    self.arena[oldest_idx].last_active_tsc = current_tsc;
                    timed_out_keys.push(key);

                    self.unlink(oldest_idx);
                    self.push_tail(oldest_idx);
                } else {
                    // Already closed/dead — free the slot directly.
                    self.remove(&key);
                }
            } else {
                // The oldest connection is still active! 
                // Therefore, all subsequent connections are also active. We are done!
                break;
            }
        }

        timed_out_keys
    }
}