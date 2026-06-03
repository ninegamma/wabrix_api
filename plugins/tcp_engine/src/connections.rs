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

// The sentinel value replacing `None`
pub const NULL_NODE: usize = usize::MAX;

pub(crate) struct ConnectionNode {
    // -----------------------------------------
    // 8-BYTE ALIGNED FIELDS
    // -----------------------------------------
    pub(crate) last_active_tsc: u64, // 8 bytes

    // -----------------------------------------
    // 4-BYTE ALIGNED FIELDS
    // -----------------------------------------
    // Assuming FlowKey is (usize, usize, u16, u16) = 12 bytes
    pub(crate) key: FlowKey,         // 12 bytes
    pub(crate) snd_nxt: u32,         // 4 bytes
    pub(crate) rcv_nxt: u32,         // 4 bytes

    // Replaced Option<usize> (8 bytes each) with usize (4 bytes each)
    pub(crate) prev: usize,            // 4 bytes
    pub(crate) next: usize,            // 4 bytes

    // -----------------------------------------
    // 1-BYTE ALIGNED FIELDS
    // -----------------------------------------
    pub(crate) state: TcpState,      // 1 byte

    // -----------------------------------------
    // RUST COMPILER INJECTS 3 BYTES OF PADDING HERE
    // TO MAKE THE TOTAL STRUCT ALIGN TO 8 BYTES
    // -----------------------------------------
    // TOTAL: 40 Bytes
}

pub(crate) struct ConnectionPool {
    map: BTreeMap<FlowKey, usize>,
    arena: Vec<ConnectionNode>,

    // The active Doubly Linked List
    head: usize, // Oldest connections (Timeouts)
    tail: usize, // Newest / Recently Active connections

    // A list of empty slots in the arena to reuse memory without allocating
    free_head: usize,
}

impl ConnectionPool {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            arena: Vec::with_capacity(capacity),
            head: NULL_NODE,
            tail: NULL_NODE,
            free_head: NULL_NODE,
        }
    }
    pub fn clear(&mut self) {
        self.map.clear();
        self.arena.clear(); // Keeps the 524,288 capacity, but sets length to 0
        self.head = NULL_NODE;
        self.tail = NULL_NODE;
        self.free_head = NULL_NODE;
    }

    /// O(1) Unlink a node from its current position in the linked list
    fn unlink(&mut self, index: usize) {
        let prev = self.arena[index].prev;
        let next = self.arena[index].next;

        // 1. Update the previous node (or the head pointer)
        if prev != NULL_NODE {
            self.arena[prev as usize].next = next;
        } else {
            self.head = next;
        }

        // 2. Update the next node (or the tail pointer)
        if next != NULL_NODE {
            self.arena[next as usize].prev = prev;
        } else {
            self.tail = prev;
        }

        // 3. Clear the links of the removed node
        self.arena[index].prev = NULL_NODE;
        self.arena[index].next = NULL_NODE;
    }

    /// O(1) Push a node to the tail of the linked list (Mark as newest)
    fn push_tail(&mut self, index: usize) {
        self.arena[index].prev = self.tail;
        self.arena[index].next = NULL_NODE;

        if self.tail != NULL_NODE {
            self.arena[self.tail].next = index;
        }
        self.tail = index;

        if self.head == NULL_NODE {
            self.head = index;
        }
    }

    /// O(log N) Insert a brand new connection
    pub fn insert(&mut self, key: FlowKey, state: TcpState, snd_nxt: u32, rcv_nxt: u32, tsc: u64) {
        let index = if self.free_head != NULL_NODE {
            let free_idx = self.free_head;
            // Reuse an empty slot
            self.free_head = self.arena[free_idx].next;
            self.arena[free_idx] = ConnectionNode { key, state, snd_nxt, rcv_nxt, last_active_tsc: tsc, prev: NULL_NODE, next: NULL_NODE };
            free_idx
        } else {
            // SAFETY VALVE: Prevent Wasm OOM by stopping vector reallocation
            if self.arena.len() == self.arena.capacity() {
                log::error!(
                    "TCP Engine: Connection pool capacity ({}) exhausted! Dropping new connection: {:?}",
                    self.arena.capacity(),
                    key
                );
                return;
            }
            // Allocate a new slot
            let new_idx = self.arena.len();
            self.arena.push(ConnectionNode { key, state, snd_nxt, rcv_nxt, last_active_tsc: tsc, prev: NULL_NODE, next: NULL_NODE });
            new_idx
        };

        let v= self.map.insert(key, index);
        if v.is_some() { log::warn!("Btree contains already connection key: {:?}", key); }
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
            self.free_head = index;
        }
    }

    /// O(1) Check the oldest connections. Returns keys that need a FIN sent.
    pub fn scavenge_timeouts(&mut self, current_tsc: u64, timeout_cycles: u64) -> Vec<FlowKey> {
        let mut timed_out_keys = Vec::new();

        while self.head != NULL_NODE {
            let oldest_idx = self.head;
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
                    /*
                    if timed_out_keys.len() >= limit {
                        break; // STOP collecting to prevent OOM
                    }
                     */
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