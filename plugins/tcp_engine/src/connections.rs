use crate::MAX_CONNECTIONS;

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


// - Removed alloc crate dependencies
// - Rely strictly on core primitives

const HASH_TABLE_SIZE: usize = 1_048_576; // - Must be a power of two for fast masking

// - Sentinel values
pub const NULL_NODE:  usize = usize::MAX;       // arena free-list / linked-list sentinel
pub const EMPTY_SLOT: usize = usize::MAX;       // hash table: slot was never occupied — stops linear probe
pub const TOMBSTONE:  usize = usize::MAX - 1;   // hash table: slot was deleted — probe must continue

pub(crate) struct ConnectionPool {
    // - Open addressing hash table mapping FlowKey hash to arena index
    hash_table: [usize; HASH_TABLE_SIZE],

    // - Fixed-size arena containing all node data
    // - Uses MaybeUninit in a real implementation to avoid boot-time initialization overhead,
    //   but simplified here for clarity.
    arena: [ConnectionNode; MAX_CONNECTIONS],

    // - Active doubly linked list
    head: usize,
    tail: usize,

    // - Free list for reusing dead connections
    free_head: usize,

    // - Watermark for the uninitialized portion of the arena
    pub(crate) watermark: usize,
}

impl FlowKey {
    // - Simple, fast hash function for the TCP 4-tuple
    // - Avoids cryptographic overhead of standard SipHash
    #[inline]
    fn hash_index(&self) -> usize {
        let mut h = self.0.wrapping_add(self.2);
        h ^= (self.1 as u32).wrapping_shl(16) | (self.3 as u32);
        h = h.wrapping_mul(0x85ebca6b);
        (h as usize) & (HASH_TABLE_SIZE - 1)
    }

    /* much two slow
    #[inline]
    fn hash_index(&self) -> usize {
        // MurmurHash3-style finalizer for high avalanche effect
        let mut h = self.0.wrapping_mul(0x45d9f3b) ^ (self.2 as u32);
        h = h.wrapping_mul(0x45d9f3b) ^ (self.1 as u32);
        h = h.wrapping_mul(0x45d9f3b) ^ (self.3 as u32);
        (h as usize) & (HASH_TABLE_SIZE - 1)
    }
    */
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            hash_table: [EMPTY_SLOT; HASH_TABLE_SIZE],
            arena: core::array::from_fn(|_| ConnectionNode {
                last_active_tsc: 0,
                key: FlowKey(0, 0, 0, 0),
                snd_nxt: 0,
                rcv_nxt: 0,
                prev: NULL_NODE,
                next: NULL_NODE,
                state: TcpState::Closed,
            }),
            head: NULL_NODE,
            tail: NULL_NODE,
            free_head: NULL_NODE,
            watermark: 0,
        }
    }

    pub fn clear(&mut self) {
        self.hash_table.fill(EMPTY_SLOT);
        self.head = NULL_NODE;
        self.tail = NULL_NODE;
        self.free_head = NULL_NODE;
        self.watermark = 0;
    }

    // - Internal hash table lookup using linear probing
    fn find_hash_slot(&self, key: &FlowKey) -> Option<usize> {
        let mut idx = key.hash_index();

        // - Bound the loop to prevent infinite hangs if the table gets completely full
        for _ in 0..HASH_TABLE_SIZE {
            let slot_val = self.hash_table[idx];
            if slot_val == EMPTY_SLOT {
                // Genuine gap: key cannot exist beyond this point in the probe chain.
                return None;
            }
            if slot_val == TOMBSTONE {
                // Deleted slot: skip over it, the key may still be further along the chain.
                idx = (idx + 1) & (HASH_TABLE_SIZE - 1);
                continue;
            }
            if self.arena[slot_val].key == *key {
                return Some(idx);
            }
            // - Linear probe
            idx = (idx + 1) & (HASH_TABLE_SIZE - 1);
        }
        None
    }
    pub fn insert(&mut self, key: FlowKey, state: TcpState, snd_nxt: u32, rcv_nxt: u32, tsc: u64) {
        if self.find_hash_slot(&key).is_some() {
            log::warn!("TCP Engine: insert called for already-tracked flow key {:?}", key);
            return;
        }

        let index = if self.free_head != NULL_NODE {
            let free_idx = self.free_head;
            self.free_head = self.arena[free_idx].next;
            free_idx
        } else if self.watermark < MAX_CONNECTIONS {
            let new_idx = self.watermark;
            self.watermark += 1;
            new_idx
        } else {
            log::error!("TCP Engine: Connection pool exhausted!");
            return;
        };

        // - Update the arena data
        self.arena[index] = ConnectionNode {
            key, state, snd_nxt, rcv_nxt, last_active_tsc: tsc, prev: NULL_NODE, next: NULL_NODE
        };

        // - Insert into the hash table; prefer reclaiming a TOMBSTONE slot over a pristine slot.
        let mut hash_idx = key.hash_index();
        let mut tombstone_slot: Option<usize> = None;
        for _ in 0..HASH_TABLE_SIZE {
            let slot_val = self.hash_table[hash_idx];
            if slot_val == EMPTY_SLOT {
                let target = tombstone_slot.unwrap_or(hash_idx);
                self.hash_table[target] = index;
                break;
            }
            if slot_val == TOMBSTONE && tombstone_slot.is_none() {
                tombstone_slot = Some(hash_idx);
            }
            hash_idx = (hash_idx + 1) & (HASH_TABLE_SIZE - 1);
        }

        self.push_tail(index);
    }

    pub fn get_mut(&mut self, key: &FlowKey) -> Option<&mut ConnectionNode> {
        let slot = self.find_hash_slot(key)?;
        let arena_idx = self.hash_table[slot];
        Some(&mut self.arena[arena_idx])
    }

    pub fn remove(&mut self, key: &FlowKey) {
        if let Some(slot) = self.find_hash_slot(key) {
            let index = self.hash_table[slot];

            self.hash_table[slot] = TOMBSTONE;

            self.unlink(index);
            self.arena[index].next = self.free_head;
            self.free_head = index;
        }
    }

    /// O(1) Get a connection and instantly move it to the tail
    pub fn get_mut_and_touch(&mut self, key: &FlowKey, current_tsc: u64) -> Option<&mut ConnectionNode> {
        let slot = self.find_hash_slot(key)?;
        let index = self.hash_table[slot];

        self.unlink(index);
        self.push_tail(index);
        self.arena[index].last_active_tsc = current_tsc;

        Some(&mut self.arena[index])
    }

    /// O(1) Unlink a node from its current position in the linked list
    fn unlink(&mut self, index: usize) {
        let prev = self.arena[index].prev;
        let next = self.arena[index].next;

        // Update the previous node (or the head pointer)
        if prev != NULL_NODE {
            self.arena[prev].next = next;
        } else {
            self.head = next;
        }

        // Update the next node (or the tail pointer)
        if next != NULL_NODE {
            self.arena[next].prev = prev;
        } else {
            self.tail = prev;
        }

        // Clear the links of the removed node
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

    /// O(1) Check the oldest connections. Returns keys that need a FIN sent.
    pub fn scavenge_timeouts(&mut self, current_tsc: u64, timeout_cycles: u64) -> alloc::vec::Vec<FlowKey> {
        // Note: Using alloc::vec::Vec here is perfectly fine even with the bump allocator,
        // as this vector is immediately drained into the static TIMEOUT_QUEUE in lib.rs
        // and drops naturally. It does not persist across batches.
        let mut timed_out_keys = alloc::vec::Vec::new();

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
                    // Let the tick handler own the state transition.
                    // Bump the timestamp so this connection gets a fresh window before the
                    // next scavenge fires again.
                    self.arena[oldest_idx].last_active_tsc = current_tsc;
                    timed_out_keys.push(key);

                    self.unlink(oldest_idx);
                    self.push_tail(oldest_idx);
                } else {
                    // Already closed/dead — free the slot directly.
                    // We must use the hash-aware remove method to clear the tombstone.
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
