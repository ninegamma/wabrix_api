### Core Problem Analysis

In a Pipeline Direct Acyclic Graph (DAG) operating on a high-throughput kernel-bypass architecture (AF_XDP), sharing a single packet header pointer across multiple processing nodes concurrently creates severe concurrency and memory safety issues:

* **Data Races and Undefined Behavior:** Allowing multiple threads or nodes in a DAG to concurrently mutate or read a raw `HeaderPtr` (`*mut Header`) directly violates Rust's aliasing rules. Concurrent mutable access to memory backing a `#[repr(C, packed)]` header results in Undefined Behavior (UB), corrupted packet states, and invalid hardware checksum calculations.
* **Pipeline DAG Topology Conflicts:** Standard data planes process packets either via **Run-To-Completion (Sequential DAG)** on a single worker thread, or via **Pipelined Stages (Thread-per-Node)**. If multiple nodes execute concurrently on the *same* packet, the system loses determinism regarding which node mutated the memory first (e.g., Node A rewriting IP addresses while Node B computes the TCP checksum).
* **Cache-Line Bouncing:** Even if synchronized with mutexes or spinlocks, shared atomic access on the hot path causes severe cache-line bouncing across CPU cores, completely destroying the target 25 Gbps to 100 Gbps line-rate performance.

---

### Architectural Proposal: Run-To-Completion with Ownership Transfer

To resolve packet aliasing cleanly without introduce locking or performance degradation, the system must enforce strict **Run-To-Completion per Batch** paired with **Sequential Ownership Transfer**.

```
               Batch Execution Flow (Run-To-Completion)
  
┌──────────────────────────────────────────────────────────────────┐
│ Worker Thread (Pinned Core)                                      │
│                                                                  │
│  ┌───────────────┐     Directive::Next     ┌───────────────┐     │
│  │  Node A (RX)  │ ──────────────────────> │ Node B (NAT)  │     │
│  └───────┬───────┘                         └───────┬───────┘     │
│          │ Exclusive &mut Access                   │             │
│          ▼                                         ▼             │
│  ┌────────────────┐                        ┌────────────────┐    │
│  │ HeaderPtr /    │                        │ HeaderPtr /    │    │
│  │ Packet Memory  │                        │ Packet Memory  │    │
│  └────────────────┘                        └────────────────┘    │
└──────────────────────────────────────────────────────────────────┘

```

#### Node Trait Contract (Sequential Borrowing)

* A single `Worker Thread` owns the entire `Batch` of `Pdu`s during its execution cycle.
* Nodes within a pipeline DAG implement `Node::process(&mut self, batch: &mut Batch) -> Directive`.
* When Node A processes a batch, it receives exclusive, mutable access to the underlying `HeaderPtr` references within that batch. Node B cannot execute until Node A completes and returns a `Directive::Next`.
* Because processing is strictly sequential on the assigned worker thread, true multi-threaded concurrency on a single `HeaderPtr` never occurs. This satisfies Rust's aliasing guarantees without atomic overhead.

#### Explicit Branching and Cloning (`Directive::Split`)

When a DAG node requires parallel pipeline branches (for example, sending one packet copy to a logging/telemetry node and another to a forwarding TX node):

* **Zero-Copy Frame Duplication (Retain Semantics):** The node must NOT share a mutable `HeaderPtr`. Instead, it increments the frame's reference count in the worker's `FrameRegistry` using a `Retain` command.
* **Read-Only Fan-Out:** Branching nodes can pass read-only references (`&HeaderPtr`) down multiple read-only evaluation paths within the same thread.
* **Copy-On-Write for Mutation:** If a downstream branch node needs to modify the header of a shared/retained frame, it must allocate a fresh frame descriptor from its local `FrameRegistry`, copy the frame payload, and construct a new `HeaderPtr`. This isolates mutations and guarantees that concurrent or subsequent nodes see an uncorrupted frame state.

#### Worker-Boundary Handoff via SystemBus

If a DAG node routes packets across worker/core boundaries (e.g., steering flows from Core 0 to Core 1):

* The originating worker yields ownership of the `Pdu` and its associated `HeaderPtr`.
* The `Pdu` descriptor is transferred lock-free via the cross-worker ring buffer (`SystemBus`).
* Core 0 completely relinquishes access to the frame; Core 1 assumes full, exclusive ownership upon popping the frame descriptor from its queue.

---

### Implementation Guidelines for Header Mutability

To enforce this design in code without violating memory rules, adhere to these structural constraints:

* **No Mutexes or Atomic Locks on Headers:** `HeaderPtr` must remain a direct, raw pointer wrapper mapped over UMEM. Synchronization must be guaranteed by the DAG scheduler architecture, not by locking the header structure itself.
* **Short-Lived Accessors:** Accessor methods on `HeaderPtr` (such as `as_ip_mut()`) must generate short-lived, unbounded lifetime references (`&mut IpHeader`) that do not persist across node execution boundaries.
* **Sanity Gate in Node Execution:** Ensure that nodes operating in a `Split` directive return distinct `Batch` containers, preventing two active pipeline nodes from holding references to the same `HeaderPtr` simultaneously.