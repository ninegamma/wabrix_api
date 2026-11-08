# AGENTS.md — AI Assistant Project Constitution

## 1. Project Overview & Philosophy

The project is split into three repositories:

* **wabrix:** Contains the code for the platform of the dataplane engine.
* **wabrix_api:** This repository. Contains the generic `wabrix_api` SDK crate and canonical `.wit` interface definitions.
* **wabrix_plugins:** Independent sibling repository with reusable implementations and example plugin crates.

These repositories implement a high-performance, software-based networking engine/router. The system processes packets at high throughput (target: 25 Gbps – 100 Gbps) using Linux kernel-bypass via AF_XDP, and features a sandboxed WebAssembly plugin architecture for data-plane programmability.

**Core Engineering Principles:**
1. **Zero-Copy First:** Avoid per-packet allocations and copies in the processing hot path. Prefer operating on the host-provided packet and mailbox memory; justify any batch-level allocation.
2. **Predictable Latency:** Favor deterministic execution paths over peak theoretical throughput.
3. **Strict Memory Safety:** Use Rust's type system for safe access and keep the unsafe code that bridges Rust, Wasm linear memory, and native packet layouts tightly scoped.


***This file is for the wabrix_api repository, only.***

---

## 2. Package Structure & Module Boundaries

The standalone `wabrix_api` Cargo package (`Cargo.toml` at the repository root) contains the generic SDK library:

```
wabrix_api/
├── abi/                 # C shared-memory ABI header and layout-check translation unit
├── docs/                # SDK design notes
├── src/                 # Packet/header APIs, shared memory, mailbox, shared state, control types
├── wit/wabrix.wit       # Canonical host/plugin interface definitions
├── AGENTS.md
├── Cargo.toml
├── Cargo.lock
├── LICENSE
└── README.md
```

Plugin implementations and plugin crates live in the independent sibling
`../wabrix_plugins` repository, which has its own Cargo workspace and build settings.

### Crate responsibilities & allowed dependencies

| Crate | Role | May depend on |
|---|---|---|
| `wabrix_api` | `no_std` SDK: packet and batch access, shared-memory layouts, shared state, timers, and control types | `anyhow`, `byteorder`, `fnv`, `hashbrown`, `network-types`, `serde`, `zerocopy` |

**Dependency direction is strictly one-way:** plugin crates → `wabrix_plugins` → `wabrix_api`, or plugin crates → `wabrix_api` directly. Never introduce reverse or circular dependencies. Generic API types, including `EngineTimerPlan`, stay in `wabrix_api`.

### Key source files

| File | Contains |
|---|---|
| `wit/wabrix.wit` | WIT interface definitions: `packet-engine`, `logging`, `shared-state`, `generator`; worlds: `generator-plugin`, `engine-plugin` |
| `abi/wabrix_shared_memory.h`, `abi/layout_check.c` | C shared-memory ABI declarations and a C11 translation unit that checks their layouts; these describe linear-memory bytes, not WIT component-model records |
| `src/lib.rs` | Crate root, public exports, control/opcode types, timer-kind constants, and host-feature-gated layout re-exports |
| `src/packet.rs` | Safe `Packet<'a>` accessors and `PacketBatch` iteration over shared packet descriptors and UMEM |
| `src/mailbox_api.rs` | `MailboxBatch` and `MailboxPacket`, which pair packet access with per-packet actions in the shared mailbox |
| `src/shared_memory.rs` | `HeaderStack`, `PduCore`, `SharedPdu`, mailbox layouts, batch limits, and Rust layout assertions |
| `src/shared_state.rs` | Typed access to a host-validated shared-state payload |
| `src/headers/mod.rs` | Header kinds, pointer wrappers, and protocol-header constructors/accessors based on `network-types` |
| `src/headers/hstack.rs` | `HeaderStack` operations, typed header lookup, and protocol fingerprinting; the layout itself is in `shared_memory.rs` |
| `src/headers/flow.rs` | IPv4 five-tuple extraction and flow hashing |
| `src/headers/check.rs` | Internet checksum helpers |
| `src/headers/end_offset.rs` | Ethernet and VLAN header-size constants |
| `src/wpdu_impl.rs` | `SharedPdu` packet parsing and packet-data/header access and mutation methods |
| `src/helpers.rs` | Parsers for suffixed rates, MAC addresses, and IPv4 addresses |
| `src/timers.rs` | `EngineTimerPlan`, shared by native engines and the Wasm host |
| `docs/aliasing_guidelines.md` | Design notes on packet-header aliasing and ownership |

---

## 3. Technical Stack & Hard Boundaries

### Language & Compiler
* **Language:** Rust (Edition 2021).
* **`no_std`:** `wabrix_api` is `#![no_std]` (uses `extern crate alloc`). Never introduce `std`-only dependencies into it.
* **Build-time ABI checks:** Building this package runs the C/Rust ABI consistency and C layout checks. It requires `python3` and a C11 compiler (`CC` may select the compiler; defaults to `cc`).
* **Linting:** Run `cargo clippy -p wabrix_api` (native) and `cargo clippy -p wabrix_api --target wasm32-wasip2` (Wasm SDK). The codebase has a pre-existing warning backlog; `-D warnings` is the goal once that backlog is cleared. Until then, **new code must introduce zero new warnings** on either target. Do not use `#[allow(...)]` without a comment explaining why it is unavoidable.

### Plugin Build Target
* **Target:** Plugin crates in `../wabrix_plugins` target `wasm32-wasip2` (WASI 0.2 / Component Model) and are built as `cdylib`s. `wabrix_api` itself is an SDK library, not a plugin component.
* **FORBIDDEN:** Do NOT use `std::net`, OS threads, file I/O, or any syscall that is not available in the WASI Component Model sandbox.

### WIT Interface Standard
* **Bindgen:** `wit-bindgen` generates WASM guest bindings from `wit/wabrix.wit`. Import it at the top of each plugin's `lib.rs` via `wit_bindgen::generate!`.
* **Interface selection:** Use `engine-plugin` for new plugins, including generators. It exports `packet-engine` and imports `logging` and `shared-state`. The legacy `generator-plugin` world and its `generator` interface are deprecated and will be removed in one of the next versions; replace `generator_plugin.wasm` with `generator_engine.wasm`. The current WIT has no `filter-plugin` world.
* The `.wit` file is the source of truth for the host/plugin ABI. Never hand-code the ABI. The sibling plugin repository records a snapshot's SDK origin revision, version, and checksum; sync it there after committing canonical interface changes. SDK dependencies use Cargo version compatibility rather than requiring that exact commit. Breaking WIT changes must bump the SDK's compatibility series too.

### Plugin State
* In plugin code in `../wabrix_plugins`, **`spin::Mutex`** can protect `static` state in `no_std` contexts (for example, `static STATE: spin::Mutex<Option<PluginState>> = spin::Mutex::new(None)`). `spin` is a plugin-side dependency, not a `wabrix_api` dependency.
* Initialize state in the selected world's `init-data` callback. For `packet-engine`, it receives key/value data and the TSC frequency and returns `bool`; for `generator`, it receives key/value data and a worker ID and has no return value. Subsequent callbacks must assume initialization completed successfully.

### SDK Dependencies
* `network-types` — protocol header types used by the packet API.
* `zerocopy` — byte-layout and unaligned-access support for packet headers.
* `byteorder` and `fnv` — network-order field access and flow hashing.
* `hashbrown` and `serde` — `no_std`-compatible hash map and serialization support for SDK data types.
* `anyhow` — fallible packet/header operations and parsing helpers; avoid constructing formatted errors in per-packet loops.

WIT binding generation (`wit-bindgen`) and `spin` are used by plugin crates in the sibling `wabrix_plugins` repository; they are not dependencies of this SDK package.

---

## 4. Coding Commandments

### A. The Hot Path (Batch Callbacks)

When writing or refactoring packet-processing code in `process-batch` or `generate-batch`:

* **No Per-Packet Allocations:** For callbacks that construct a returned batch list, one pre-sized `Vec` allocation per batch call is acceptable, but never grow it inside the per-packet loop. `process-batch` writes actions and updated lengths to the host-provided mailbox. Never use `Box`, growing `Vec`s, `String::new`, or `Arc::new` inside the per-packet loop body. Use pre-allocated buffers, stack arrays, or state initialized in `init-data` for loop work.
* **No Panics:** Never `.unwrap()` or `.expect()` on the hot path. Handle malformed packets explicitly and follow the host/plugin contract for the callback; the WIT defines `process-batch` status `0` as success but does not define other status codes or action values.
* **No Dynamic Dispatch:** Avoid `dyn Trait` on the hot path; prefer generics or enum dispatch so the compiler can inline and devirtualize.
* **Parse Before Access:** Before accessing `packet.headers()` or any typed header accessor, the `HeaderStack` must be populated. Either call `packet.parse_fast()` before accessing headers, or rely on a preceding `FastParserNode` in the host pipeline. In the latter case the host has already populated the stack; this is a deployment contract, so call `parse_fast()` when that contract is not guaranteed.
  Accessing header offsets on an unparsed `Packet` (all offsets zero, `hc == 0`) silently returns `None` from all typed accessors — wrong results, not a crash.
* **Fingerprint First:** Use `headers().fingerprint()` against constants like `Packet::TCP_OVER_IPV4` for compact protocol matching. Do not iterate header slots manually.

### B. The Cold Path (init-data, on-control-event)

Standard Rust ergonomics apply. Heap allocations and `anyhow`-based error handling are permitted. `on-control-event` must still return promptly and must not block.

### C. Unsafe Code Guidelines

* Keep `unsafe` limited to low-level UMEM/mailbox access, shared-state region access, and unaligned protocol-header operations, with safe wrappers around those operations where practical.
* **MANDATORY:** Every `unsafe` block must be preceded by a `// SAFETY:` comment explaining the required bounds, alignment, aliasing, lifetime, and layout invariants.

### D. The `host` Feature Flag

* The `host` feature on `wabrix_api` re-exports low-level `SharedPdu`, `PduCore`, and `HeaderStack` layouts; it is **reserved for the host engine** (`wabrix` repo).
* **NEVER** enable `host` in a plugin's `Cargo.toml`. Plugins should use the public packet, mailbox, and shared-state APIs instead of depending on host-only layout exports.

### E. Unrequested Code Changes

* **NEVER** change fundamental structs and interfaces except if explicitly requested. In case you need to do the change, ask for permission with the exact reasoning.

---

## 5. Plugin API Quick Reference

> Full WIT definition: `wit/wabrix.wit`

The WIT package is `wabrix:plugins@0.2.0`. Its engine and generator worlds have different exports:

### `engine-plugin`

Exports `packet-engine` and imports `logging` and `shared-state`.

* **`init-data(data: list<tuple<string, string>>, tsc-frequency: u64) -> bool`** — startup key/value data from the node config plus the TSC frequency; `false` indicates unsuccessful initialization.
* **`process-batch(batch-size: u32, umem-offset: u32, mailbox-offset: u32) -> u32`** — zero-copy packet batch callback. The host writes descriptor addresses and lengths to the shared UMEM mailbox; the plugin writes actions and updated lengths there. The WIT comment defines status `0` as success.
* **`process-timers(current-tsc: u64) -> timer-plan`** — processes timers and returns `timeout-frames` and `packet-frames` for the next batch.
* **`on-control-event(opcode: u32, payload: list<u8>) -> bool`** — receives a control event and reports whether it was handled.
* **`get-telemetry-schema() -> telemetry-schema`** — describes stable counter names and histogram definitions for the initialized instance.
* **`get-telemetry() -> list<telemetry-metric>`** — returns counters and/or structured histograms; an empty list means no snapshot is available for that poll.
* **`upgrade-shared-state(source-schema-version: u32, source-payload-size: u32) -> result<_, string>`** — initializes appended fields during a compatible shared-state upgrade after the old runtime has stopped. The host commits the new schema version and size only on success.

The imported **`logging.log(level: u32, message: string)`** function sends a log message to the host. **`shared-state.attach(layout: state-layout) -> result<state-view, string>`** validates a plugin's fixed state layout and returns a guest-linear payload view or an error. The layout includes a 16-byte type ID, schema version, payload size, reserved capacity, required alignment, and compatible source versions. The returned view includes the payload offset/capacity, current schema and payload sizes, and whether the region is new or requires an upgrade.

### `generator-plugin` (deprecated)

Exports the deprecated `generator` interface. It will be removed in one of the
next versions. Migrate `generator_plugin.wasm` deployments to
`generator_engine.wasm`, which uses `engine-plugin` and its timer/mailbox API.

* **`init-data(data: list<tuple<string, string>>, worker-id: u32)`** — initializes from node key/value data and the worker ID.
* **`save-state() -> result<list<u8>, string>`** and **`restore-state(state: list<u8>) -> result<_, string>`** — serialize and restore plugin-owned runtime state.
* **`set-dst(mac: mac-addr, ip: ipv4-addr)`** — sets the destination; `mac-addr` is a tuple of six `u8` values and `ipv4-addr` is a tuple of four `u8` values.
* **`generate-batch(batch-bytes: list<u8>, umem-offset: u32) -> list<u32>`** — writes generated packet headers into the supplied empty PDU batch and returns packet lengths.

---

## 6. Verification & Tooling Commands

```bash
# Check the C ABI layout and Rust compile-time layout assertions
./abi/check_abi.sh

# Add the WASM Component Model target (once)
rustup target add wasm32-wasip2

# Build the SDK for Wasm
cargo build --release --target wasm32-wasip2

# Build wabrix_api for native (host side, with host internals exposed)
cargo build --release --features host

# Lint — wabrix_api native (default features)
cargo clippy

# Lint — wabrix_api with host internals exposed
cargo clippy --features host

# Lint — SDK on Wasm
cargo clippy --target wasm32-wasip2

# Plugin builds and tests run in ../wabrix_plugins; see its AGENTS.md.

# Note: the codebase has a pre-existing warning backlog across all targets.
# Run without -D warnings until the backlog is resolved. New code must add zero
# new warnings. Once the backlog is clear, add -- -D warnings to all commands above.

# Unit tests (native)
cargo test
```

---

## 7. AI Persona & Output Formatting

1. **Expert Systems Tone:** Do not explain basic Rust concepts (ownership, borrow checker, lifetimes). Assume the reader is a senior systems engineer fluent in Rust, Linux networking internals, and the WebAssembly Component Model.
2. **Hot-Path Change Rationale:** When suggesting modifications in batch callbacks, explicitly comment *why* the change avoids allocations, reduces branch mispredictions, or saves CPU cycles inside the WASM sandbox.
3. **Minimal Diffs:** When asked to fix a function, output only the relevant function or module diff — not the entire file.
4. **WIT Compatibility:** Before suggesting a new function or type, verify it is expressible in the current WIT type system. Do not silently introduce ABI-breaking changes to `wabrix.wit`.
5. **Preserve Batch Results:** Do not silently discard batch results: `process-batch` writes per-packet actions and updated lengths to the mailbox, and `generate-batch` returns generated packet lengths. The WIT does not define action-value semantics; follow the host contract for those values.
