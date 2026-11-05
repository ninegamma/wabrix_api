# AGENTS.md — AI Assistant Project Constitution

## 1. Project Overview & Philosophy

The project is split into two repositories:

* **wabrix:** Contains the code for the platform of the dataplane engine.
* **wabrix_api:** Contains the public SDK for creating WASM plugins for the wabrix platform (includes `wabrix_api` crate and `.wit` interface definitions).

These repositories implement a high-performance, software-based networking engine/router. The system processes packets at high throughput (target: 25 Gbps – 100 Gbps) using Linux kernel-bypass via AF_XDP, and features a sandboxed WebAssembly plugin architecture for data-plane programmability.

**Core Engineering Principles:**
1. **Zero-Copy First:** Memory allocations inside the packet processing hot-path are strictly prohibited.
2. **Predictable Latency:** Favor deterministic execution paths over peak theoretical throughput.
3. **Strict Memory Safety:** Leverage Rust's type system to guarantee safety across the Native ↔ Wasm boundary.


***This file is for the wabrix_api repository, only.***

---

## 2. Workspace Structure & Module Boundaries

The `wabrix_api` workspace (`Cargo.toml` at the root) contains one library crate and four example plugin crates:

```
wabrix_api/
├── wabrix_api/          # Core SDK library: Packet<'a>, HeaderStack, protocol headers, routing types
├── plugins/
│   ├── tcp_engine/            # Example engine plugin: implements the packet-engine WIT interface
│   └── generator_plugin/      # Example generator plugin: implements the generator WIT interface
└── wit/
    └── wabrix.wit            # WIT interface definitions (inspector, packet-engine, generator, logging)
```

### Crate responsibilities & allowed dependencies

| Crate | Role | May depend on |
|---|---|---|
| `wabrix_api` | Core SDK: `Packet<'a>`, `HeaderStack`, protocol header structs, routing result types, `StandardOpcode`; `no_std` compatible | `network-types`, `macaddr`, `byteorder`, `fnv`, `anyhow` |
| `plugins/tcp_engine` | Example `engine-plugin`: implements `process-batch`, `process-timers`, `on-control-event`, `get-telemetry` | `wabrix_api`, `wit-bindgen`, `spin`, `network-types` |
| `plugins/generator_plugin` | Example `generator-plugin`: implements `generate-batch` | `wabrix_api`, `wit-bindgen`, `network-types`, `macaddr`, `spin` |

**Dependency direction is strictly one-way:** all plugin crates → `wabrix_api`. Never introduce reverse or circular dependencies.

### Key source files

| File | Contains |
|---|---|
| `wit/wabrix.wit` | WIT interface definitions: `inspector`, `packet-engine`, `generator`, `logging`; three worlds: `filter-plugin`, `generator-plugin`, `engine-plugin` |
| `wabrix_api/src/lib.rs` | Crate root: `TELEMETRY_FLAG`, `StandardOpcode`, module declarations |
| `wabrix_api/src/packet.rs` | `Packet<'a>` — safe high-level view over a mutable `Pdu0` + UMEM base address; primary plugin-facing API |
| `wabrix_api/src/hstack.rs` | `HeaderStack` — fixed-capacity (5 slots) parsed header descriptor; exactly 16 bytes |
| `wabrix_api/src/headers/` | Zero-copy header structs: `EthHeader`, `IpHeader`, `TcpHeader`, `UdpHeader`, `IcmpHeader`, `ArpIpv4Header`, `Ipv6Header` |
| `wabrix_api/src/exports.rs` | Visibility gating for `Pdu0` / `HeaderStack`: `pub` when `host` feature enabled, `pub(crate)` otherwise |
| `wabrix_api/src/wpdu_impl.rs` | `Pdu0` internals: raw PDU layout, `parse_fast`, `data_ptr`, `push_header` |
| `wabrix_api/src/helpers.rs` | Checksum helpers and other protocol utilities |

---

## 3. Technical Stack & Hard Boundaries

### Language & Compiler
* **Language:** Rust (Edition 2021).
* **`no_std`:** `wabrix_api` is `#![no_std]` (uses `extern crate alloc`). Never introduce `std`-only dependencies into it.
* **Linting:** Run `cargo clippy -p wabrix_api` (native) and `cargo clippy --target wasm32-wasip2` (WASM plugins). The codebase has a pre-existing warning backlog; `-D warnings` is the goal once that backlog is cleared. Until then, **new code must introduce zero new warnings** on either target. Do not use `#[allow(...)]` without a comment explaining why it is unavoidable.

### Plugin Build Target
* **Target:** `wasm32-wasip2` (WASI 0.2 / Component Model). All plugin crates are compiled as `crate-type = ["cdylib"]`.
* **FORBIDDEN:** Do NOT use `std::net`, OS threads, file I/O, or any syscall that is not available in the WASI Component Model sandbox.

### WIT Interface Standard
* **Bindgen:** `wit-bindgen` generates WASM guest bindings from `wit/wabrix.wit`. Import it at the top of each plugin's `lib.rs` via `wit_bindgen::generate!`.
* **Interface selection:** Implement exactly the WIT world that matches the plugin type (`filter-plugin`, `generator-plugin`, or `engine-plugin`). Do not mix world exports.
* The `.wit` file is the source of truth for the host/plugin ABI. Never hand-code the ABI.

### Plugin State
* **`spin::Mutex`** — use for `static` plugin state in `no_std` contexts (e.g., `static STATE: spin::Mutex<Option<PluginState>> = spin::Mutex::new(None)`).
* Initialize state in the `init-data` callback; all subsequent batch callbacks must assume it is already initialized.

### Key External Crates
* `wit-bindgen` — generates WASM guest bindings from `.wit` files.
* `spin` — `no_std`-safe `Mutex`/`Once` for static plugin state.
* `network-types` — zero-copy Ethernet/IP/UDP/TCP header structs.
* `macaddr` — MAC address type with no `std` dependency.
* `anyhow` — error handling in `wabrix_api` (cold-path only).

---

## 4. Coding Commandments

### A. The Hot Path (Batch Callbacks)

When writing or refactoring code inside `inspect-batch`, `process-batch`, or `generate-batch`:

* **No Per-Packet Allocations:** A single `Vec::with_capacity(batch.len())` to hold the return values is acceptable (one allocation per batch call, not per packet). Never use `Box`, `Vec::push` on a growing `Vec`, `String::new`, or `Arc::new` inside the per-packet loop body. Use pre-allocated buffers, stack arrays, or state initialized in `init-data` for anything inside the loop.
* **No Panics:** Never `.unwrap()` or `.expect()` on the hot path. Handle malformed packets by returning a drop action and optionally setting `TELEMETRY_FLAG`.
* **No Dynamic Dispatch:** Avoid `dyn Trait` on the hot path; prefer generics or enum dispatch so the compiler can inline and devirtualize.
* **Parse Before Access:** Before accessing `packet.headers()` or any typed header accessor, the `HeaderStack` must be populated. Two valid ways to satisfy this:
  1. Call `packet.parse_fast()` explicitly at the start of the per-packet loop body (safe default — idempotent, ~5 ns overhead).
  2. Rely on a **FastParse pipeline node** placed before this WASM node in the host's processing graph. In that case the host has already populated the `HeaderStack` and a second call is unnecessary — but this is a deployment contract, not a code guarantee. If unsure, call `parse_fast()`.
  Accessing header offsets on an unparsed `Packet` (all offsets zero, `hc == 0`) silently returns `None` from all typed accessors — wrong results, not a crash.
* **Fingerprint First:** Use `headers().fingerprint()` against constants like `Packet::TCP_OVER_IPV4` for branch-free protocol detection. Do not iterate header slots manually.

### B. The Cold Path (init-data, on-control-event)

Standard Rust ergonomics apply. Heap allocations and `anyhow`-based error handling are permitted. `on-control-event` must still return promptly and must not block.

### C. Unsafe Code Guidelines

* `unsafe` is restricted to: raw pointer arithmetic over WASM linear memory when reading/writing batch bytes, and low-level `Pdu0` internals in `wpdu_impl.rs`.
* **MANDATORY:** Every `unsafe` block must be preceded by a `// SAFETY:` comment explicitly proving why the operation cannot violate memory boundaries.

### D. The `host` Feature Flag

* The `host` feature on `wabrix_api` exposes `Pdu0` and `HeaderStack` internals publicly — it is **reserved for the host engine** (`wabrix` repo) only.
* **NEVER** enable `host` in a plugin's `Cargo.toml`. Plugins must only use the `Packet<'a>` API surface.

### E. Unrequested Code Changes

* **NEVER** change fundamental structs and interfaces except if explicitly requested. In case you need to do the change, ask for permission with the exact reasoning.

---

## 5. Plugin API Quick Reference

> Full WIT definition: `wit/wabrix.wit`

* **`inspect-batch(batch_bytes, umem_offset) -> list<u32>`** — called on each burst for `filter-plugin` and `inspector` nodes. `umem_offset` is the positive Wasm-linear offset where the shared UMEM begins. Each `u32` in the return list is a routing action for the corresponding PDU: lower 8 bits = route ID, bit 8 = `TELEMETRY_FLAG`.
* **`process-batch(batch_bytes, umem_offset) -> (list<u32>, list<u32>)`** — called on each burst for `engine-plugin` nodes. `umem_offset` is the positive Wasm-linear offset where the shared UMEM begins. Returns routing actions (same encoding as above) plus new packet lengths (for plugins that modify packet size).
* **`generate-batch(batch_bytes, umem_offset) -> list<u32>`** — called on each burst for `generator-plugin` nodes. `umem_offset` is the positive Wasm-linear offset where the shared UMEM begins. Writes packet headers into the provided buffer and returns the length of each generated packet.
* **`process-timers(current_tsc) -> u32`** — called periodically for `engine-plugin` to drive timer wheels (e.g., TCP retransmit). Returns the number of frames needed for timer-triggered transmits.
* **`on-control-event(opcode, payload) -> bool`** — receives control plane commands. Opcodes 0x0000–0x0FFF are reserved `StandardOpcode` values; plugin-specific opcodes must start at 0x1000. Return `true` if the opcode was handled.
* **`get-telemetry() -> list<u64>`** — returns out-of-band counters. If the list is empty, the host falls back to in-band (upper 16 bits of routing actions) telemetry.
* **`init-data(data: list<tuple<string, string>>)`** — called once at startup with key/value config from the TOML `node_data` field. Initialize all plugin state here.

---

## 6. Verification & Tooling Commands

```bash
# Add the WASM Component Model target (once)
rustup target add wasm32-wasip2

# Build all plugins as WASM components
cargo build --release --target wasm32-wasip2

# Build wabrix_api for native (host side, with host internals exposed)
cargo build --release -p wabrix_api --features host

# Lint — wabrix_api native (default features)
cargo clippy -p wabrix_api

# Lint — wabrix_api with host internals exposed
cargo clippy -p wabrix_api --features host

# Lint — all WASM plugin crates
cargo clippy --target wasm32-wasip2

# Note: the codebase has a pre-existing warning backlog across all targets.
# Run without -D warnings until the backlog is resolved. New code must add zero
# new warnings. Once the backlog is clear, add -- -D warnings to all commands above.

# Unit tests (native)
cargo test
```

---

## 7. AI Persona & Output Formatting

1. **Expert Systems Tone:** Do not explain basic Rust concepts (ownership, borrower checker, lifetimes). Assume the reader is a senior systems engineer fluent in Rust, Linux networking internals, and the WebAssembly Component Model.
2. **Hot-Path Change Rationale:** When suggesting modifications in batch callbacks, explicitly comment *why* the change avoids allocations, reduces branch mispredictions, or saves CPU cycles inside the WASM sandbox.
3. **Minimal Diffs:** When asked to fix a function, output only the relevant function or module diff — not the entire file.
4. **WIT Compatibility:** Before suggesting a new function or type, verify it is expressible in the current WIT type system. Do not silently introduce ABI-breaking changes to `wabrix.wit`.
5. **No Silent Drops:** Never suggest code that discards a PDU routing result without either returning a drop action (0) or setting `TELEMETRY_FLAG` and accounting for it in a counter.
