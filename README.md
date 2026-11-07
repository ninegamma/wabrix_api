[![Wabrix Core](https://img.shields.io/badge/Engine-Wabrix-blue)](https://github.com/ninegamma/wabrix)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
# Wabrix API

**Wabrix API** provides the Rust bindings, traits, and SDK necessary to develop independent WebAssembly (Wasm) plugins for the [Wabrix Data Plane Engine](https://github.com/ninegamma/wabrix/blob/master/README.md).

Because Wabrix executes plugins as isolated, programmable execution units within its packet processing pipeline, this API allows developers to write custom network functions, telemetry extractors, and protocol parsers without modifying the core engine.

## 🔗 Related Repositories

* **[Wabrix (Main Engine)](https://github.com/ninegamma/wabrix):** The core high-performance AF_XDP and eBPF data plane engine.

---

## 🚀 Getting Started

To create a new Wabrix plugin, create a standard Rust library crate and add `wabrix_api` as a dependency.

### 1. Set up `Cargo.toml`

Configure your plugin to compile as a dynamic C-library (`cdylib`), which is required for WebAssembly components. See [wabrix_plugins/plugins](../wabrix_plugins/plugins) for examples.

### 2. Build the Plugin

Wabrix uses the WASI preview 2 standard for its execution environment. You must compile your plugins against the `wasm32-wasip2` target.

First, ensure the target is installed on your local toolchain:
```bash
rustup target add wasm32-wasip2
```

Next, compile your plugin:
```bash
cargo build --target wasm32-wasip2 --release
```

The resulting `.wasm` file will be located at `target/wasm32-wasip2/release/my_wabrix_plugin.wasm` and is ready to be loaded via your Wabrix TOML configuration.

## 🛠 Architecture

Wabrix plugins operate as nodes within a unified processing graph. By utilizing this API, your compiled `.wasm` modules can natively receive parsed network packets and events, interact with the engine's control plane via opcodes, and dispatch packets to subsequent routing nodes.

The generic SDK and plugin implementations live in separate Git repositories and Cargo workspaces:

* `wabrix_api` provides packet and header access, shared-memory layouts, mailbox
  batches, shared state, control opcodes, and `EngineTimerPlan`. It remains
  independent of plugin implementations.
* `wabrix_plugins` depends on `wabrix_api` and provides `tcp_common`,
  `connections`, and `engine_common`: the TCP state machine, connection pool,
  packet generator, configuration parsing, and engine control handling. It is
  `no_std` and can also be used by native engine nodes. Its sibling repository
  contains the example plugin crates under `plugins/`, with its own lockfile and
  Wasm build configuration.

Plugins using those implementations should add `wabrix_plugins` alongside
`wabrix_api` and import them through `wabrix_plugins::{tcp_common, connections,
engine_common}`. The generic timer plan is available as
`wabrix_api::EngineTimerPlan`. Filter and inspector plugins only need
`wabrix_api`.

The canonical WIT interfaces remain in `wit/wabrix.wit`. The plugin repository
uses a snapshot pinned to an SDK Git revision and SHA-256 checksum; its
`scripts/sync_wit.py` tool updates and verifies that snapshot. See the sibling
[plugin README](../wabrix_plugins/README.md) for plugin builds and diagnostics.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/ninegamma/wabrix_api/blob/master/LICENSE) file for details.
