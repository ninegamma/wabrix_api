[![Wabrix Core](https://img.shields.io/badge/Engine-Wabrix-blue)](https://github.com/ninegamma/wabrix)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
# Wabrix API

**Wabrix API** provides the Rust bindings, traits, and SDK necessary to develop independent WebAssembly (Wasm) plugins for the [Wabrix Data Plane Engine](https://github.com/ninegamma/wabrix/blob/main/README.md).

Because Wabrix executes plugins as isolated, programmable execution units within its packet processing pipeline, this API allows developers to write custom network functions, telemetry extractors, and protocol parsers without modifying the core engine.

## 🔗 Related Repositories

* **[Wabrix (Main Engine)](https://github.com/ninegamma/wabrix):** The core high-performance AF_XDP and eBPF data plane engine.

---

## 🚀 Getting Started

To create a new Wabrix plugin, create a standard Rust library crate and add `wabrix_api` as a dependency.

### 1. Set up `Cargo.toml`

Configure your plugin to compile as a dynamic C-library (`cdylib`), which is required for WebAssembly components. See wabrix_api/plugins for examples.

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

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/ninegamma/wabrix_api/blob/master/LICENSE) file for details.
