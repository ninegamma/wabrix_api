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

### Generator Runtime Diagnostics

The example `generator_engine` plugin provides an optional
`runtime-diagnostics` feature for investigating timer-based rate control. It
adds completion-time counters for `process_timers()` calls, credited timer
cycles, requested frames, timer timestamps, the final cycle accumulator, and
available/final-frame histograms. The feature is disabled by default to keep
the normal plugin build free of diagnostic counter updates.

Build it with:

```bash
cargo build -p generator_engine --target wasm32-wasip2 --release \
  --features runtime-diagnostics
```

Host-side final timer summaries are controlled separately by the Wabrix engine’s
`runtime-diagnostics` feature.

## 🛠 Architecture

Wabrix plugins operate as nodes within a unified processing graph. By utilizing this API, your compiled `.wasm` modules can natively receive parsed network packets and events, interact with the engine's control plane via opcodes, and dispatch packets to subsequent routing nodes.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/ninegamma/wabrix_api/blob/master/LICENSE) file for details.
