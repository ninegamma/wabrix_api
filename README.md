[![Wabrix Core](https://img.shields.io/badge/Engine-Wabrix-blue)](https://github.com/ninegamma/wabrix)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
# Wabrix API

`wabrix_api` is the generic, `no_std` Rust SDK shared by the Wabrix native host
and its WebAssembly plugins. With version >= 0.7 it is a standalone Cargo package with
`Cargo.toml` and `src/` at the repository root.

The SDK provides packet and header access, shared-memory mailbox layouts,
shared-state access, control opcodes, and timer types. The canonical WIT
interfaces and C declarations of the shared-memory ABI also live here.

## Repository boundaries

The project is split into three independent repositories:

| Repository | Responsibility |
| --- | --- |
| [wabrix](https://github.com/ninegamma/wabrix) | Native AF_XDP data plane, pipeline engine, Wasm runtime, and management binary |
| [wabrix_api](https://github.com/ninegamma/wabrix_api) | Generic SDK, canonical WIT interfaces, shared-memory layouts, and ABI checks |
| [wabrix_plugins](https://github.com/ninegamma/wabrix_plugins) | Reusable TCP/generator implementations and the TCP, generator, filter, and inspector plugin crates |

Plugin implementations and plugin crates live in the sibling
[wabrix_plugins repository](../wabrix_plugins/README.md), which has its own
workspace, lockfile, and Wasm build settings. Dependencies flow from plugins to
`wabrix_api`, optionally through the `wabrix_plugins` library. The SDK remains
independent of plugin implementations.

```text
wabrix_api/
├── Cargo.toml                  # Standalone SDK package
├── build.rs                    # Automatic shared-memory ABI checks
├── src/
│   ├── lib.rs                  # Public API and host-only layout exports
│   ├── packet.rs               # Packet and packet-batch access
│   ├── mailbox_api.rs          # MailboxBatch and MailboxPacket
│   ├── shared_memory.rs        # Raw layouts and Rust compile-time assertions
│   ├── shared_state.rs         # Typed shared-state access
│   ├── timers.rs               # EngineTimerPlan
│   └── headers/                # Header access, checksums, and flow helpers
├── abi/
│   ├── wabrix_shared_memory.h  # C shared-memory declarations and assertions
│   ├── layout_check.c          # C11 layout-check translation unit
│   ├── check_abi_consistency.py
│   └── check_abi.sh            # Cargo-based ABI verification wrapper
├── wit/wabrix.wit              # Canonical Component Model interfaces
└── aliasing_guidelines.md      # SDK design notes
```

## Prerequisites

These tools must be available on the build machine, including when
`wabrix_api` is compiled as a dependency of the host or a plugin:

- Rust and Cargo; a current stable toolchain installed through `rustup` is
  recommended. The package uses Rust edition 2021.
- Python 3, available as `python3`. The ABI checker uses only the Python
  standard library.
- A C11 compiler and standard C development headers. GCC or Clang supports
  the command-line options and 64-byte alignment used by the layout checks.
  The compiler defaults to `cc`; set `CC` to another compiler executable or
  executable path when needed.
- Git and access to the Git/crates.io dependencies for the initial Cargo fetch.
- Bash to run `abi/check_abi.sh`.

For Debian, Ubuntu, or Linux Mint, the native prerequisites can be installed
with:

```bash
sudo apt-get update
sudo apt-get install build-essential python3 bash git
```

Install the Wasm target when building the SDK or plugin components for WASI 0.2:

```bash
rustup target add wasm32-wasip2
```

The C check runs on the build host in syntax-only mode. A native GCC or Clang
compiler is sufficient when compiling the Rust SDK for `wasm32-wasip2` as well.

## Using the SDK

A plugin can depend on the SDK directly:

```toml
[dependencies]
wabrix_api = { git = "https://github.com/ninegamma/wabrix_api.git", branch = "main", version = "0.7" }

[patch.crates-io]
network-types = { git = "https://github.com/ninegamma/network-types.git", branch = "zerocopy" }
```

Apply the `network-types` patch in the consuming workspace's root manifest,
as the host and plugin workspaces do. Cargo uses patches from the build's root
manifest rather than a dependency's manifest.

Plugin crates use the public packet, mailbox, and shared-state APIs. Reserve
the `host` feature for the native host: it re-exports `PduCore`, `SharedPdu`,
and `HeaderStack` at the crate root for low-level layout access. `PduCore`
replaces the historical `WPdu` name; `SharedPdu` replaces `Pdu0`.

Build and check this SDK from the repository root:

```bash
cargo check --locked
cargo build --release --locked --features host
cargo check --locked --target wasm32-wasip2
cargo test --locked
```

`wabrix_api` builds as a Rust library. Build loadable Wasm components from the
separate plugin repository:

```bash
cd ../wabrix_plugins
cargo build --workspace --release --target wasm32-wasip2 --locked
```

Component artifacts are written to that repository's
`target/wasm32-wasip2/release/` directory. See the
[plugin README](../wabrix_plugins/README.md) for plugin configuration and
runtime diagnostics.

## Automatic shared-memory ABI checks

The host and guest exchange packet descriptors and actions through shared
Wasm linear memory. Their Rust and C representations must agree on numeric
constants, field offsets, sizes, and alignment.

Cargo builds and checks this package, including dependency builds, through
three complementary checks. [`build.rs`](build.rs) runs the first two; the
Rust compiler evaluates the third:

1. Run [`abi/check_abi_consistency.py`](abi/check_abi_consistency.py) with
   `python3`. It compares the batch/header limits, `HeaderKind` values and
   compatibility aliases, and paired layout-assertion values in the C header
   and Rust sources. It also checks the mailbox action offset and total size.
2. Compile [`abi/layout_check.c`](abi/layout_check.c) with the selected C
   compiler using `-std=c11 -Wall -Wextra -Werror -fsyntax-only`. This evaluates
   the C header's static size, alignment, offset, and capacity assertions
   without generating an object file.
3. Evaluate the SDK's Rust layout assertions in
   [`src/shared_memory.rs`](src/shared_memory.rs) for the selected Rust target.
   These check `HeaderStack`, `PduCore`, `SharedPdu`, and the mailbox layout.

A missing tool, numeric mismatch, or failed layout assertion causes Cargo to
fail. The build script includes the failed check's output in its diagnostic.
Cargo reruns the build-script checks when the watched ABI files, Rust layout
or header-kind definitions, `CC`, or `WABRIX_API_ABI_VERBOSE` change; otherwise
it can reuse the previous successful result.

Successful build-script checks are quiet by default. To show their success
messages as Cargo warnings, run:

```bash
WABRIX_API_ABI_VERBOSE=1 cargo check --locked
```

### Running the ABI check explicitly

From the SDK repository root, run:

```bash
./abi/check_abi.sh
```

The Bash wrapper locates the SDK root and invokes `cargo check --locked` with
`WABRIX_API_ABI_VERBOSE=1`. This uses the same automatic C/Rust consistency,
C layout, and Rust compilation checks, prints PASS or FAIL, and returns a
nonzero status on failure. Its Cargo check uses the native Rust target unless
Cargo configuration or the environment selects another target. Verify the Wasm
Rust layout explicitly with
`cargo check --locked --target wasm32-wasip2`.

To select Clang instead of the default `cc`:

```bash
CC=clang ./abi/check_abi.sh
```

`CC` selects a single compiler executable, rather than a command plus flags.
The build script supplies the compiler arguments.

For focused checks, run the underlying stages directly:

```bash
python3 abi/check_abi_consistency.py
cc -std=c11 -Wall -Wextra -Werror -I abi -fsyntax-only abi/layout_check.c
```

Those focused commands cover the source-level numeric comparison and C
assertions. A Cargo check also compiles the Rust assertions. When changing a
shared-memory layout, update both language representations and their assertions
and extend the consistency checker for new fields or header kinds.

## WIT interfaces and shared state

See [wit_doc.md](wit_doc.md) for the complete interface guide, including callback
signatures, telemetry types, and the shared-state reload lifecycle.

[`wit/wabrix.wit`](wit/wabrix.wit) defines the Component Model package
`wabrix:plugins@0.2.0`. Its `engine-plugin` world exports `packet-engine` and
imports `logging` and `shared-state`; `generator-plugin` exports `generator`.
Plugin crates generate bindings for their selected world with `wit-bindgen`.

**`generator-plugin` and its `generator` interface are deprecated and will be
removed in one of the next versions. Replace `generator_plugin.wasm` with
`generator_engine.wasm`, which uses the `engine-plugin` world.** See the
[migration guide](wit_doc.md#generator-plugin-deprecation-and-migration) for the
corresponding host configuration and callback changes.

The C header and layout checks describe bytes in shared linear memory. WIT
records and function signatures use the Component Model's canonical ABI.
The automatic shared-memory checks cover the declared numeric comparisons
and compiler layout assertions; WIT interface compatibility and shared-state
schema upgrades follow their respective contracts.

The plugin repository maintains a WIT snapshot with its SDK origin revision,
version, and SHA-256 checksum. Its `scripts/sync_wit.py` tool manages that snapshot;
the canonical interface remains in this SDK repository. Commit canonical WIT
changes here before updating the plugin snapshot. The check requires a
Cargo-compatible SDK version; the SDK dependency may use another commit or a
compatible local path checkout. Breaking WIT changes must also bump the SDK's
compatibility series. See
[`SharedState`](src/shared_state.rs) and the WIT `shared-state` interface for
shared-state layout declarations and compatible upgrades.

## License

MIT; see [LICENSE](LICENSE).
