# Wabrix WIT interface

This document describes [wit/wabrix.wit](wit/wabrix.wit), the canonical interface
between the Wabrix host and its WebAssembly components. Its package identifier is:

```wit
package wabrix:plugins@0.2.0;
```

The WIT package version is independent of the Rust SDK crate version. WIT defines
component imports, exports, function signatures, and exchanged value types.
Shared packet and mailbox memory has a separate byte-layout contract.

## Worlds and call directions

A WIT world selects the interfaces a component implements and the services it
expects from its host. Imports and exports below are from the plugin's perspective.

| World | Plugin exports, called by the host | Host services imported by the plugin |
| --- | --- | --- |
| `engine-plugin` | `packet-engine` | `logging`, `shared-state` |
| `generator-plugin` (deprecated) | `generator` | None declared in this world |

```wit
world engine-plugin {
    export packet-engine;
    import logging;
    import shared-state;
}

world generator-plugin {
    export generator;
}
```

TCP, filter, inspector, and `generator_engine.wasm` components use the engine
contract. The deprecated generator contract remains available for legacy
synthetic traffic generators and serialized state transfer during the
deprecation period.

### Generator-plugin deprecation and migration

**`generator-plugin` and its `generator` interface are deprecated and will be
removed in one of the next versions. Replace `generator_plugin.wasm` with
`generator_engine.wasm`.**

The replacement implements `engine-plugin`, exporting `packet-engine` and using
its timer/mailbox callbacks. New generator implementations should use that
world. Existing deployments must adapt their host node configuration and startup
parameters to the engine contract when switching artifacts; the worlds have
different callbacks and batch representations.

Build the replacement from the `wabrix_plugins` repository:

```bash
cargo build -p generator_engine --release --target wasm32-wasip2 --locked
```

The artifact is `target/wasm32-wasip2/release/generator_engine.wasm`. See the
[generator-engine configuration example](../wabrix/wabrix/examples/gen_engine.toml)
for the host engine-node setup. The legacy interface reference below documents
existing components until removal.

In the signatures below, `result<T, string>` returns either a successful value
or an error message. `result<_, string>` has no success payload. Generated Rust
bindings represent these results with `Result`; WIT names containing hyphens
become Rust names with underscores.

## `packet-engine`: host-to-plugin calls

### Initialization

```wit
init-data: func(data: list<tuple<string, string>>, tsc-frequency: u64) -> bool;
```

The host supplies startup configuration as key/value pairs and the TSC frequency
used for timer calculations. Initialize plugin configuration and runtime state
here. Return `true` on successful initialization and `false` on failure; packet
and timer processing requires a successfully initialized instance.

An engine that needs persistent shared state can call the imported
`shared-state.attach` service during initialization. Obtaining a state view and
having permission to dereference its payload are separate lifecycle steps; see
[shared state](#shared-state-plugin-to-host-calls).

### Packet batches

```wit
process-batch: func(batch-size: u32, umem-offset: u32, mailbox-offset: u32) -> u32;
```

This is the engine's zero-copy packet-processing entry point.

| Parameter | Meaning |
| --- | --- |
| `batch-size` | Number of active packet slots in this call, bounded by the SDK's `MAX_BATCH_SIZE` |
| `umem-offset` | Guest-linear base address of the shared packet-data UMEM |
| `mailbox-offset` | Guest-linear address of this instance's shared metadata mailbox |

The call follows this sequence:

1. The host fills the active mailbox descriptor slots with packet offsets,
   lengths, and metadata.
2. The plugin processes packet bytes through the shared UMEM mapping, updates
   descriptor lengths when it changes packet sizes, and writes an action for
   each packet into the mailbox's action array.
3. The plugin returns a batch status. Status `0` means success. The host reads
   the updated descriptors and actions from the same mailbox.

WIT specifies the parameter and status types. The numeric meanings of routing
actions and nonzero batch statuses belong to the host/plugin processing
contract; this interface declares no action enum or nonzero error-code table.

Rust plugins should use [`MailboxBatch`](src/mailbox_api.rs) and
[`Packet`](src/packet.rs) to access the host-provided memory. A descriptor's
`desc_addr` is UMEM-relative, so its packet-data address in guest memory is
`umem-offset + desc_addr`. The mailbox itself is addressed by `mailbox-offset`.
Keep packet borrows within the callback, populate parsed header metadata before
using typed header accessors, and preserve the descriptor's opaque host-only
padding.

### Timers

```wit
record timer-plan {
    timeout-frames: u32,
    packet-frames: u32,
}

process-timers: func(current-tsc: u64) -> timer-plan;
```

The host supplies the current TSC value. The plugin advances its timers and
requests frames for a subsequent batch:

- `timeout-frames` identifies work caused by timeouts, such as retransmissions.
- `packet-frames` identifies new packet-generation work, such as SYN generation.

These are requested frame counts before host allocation. Actual frame allocation
depends on the host. The SDK's [`EngineTimerPlan`](src/timers.rs) additionally
tracks allocation and routing information; the WIT record contains only the two
request counts above.

### Control events

```wit
on-control-event: func(opcode: u32, payload: list<u8>) -> bool;
```

The host sends a command number and an opaque byte payload. The plugin returns
whether it handled the event. Payload encoding and command-specific validation
are agreed between the host and plugin.

The SDK defines `StandardOpcode` and `PluginOpcode` in [src/lib.rs](src/lib.rs).
Its standard command space is `0x0000` through `0x0FFF`; custom plugin commands
start at `0x1000`. WIT carries the raw `u32` and bytes, so it does not validate
those opcode assignments or payload schemas.

### Telemetry

```wit
get-telemetry-schema: func() -> telemetry-schema;
get-telemetry: func() -> list<telemetry-metric>;
```

The schema describes the stable counter names and histogram definitions of an
initialized instance. Telemetry snapshots must use matching names and histogram
definitions. Counter entries retain their configured order. An empty metric list
means no snapshot is available for that poll.

```wit
record counter {
    name: string,
    value: u64,
}

record histogram {
    name: string,
    sum: u64,
    count: u64,
    buckets: list<u64>,
}

record histogram-schema {
    name: string,
    bucket-count: u32,
}

record telemetry-schema {
    counters: list<string>,
    histograms: list<histogram-schema>,
}

variant telemetry-metric {
    counter(counter),
    hist(histogram),
}
```

`counter` carries a named `u64` value. `histogram` carries a named cumulative
histogram with its sum, sample count, and bucket counts. The schema declares each
histogram's name and bucket count. Measurement units and bucket boundaries must
be agreed by the plugin and its consumers; these WIT records do not encode them.

### Shared-state upgrade callback

```wit
upgrade-shared-state: func(
    source-schema-version: u32,
    source-payload-size: u32
) -> result<_, string>;
```

During a compatible reload, the host stops the old runtime before calling this
function in the replacement instance. The arguments describe the existing
payload. The replacement may initialize appended fields only, preserving the
old payload prefix. The host commits the new schema version and payload size
only after the callback succeeds. An error string reports upgrade failure.

The full attach/upgrade sequence is described below.

## `logging`: plugin-to-host calls

```wit
log: func(level: u32, message: string);
```

An engine plugin uses this import to send a message to the host's logging
service. The level is a raw `u32`; WIT declares no logging-level enum or numeric
mapping. Use the level convention implemented by the host and the plugin's
logging adapter. This call has no return value.

## `shared-state`: plugin-to-host calls

```wit
attach: func(layout: state-layout) -> result<state-view, string>;
```

The plugin declares its fixed state layout. The host validates that declaration
against the region belonging to the reloadable node and returns a view into
guest linear memory or an error string. Active and staged instances can refer to
the same persistent payload across a reload.

### Layout declaration

```wit
record state-layout {
    type-id: list<u8>,
    schema-version: u32,
    payload-size: u32,
    reserved-capacity: u32,
    required-alignment: u32,
    compatible-source-versions: list<u32>,
}
```

| Field | Meaning |
| --- | --- |
| `type-id` | Exactly 16 bytes identifying the state type across plugin releases; the host checks the length of this WIT list |
| `schema-version` | Schema version the requesting plugin implements |
| `payload-size` | Number of bytes used by that schema |
| `reserved-capacity` | Capacity reserved for the payload and compatible future growth, in bytes |
| `required-alignment` | Required payload alignment, in bytes |
| `compatible-source-versions` | Older schema versions this plugin can extend compatibly |

### Returned view

```wit
record state-view {
    payload-offset: u32,
    payload-capacity: u32,
    current-schema-version: u32,
    current-payload-size: u32,
    is-new: bool,
    upgrade-required: bool,
}
```

| Field | Meaning |
| --- | --- |
| `payload-offset` | Guest-linear address of the payload, after the host-owned header |
| `payload-capacity` | Available payload capacity in bytes |
| `current-schema-version` | Schema version currently committed in the region |
| `current-payload-size` | Payload size currently committed in the region |
| `is-new` | The region is newly created and needs the plugin's initial payload setup |
| `upgrade-required` | The current payload needs a compatible upgrade before the target schema can be used |

The host writes the header for a fresh region. A returned offset is local to
the calling instance's linear memory; keep it separate from host-native pointers
and UMEM-relative packet offsets.

### Access and reload lifecycle

1. The new instance declares its layout with `attach`. The returned view states
   whether the region is new, already compatible, or requires an upgrade.
2. The plugin initializes a fresh payload when `is-new` is set. For an existing
   region, staging must preserve the active instance's state.
3. Shared payload access follows a single-active-writer lifecycle. A staged
   instance may retain its validated view while the old runtime is active, but
   must wait for the appropriate lifecycle checkpoint before accessing it.
4. If an append-compatible upgrade is required, the host quiesces the old
   runtime and calls the replacement's `upgrade-shared-state` callback.
5. After a successful upgrade, the host commits the new header schema and size
   before the replacement processes packets using its target layout.

[`SharedState<T>`](src/shared_state.rs) provides Rust size/alignment validation
and typed access. Its safety contract still requires exclusive lifecycle access.
Use a fixed-layout type with fixed-width fields and arrays; keep pointers,
references, and allocation-owning Rust values out of the persistent payload.
When `upgrade-required` is true, initialize appended fields before dereferencing
the payload as the complete target type.

## `generator`: host-to-plugin calls (deprecated)

This interface belongs to the deprecated `generator-plugin` world. Migrate from
`generator_plugin.wasm` to `generator_engine.wasm` as described in the
[migration guide](#generator-plugin-deprecation-and-migration).

The generator world uses serialized batch descriptors and returns packet lengths.
Its state-transfer callbacks exchange plugin-owned bytes.

### Initialization

```wit
init-data: func(data: list<tuple<string, string>>, worker-id: u32);
```

Initialize generator configuration and worker-specific sequence state. This
callback receives a worker ID and has no return value. The engine world's
initialization callback instead receives the TSC frequency and returns a boolean.

### Saving and restoring state

```wit
save-state: func() -> result<list<u8>, string>;
restore-state: func(state: list<u8>) -> result<_, string>;
```

`save-state` serializes plugin-owned state for transfer to a replacement instance.
`restore-state` accepts a snapshot produced by a compatible plugin version.
Serialization format and version compatibility are the plugin's responsibility;
failures are returned as strings. These callbacks are a separate state-transfer
mechanism from the engine world's host-managed shared-state region.

### Destination addresses

```wit
type ipv4-addr = tuple<u8, u8, u8, u8>;
type mac-addr = tuple<u8, u8, u8, u8, u8, u8>;

set-dst: func(mac: mac-addr, ip: ipv4-addr);
```

Set the packet destination using six MAC-address octets and four IPv4-address
octets. The interface passes address bytes rather than textual address strings.

### Generating packets

```wit
generate-batch: func(batch-bytes: list<u8>, umem-offset: u32) -> list<u32>;
```

The host supplies an empty PDU batch encoded as bytes and the guest-linear UMEM
base offset. The plugin writes generated packet headers into the identified
packet buffers and returns packet lengths in batch order. The returned list
contains lengths, whereas the engine callback writes routing actions into its
mailbox and returns a batch status.

WIT declares `batch-bytes` as an opaque byte list. Interpret its descriptor
encoding according to the host and SDK memory contract.

## WIT values, shared memory, and ABI checks

WIT records, variants, strings, and lists cross the Component Model boundary
through generated canonical-ABI bindings. Packet bytes, descriptors, mailbox
actions, and persistent payload bytes are accessed through their shared-memory
contracts. WIT's `u32` offset parameters refer to guest linear memory.

The SDK defines the raw layouts in [src/shared_memory.rs](src/shared_memory.rs)
and [abi/wabrix_shared_memory.h](abi/wabrix_shared_memory.h). Cargo's build script
and Rust compiler check their declared constants and layouts; run
`./abi/check_abi.sh` to invoke those checks explicitly. See the
[README ABI guide](README.md#automatic-shared-memory-abi-checks) for prerequisites,
coverage, and native/Wasm verification commands.

Coordinate WIT signature changes with host and guest binding generation.
Coordinate shared-memory layout changes with both sides of the memory contract.
The shared-memory checks and the WIT package version cover these respective
compatibility concerns.

## Generating guest bindings

Plugin crates live in the independent `wabrix_plugins` repository. A crate under
`wabrix_plugins/plugins/<name>/` can generate bindings from that repository's
versioned WIT snapshot with:

```rust
wit_bindgen::generate!({
    path: "../../wit/wabrix.wit",
    world: "engine-plugin",
});
```

Use `engine-plugin` for new generators, following `generator_engine.wasm`.
The deprecated `generator-plugin` world is retained for existing components
until its removal. Implement the generated guest traits and use the generated
export macro for the selected world. Keep the SDK's `host` feature reserved for
the native host.

The canonical interface is maintained in this repository. The plugin repository
records its snapshot's SDK Git revision and checksum alongside its local WIT
file. Keep the snapshot and bindings aligned when releasing interface changes.
