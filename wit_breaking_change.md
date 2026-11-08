# Making a breaking WIT API change

This is the maintainer workflow for changing the contract between the Wabrix
host and Wasm plugins. Changes to function signatures, imported/exported
interfaces, worlds, or exchanged record/variant definitions can require changes
on both sides. Coordinate the SDK, plugins, and native host as one release.

The order is: commit and publish the canonical SDK interface, synchronize and
adapt plugins, update the host, test the host/component combinations, then
release the matching artifacts.

## 1. Prepare the repositories and choose versions

Use sibling checkouts for this workflow:

```text
wabrix_prj/
├── wabrix_api/       # Canonical WIT and generic Rust SDK
├── wabrix_plugins/   # WIT snapshot and plugin implementations
└── wabrix/           # Native host and Wasmtime bindings
```

Start from clean working trees on your development/release branches. The shell
blocks below run in the same Bash session; replace the example root path. Run
them in order and stop to resolve any failed command before proceeding:

```bash
WABRIX_ROOT=/path/to/wabrix_prj
git -C "$WABRIX_ROOT/wabrix_api" status --short
git -C "$WABRIX_ROOT/wabrix_plugins" status --short
git -C "$WABRIX_ROOT/wabrix" status --short
rustup target add wasm32-wasip2
```

Install Rust/Cargo, Git, Python 3.11+, Bash, and a C11 compiler (`cc`, or the
executable selected by `CC`). Building the native host also needs the tools and
libraries listed in its README, including Clang/LLVM, libelf, zlib, and libpcap.
Maintainers need permission to publish changes through each repository's normal
review process. Plugin consumers only need read access to fetch the SDK.

Choose the versions before editing. The following are examples for the current
pre-1.0 versions, not values that the sync script chooses automatically:

| Version | Example | Action |
| --- | --- | --- |
| WIT package | `wabrix:plugins@0.2.0` to `wabrix:plugins@0.3.0` | Bump for the breaking component contract. |
| Rust SDK crate | `wabrix_api` `0.7.0` to `0.8.0` | Bump the compatibility series for breaking WIT or public Rust API changes. |
| Plugins and host | Their respective release versions | Update according to their public API and release policy. |

After 1.0, use a major version bump for breaking public APIs. Changing a version
alone does not provide an adapter or migrate existing components or state.
The WIT and SDK version numbers are independent, but the SDK version check uses
Cargo's default caret rules. For example, snapshot SDK `0.7.0` permits compatible
`0.7.x` releases and rejects `0.8.0`. A breaking WIT change therefore also needs
a breaking SDK version bump, even if the Rust signatures are unchanged.

## 2. Change and validate the canonical SDK

```bash
cd "$WABRIX_ROOT/wabrix_api"
```

Edit `wit/wabrix.wit`, including its `package` version. Update `wit_doc.md`, SDK
code affected by the new contract, the package version in `Cargo.toml`, and
release/migration notes. Describe the old/new signatures, changed semantics,
and the host/plugin versions that can interoperate.

Treat shared-memory layout and persistent-state changes separately. If packet
or mailbox bytes change, update the Rust declarations, C declarations in
`abi/`, and their assertions/checker together. Review the shared-memory ABI
version when applicable. If plugin-owned shared state changes, define its
schema/version and migration or reset policy before rollout. A WIT version bump
does not validate either byte-layout compatibility or state migration.

Refresh the SDK lockfile after changing its package version, then validate:

```bash
cargo check
./abi/check_abi.sh
cargo test --all-features --locked
cargo check --features host --locked
cargo check --target wasm32-wasip2 --locked
cargo clippy --all-targets --all-features --locked
cargo clippy --target wasm32-wasip2 --locked
git diff --check
git diff
```

`build.rs` and `abi/check_abi.sh` check C/Rust shared-memory declarations and
layout assertions. They do not prove WIT compatibility or exercise a host with
a component. Binding compilation and runtime tests follow below.

Stage the changed SDK files, including any migration/release notes:

```bash
git add Cargo.toml Cargo.lock wit/wabrix.wit wit_doc.md src abi
git diff --cached --check
git diff --cached
git commit -m "Introduce the next breaking WIT contract"
git push -u origin HEAD
```

Complete the SDK review/merge and select the published SDK checkout containing
the new contract before syncing the plugin snapshot. `sync_wit.py` records its
`HEAD` as snapshot provenance:

```bash
git show --stat HEAD
```

Publish the SDK changes on the branch consumers use (`main` in the examples).
Dependencies use a Cargo version requirement and can advance to later compatible
commits. If further changes affect the WIT snapshot or its minimum SDK version,
repeat the sync and validation below. An ordinary compatible SDK implementation
change does not require refreshing the snapshot.

## 3. Synchronize and adapt the plugins

```bash
cd "$WABRIX_ROOT/wabrix_plugins"
python3 scripts/sync_wit.py --source ../wabrix_api
```

This updates `wit/wabrix.wit` and `wit/source.lock.json`. It requires committed
canonical WIT changes. Update `[workspace.dependencies].wabrix_api` in
`Cargo.toml` to the new Cargo compatibility series, keeping the development
branch. Remove any exact `rev` selector. For the example SDK release above:

```toml
wabrix_api = { git = "https://github.com/ninegamma/wabrix_api.git", branch = "main", version = "0.8" }
```

Compatible local SDK path patches/overrides are allowed while prototyping.
Disable them when validating what other developers will fetch from Git. Do not
edit the generated snapshot or its checksum to resolve an integrity failure;
fix the SDK source and sync it.

```bash
cargo update -p wabrix_api
python3 scripts/sync_wit.py --check
```

Adapt each affected implementation under `plugins/` and reusable code under
`src/` to the new callbacks/types. Update tests and startup configuration as
needed. `wit-bindgen` regenerates bindings when the plugins compile; implement
the new generated traits rather than hand-editing bindings. Update the plugins'
release version in `[workspace.package]` when appropriate.

New generators use `engine-plugin`. If this change removes the deprecated
`generator-plugin` world, also remove its `generator_plugin` member and build
references, and migrate deployments to `generator_engine.wasm`.

Refresh local package versions in the lockfile and run the plugin checks:

```bash
cargo check --workspace --all-features
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/sync_wit.py --check
cargo test --workspace --all-features --locked
cargo clippy -p wabrix_plugins --all-targets --locked
cargo clippy --workspace --all-features --target wasm32-wasip2 --locked
cargo build --workspace --release --target wasm32-wasip2 --all-features --locked
git diff --check
```

The WIT check verifies the snapshot hash and that Cargo's resolved SDK version
satisfies the snapshot's caret requirement. Cargo also checks the manifest's
dependency range. Git revisions and SDK WIT bytes are not compared. `Cargo.lock`
still records the selected commit for reproducible builds, but that commit need
not match the snapshot's recorded origin. Cargo may download dependencies; it
only reads the remote repository. With dependencies cached, use
`CARGO_NET_OFFLINE=true python3 scripts/sync_wit.py --check`.

Commit the manifest, dependency lock, snapshot, and provenance lock together
with the implementation and documentation changes:

```bash
git add Cargo.toml Cargo.lock wit/wabrix.wit wit/source.lock.json src plugins
# Also stage the changed tests, documentation, and release notes.
git diff --cached --check
git diff --cached
git commit -m "Adapt plugins to the next WIT contract"
git push -u origin HEAD
```

## 4. Align and rebuild the native host

```bash
cd "$WABRIX_ROOT/wabrix"
python3 ../wabrix_plugins/scripts/sync_wit.py --check --source ../wabrix_api
```

The current host's
`wabrix_wasm/src/wasm_engine.rs` generates Wasmtime bindings from
`../../wabrix_api/wit/wabrix.wit`, relative to the `wabrix_wasm` crate. Its Rust
SDK dependency is resolved independently by Cargo. Use a sibling SDK checkout
containing the new contract and a Cargo-compatible SDK version. It need not
match the dependency's exact commit. The command above checks the plugin's
resolved SDK and the sibling checkout's version; the host's own Cargo resolution
is checked below. Runtime tests verify that host and plugin contracts agree.

In the host's root `Cargo.toml`, change
`[workspace.dependencies].wabrix_api` to the same SDK compatibility series as the
plugins, keeping `branch = "main"` and `features = ["host"]`. Remove any exact
`rev` selector. Disable local SDK path patches when validating the published
dependency for release. For example:

```toml
wabrix_api = { git = "https://github.com/ninegamma/wabrix_api.git", branch = "main", version = "0.8", features = ["host"] }
```

```bash
cargo update -p wabrix_api
cargo tree -i wabrix_api --locked
```

Confirm Cargo resolves the intended SDK version. Update the host's imported
service implementations, callback calls, record conversions, tests, and
configuration to match the new generated bindings. If changing the host release
version, update `[workspace.package]` and refresh `Cargo.lock` with `cargo check`.
Then validate:

```bash
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build -p wabrix --release --features wasm --locked
git diff --check
```

Stage the changed host sources, tests, manifests, lockfile, and migration/release
notes. Review the staged diff, commit, and publish through the normal host review
process. The SDK and plugins are separate repositories; a host commit does not
include their changes.

## 5. Test compatibility and deploy matching artifacts

Rebuild plugin artifacts with the intended production features. The validation
build above enables all features, including optional runtime diagnostics:

```bash
cd "$WABRIX_ROOT/wabrix_plugins"
cargo build --workspace --release --target wasm32-wasip2 --locked
```

The components are under `target/wasm32-wasip2/release/`. Configure a staging
host to load these newly built files, using the appropriate NICs, routes, and
startup parameters. From the host repository, run your staging configuration:

```bash
cd "$WABRIX_ROOT/wabrix"
sudo ./target/release/wabrix --config /path/to/staging-wabrix.toml
```

Exercise every changed import/export: instantiation, `init-data`, packet
batches, timers, control callbacks, telemetry, and shared-state lifecycle as
applicable. Test the compatibility matrix explicitly:

| Host | Component | Required result |
| --- | --- | --- |
| Previous release | Previous release | Retained working baseline and rollback set. |
| Updated host | Updated component | Successful initialization and correct runtime behavior. |
| Previous release | Updated component | Supported behavior or controlled rejection according to the migration policy. |
| Updated host | Previous release | Supported behavior or controlled rejection according to the migration policy. |

For unsupported combinations, verify rejection before packet processing. Add
explicit compatibility checks where changed semantics or shared-memory layouts
cannot be distinguished by WIT signatures alone. A successful build or snapshot
check cannot replace these runtime tests.

Record the SDK commit, plugin commit/artifact checksums, host commit, WIT package
version, and any state/configuration migration in the release notes. Deploy the
matching host, components, and configuration together. Use a controlled host
restart for a breaking contract unless the host explicitly implements both
versions; replacing a `.wasm` file does not upgrade a running host's bindings.
Retain the previous matched artifacts/configuration and define how state is
restored or reset if rollback is needed.
