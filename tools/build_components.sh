#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)
target_dir="$root_dir/target/wasm32-wasip2/release"

# Cargo discovers `.cargo/config.toml` relative to its current directory, not
# `--manifest-path`. Enter the repository so IDE launches also select rust-lld.
cd "$root_dir"
cargo build --release --target wasm32-wasip2

for plugin in tcp_engine filter_engine generator_plugin; do
    core="$target_dir/$plugin.core.wasm"
    component="$target_dir/$plugin.wasm"
    composed="$target_dir/$plugin.component.tmp.wasm"
    cp "$component" "$core"
    python3 "$root_dir/tools/compose_umem.py" "$core" "$composed"
    mv "$composed" "$component"
done
