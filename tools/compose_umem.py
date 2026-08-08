#!/usr/bin/env python3
import pathlib
import re
import subprocess
import sys
import tempfile


def run(*args: str) -> None:
    subprocess.run(args, check=True)


if len(sys.argv) != 3:
    raise SystemExit("usage: compose_umem.py CORE_WASM OUTPUT_COMPONENT")

core = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
adapter_wat = pathlib.Path(__file__).with_name("umem_adapter.wat")

with tempfile.TemporaryDirectory(prefix="wabrix-compose-") as directory:
    temp = pathlib.Path(directory)
    adapter = temp / "umem-adapter.wasm"
    initial = temp / "initial.component.wasm"
    wat = temp / "composed.wat"

    run("wasm-tools", "parse", str(adapter_wat), "-o", str(adapter))
    run(
        "wasm-tools", "component", "new", str(core),
        "--adapt", f"wabrix_umem={adapter}", "-o", str(initial),
    )
    text = subprocess.check_output(
        ["wasm-tools", "print", str(initial)], text=True
    )
    text = text.replace(
        "(component\n",
        "(component\n"
        "  (core module $wabrix-umem-memory\n"
        "    (memory (export \"memory\") 1 65536)\n"
        "  )\n",
        1,
    )
    new = (
        "  (core instance $wabrix-umem-memory-instance "
        "(instantiate $wabrix-umem-memory))\n"
        "  (alias core export $wabrix-umem-memory-instance \"memory\" "
        "(core memory $wabrix-umem-memory-export))\n"
        "  (core instance $env\n"
        "    (export \"memory\" (memory $wabrix-umem-memory-export))\n"
        "  )"
    )
    pattern = re.compile(
        r'  \(core instance \$env \(;\d+;\)\n'
        r'    \(export "memory" \(memory \$memory\)\)\n'
        r'  \)'
    )
    if not pattern.search(text):
        raise SystemExit("generated component layout changed: adapter env block not found")
    wat.write_text(pattern.sub(new, text, count=1))
    run("wasm-tools", "parse", str(wat), "-o", str(output))
    run("wasm-tools", "validate", "--features", "all", str(output))
