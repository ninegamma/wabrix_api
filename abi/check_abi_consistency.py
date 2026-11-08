#!/usr/bin/env python3
"""Check that numeric ABI definitions are consistent between C and Rust."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
C_HEADER = ROOT / "abi" / "wabrix_shared_memory.h"
RUST_MEMORY = ROOT / "src" / "shared_memory.rs"
RUST_HEADERS = ROOT / "src" / "headers" / "mod.rs"


class ConsistencyError(Exception):
    pass


def require_match(pattern: str, source: str, description: str, flags: int = 0) -> re.Match[str]:
    match = re.search(pattern, source, flags)
    if match is None:
        raise ConsistencyError(f"could not find {description}")
    return match


def decimal(value: str) -> int:
    return int(value.replace("_", ""), 10)


def read_numeric_define(source: str, name: str) -> int:
    match = require_match(
        rf"^#define\s+{re.escape(name)}\s+([0-9][0-9_]*)\s*$",
        source,
        f"C definition {name}",
        re.MULTILINE,
    )
    return decimal(match.group(1))


def read_rust_constant(source: str, name: str) -> int:
    match = require_match(
        rf"^pub const {re.escape(name)}:\s*usize\s*=\s*([0-9][0-9_]*)\s*;",
        source,
        f"Rust constant {name}",
        re.MULTILINE,
    )
    return decimal(match.group(1))


def read_c_header_kinds(source: str) -> dict[str, int]:
    body = require_match(
        r"enum\s+wabrix_header_kind\s*\{(.*?)\};",
        source,
        "C header-kind enum",
        re.DOTALL,
    ).group(1)
    unresolved: dict[str, str] = {}
    for name, value in re.findall(
        r"\b(WABRIX_HEADER_\w+)\s*=\s*(WABRIX_HEADER_\w+|[0-9][0-9_]*)\s*,",
        body,
    ):
        unresolved[name] = value

    resolved: dict[str, int] = {}
    while unresolved:
        progress = False
        for name, value in list(unresolved.items()):
            if value.startswith("WABRIX_HEADER_"):
                if value not in resolved:
                    continue
                resolved[name] = resolved[value]
            else:
                resolved[name] = decimal(value)
            del unresolved[name]
            progress = True
        if not progress:
            raise ConsistencyError(
                "could not resolve C header-kind aliases: "
                + ", ".join(sorted(unresolved))
            )
    return resolved


def read_rust_header_kinds(source: str) -> dict[str, int]:
    body = require_match(
        r"pub enum HeaderKind\s*\{(.*?)\n\}",
        source,
        "Rust HeaderKind enum",
        re.DOTALL,
    ).group(1)
    values: dict[str, int] = {}
    previous = -1
    for line in body.splitlines():
        line = line.split("//", 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r"(\w+)(?:\s*=\s*([0-9][0-9_]*))?\s*,?", line)
        if match is None:
            raise ConsistencyError(f"could not parse Rust HeaderKind variant: {line}")
        name, explicit_value = match.groups()
        previous = decimal(explicit_value) if explicit_value else previous + 1
        values[name] = previous
    return values


def read_c_layout_assertions(source: str) -> dict[str, int]:
    assertions: dict[str, int] = {}
    for name, expression in re.findall(
        r"^[ \t]*WABRIX_STATIC_ASSERT\(([A-Za-z0-9_]+),[ \t]*(.*?)\);[ \t]*$",
        source,
        re.MULTILINE,
    ):
        value = re.search(r"==\s*([0-9][0-9_]*)\s*$", expression.strip())
        if value is not None:
            assertions[name] = decimal(value.group(1))
    return assertions


def read_rust_layout_assertions(source: str) -> tuple[dict[str, int], set[str]]:
    direct: dict[str, int] = {}
    expressions: set[str] = set()
    for expression in re.findall(r"assert!\(\s*(.*?)\s*\);", source, re.DOTALL):
        normalized = re.sub(r"\s+", " ", expression.strip())
        expressions.add(normalized)

        size = re.fullmatch(
            r"core::mem::(size_of|align_of)::<(\w+)>\(\)\s*==\s*([0-9][0-9_]*)",
            normalized,
        )
        if size is not None:
            operation, type_name, expected = size.groups()
            direct[f"{operation}:{type_name}"] = decimal(expected)
            continue

        offset = re.fullmatch(
            r"core::mem::offset_of!\((\w+),\s*(\w+)\)\s*==\s*([0-9][0-9_]*)",
            normalized,
        )
        if offset is not None:
            type_name, field_name, expected = offset.groups()
            direct[f"offset:{type_name}.{field_name}"] = decimal(expected)
    return direct, expressions


def check_equal(label: str, c_value: int, rust_value: int) -> None:
    if c_value != rust_value:
        raise ConsistencyError(
            f"{label} differs: C has {c_value}, Rust has {rust_value}"
        )


def main() -> int:
    c_source = C_HEADER.read_text(encoding="utf-8")
    rust_memory = RUST_MEMORY.read_text(encoding="utf-8")
    rust_headers = RUST_HEADERS.read_text(encoding="utf-8")

    c_batch_size = read_numeric_define(c_source, "WABRIX_MAX_BATCH_SIZE")
    rust_batch_size = read_rust_constant(rust_memory, "MAX_BATCH_SIZE")
    check_equal("maximum batch size", c_batch_size, rust_batch_size)

    c_header_count = read_numeric_define(c_source, "WABRIX_MAX_HEADERS")
    rust_header_count = read_rust_constant(rust_memory, "MAX_HEADERS")
    check_equal("maximum header count", c_header_count, rust_header_count)

    c_kinds = read_c_header_kinds(c_source)
    rust_kinds = read_rust_header_kinds(rust_headers)
    variant_names = {
        "Null": "WABRIX_HEADER_NULL",
        "Eth": "WABRIX_HEADER_ETH",
        "ArpIpv4": "WABRIX_HEADER_ARP_IPV4",
        "Ip": "WABRIX_HEADER_IP",
        "Ipv6": "WABRIX_HEADER_IPV6",
        "Tcp": "WABRIX_HEADER_TCP",
        "Udp": "WABRIX_HEADER_UDP",
        "Icmpv4": "WABRIX_HEADER_ICMPV4",
        "Icmpv6": "WABRIX_HEADER_ICMPV6",
    }
    if set(rust_kinds) != set(variant_names):
        raise ConsistencyError(
            "Rust HeaderKind variants changed; update the C mapping in this checker"
        )
    for rust_name, c_name in variant_names.items():
        if c_name not in c_kinds:
            raise ConsistencyError(f"missing C header-kind value {c_name}")
        check_equal(f"HeaderKind::{rust_name}", c_kinds[c_name], rust_kinds[rust_name])

    for alias, target in {
        "WABRIX_HEADER_MAC": "WABRIX_HEADER_ETH",
        "WABRIX_HEADER_ICMP": "WABRIX_HEADER_ICMPV4",
    }.items():
        if c_kinds.get(alias) != c_kinds.get(target):
            raise ConsistencyError(f"C compatibility alias {alias} does not match {target}")

    c_assertions = read_c_layout_assertions(c_source)
    rust_assertions, rust_expressions = read_rust_layout_assertions(rust_memory)
    paired_layouts = {
        "header_stack_size": "size_of:HeaderStack",
        "header_stack_offsets": "offset:HeaderStack.offsets",
        "header_stack_kinds": "offset:HeaderStack.kinds",
        "header_stack_count": "offset:HeaderStack.hc",
        "wpdu_size": "size_of:PduCore",
        "wpdu_header_stack": "offset:PduCore.header_stack",
        "wpdu_desc_addr": "offset:PduCore.desc_addr",
        "wpdu_desc_len": "offset:PduCore.desc_len",
        "wpdu_desc_options": "offset:PduCore.desc_options",
        "wpdu_umem_group_id": "offset:PduCore.umem_group_id",
        "wpdu_frame_size_log2": "offset:PduCore.frame_size_log2",
        "wpdu_worker_id": "offset:PduCore.worker_id",
        "wpdu_flags": "offset:PduCore.flags",
        "wpdu_timer_kind": "offset:PduCore.timer_kind",
        "wpdu_rx_timestamp": "offset:PduCore.rx_timestamp",
        "wpdu_timestamp": "offset:PduCore.timestamp",
        "pdu_size": "size_of:SharedPdu",
        "pdu_alignment": "align_of:SharedPdu",
        "pdu_core": "offset:SharedPdu.w",
        "pdu_host_padding": "offset:SharedPdu._do_not_touch_padding",
        "mailbox_pdus": "offset:BatchMetadata.pdus",
    }
    for c_name, rust_name in paired_layouts.items():
        if c_name not in c_assertions:
            raise ConsistencyError(f"missing C layout assertion {c_name}")
        if rust_name not in rust_assertions:
            raise ConsistencyError(f"missing Rust layout assertion {rust_name}")
        check_equal(c_name, c_assertions[c_name], rust_assertions[rust_name])

    rust_shared_pdu_size = rust_assertions["size_of:SharedPdu"]
    expected_actions_offset = rust_batch_size * rust_shared_pdu_size
    expected_mailbox_size = expected_actions_offset + rust_batch_size * 4
    check_equal(
        "mailbox actions offset",
        c_assertions.get("mailbox_actions", -1),
        expected_actions_offset,
    )
    check_equal(
        "mailbox size",
        c_assertions.get("mailbox_size", -1),
        expected_mailbox_size,
    )
    check_equal(
        "batch capacity assertion",
        c_assertions.get("batch_capacity", -1),
        rust_batch_size,
    )

    expected_rust_expressions = {
        "core::mem::offset_of!(BatchMetadata, actions) == MAX_BATCH_SIZE * core::mem::size_of::<SharedPdu>()",
        "core::mem::size_of::<BatchMetadata>() == MAX_BATCH_SIZE * core::mem::size_of::<SharedPdu>() + MAX_BATCH_SIZE * core::mem::size_of::<u32>()",
    }
    if not expected_rust_expressions.issubset(rust_expressions):
        raise ConsistencyError("Rust mailbox layout assertions changed unexpectedly")

    print(
        "C and Rust ABI literals match: batch/header counts, header kinds, "
        "field offsets, and mailbox sizes."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ConsistencyError) as error:
        print(f"ABI consistency check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
