#ifndef WABRIX_SHARED_MEMORY_H
#define WABRIX_SHARED_MEMORY_H

/*
 * Wabrix shared Wasm mailbox ABI, version 1.
 *
 * These structures describe bytes in Wasm linear memory. They are not WIT
 * component-model records and must not be passed through the canonical ABI.
 * Multi-byte values use the little-endian representation used by Wasm.
 */

#include <stddef.h>
#include <stdint.h>

#define WABRIX_SHARED_MEMORY_ABI_VERSION 1
#define WABRIX_MAX_BATCH_SIZE 512
#define WABRIX_MAX_HEADERS 5

enum wabrix_header_kind {
    WABRIX_HEADER_NULL = 0,
    WABRIX_HEADER_MAC = 1,
    WABRIX_HEADER_ARP_IPV4 = 2,
    WABRIX_HEADER_IP = 3,
    WABRIX_HEADER_IPV6 = 4,
    WABRIX_HEADER_TCP = 5,
    WABRIX_HEADER_UDP = 6,
    WABRIX_HEADER_ICMP = 7,
};

typedef struct wabrix_header_stack {
    uint16_t offsets[WABRIX_MAX_HEADERS];
    uint8_t kinds[WABRIX_MAX_HEADERS];
    uint8_t header_count;
} wabrix_header_stack_t;

typedef struct wabrix_wpdu {
    wabrix_header_stack_t header_stack;
    uint64_t desc_addr;
    uint32_t desc_len;
    uint32_t desc_options;
    uint32_t umem_group_id;
    uint8_t frame_size_log2;
    uint8_t worker_id;
    uint8_t flags;
    uint8_t timer_kind;
    uint64_t rx_timestamp;
    uint64_t timestamp;
} wabrix_wpdu_t;

#if defined(__GNUC__) || defined(__clang__)
#define WABRIX_ALIGN_64 __attribute__((aligned(64)))
#else
#define WABRIX_ALIGN_64
#endif

typedef struct WABRIX_ALIGN_64 wabrix_pdu {
    wabrix_wpdu_t core;
    uint64_t host_padding;
} wabrix_pdu_t;

typedef struct wabrix_batch_metadata {
    wabrix_pdu_t pdus[WABRIX_MAX_BATCH_SIZE];
    uint32_t actions[WABRIX_MAX_BATCH_SIZE];
} wabrix_batch_metadata_t;

#define WABRIX_STATIC_ASSERT(name, expression) _Static_assert(expression, #name)

WABRIX_STATIC_ASSERT(header_stack_size, sizeof(wabrix_header_stack_t) == 16);
WABRIX_STATIC_ASSERT(header_stack_offsets, offsetof(wabrix_header_stack_t, offsets) == 0);
WABRIX_STATIC_ASSERT(header_stack_kinds, offsetof(wabrix_header_stack_t, kinds) == 10);
WABRIX_STATIC_ASSERT(header_stack_count, offsetof(wabrix_header_stack_t, header_count) == 15);

WABRIX_STATIC_ASSERT(wpdu_size, sizeof(wabrix_wpdu_t) == 56);
WABRIX_STATIC_ASSERT(wpdu_header_stack, offsetof(wabrix_wpdu_t, header_stack) == 0);
WABRIX_STATIC_ASSERT(wpdu_desc_addr, offsetof(wabrix_wpdu_t, desc_addr) == 16);
WABRIX_STATIC_ASSERT(wpdu_desc_len, offsetof(wabrix_wpdu_t, desc_len) == 24);
WABRIX_STATIC_ASSERT(wpdu_desc_options, offsetof(wabrix_wpdu_t, desc_options) == 28);
WABRIX_STATIC_ASSERT(wpdu_umem_group_id, offsetof(wabrix_wpdu_t, umem_group_id) == 32);
WABRIX_STATIC_ASSERT(wpdu_frame_size_log2, offsetof(wabrix_wpdu_t, frame_size_log2) == 36);
WABRIX_STATIC_ASSERT(wpdu_worker_id, offsetof(wabrix_wpdu_t, worker_id) == 37);
WABRIX_STATIC_ASSERT(wpdu_flags, offsetof(wabrix_wpdu_t, flags) == 38);
WABRIX_STATIC_ASSERT(wpdu_timer_kind, offsetof(wabrix_wpdu_t, timer_kind) == 39);
WABRIX_STATIC_ASSERT(wpdu_rx_timestamp, offsetof(wabrix_wpdu_t, rx_timestamp) == 40);
WABRIX_STATIC_ASSERT(wpdu_timestamp, offsetof(wabrix_wpdu_t, timestamp) == 48);

WABRIX_STATIC_ASSERT(pdu_size, sizeof(wabrix_pdu_t) == 64);
WABRIX_STATIC_ASSERT(pdu_alignment, _Alignof(wabrix_pdu_t) == 64);
WABRIX_STATIC_ASSERT(pdu_core, offsetof(wabrix_pdu_t, core) == 0);
WABRIX_STATIC_ASSERT(pdu_host_padding, offsetof(wabrix_pdu_t, host_padding) == 56);

WABRIX_STATIC_ASSERT(mailbox_pdus, offsetof(wabrix_batch_metadata_t, pdus) == 0);
WABRIX_STATIC_ASSERT(mailbox_actions, offsetof(wabrix_batch_metadata_t, actions) == 32768);
WABRIX_STATIC_ASSERT(mailbox_size, sizeof(wabrix_batch_metadata_t) == 34816);

#undef WABRIX_STATIC_ASSERT
#undef WABRIX_ALIGN_64

#endif /* WABRIX_SHARED_MEMORY_H */
