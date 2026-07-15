#![no_std]
extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use wabrix_api::packet::PacketBatch;
use crate::exports::wabrix::plugins::inspector::Guest;

// Point this to the EXACT SAME .wit file you used for your first plugin!
wit_bindgen::generate!({
    path: "../../wit/wabrix.wit",
    world: "filter-plugin",
});

// Create a new struct specifically for this plugin
struct IcmpFilter;

// =====================================================================
// WASM LOCAL STATE
// Because each Wasm node is instantiated per worker, these statics
// live safely inside the Wasm sandbox memory and persist across batches!
// =====================================================================
static PING_REQUESTS: AtomicU64 = AtomicU64::new(0);
static PING_REPLIES: AtomicU64 = AtomicU64::new(0);

// Routing Constants
const ROUTE_DROP: u32 = 1;
const ROUTE_STANDARD: u32 = 0;

impl Guest for IcmpFilter {
    fn init_data(_data: Vec<(alloc::string::String, alloc::string::String)>) {}

    fn inspect_batch(mut batch_bytes: Vec<u8>, partition_offset: u32) -> Vec<u32> {
        let mut batch = PacketBatch::new(&mut batch_bytes, partition_offset);
        let mut actions = Vec::with_capacity(batch.len());

        for packet in batch.iter_mut() {
            if packet.headers().count() == 0 {
                actions.push(ROUTE_DROP);
                continue;
            }

            let bucket = match packet.icmp_header() {
                None => 3 << 16, // non-ICMP traffic (TCP/UDP/ARP)
                Some(icmp_hdr) => {
                    let is_ipv6 = packet.ipv6_header().is_some();
                    match icmp_hdr.icmp_type() {
                        8 if !is_ipv6 => {
                            PING_REQUESTS.fetch_add(1, Ordering::Relaxed);
                            0 << 16
                        }
                        128 if is_ipv6 => {
                            PING_REQUESTS.fetch_add(1, Ordering::Relaxed);
                            0 << 16
                        }
                        0 if !is_ipv6 => {
                            PING_REPLIES.fetch_add(1, Ordering::Relaxed);
                            1 << 16
                        }
                        129 if is_ipv6 => {
                            PING_REPLIES.fetch_add(1, Ordering::Relaxed);
                            1 << 16
                        }
                        _ => 2 << 16,
                    }
                }
            };

            actions.push(bucket | ROUTE_STANDARD);
        }
        actions
    }
}

// Export your new struct
export!(IcmpFilter);
