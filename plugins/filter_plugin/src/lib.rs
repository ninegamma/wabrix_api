#![no_std]
extern crate alloc;

use crate::exports::wabrix::plugins::inspector::Guest;
use alloc::vec::Vec;
use core::slice;
use wabrix_api::headers::HeaderKind;
use wabrix_api::packet::PacketBatch;

// 1. Tell the macro to read the .wit file and generate the bindings
wit_bindgen::generate!({
    path: "../../wit/wabrix.wit",
    world: "filter-plugin",
});

// Assuming your Pdu0 definition is imported
// use crate::pdu::Pdu0;

// Constants for our Action Bitfield
const ROUTE_DROP: u32 = 1;
const ROUTE_STANDARD: u32 = 0;

// DISTRIBUTE AND EXECUTE ACTIONS
// u32 action:
// Bits 0-7 (Route ID): Which output port to send the packet to (0-254). 255 = DROP.
// Bit 8 (Telemetry Flag): 1 = Send a telemetry event for this packet.
// Bits 16-31 (Telemetry Meta): An ID, counter, or metric value for the telemetry subsystem.

struct MyInspector;

impl Guest for MyInspector {
    fn init_data(_data: Vec<(alloc::string::String, alloc::string::String)>) {}

    fn inspect_batch(mut batch_bytes: Vec<u8>, partition_offset: u32) -> Vec<u32> {
        let mut batch = PacketBatch::new(&mut batch_bytes, partition_offset);
        let mut actions = Vec::with_capacity(batch.len());

        for packet in batch.iter_mut() {
            let mut action = 0u32;

            let is_v4 = packet.ipv4_header().is_some();
            let dst_port = if let Some(tcp) = packet.tcp_header() {
                Some(tcp.dst_port())
            } else if let Some(udp) = packet.udp_header() {
                Some(udp.dst_port())
            } else {
                None
            };

            // Execute Routing Logic
            if is_v4 && dst_port.is_some() {
                action |= ROUTE_STANDARD;
                let port = dst_port.unwrap_or(0);
                let telemetry_bucket = if port <= 9 { port as u32 } else { 10 };
                action |= telemetry_bucket << 16;
            } else {
                action |= ROUTE_STANDARD;
                let telemetry_bucket = 9u32;
                action |= telemetry_bucket << 16;
            }

            actions.push(action);
        }

        actions
    }
    
/*
    fn inspect_batch(mut batch_bytes: Vec<u8>, partition_offset: u32) -> Vec<u32> {
        // Zero-copy: Parse the entire batch directly from shared UMEM
        let mut batch = PacketBatch::new(&mut batch_bytes, partition_offset);
        let mut actions = Vec::with_capacity(batch.len());

        for packet in batch.iter_mut() {
            let mut action = 0u32;

            let is_v4 = packet.ipv4_header().is_some();
            let dst_port = packet.udp_header().map(|udp| udp.dst_port());

            // --- CUSTOM PROTOCOL LOGIC (The "Aha" Moment) ---
            if is_v4 && dst_port == Some(9000) {
                if let Some(payload) = packet.payload() {
                    // Deep Packet Inspection: Drop malicious debug commands instantly
                    if payload.len() >= 5 && payload[4] == 0xFF {
                        action |= ROUTE_DROP;
                        action |= 99 << 16; // Send to Telemetry bucket 99 ("Threat Blocked")
                        actions.push(action);
                        continue;
                    }
                }
            }

            // --- STANDARD ROUTING & TELEMETRY ---
            action |= ROUTE_STANDARD;

            // Dynamic telemetry binning based on destination port
            let port = dst_port.unwrap_or(0);
            let port_bin = port >> 10;
            let telemetry_bucket = if port_bin <= 9 { port_bin as u32 } else { 10 };
            action |= telemetry_bucket << 16;

            actions.push(action);
        }

        actions
    }
*/
}

export!(MyInspector);
