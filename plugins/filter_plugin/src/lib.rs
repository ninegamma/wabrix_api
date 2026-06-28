#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use core::slice;
use xbricks_protocol::headers::HeaderKind;
use xbricks_protocol::packet::PacketBatch;
use crate::exports::xbricks::plugins::inspector::{Guest};

// 1. Tell the macro to read the .wit file and generate the bindings
wit_bindgen::generate!({
    path: "../../wit/xbricks.wit",
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
                let telemetry_bucket = if port <= 9 {
                    port as u32
                } else {
                    10
                };
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
}

export!(MyInspector);