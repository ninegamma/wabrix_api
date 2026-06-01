#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use core::slice;
use xbricks_protocol::headers::HeaderKind;
use xbricks_protocol::wpdu::{Packet, Pdu0};
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
        let pdus = unsafe {
            slice::from_raw_parts_mut(
                batch_bytes.as_mut_ptr() as *mut Pdu0,
                batch_bytes.len() / core::mem::size_of::<Pdu0>(),
            )
        };

        let mut actions = Vec::with_capacity(pdus.len());

        // MAGIC: Calculate the virtual UMEM address for this sandbox.
        // E.g., if partition is 10MB, this becomes -10MB (in 2's complement).
        let umem_addr = (0u32).wrapping_sub(partition_offset) as usize;

        for pdu in pdus {
            // Wrap the raw PDU in a safe Packet Context Wrapper
            let packet = Packet::new(pdu, umem_addr);
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
                // action |= ROUTE_FAST_PATH;
                // Safe to unwrap because of the if condition
                action |= ROUTE_STANDARD;
                let port = dst_port.unwrap();
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