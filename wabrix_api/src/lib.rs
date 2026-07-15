#![no_std]
extern crate alloc;

use crate::wpdu_impl::Pdu0;

pub mod headers;
pub mod helpers;
pub mod packet;
pub mod mailbox_api;
// Declare the implementation file, but keep it hidden from the outside world.
mod wpdu_impl;
// Declare the routing module as public.
// (It will decide internally what to actually export).
pub mod exports;
mod hstack;
pub mod connections;
pub mod tcp_common;

/// The maximum number of packets in a single batch.
pub const MAX_BATCH_SIZE: usize = 512;

pub const TELEMETRY_FLAG: u32  = 1 << 8; // Bit 8

/// Strongly typed enum for the reserved standard opcodes (0x0000 - 0x0FFF).
/// These represent generic system events that any plugin should understand.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardOpcode {
    // --- State & Lifecycle (0x0001 - 0x000F) ---
    /// Payload: u8 (0=Offline, 1=Online, 2=Bypass)
    SetOperationalState = 0x0001,
    /// Payload: Empty, or u8 flag for specific tables
    FlushState          = 0x0002,

    // --- Observability & Debugging (0x0010 - 0x001F) ---
    /// Payload: u8 (0=Error, 1=Warn, 2=Info, 3=Debug, 4=Trace)
    SetLogLevel         = 0x0010,
    /// Payload: Empty. Triggers a dump to stdout/telemetry.
    TriggerMemoryDump   = 0x0011,

    // --- Traffic Shaping & Protection (0x0020 - 0x002F) ---
    /// Payload: u64 (PPS) or JSON string
    SetRateLimit        = 0x0020,
    /// Payload: JSON list of IPs/CIDRs
    UpdateBlocklist     = 0x0021,

    // --- Schema & Capabilities (0x00F0 - 0x00FF) ---
    /// Payload: Empty. Tells the plugin to push a new UI JSON manifest.
    RefreshManifest     = 0x00FE,
    /// Payload: u64 timestamp or sequence number for health checks.
    Ping                = 0x00FF,
}

/// The overarching opcode representation that gracefully handles
/// both standard system commands and custom plugin-specific commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginOpcode {
    Standard(StandardOpcode),
    /// Represents any opcode >= 0x1000
    Custom(u32),
    /// Represents an opcode in the reserved space that is not yet implemented
    UnknownReserved(u32),
}

impl From<u32> for PluginOpcode {
    fn from(value: u32) -> Self {
        match value {
            0x0001 => Self::Standard(StandardOpcode::SetOperationalState),
            0x0002 => Self::Standard(StandardOpcode::FlushState),
            0x0010 => Self::Standard(StandardOpcode::SetLogLevel),
            0x0011 => Self::Standard(StandardOpcode::TriggerMemoryDump),
            0x0020 => Self::Standard(StandardOpcode::SetRateLimit),
            0x0021 => Self::Standard(StandardOpcode::UpdateBlocklist),
            0x00FE => Self::Standard(StandardOpcode::RefreshManifest),
            0x00FF => Self::Standard(StandardOpcode::Ping),

            // If it's in the reserved block but not matched above
            0x0000..=0x0FFF => Self::UnknownReserved(value),

            // 0x1000 and above are open for plugin developers
            _ => Self::Custom(value),
        }
    }
}

// Optional: Easily convert back to u32 for the wire
impl From<PluginOpcode> for u32 {
    fn from(opcode: PluginOpcode) -> Self {
        match opcode {
            PluginOpcode::Standard(std) => std as u32,
            PluginOpcode::Custom(val) => val,
            PluginOpcode::UnknownReserved(val) => val,
        }
    }
}

/// Shared zero-copy mailbox between host and plugin.
/// Layout MUST match `wabrix_base::mailbox::BatchMetadata` on the host exactly.
#[repr(C)]
pub struct BatchMetadata {
    /// Written by host before calling process-batch: AF_XDP frame descriptor offsets (UMEM-relative)
    pub pdus:  [Pdu0; MAX_BATCH_SIZE],
    /// Written by plugin during process-batch: routing decisions (route_id)
    pub actions:     [u32; MAX_BATCH_SIZE],
}