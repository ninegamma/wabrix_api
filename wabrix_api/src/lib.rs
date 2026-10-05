#![no_std]
extern crate alloc;

use alloc::string::String;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

pub mod headers;
pub mod helpers;
pub mod mailbox_api;
pub mod packet;
pub mod shared_memory;
// Declare the implementation file, but keep it hidden from the outside world.
mod wpdu_impl;
// Declare the routing module as public.
// (It will decide internally what to actually export).
pub mod connections;
pub mod engine_common;
pub mod exports;
mod hstack;
pub mod tcp_common;

pub use shared_memory::{BatchMetadata, SharedMailbox, SharedPdu, WpduCore, MAX_BATCH_SIZE};

/// Timer frame kinds stored in the reserved WPdu padding byte.
pub const TIMER_KIND_NONE: u8 = 0;
pub const TIMER_KIND_TIMEOUT: u8 = 1;
pub const TIMER_KIND_SYN: u8 = 2;

/// Histogram resolution and range shared by the inspector plugin and host.
pub const INSPECTOR_DELAY_HISTOGRAM_BUCKET_WIDTH_US: u64 = 10;
pub const INSPECTOR_DELAY_HISTOGRAM_FINITE_BUCKETS: usize = 100;
pub const INSPECTOR_DELAY_HISTOGRAM_BUCKETS: usize = INSPECTOR_DELAY_HISTOGRAM_FINITE_BUCKETS + 1;

/// Strongly typed enum for the reserved standard opcodes (0x0000 - 0x0FFF).
/// These represent generic system events that any plugin should understand.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardOpcode {
    // --- State & Lifecycle (0x0001 - 0x000F) ---
    /// Payload: u8 (0=Offline, 1=Online, 2=Bypass)
    SetOperationalState = 0x0001,
    /// Payload: Empty, or u8 flag for specific tables
    FlushState = 0x0002,
    /// Hot updating the configuration
    UpdateConfiguration = 0x0003,
    // --- Observability & Debugging (0x0010 - 0x001F) ---
    /// Payload: u8 (0=Error, 1=Warn, 2=Info, 3=Debug, 4=Trace)
    SetLogLevel = 0x0010,
    /// Payload: Empty. Triggers a dump to stdout/telemetry.
    TriggerMemoryDump = 0x0011,

    /// Payload: JSON list of IPs/CIDRs
    UpdateBlocklist = 0x0021,

    // --- Schema & Capabilities (0x00F0 - 0x00FF) ---
    /// Payload: Empty. Tells the plugin to push a new UI JSON manifest.
    RefreshManifest = 0x00FE,
    /// Payload: u64 timestamp or sequence number for health checks.
    Ping = 0x00FF,
}

/// Operational states shared by native and Wasm engine nodes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalState {
    /// Stop synthetic generation while continuing normal packet processing.
    Offline = 0,
    /// Enable synthetic generation and normal packet processing.
    Online = 1,
    /// Stop generation and bypass packet processing.
    Bypass = 2,
}

impl OperationalState {
    /// Converts the wire payload used by StandardOpcode::SetOperationalState.
    pub const fn from_payload(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Offline),
            1 => Some(Self::Online),
            2 => Some(Self::Bypass),
            _ => None,
        }
    }
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
            0x0003 => Self::Standard(StandardOpcode::UpdateConfiguration),
            0x0010 => Self::Standard(StandardOpcode::SetLogLevel),
            0x0011 => Self::Standard(StandardOpcode::TriggerMemoryDump),
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

#[derive(Serialize, Deserialize)]
pub struct HotWasmPayload {
    pub updates: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::{OperationalState, PluginOpcode, StandardOpcode};

    #[test]
    fn standard_control_opcode_values_are_stable() {
        assert_eq!(StandardOpcode::SetOperationalState as u32, 0x0001);
        assert_eq!(StandardOpcode::FlushState as u32, 0x0002);
        assert_eq!(StandardOpcode::UpdateConfiguration as u32, 0x0003);
        assert_eq!(StandardOpcode::Ping as u32, 0x00FF);
    }

    #[test]
    fn operational_state_payload_contract_is_shared() {
        assert_eq!(
            OperationalState::from_payload(0),
            Some(OperationalState::Offline)
        );
        assert_eq!(
            OperationalState::from_payload(1),
            Some(OperationalState::Online)
        );
        assert_eq!(
            OperationalState::from_payload(2),
            Some(OperationalState::Bypass)
        );
        assert_eq!(OperationalState::from_payload(3), None);
    }

    #[test]
    fn plugin_opcode_mapping_preserves_standard_values() {
        assert_eq!(
            PluginOpcode::from(1),
            PluginOpcode::Standard(StandardOpcode::SetOperationalState)
        );
        assert_eq!(
            PluginOpcode::from(2),
            PluginOpcode::Standard(StandardOpcode::FlushState)
        );
        assert_eq!(
            PluginOpcode::from(3),
            PluginOpcode::Standard(StandardOpcode::UpdateConfiguration)
        );
        assert_eq!(
            PluginOpcode::from(255),
            PluginOpcode::Standard(StandardOpcode::Ping)
        );
    }
}
