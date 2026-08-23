#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Ref, RefCell, RefMut};

use crate::exports::wabrix::plugins::packet_engine::{Guest, TimerPlan};
use crate::wabrix::plugins::logging;
use wabrix_api::mailbox_api::MailboxBatch;
use wabrix_api::{HotWasmPayload, PluginOpcode, StandardOpcode};

wit_bindgen::generate!({
    path: "../../wit/wabrix.wit",
    world: "engine-plugin",
});

const ROUTE_TX: u32 = 0;
const ROUTE_DROP: u32 = 2;

struct WasmCell<T>(RefCell<T>);

unsafe impl<T> Sync for WasmCell<T> {}

impl<T> WasmCell<T> {
    const fn new(value: T) -> Self {
        Self(RefCell::new(value))
    }

    fn borrow(&self) -> Ref<'_, T> {
        self.0.borrow()
    }

    fn borrow_mut(&self) -> RefMut<'_, T> {
        self.0.borrow_mut()
    }
}

#[derive(Default)]
struct InspectorConfig {
    bypass: bool,
    packets_inspected: u64,
    bytes_inspected: u64,
}

static CONFIG: WasmCell<InspectorConfig> = WasmCell::new(InspectorConfig {
    bypass: false,
    packets_inspected: 0,
    bytes_inspected: 0,
});

struct HostLogger;

impl log::Log for HostLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let message = alloc::format!("inspector_engine: {}", record.args());
            logging::log(record.level() as u32, &message);
        }
    }

    fn flush(&self) {}
}

fn init_logging() {
    static LOGGER: HostLogger = HostLogger;
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info);
}

struct InspectorEngine;

impl Guest for InspectorEngine {
    fn init_data(_data: Vec<(String, String)>, _tsc_frequency: u64) -> bool {
        init_logging();
        *CONFIG.borrow_mut() = InspectorConfig::default();
        log::info!("InspectorEngine initialized");
        true
    }

    fn process_batch(batch_size: u32, partition_offset: u32, mailbox_offset: u32) -> u32 {
        let mut batch = MailboxBatch::new(batch_size, partition_offset, mailbox_offset);
        let mut config = CONFIG.borrow_mut();
        let mut processed = 0;

        for mut packet in batch.iter_mut() {
            if packet.tick_kind().is_some() {
                packet.set_action(ROUTE_DROP);
                continue;
            }

            if !config.bypass {
                config.packets_inspected += 1;
                config.bytes_inspected += packet.data_len() as u64;

                // Add protocol/content inspection here. Set ROUTE_DROP when
                // the packet should be discarded; otherwise forward it.
                packet.set_action(ROUTE_TX);
            } else {
                packet.set_action(ROUTE_TX);
            }

            processed += 1;
        }

        processed
    }

    fn process_timers(_current_tsc: u64) -> TimerPlan {
        TimerPlan {
            timeout_frames: 0,
            syn_frames: 0,
        }
    }

    fn on_control_event(raw_opcode: u32, payload: Vec<u8>) -> bool {
        match PluginOpcode::from(raw_opcode) {
            PluginOpcode::Standard(StandardOpcode::SetOperationalState) if payload.len() == 1 => {
                CONFIG.borrow_mut().bypass = payload[0] == 2;
                true
            }
            PluginOpcode::Standard(StandardOpcode::UpdateConfiguration) => {
                let Ok(data) = postcard::from_bytes::<HotWasmPayload>(&payload) else {
                    return false;
                };

                if let Some(value) = data.updates.get("bypass") {
                    CONFIG.borrow_mut().bypass = value == "true" || value == "1";
                }
                true
            }
            _ => false,
        }
    }

    fn get_telemetry() -> Vec<u64> {
        let config = CONFIG.borrow();
        alloc::vec![config.packets_inspected, config.bytes_inspected]
    }
}

export!(InspectorEngine);
