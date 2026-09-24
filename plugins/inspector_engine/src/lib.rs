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
const TIMESTAMP_MAGIC: [u8; 4] = *b"WABR";

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
    tsc_frequency: u64,
    packets_inspected: u64,
    bytes_inspected: u64,
    unexpected: u64,
    delay_samples: u64,
    mean_delay_us: f64,
    delay_m2: f64,
}

static CONFIG: WasmCell<InspectorConfig> = WasmCell::new(InspectorConfig {
    bypass: false,
    tsc_frequency: 0,
    packets_inspected: 0,
    bytes_inspected: 0,
    unexpected: 0,
    delay_samples: 0,
    mean_delay_us: 0.0,
    delay_m2: 0.0,
});

fn packet_delay_us(receive_tsc: u64, send_tsc: u64, tsc_frequency: u64) -> Option<u64> {
    if tsc_frequency == 0 || receive_tsc < send_tsc {
        return None;
    }

    let elapsed_cycles = receive_tsc - send_tsc;
    Some(((elapsed_cycles as u128 * 1_000_000) / tsc_frequency as u128) as u64)
}

fn square_root(value: f64) -> f64 {
    if value <= 0.0 {
        return 0.0;
    }

    let mut estimate = if value < 1.0 { 1.0 } else { value };
    for _ in 0..64 {
        let next = 0.5 * (estimate + value / estimate);
        if next == estimate {
            break;
        }
        estimate = next;
    }
    estimate
}

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
    fn init_data(_data: Vec<(String, String)>, tsc_frequency: u64) -> bool {
        init_logging();
        *CONFIG.borrow_mut() = InspectorConfig {
            tsc_frequency,
            ..InspectorConfig::default()
        };
        log::info!("InspectorEngine initialized");
        true
    }

    fn process_batch(batch_size: u32, umem_offset: u32, mailbox_offset: u32) -> u32 {
        let mut batch = MailboxBatch::new(batch_size, umem_offset, mailbox_offset);
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

                let send_tsc = if packet.udp_header().is_some() {
                    packet.payload().and_then(|payload| {
                        let timestamp_start = TIMESTAMP_MAGIC.len();
                        let timestamp_end = timestamp_start + core::mem::size_of::<u64>();
                        let bytes = payload.get(..timestamp_end)?;
                        (bytes[..timestamp_start] == TIMESTAMP_MAGIC)
                            .then(|| bytes[timestamp_start..timestamp_end].try_into().ok())
                            .flatten()
                            .map(u64::from_be_bytes)
                    })
                } else {
                    None
                };

                match send_tsc.and_then(|send_tsc| {
                    packet_delay_us(packet.timestamp(), send_tsc, config.tsc_frequency)
                }) {
                    Some(delay_us) => {
                        // Welford's online algorithm avoids storing samples and
                        // remains numerically stable for long-running pipelines.
                        config.delay_samples += 1;
                        let delay = delay_us as f64;
                        let delta = delay - config.mean_delay_us;
                        config.mean_delay_us += delta / config.delay_samples as f64;
                        let delta_after_mean = delay - config.mean_delay_us;
                        config.delay_m2 += delta * delta_after_mean;
                    }
                    None => config.unexpected += 1,
                }

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
            packet_frames: 0,
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
        let variance = if config.delay_samples == 0 {
            0.0
        } else {
            config.delay_m2 / config.delay_samples as f64
        };
        let average_delay_us = (config.mean_delay_us + 0.5) as u64;
        let standard_deviation_us = (square_root(variance) + 0.5) as u64;

        alloc::vec![
            config.packets_inspected,
            config.bytes_inspected,
            config.unexpected,
            average_delay_us,
            standard_deviation_us,
        ]
    }
}

export!(InspectorEngine);
