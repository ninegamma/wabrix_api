#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Ref, RefCell, RefMut};

use crate::exports::wabrix::plugins::packet_engine::{
    Counter, Guest, Histogram, TelemetryMetric, TimerPlan,
};
use crate::wabrix::plugins::logging;
use macaddr::MacAddr6;
use wabrix_api::helpers::parse_mac;
use wabrix_api::mailbox_api::MailboxBatch;
use wabrix_api::{
    HotWasmPayload, PluginOpcode, StandardOpcode, INSPECTOR_DELAY_HISTOGRAM_BUCKETS,
    INSPECTOR_DELAY_HISTOGRAM_BUCKET_WIDTH_US, INSPECTOR_DELAY_HISTOGRAM_FINITE_BUCKETS,
};

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

struct InspectorConfig {
    bypass: bool,
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
    tsc_frequency: u64,
    packets_inspected: u64,
    bytes_inspected: u64,
    unexpected: u64,
    delay_samples: u64,
    mean_delay_us: f64,
    delay_m2: f64,
    delay_sum_us: u64,
    delay_histogram: [u64; INSPECTOR_DELAY_HISTOGRAM_BUCKETS],
}

impl Default for InspectorConfig {
    fn default() -> Self {
        Self {
            bypass: false,
            src_mac: None,
            dst_mac: None,
            tsc_frequency: 0,
            packets_inspected: 0,
            bytes_inspected: 0,
            unexpected: 0,
            delay_samples: 0,
            mean_delay_us: 0.0,
            delay_m2: 0.0,
            delay_sum_us: 0,
            delay_histogram: [0; INSPECTOR_DELAY_HISTOGRAM_BUCKETS],
        }
    }
}

static CONFIG: WasmCell<InspectorConfig> = WasmCell::new(InspectorConfig {
    bypass: false,
    src_mac: None,
    dst_mac: None,
    tsc_frequency: 0,
    packets_inspected: 0,
    bytes_inspected: 0,
    unexpected: 0,
    delay_samples: 0,
    mean_delay_us: 0.0,
    delay_m2: 0.0,
    delay_sum_us: 0,
    delay_histogram: [0; INSPECTOR_DELAY_HISTOGRAM_BUCKETS],
});

fn packet_delay_us(receive_tsc: u64, send_tsc: u64, tsc_frequency: u64) -> Option<u64> {
    if tsc_frequency == 0 || receive_tsc < send_tsc {
        return None;
    }

    let elapsed_cycles = receive_tsc - send_tsc;
    // Normal packet delays need only a native multiply and divide, avoiding
    // Wasm's software implementation of wide integer division.
    if let Some(scaled_cycles) = elapsed_cycles.checked_mul(1_000_000) {
        return Some(scaled_cycles / tsc_frequency);
    }

    let seconds = elapsed_cycles / tsc_frequency;
    let remainder = elapsed_cycles % tsc_frequency;
    let fractional_us = if let Some(scaled_remainder) = remainder.checked_mul(1_000_000) {
        scaled_remainder / tsc_frequency
    } else {
        // Compute the fractional part exactly even for unusually large TSC
        // frequencies. Modular doubling/addition keeps every intermediate u64.
        let mut fraction = 0u64;
        let mut residual = 0u64;
        for bit in (0..20).rev() {
            fraction *= 2;
            if residual >= tsc_frequency - residual {
                residual -= tsc_frequency - residual;
                fraction += 1;
            } else {
                residual *= 2;
            }
            if (1_000_000u64 >> bit) & 1 != 0 {
                if residual >= tsc_frequency - remainder {
                    residual -= tsc_frequency - remainder;
                    fraction += 1;
                } else {
                    residual += remainder;
                }
            }
        }
        fraction
    };
    // Preserve the original narrowing cast's wraparound for oversized results.
    Some(seconds.wrapping_mul(1_000_000).wrapping_add(fractional_us))
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
    fn init_data(data: Vec<(String, String)>, tsc_frequency: u64) -> bool {
        init_logging();
        let mut config = InspectorConfig {
            tsc_frequency,
            ..InspectorConfig::default()
        };
        for (key, value) in data {
            match key.as_str() {
                "src_mac" => config.src_mac = parse_mac(&value),
                "dst_mac" => config.dst_mac = parse_mac(&value),
                _ => {}
            }
        }
        *CONFIG.borrow_mut() = config;
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
                        config.delay_sum_us = config.delay_sum_us.saturating_add(delay_us);
                        // Prometheus bounds are inclusive (le=10us), so a
                        // sample exactly on a boundary belongs in that bucket.
                        let bucket = (delay_us.saturating_sub(1)
                            / INSPECTOR_DELAY_HISTOGRAM_BUCKET_WIDTH_US)
                            .min(INSPECTOR_DELAY_HISTOGRAM_FINITE_BUCKETS as u64)
                            as usize;
                        config.delay_histogram[bucket] =
                            config.delay_histogram[bucket].saturating_add(1);
                    }
                    None => config.unexpected += 1,
                }

                packet.set_action(ROUTE_TX);
            } else {
                packet.set_action(ROUTE_TX);
            }

            // The packet crossed the cable and is being sent back through the
            // receiving interface. Apply the configured reverse Ethernet
            // addresses so the frame reaches the other NIC port.
            if let Some(mac) = config.src_mac {
                let mac = MacAddr6::from(mac);
                if let Some(header) = packet.mac_header_mut() {
                    header.set_smac(&mac);
                }
            }
            if let Some(mac) = config.dst_mac {
                let mac = MacAddr6::from(mac);
                if let Some(header) = packet.mac_header_mut() {
                    header.set_dmac(&mac);
                }
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

    fn get_telemetry() -> Vec<TelemetryMetric> {
        let config = CONFIG.borrow();
        let variance = if config.delay_samples == 0 {
            0.0
        } else {
            config.delay_m2 / config.delay_samples as f64
        };
        let average_delay_us = (config.mean_delay_us + 0.5) as u64;
        let standard_deviation_us = (square_root(variance) + 0.5) as u64;

        let telemetry = alloc::vec![
            TelemetryMetric::Counter(Counter { name: String::from("packets_inspected"), value: config.packets_inspected }),
            TelemetryMetric::Counter(Counter { name: String::from("bytes_inspected"), value: config.bytes_inspected }),
            TelemetryMetric::Counter(Counter { name: String::from("unexpected"), value: config.unexpected }),
            TelemetryMetric::Counter(Counter { name: String::from("average_delay_us"), value: average_delay_us }),
            TelemetryMetric::Counter(Counter { name: String::from("stddev_delay_us"), value: standard_deviation_us }),
            TelemetryMetric::Hist(Histogram {
                name: String::from("delay"),
                sum: config.delay_sum_us,
                count: config.delay_samples,
                buckets: config.delay_histogram.to_vec(),
            }),
        ];
        telemetry
    }
}

export!(InspectorEngine);

#[cfg(test)]
mod tests {
    use super::packet_delay_us;

    #[test]
    fn packet_delay_rejects_invalid_timestamps_and_frequency() {
        assert_eq!(packet_delay_us(10, 0, 0), None);
        assert_eq!(packet_delay_us(9, 10, 1), None);
        assert_eq!(packet_delay_us(10, 10, 1), Some(0));
    }

    #[test]
    fn packet_delay_matches_wide_arithmetic() {
        let values = [
            1,
            999_999,
            1_000_000,
            3_000_000_000,
            u64::MAX / 1_000_000,
            u64::MAX / 1_000_000 + 1,
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ];
        let check = |elapsed: u64, frequency: u64| {
            let expected = ((elapsed as u128 * 1_000_000) / frequency as u128) as u64;
            assert_eq!(packet_delay_us(elapsed, 0, frequency), Some(expected));
        };
        for elapsed in values {
            for frequency in values {
                check(elapsed, frequency);
            }
        }
        let mut state = 42u64;
        for _ in 0..10_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let elapsed = state;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            check(elapsed, state.max(1));
        }
    }
}
