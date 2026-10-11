#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Ref, RefCell, RefMut};

use crate::exports::wabrix::plugins::packet_engine::{
    Counter, Guest, Histogram, TelemetryMetric, TimerPlan,
};
use crate::wabrix::plugins::logging;
//use macaddr::MacAddr6;
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
const ROUTE_DROP: u32 = 1;
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
    delay_scale: DelayScale,
    packets_inspected: u64,
    bytes_inspected: u64,
    unexpected: u64,
    delay_samples: u64,
    delay_sum_us: u64,
    delay_histogram: [u64; INSPECTOR_DELAY_HISTOGRAM_BUCKETS],
}

impl Default for InspectorConfig {
    fn default() -> Self {
        Self {
            bypass: false,
            src_mac: None,
            dst_mac: None,
            delay_scale: DelayScale::new(0),
            packets_inspected: 0,
            bytes_inspected: 0,
            unexpected: 0,
            delay_samples: 0,
            delay_sum_us: 0,
            delay_histogram: [0; INSPECTOR_DELAY_HISTOGRAM_BUCKETS],
        }
    }
}

static CONFIG: WasmCell<InspectorConfig> = WasmCell::new(InspectorConfig {
    bypass: false,
    src_mac: None,
    dst_mac: None,
    delay_scale: DelayScale::new(0),
    packets_inspected: 0,
    bytes_inspected: 0,
    unexpected: 0,
    delay_samples: 0,
    delay_sum_us: 0,
    delay_histogram: [0; INSPECTOR_DELAY_HISTOGRAM_BUCKETS],
});

#[derive(Clone, Copy)]
struct DelayScale {
    frequency: u64,
    numerator: u32,
    denominator: u32,
    max_fast_cycles: u32,
}

impl DelayScale {
    const fn new(frequency: u64) -> Self {
        // Reduce cycles * 1_000_000 / frequency once at initialization.
        let mut a = frequency;
        let mut b = 1_000_000u64;
        while b != 0 {
            let remainder = a % b;
            a = b;
            b = remainder;
        }
        let numerator = (1_000_000 / a) as u32;
        let denominator = frequency / a;
        if denominator <= u32::MAX as u64 {
            Self {
                frequency,
                numerator,
                denominator: denominator as u32,
                max_fast_cycles: u32::MAX / numerator,
            }
        } else {
            Self {
                frequency,
                numerator,
                denominator: 0,
                max_fast_cycles: 0,
            }
        }
    }
}

#[inline]
fn packet_delay_us(receive_tsc: u64, send_tsc: u64, scale: DelayScale) -> Option<u64> {
    if scale.frequency == 0 || receive_tsc < send_tsc {
        return None;
    }

    let elapsed_cycles = receive_tsc - send_tsc;
    if scale.denominator != 0 && elapsed_cycles <= scale.max_fast_cycles as u64 {
        return Some(((elapsed_cycles as u32 * scale.numerator) / scale.denominator) as u64);
    }

    Some(packet_delay_us_fallback(elapsed_cycles, scale.frequency))
}

#[cold]
fn packet_delay_us_fallback(elapsed_cycles: u64, tsc_frequency: u64) -> u64 {
    // Keep the exact wide-range behavior for values outside the 32-bit path.
    // The first case still avoids Wasm's software 128-bit division.
    if let Some(scaled_cycles) = elapsed_cycles.checked_mul(1_000_000) {
        return scaled_cycles / tsc_frequency;
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
    seconds.wrapping_mul(1_000_000).wrapping_add(fractional_us)
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
            delay_scale: DelayScale::new(tsc_frequency),
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
        let bypass = config.bypass;
        let delay_scale = config.delay_scale;
        let mut processed = 0;

        for mut packet in batch.iter_mut() {
            if packet.tick_kind().is_some() {
                packet.set_action(ROUTE_DROP);
                continue;
            }

            if !bypass {
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
                    packet_delay_us(packet.timestamp(), send_tsc, delay_scale)
                }) {
                    Some(delay_us) => {
                        config.delay_samples += 1;
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

            /* As we drop the packet currently, we do not need this:
            // The packet crossed the cable and is being sent back through the
            // receiving interface. Apply the configured reverse Ethernet
            // addresses so the frame reaches the other NIC port.
            if config.src_mac.is_some() || config.dst_mac.is_some() {
                if let Some(header) = packet.mac_header_mut() {
                    if let Some(mac) = config.src_mac {
                        let mac = MacAddr6::from(mac);
                        header.set_smac(&mac);
                    }
                    if let Some(mac) = config.dst_mac {
                        let mac = MacAddr6::from(mac);
                        header.set_dmac(&mac);
                    }
                }
            }
            */
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

        let telemetry = alloc::vec![
            TelemetryMetric::Counter(Counter {
                name: String::from("packets_inspected"),
                value: config.packets_inspected
            }),
            TelemetryMetric::Counter(Counter {
                name: String::from("bytes_inspected"),
                value: config.bytes_inspected
            }),
            TelemetryMetric::Counter(Counter {
                name: String::from("unexpected"),
                value: config.unexpected
            }),
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
    use super::{packet_delay_us, DelayScale};

    #[test]
    fn packet_delay_rejects_invalid_timestamps_and_frequency() {
        assert_eq!(packet_delay_us(10, 0, DelayScale::new(0)), None);
        assert_eq!(packet_delay_us(9, 10, DelayScale::new(1)), None);
        assert_eq!(packet_delay_us(10, 10, DelayScale::new(1)), Some(0));
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
            assert_eq!(
                packet_delay_us(elapsed, 0, DelayScale::new(frequency)),
                Some(expected),
                "elapsed={elapsed} frequency={frequency}"
            );
        };
        for frequency in [1_000_000, 3_417_600_000, 4_294_967_295, u64::MAX] {
            let scale = DelayScale::new(frequency);
            for elapsed in [
                0,
                1,
                scale.max_fast_cycles as u64,
                scale.max_fast_cycles as u64 + 1,
                1_000_000,
                u64::MAX,
            ] {
                check(elapsed, frequency);
            }
        }
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
