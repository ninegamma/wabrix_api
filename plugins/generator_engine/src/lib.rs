#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use crate::exports::wabrix::plugins::packet_engine::{Guest, TimerPlan};
use crate::wabrix::plugins::logging;
use wabrix_api::connections::ConnectionPool;
use wabrix_api::engine_common::{handle_control_event, ControlResult};
use wabrix_api::engine_common::{parse_generator_config, SeparatedString, WasmCell, WasmValue};
use wabrix_api::mailbox_api::{MailboxBatch, MailboxPacket};
use wabrix_api::{MAX_BATCH_SIZE, TIMER_KIND_TIMEOUT};

use wabrix_api::tcp_common::{
    write_tcp_reply, write_udp_packet, GeneratorConfig, GeneratorProtocol, SynGenerator, FLAG_SYN,
    PORT_END_RANGE, PORT_START_RANGE, STAT_COUNT, STAT_DROP, STAT_SENT_SYN, STAT_TICK_DROP,
    STAT_TO_LINUX,
};

// 1. Tell the macro to read the .wit file and generate the bindings
wit_bindgen::generate!({
    path: "../../wit/wabrix.wit",
    world: "engine-plugin",
});

static CONFIG: WasmCell<Option<GeneratorConfig>> = WasmCell::new(None);
static CONNECTIONS: WasmCell<Option<ConnectionPool>> = WasmCell::new(None);
static TIMEOUT_QUEUE: WasmCell<wabrix_api::tcp_common::TimeoutStack> =
    WasmCell::new(wabrix_api::tcp_common::TimeoutStack::new());
static SYN_GEN: WasmCell<SynGenerator> = WasmCell::new(SynGenerator {
    last_tsc: 0,
    cycle_accumulator: 0,
    port_counter: PORT_START_RANGE,
    ip_offset: 0,
    prng_state: 1,
    syns_sent: 0,
    activated: true,
});

static CURRENT_TSC: WasmValue<u64> = WasmValue::new(0);
static RUN_START_TSC: WasmValue<u64> = WasmValue::new(0);
static GENERATION_START_TSC: WasmValue<u64> = WasmValue::new(0);

const ROUTE_TX: u32 = 0;
const ROUTE_LINUX: u32 = 1;
const ROUTE_DROP: u32 = 2;

// The zero-cost global counter array
static TCP_STATS: WasmCell<[u64; STAT_COUNT]> = WasmCell::new([0; STAT_COUNT]);

struct HostLogger;

impl log::Log for HostLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true // You can add level filtering here if you want to save cycles
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            // Format the message using the alloc crate
            let msg = alloc::format!("generator_engine: {}", record.args());
            // Call the WIT-generated host function.
            // The path matches your package: wabrix:plugins/logging
            logging::log(record.level() as u32, &msg);
        }
    }

    fn flush(&self) {}
}

// 2. Add an init function to wire it up when the plugin starts
pub fn init_logging() {
    // We use set_logger instead of set_boxed_logger to avoid allocations if possible,
    // or Box::new if required by the log crate version.
    static LOGGER: HostLogger = HostLogger;
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info); // Set your desired Wasm log level
}

#[inline(always)]
fn prepare_syn_packet(
    packet: &mut MailboxPacket<'_>,
    gen: &mut SynGenerator,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: u32,
    dst_ip: u32,
) {
    gen.syns_sent += 1;
    let src_port = gen.port_counter;
    gen.prng_state = gen
        .prng_state
        .wrapping_mul(1664525)
        .wrapping_add(1013904223);
    let isn = gen.prng_state;
    let packet_src_ip = src_ip.wrapping_add(gen.ip_offset);

    if gen.port_counter == PORT_END_RANGE {
        gen.port_counter = PORT_START_RANGE;
        gen.ip_offset = (gen.ip_offset + 1) % 250;
    } else {
        gen.port_counter += 1;
    }

    let data_ptr = packet.data_ptr_mut();

    // SAFETY: The host-owned timer frame has capacity for the generated SYN
    // packet and grants this plugin exclusive access during process_batch.
    let packet_len = unsafe {
        write_tcp_reply(
            data_ptr,
            src_mac,
            dst_mac,
            packet_src_ip,
            src_port,
            dst_ip,
            80,
            isn,
            0,
            FLAG_SYN,
        )
    };
    packet.resize_payload(packet_len);
}

#[inline(never)]
fn prepare_udp_packet(
    packet: &mut MailboxPacket<'_>,
    gen: &mut SynGenerator,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: u32,
    dst_ip: u32,
) {
    gen.syns_sent += 1;
    let src_port = gen.port_counter;
    if gen.port_counter == PORT_END_RANGE {
        gen.port_counter = PORT_START_RANGE;
    } else {
        gen.port_counter += 1;
    }

    let data_ptr = packet.data_ptr_mut();

    // SAFETY: The host-owned timer frame has capacity for the generated UDP
    // packet and grants this plugin exclusive access during process_batch.
    let packet_len =
        unsafe { write_udp_packet(data_ptr, src_mac, dst_mac, src_ip, src_port, dst_ip, 80) };
    packet.resize_payload(packet_len);
}

#[derive(Clone, Copy)]
struct GeneratorBatchConfig {
    generation_rate: u64,
    generation_limit: Option<u64>,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    tsc_frequency: u64,
}

#[inline(always)]
fn process_batch_for_protocol<const UDP: bool>(
    batch_size: u32,
    partition_offset: u32,
    mailbox_offset: u32,
    config: GeneratorBatchConfig,
) -> u32 {
    let mut batch = MailboxBatch::new(batch_size, partition_offset, mailbox_offset);
    let mut stats = TCP_STATS.borrow_mut();

    for mut packet in batch.iter_mut() {
        let action = if let Some(timer_kind) = packet.tick_kind() {
            let mut generated_reply = false;

            if timer_kind != TIMER_KIND_TIMEOUT && config.generation_rate > 0 {
                let mut gen = SYN_GEN.borrow_mut();
                let allowed_to_send = gen.activated
                    && match config.generation_limit {
                        Some(max_packets) => gen.syns_sent < max_packets || max_packets == 0,
                        None => true,
                    };

                if allowed_to_send {
                    let packet_start_tsc = CURRENT_TSC.get();
                    let src_ip = u32::from_be_bytes(config.src_ip);
                    let dst_ip = u32::from_be_bytes(config.dst_ip);

                    if UDP {
                        prepare_udp_packet(
                            &mut packet,
                            &mut gen,
                            config.src_mac,
                            config.dst_mac,
                            src_ip,
                            dst_ip,
                        );
                    } else {
                        prepare_syn_packet(
                            &mut packet,
                            &mut gen,
                            config.src_mac,
                            config.dst_mac,
                            src_ip,
                            dst_ip,
                        );
                    }

                    let packet_end_tsc = CURRENT_TSC.get();
                    if gen.syns_sent == 1 {
                        GENERATION_START_TSC.set(packet_start_tsc);
                    }

                    let generation_complete = config
                        .generation_limit
                        .is_some_and(|limit| limit > 0 && gen.syns_sent == limit);
                    if generation_complete {
                        let start_tsc = GENERATION_START_TSC.get();
                        let elapsed_tsc = packet_end_tsc.saturating_sub(start_tsc);
                        let elapsed_micros = if config.tsc_frequency > 0 {
                            (elapsed_tsc as u128 * 1_000_000) / config.tsc_frequency as u128
                        } else {
                            0
                        };
                        let packets = gen.syns_sent as u128;
                        let packets_per_second = if elapsed_micros > 0 {
                            packets * 1_000_000 / elapsed_micros
                        } else {
                            0
                        };

                        log::info!(
                            "generation run complete: packets={}, elapsed={}us, speed={} packets/s",
                            packets.separated_string(),
                            elapsed_micros.separated_string(),
                            packets_per_second.separated_string()
                        );
                    }

                    stats[STAT_SENT_SYN] += 1;
                    generated_reply = true;
                }
            }

            if !generated_reply {
                stats[STAT_DROP] += 1;
                stats[STAT_TICK_DROP] += 1;
                ROUTE_DROP
            } else {
                ROUTE_TX
            }
        } else {
            stats[STAT_TO_LINUX] += 1;
            ROUTE_LINUX
        };
        packet.set_action(action);
    }

    batch_size
}

struct GeneratorEngine;

impl Guest for GeneratorEngine {
    // - init_data is called once per plugin instance, and is responsible for initializing the state of the plugin.
    // - It is called before any other function in the plugin.
    // - The init_data function is called with the following arguments:
    //   - data: A vector of key-value pairs, where each pair is a (key, value) tuple.
    //     The key value pairs are set in the .toml file for a node of type WasmEngine in the section "wasm_data"
    //   - tsc_frequency: The frequency of the TSC counter, in Hz.
    // - The init_data function should initialize the plugin's state, such as the connection pool
    //   or any other state that needs to be maintained across batches.
    // - The init_data function also stores the TSC frequency in GeneratorConfig.
    // - The init_data function returns a boolean value indicating whether the initialization was successful.
    // - If the initialization is successful, the plugin will be ready to process batches.
    fn init_data(
        data: Vec<(alloc::string::String, alloc::string::String)>,
        tsc_frequency: u64,
    ) -> bool {
        init_logging();
        let Some((config, _node_name)) = parse_generator_config(data, tsc_frequency) else {
            return false;
        };
        *CONFIG.borrow_mut() = Some(config);

        true
    }

    fn process_batch(batch_size: u32, partition_offset: u32, mailbox_offset: u32) -> u32 {
        let config_guard = CONFIG.borrow();
        let (protocol, config) = config_guard.as_ref().map_or(
            (
                GeneratorProtocol::Syn,
                GeneratorBatchConfig {
                    generation_rate: 0,
                    generation_limit: None,
                    src_ip: [0; 4],
                    dst_ip: [0; 4],
                    src_mac: [0; 6],
                    dst_mac: [0xff; 6],
                    tsc_frequency: 0,
                },
            ),
            |config| {
                (
                    config.protocol,
                    GeneratorBatchConfig {
                        generation_rate: config.generation_rate.unwrap_or(0),
                        generation_limit: config.generation_limit,
                        src_ip: config.src_ip.unwrap_or([0; 4]),
                        dst_ip: config.dst_ip.unwrap_or([0; 4]),
                        src_mac: config.src_mac.unwrap_or([0; 6]),
                        dst_mac: config.dst_mac.unwrap_or([0xff; 6]),
                        tsc_frequency: config.tsc_frequency,
                    },
                )
            },
        );
        match protocol {
            GeneratorProtocol::Syn => process_batch_for_protocol::<false>(
                batch_size,
                partition_offset,
                mailbox_offset,
                config,
            ),
            GeneratorProtocol::Udp => process_batch_for_protocol::<true>(
                batch_size,
                partition_offset,
                mailbox_offset,
                config,
            ),
        }
    }

    fn process_timers(current_tsc: u64) -> TimerPlan {
        // Share time with process_batch
        CURRENT_TSC.set(current_tsc);

        if RUN_START_TSC.get() == 0 {
            RUN_START_TSC.set(current_tsc);
        }

        // Keep the configuration borrowed for the duration of this read-only
        // operation. Cloning `GeneratorConfig` here would clone its optional
        // node name on every timer callback.
        let config_guard = CONFIG.borrow();
        let Some(config) = config_guard.as_ref() else {
            return TimerPlan {
                timeout_frames: 0,
                syn_frames: 0,
            };
        };
        let tsc_freq = config.tsc_frequency;

        if tsc_freq == 0 {
            return TimerPlan {
                timeout_frames: 0,
                syn_frames: 0,
            };
        }

        // =================================================================
        // SYN GENERATOR
        // =================================================================
        let generation_rate = config.generation_rate.unwrap_or(0);
        let mut desired_syn_frames = 0;
        if generation_rate > 0 {
            let mut gen = SYN_GEN.borrow_mut();

            let allowed_to_send = gen.activated
                && match config.generation_limit {
                    Some(max_syns) => gen.syns_sent < max_syns || max_syns == 0,
                    None => true,
                };

            if allowed_to_send {
                if gen.last_tsc == 0 {
                    gen.last_tsc = current_tsc;
                }
                let delta_tsc = current_tsc.saturating_sub(gen.last_tsc);
                gen.last_tsc = current_tsc;

                gen.cycle_accumulator = gen
                    .cycle_accumulator
                    .saturating_add((delta_tsc as u128) * (generation_rate as u128));
                let syn_frames = (gen.cycle_accumulator / (tsc_freq as u128)) as u32;

                if let Some(max_syns) = config.generation_limit {
                    let mut syn_frames = syn_frames;
                    let remaining = max_syns.saturating_sub(gen.syns_sent);
                    if (syn_frames as u64) > remaining {
                        syn_frames = remaining as u32;
                    }
                    desired_syn_frames = syn_frames;
                } else {
                    desired_syn_frames = syn_frames;
                }
            }
        }

        let max_batch = MAX_BATCH_SIZE as u32;
        let syn_frames = desired_syn_frames.min(max_batch);

        if syn_frames > 0 {
            let mut gen = SYN_GEN.borrow_mut();
            gen.cycle_accumulator = gen
                .cycle_accumulator
                .saturating_sub((syn_frames as u128) * (tsc_freq as u128));
        }

        TimerPlan {
            timeout_frames: 0,
            syn_frames,
        }
    }

    // Inside the Wasm plugin code

    fn on_control_event(raw_opcode: u32, payload: Vec<u8>) -> bool {
        return match handle_control_event(raw_opcode, &payload, &CONFIG, &SYN_GEN) {
            ControlResult::Flush(mode) => {
                flush_state(mode);
                true
            }
            ControlResult::Handled => true,
            ControlResult::Invalid => false,
        };
    }
    fn get_telemetry() -> Vec<u64> {
        let mut stats = TCP_STATS.borrow().to_vec();
        // Add current pool usage to stats
        if let Some(pool) = CONNECTIONS.borrow().as_ref() {
            stats.push(pool.watermark as u64); // Current active/reused nodes
        }
        stats
    }
}

fn set_state(state: u8) {
    let mut syn_gen = SYN_GEN.borrow_mut();
    let mut config_guard = CONFIG.borrow_mut();

    // Safely attempt to modify the config only if it exists
    if let Some(config) = config_guard.as_mut() {
        match state {
            0 => {
                // State 0: Offline / Paused
                syn_gen.activated = false;
                config.bypass = false;
            }
            1 => {
                // State 1: Online / Active
                syn_gen.activated = true;
                config.bypass = false;
            }
            2 => {
                // State 2: Bypass Mode
                // Disable generation, let all traffic flow transparently
                syn_gen.activated = false;
                config.bypass = true;
            }
            _ => {
                // Ignore unknown states
            }
        }
    }
}

fn flush_state(mode: u8) {
    // This stops the generator and prevents a new run from starting automatically.
    set_state(0);

    // Clear the pool in-place instead of re-allocating
    if let Some(pool) = CONNECTIONS.borrow_mut().as_mut() {
        pool.clear();
    }

    // Clear the pending timeout teardowns so we don't send FINs for connections
    // that just got wiped out.
    TIMEOUT_QUEUE.borrow_mut().clear();

    // Reset the SYN generator tracking
    {
        let mut syn_gen = SYN_GEN.borrow_mut();
        syn_gen.syns_sent = 0;
        syn_gen.cycle_accumulator = 0;
        syn_gen.last_tsc = 0;

        // Optional: If mode == 1 (Hard Reset), also reset the PRNG and Port Counter
        // to ensure perfectly repeatable PCAP generation across test runs.
        if mode == 1 {
            syn_gen.port_counter = PORT_START_RANGE;
            syn_gen.prng_state = 1;
        }
    }

    // 5. Clear all telemetry counters
    *TCP_STATS.borrow_mut() = [0; STAT_COUNT];

    log::trace!("TCP Engine state flushed (mode: {})", mode);
}

// Export the implementation to the runtime
export!(GeneratorEngine);
