//! Shared, WIT-independent support for `engine-plugin` implementations.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use hashbrown::HashMap;

use crate::helpers::{parse_ip, parse_mac, parse_suffixed_number};
use crate::tcp_common::{
    CommonEngineConfig, GeneratorConfig, GeneratorProtocol, SynGenerator, TcpEngineConfig,
};
use crate::{HotWasmPayload, PluginOpcode, StandardOpcode};

/// No-std equivalent of the formatting helper used by the native tools.
pub trait SeparatedString {
    fn separated_string(&self) -> String;
}

impl SeparatedString for u128 {
    fn separated_string(&self) -> String {
        let value = self.to_string();
        let mut result = String::with_capacity(value.len() + value.len() / 3);

        for (index, character) in value.chars().enumerate() {
            if index > 0 && (value.len() - index) % 3 == 0 {
                result.push(',');
            }
            result.push(character);
        }
        result
    }
}

impl SeparatedString for u64 {
    fn separated_string(&self) -> String {
        (*self as u128).separated_string()
    }
}

/// A zero-cost state container for single-threaded WASM plugin state.
pub struct WasmCell<T>(RefCell<T>);

// SAFETY: A WASM component instance is single-threaded. The `Sync` implementation is
// required only so the container can be used in a static and cannot be observed concurrently.
unsafe impl<T> Sync for WasmCell<T> {}

impl<T> WasmCell<T> {
    pub const fn new(value: T) -> Self {
        Self(RefCell::new(value))
    }

    pub fn borrow(&self) -> core::cell::Ref<'_, T> {
        self.0.borrow()
    }

    pub fn borrow_mut(&self) -> core::cell::RefMut<'_, T> {
        self.0.borrow_mut()
    }
}

/// A zero-cost state container for simple `Copy` values in a WASM plugin.
pub struct WasmValue<T>(Cell<T>);

// SAFETY: As with `WasmCell`, plugin state is accessed by one WASM thread only.
unsafe impl<T> Sync for WasmValue<T> {}

impl<T> WasmValue<T> {
    pub const fn new(value: T) -> Self {
        Self(Cell::new(value))
    }

    pub fn get(&self) -> T
    where
        T: Copy,
    {
        self.0.get()
    }

    pub fn set(&self, value: T) {
        self.0.set(value)
    }
}

pub enum ControlResult {
    Handled,
    Flush(u8),
    Invalid,
}

pub trait EngineConfigModel {
    fn common_mut(&mut self) -> &mut CommonEngineConfig;
    fn apply_updates(&mut self, updates: &HashMap<String, String>) -> bool;
}

fn parse_update_number(updates: &HashMap<String, String>, key: &str) -> Result<Option<Option<u64>>, ()> {
    match updates.get(key) {
        Some(value) if value.is_empty() => Ok(Some(None)),
        Some(value) => parse_suffixed_number(value).map(|number| Some(Some(number))).map_err(|_| ()),
        None => Ok(None),
    }
}

impl EngineConfigModel for TcpEngineConfig {
    fn common_mut(&mut self) -> &mut CommonEngineConfig {
        &mut self.common
    }

    fn apply_updates(&mut self, updates: &HashMap<String, String>) -> bool {
        let Ok(syn_rate) = parse_update_number(updates, "syn_rate") else {
            return false;
        };
        let Ok(syn_limit) = parse_update_number(updates, "syn_limit") else {
            return false;
        };
        let close_timeout = match updates.get("close_timeout") {
            Some(value) if value.is_empty() => Some(None),
            Some(value) => match value.parse::<u64>() {
                Ok(number) => Some(Some(number)),
                Err(_) => return false,
            },
            None => None,
        };

        if let Some(value) = syn_rate {
            self.syn_rate = value;
        }
        if let Some(value) = syn_limit {
            self.syn_limit = value;
        }
        if let Some(value) = close_timeout {
            self.close_timeout_millis = value;
        }
        true
    }
}

impl EngineConfigModel for GeneratorConfig {
    fn common_mut(&mut self) -> &mut CommonEngineConfig {
        &mut self.common
    }

    fn apply_updates(&mut self, updates: &HashMap<String, String>) -> bool {
        let rate_key = if updates.contains_key("generation_rate") {
            "generation_rate"
        } else {
            "syn_rate"
        };
        let limit_key = if updates.contains_key("generation_limit") {
            "generation_limit"
        } else {
            "syn_limit"
        };
        let Ok(rate) = parse_update_number(updates, rate_key) else {
            return false;
        };
        let Ok(limit) = parse_update_number(updates, limit_key) else {
            return false;
        };
        let protocol = match updates.get("prot").or_else(|| updates.get("protocol")) {
            Some(value) => match GeneratorProtocol::parse(value) {
                Some(protocol) => Some(protocol),
                None => return false,
            },
            None => None,
        };

        if let Some(value) = rate {
            self.generation_rate = value;
        }
        if let Some(value) = limit {
            self.generation_limit = value;
        }
        if let Some(protocol) = protocol {
            self.protocol = protocol;
        }
        true
    }
}

/// Handle the control protocol shared by all `engine-plugin` implementations.
/// Plugin adapters remain responsible only for plugin-specific flush work and logging.
pub fn handle_control_event<C: EngineConfigModel>(
    raw_opcode: u32,
    payload: &[u8],
    config: &WasmCell<Option<C>>,
    syn_generator: &WasmCell<SynGenerator>,
) -> ControlResult {
    match PluginOpcode::from(raw_opcode) {
        PluginOpcode::Standard(StandardOpcode::SetOperationalState) => {
            if payload.len() != 1 {
                return ControlResult::Invalid;
            }
            set_operational_state(payload[0], config, syn_generator);
            ControlResult::Handled
        }
        PluginOpcode::Standard(StandardOpcode::FlushState) => {
            let mode = if payload.len() == 1 { payload[0] } else { 0 };
            set_operational_state(0, config, syn_generator);
            reset_syn_state(mode, syn_generator);
            ControlResult::Flush(mode)
        }
        PluginOpcode::Standard(StandardOpcode::Ping) => ControlResult::Handled,
        PluginOpcode::Standard(StandardOpcode::UpdateConfiguration) => {
            let Ok(data) = postcard::from_bytes::<HotWasmPayload>(payload) else {
                return ControlResult::Invalid;
            };
            if apply_configuration_update(&data.updates, config) {
                ControlResult::Handled
            } else {
                ControlResult::Invalid
            }
        }
        _ => ControlResult::Invalid,
    }
}

pub fn set_operational_state<C: EngineConfigModel>(
    state: u8,
    config: &WasmCell<Option<C>>,
    syn_generator: &WasmCell<SynGenerator>,
) {
    let mut generator = syn_generator.borrow_mut();
    let mut config = config.borrow_mut();

    if let Some(config) = config.as_mut() {
        match state {
            0 => {
                generator.activated = false;
                config.common_mut().bypass = false;
            }
            1 => {
                generator.activated = true;
                config.common_mut().bypass = false;
            }
            2 => {
                generator.activated = false;
                config.common_mut().bypass = true;
            }
            _ => {}
        }
    }
}

pub fn reset_syn_state(mode: u8, syn_generator: &WasmCell<SynGenerator>) {
    let mut generator = syn_generator.borrow_mut();
    generator.syns_sent = 0;
    generator.cycle_accumulator = 0;
    generator.last_tsc = 0;

    if mode == 1 {
        generator.port_counter = crate::tcp_common::PORT_START_RANGE;
        generator.prng_state = 1;
    }
}

fn apply_configuration_update<C: EngineConfigModel>(
    updates: &HashMap<String, String>,
    config: &WasmCell<Option<C>>,
) -> bool {
    let mut guard = config.borrow_mut();
    let Some(config) = guard.as_mut() else {
        return false;
    };
    config.apply_updates(updates)
}

/// Parse and validate configuration common to engine plugins.
///
/// The returned node name uses the shared engine fallback behavior: an explicit
/// `name` wins, otherwise the original `src_ip` string is used.
pub fn parse_generator_config(
    data: Vec<(String, String)>,
    tsc_frequency: u64,
) -> Option<(GeneratorConfig, String)> {
    let mut config = GeneratorConfig::default();
    let mut raw_src_ip = None;

    for (key, value) in data {
        match key.as_str() {
            "name" => config.name = Some(value),
            "src_mac" => {
                config.src_mac = parse_mac(&value);
                config.src_mac.as_ref()?;
            }
            "dst_mac" => {
                config.dst_mac = parse_mac(&value);
                config.dst_mac.as_ref()?;
            }
            "src_ip" => {
                raw_src_ip = Some(value.clone());
                config.src_ip = parse_ip(&value);
                config.src_ip.as_ref()?;
            }
            "dst_ip" => {
                config.dst_ip = parse_ip(&value);
                config.dst_ip.as_ref()?;
            }
            "rng_seed" => {
                config.rng_seed = value.parse::<u32>().ok();
                config.rng_seed.as_ref()?;
            }
            "generation_rate" | "syn_rate" => {
                config.generation_rate = parse_suffixed_number(&value).ok();
                config.generation_rate.as_ref()?;
            }
            "generation_limit" | "syn_limit" => {
                config.generation_limit = parse_suffixed_number(&value).ok();
                config.generation_limit.as_ref()?;
            }
            "protocol" | "prot" => {
                config.protocol = GeneratorProtocol::parse(&value)?;
            }
            _ => {}
        }
    }

    if config.src_ip.is_none()
        || config.src_mac.is_none()
        || config.dst_mac.is_none()
        || (config.dst_ip.is_none() && config.generation_rate.is_some_and(|rate| rate > 0))
    {
        return None;
    }

    config.common.tsc_frequency = tsc_frequency;
    let node_name = config
        .name
        .clone()
        .or(raw_src_ip)
        .unwrap_or_else(|| String::from("unknown"));

    Some((config, node_name))
}
