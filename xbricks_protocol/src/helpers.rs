use anyhow::anyhow;
use log::trace;
use crate::headers::{EndOffset, TcpHeader};
use crate::headers::check::ipv4_checksum;
use crate::exports::WPdu;


#[inline]
pub fn update_tcp_checksum(tcp_header: &mut TcpHeader, ip_payload_size: usize, ip_src: u32, ip_dst: u32) {
    let chk;
    {
        chk = ipv4_checksum(
            tcp_header as *mut TcpHeader as *mut u8,
            ip_payload_size,
            8,
            &[],
            ip_src,
            ip_dst,
            6u32,
        );
    }
    tcp_header.set_checksum(chk);
}



#[inline]
pub fn prepare_checksums_and_ttl(p: &mut WPdu, base_addr: usize) {
    let stack = p.headers_mut();
    let psz;
    let src;
    let dst;
    {
        let ip = stack.ip_mut(base_addr, 1);
        let ttl = ip.ttl();
        if ttl >= 1 {
            ip.set_ttl(ttl - 1);
        }
        ip.update_checksum();
        psz = ip.payload_size(0);
        src = ip.src();
        dst = ip.dst();
    }
    update_tcp_checksum(stack.tcp_mut(base_addr, 2), psz, src, dst);
    trace!("ip-payload_sz= {}, checksum recalc = {:X}", psz, stack.tcp_mut(base_addr, 2).checksum());
}

pub fn parse_suffixed_number(pps_str: &str) -> anyhow::Result<u64> {
    let s = pps_str.to_lowercase();

    // 1. Handle the "max" case
    if s == "max" {
        return Ok(u64::MAX);
    }

    // 2. Identify the suffix and determine the multiplier
    let (numeric_part, multiplier) = if s.ends_with('k') {
        (&s[..s.len() - 1], 1_000.0)
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], 1_000_000.0)
    } else if s.ends_with('g') {
        (&s[..s.len() - 1], 1_000_000_000.0)
    } else {
        (s.as_str(), 1.0)
    };

    // 3. Parse as f64 to allow decimals like "2.5"
    let base_val: f64 = numeric_part.trim().parse().map_err(|_| {
        anyhow!(
            "Invalid PPS format: '{}'.\n\
            Expected a number (integer or decimal) optionally followed by k, m, or g.\n\
            Examples: '500', '10k', '2.5M', or 'max'.",
            pps_str
        )
    })?;

    // 4. Validation checks
    if base_val <= 0.0 || base_val.is_nan() || base_val.is_infinite() {
        return Err(anyhow!("PPS must be a positive number or 'max'."));
    }

    // 5. Convert to u64
    Ok((base_val * multiplier) as u64)
}


// #![no_std] Safe Parsers
// =====================================================================

pub fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let mut bytes = [0u8; 6];
    let mut parts = mac.split(':');

    for i in 0..6 {
        let part = parts.next()?;
        bytes[i] = u8::from_str_radix(part, 16).ok()?;
    }

    if parts.next().is_some() {
        return None;
    }

    Some(bytes)
}

pub fn parse_ip(ip: &str) -> Option<[u8; 4]> {
    let mut bytes = [0u8; 4];
    let mut parts = ip.split('.');

    for i in 0..4 {
        let part = parts.next()?;
        bytes[i] = part.parse::<u8>().ok()?;
    }

    if parts.next().is_some() {
        return None;
    }

    Some(bytes)
}
