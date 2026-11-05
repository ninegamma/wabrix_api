use crate::exports::WPdu;
use crate::headers::check::ipv4_checksum;
use crate::headers::{
    update_ipv4_checksum, EndOffset, HeaderKind, Ipv4Hdr, TcpHdr,
};
use anyhow::anyhow;
use log::trace;
use zerocopy::FromBytes;

#[inline]
pub fn update_tcp_checksum(
    tcp_segment: &mut [u8],
    ip_src: u32,
    ip_dst: u32,
) {
    let checksum = ipv4_checksum(
        tcp_segment.as_mut_ptr(),
        tcp_segment.len(),
        8,
        &[],
        ip_src,
        ip_dst,
        6,
    );
    tcp_segment[16..18].copy_from_slice(&checksum.to_be_bytes());
}

#[inline]
pub fn prepare_checksums_and_ttl(p: &mut WPdu, base_addr: usize) {
    let frame_size = p.frame_size();
    let packet_len = p.data_len() as usize;
    let headroom = p.headroom();
    let stack = p.headers_mut();
    let Some(ip_index) = (0..stack.count()).find(|&i| stack.kinds[i] == HeaderKind::Ip) else {
        return;
    };
    let frame_offset = stack.offsets[ip_index] as usize;
    let Some(packet_offset) = frame_offset.checked_sub(headroom) else {
        return;
    };
    let Some(packet_end) = packet_offset.checked_add(Ipv4Hdr::LEN) else {
        return;
    };
    let Some(frame_end) = frame_offset.checked_add(Ipv4Hdr::LEN) else {
        return;
    };
    if packet_end > packet_len || frame_end > frame_size {
        return;
    }

    let (psz, src, dst) = {
        let ip_ptr = (base_addr + frame_offset) as *mut u8;
        // SAFETY: The stack offset and packet/frame bounds above ensure the IPv4 header is in
        // the frame. The caller owns this packet mutably for the duration of this function.
        let ip_bytes = unsafe { core::slice::from_raw_parts_mut(ip_ptr, Ipv4Hdr::LEN) };
        let Ok(ip) = Ipv4Hdr::mut_from_bytes(ip_bytes) else {
            return;
        };
        let ttl = ip.ttl;
        if ttl >= 1 {
            ip.ttl = ttl - 1;
        }
        update_ipv4_checksum(ip);
        (
            ip.payload_size(0),
            u32::from(ip.src_addr()),
            u32::from(ip.dst_addr()),
        )
    };
    let Some(tcp_index) = (0..stack.count()).find(|&i| stack.kinds[i] == HeaderKind::Tcp) else {
        return;
    };
    if psz < TcpHdr::LEN {
        return;
    }
    let tcp_frame_offset = stack.offsets[tcp_index] as usize;
    let Some(tcp_packet_offset) = tcp_frame_offset.checked_sub(headroom) else {
        return;
    };
    let Some(tcp_packet_end) = tcp_packet_offset.checked_add(psz) else {
        return;
    };
    let Some(tcp_frame_end) = tcp_frame_offset.checked_add(psz) else {
        return;
    };
    if tcp_packet_end > packet_len || tcp_frame_end > frame_size {
        return;
    }

    let checksum = {
        let tcp_ptr = (base_addr + tcp_frame_offset) as *mut u8;
        // SAFETY: The stack offset and packet/frame bounds above cover the entire TCP segment.
        let tcp_bytes = unsafe { core::slice::from_raw_parts_mut(tcp_ptr, psz) };
        update_tcp_checksum(tcp_bytes, src, dst);
        u16::from_be_bytes([tcp_bytes[16], tcp_bytes[17]])
    };
    trace!(
        "ip-payload_sz= {}, checksum recalc = {:X}",
        psz,
        checksum
    );
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

    for byte in &mut bytes {
        let part = parts.next()?;
        *byte = u8::from_str_radix(part, 16).ok()?;
    }

    if parts.next().is_some() {
        return None;
    }

    Some(bytes)
}

pub fn parse_ip(ip: &str) -> Option<[u8; 4]> {
    let mut bytes = [0u8; 4];
    let mut parts = ip.split('.');

    for byte in &mut bytes {
        let part = parts.next()?;
        *byte = part.parse::<u8>().ok()?;
    }

    if parts.next().is_some() {
        return None;
    }

    Some(bytes)
}
