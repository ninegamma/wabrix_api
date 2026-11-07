use anyhow::anyhow;

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
