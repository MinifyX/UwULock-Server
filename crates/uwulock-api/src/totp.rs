//! Authenticator codes (RFC 6238) and the base32 their secrets are written in (RFC 4648).
//!
//! Six digits, HMAC-SHA1, a new code every 30 seconds — what every authenticator app does. The
//! code of the step before and the step after count too, for phones whose clock is a little off.

use ring::hmac;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32 without padding, in upper case.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Base32 in either case, with or without padding and spaces. Nothing for anything else.
pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let value = ALPHABET.iter().position(|&a| a as char == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// The code for time step `step` (seconds since 1970 divided by 30).
pub fn code(secret: &[u8], step: i64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let digest = hmac::sign(&key, &(step as u64).to_be_bytes());
    let digest = digest.as_ref();
    let offset = (digest[19] & 0x0f) as usize;
    let value = u32::from_be_bytes([digest[offset] & 0x7f, digest[offset + 1], digest[offset + 2], digest[offset + 3]]);
    format!("{:06}", value % 1_000_000)
}

/// The time step `code` belongs to, if it is one of now's, the one before or the one after.
pub fn matching_step(secret: &[u8], code_given: &str, now_seconds: i64) -> Option<i64> {
    let code_given = code_given.trim().replace(' ', "");
    if code_given.len() != 6 || !code_given.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let now = now_seconds.div_euclid(30);
    [now - 1, now, now + 1]
        .into_iter()
        .find(|step| crate::auth::constant_time_eq(code(secret, *step).as_bytes(), code_given.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_both_ways() {
        // RFC 4648's own examples.
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(base32_decode("mzxw 6ytb oi======").unwrap(), b"foobar");
        assert!(base32_decode("NOT-BASE32!").is_none());
        let secret = crate::auth::random_bytes(20);
        let text = base32_encode(&secret);
        assert_eq!(text.len(), 32);
        assert_eq!(base32_decode(&text).unwrap(), secret);
    }

    #[test]
    fn codes_are_rfc_6238_s() {
        // RFC 6238, appendix B, SHA-1, cut to six digits.
        let secret = b"12345678901234567890";
        assert_eq!(code(secret, 59 / 30), "287082");
        assert_eq!(code(secret, 1_111_111_109 / 30), "081804");
        assert_eq!(code(secret, 2_000_000_000 / 30), "279037");
    }

    #[test]
    fn a_step_either_side_counts() {
        let secret = b"12345678901234567890";
        let now = 1_111_111_109;
        let step = now / 30;
        assert_eq!(matching_step(secret, &code(secret, step), now), Some(step));
        assert_eq!(matching_step(secret, &code(secret, step - 1), now), Some(step - 1));
        assert_eq!(matching_step(secret, &code(secret, step + 1), now), Some(step + 1));
        assert_eq!(matching_step(secret, &code(secret, step + 2), now), None);
        assert_eq!(matching_step(secret, "12345", now), None);
        assert_eq!(matching_step(secret, "abcdef", now), None);
    }
}
