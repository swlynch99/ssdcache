//! Key parsing and byte-exact echo (design §7.2 "Keys").
//!
//! A key is accepted in exactly three spellings: 16 raw bytes, 32 hex characters
//! (either case), or a 36-character UUID `8-4-4-4-12` (either case). Anything else is
//! rejected; odd keys are never hashed into 16 bytes.

pub type Key = [u8; 16];

/// How the client spelled the key, so replies can echo it byte-exactly.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum KeyRepr {
    #[default]
    Raw16,
    /// 32 hex characters. Echoed in lowercase.
    Hex32,
    /// 36-char UUID. `upper` is set if any hex letter was uppercase.
    Uuid36 { upper: bool },
}

/// Hex digit value, plus whether it was an uppercase letter.
#[inline]
fn hexval(c: u8) -> Option<(u8, bool)> {
    match c {
        b'0'..=b'9' => Some((c - b'0', false)),
        b'a'..=b'f' => Some((c - b'a' + 10, false)),
        b'A'..=b'F' => Some((c - b'A' + 10, true)),
        _ => None,
    }
}

/// Decode hex characters (an even count, filtered by `skip`) into `out`.
/// Returns `Some(any_upper)`.
fn decode_hex(s: &[u8], skip: impl Fn(usize) -> bool, out: &mut Key) -> Option<bool> {
    let mut upper = false;
    let mut nib = 0usize;
    for (i, &c) in s.iter().enumerate() {
        if skip(i) {
            continue;
        }
        let (v, u) = hexval(c)?;
        upper |= u;
        let byte = nib / 2;
        if byte >= 16 {
            return None;
        }
        if nib % 2 == 0 {
            out[byte] = v << 4;
        } else {
            out[byte] |= v;
        }
        nib += 1;
    }
    if nib == 32 { Some(upper) } else { None }
}

const UUID_HYPHENS: [usize; 4] = [8, 13, 18, 23];

/// Parse a key in one of the accepted spellings.
pub fn parse_key(s: &[u8]) -> Option<(Key, KeyRepr)> {
    let mut k = [0u8; 16];
    match s.len() {
        16 => {
            k.copy_from_slice(s);
            Some((k, KeyRepr::Raw16))
        }
        32 => {
            decode_hex(s, |_| false, &mut k)?;
            Some((k, KeyRepr::Hex32))
        }
        36 => {
            for &h in &UUID_HYPHENS {
                if s[h] != b'-' {
                    return None;
                }
            }
            let upper = decode_hex(s, |i| UUID_HYPHENS.contains(&i), &mut k)?;
            Some((k, KeyRepr::Uuid36 { upper }))
        }
        _ => None,
    }
}

/// Format `k` as the client spelled it. Returns the number of bytes written.
pub fn format_key(k: &Key, r: KeyRepr, out: &mut [u8; 36]) -> usize {
    const LO: &[u8; 16] = b"0123456789abcdef";
    const UP: &[u8; 16] = b"0123456789ABCDEF";
    match r {
        KeyRepr::Raw16 => {
            out[..16].copy_from_slice(k);
            16
        }
        KeyRepr::Hex32 => {
            for (i, &b) in k.iter().enumerate() {
                out[2 * i] = LO[(b >> 4) as usize];
                out[2 * i + 1] = LO[(b & 15) as usize];
            }
            32
        }
        KeyRepr::Uuid36 { upper } => {
            let digits = if upper { UP } else { LO };
            let mut o = 0;
            for (i, &b) in k.iter().enumerate() {
                if i == 4 || i == 6 || i == 8 || i == 10 {
                    out[o] = b'-';
                    o += 1;
                }
                out[o] = digits[(b >> 4) as usize];
                out[o + 1] = digits[(b & 15) as usize];
                o += 2;
            }
            36
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(s: &[u8]) -> Vec<u8> {
        let (k, r) = parse_key(s).unwrap();
        let mut out = [0u8; 36];
        let n = format_key(&k, r, &mut out);
        out[..n].to_vec()
    }

    #[test]
    fn raw16() {
        let s = [0u8, 1, 2, 3, 255, b' ', b'\r', b'\n', 8, 9, 10, 11, 12, 13, 14, 15];
        let (k, r) = parse_key(&s).unwrap();
        assert_eq!(k, s);
        assert_eq!(r, KeyRepr::Raw16);
        assert_eq!(roundtrip(&s), s);
    }

    #[test]
    fn hex32() {
        let s = b"00112233445566778899aabbccddeeff";
        let (k, r) = parse_key(s).unwrap();
        assert_eq!(r, KeyRepr::Hex32);
        assert_eq!(k[0], 0x00);
        assert_eq!(k[15], 0xff);
        assert_eq!(roundtrip(s), s);
        let up = b"00112233445566778899AABBCCDDEEFF";
        assert_eq!(parse_key(up).unwrap().0, k);
        assert_eq!(roundtrip(up), s.to_vec()); // lowercase echo
    }

    #[test]
    fn uuid() {
        let s = b"123e4567-e89b-12d3-a456-426614174000";
        let (k, r) = parse_key(s).unwrap();
        assert_eq!(r, KeyRepr::Uuid36 { upper: false });
        assert_eq!(k[0], 0x12);
        assert_eq!(roundtrip(s), s);
        let u = b"123E4567-E89B-12D3-A456-426614174000";
        let (k2, r2) = parse_key(u).unwrap();
        assert_eq!(k2, k);
        assert_eq!(r2, KeyRepr::Uuid36 { upper: true });
        assert_eq!(roundtrip(u), u);
    }

    #[test]
    fn rejects() {
        assert!(parse_key(b"").is_none());
        assert!(parse_key(b"abc").is_none());
        assert!(parse_key(b"0011223344556677889900aabbccddeef").is_none()); // 33
        assert!(parse_key(b"0011223344556677889g00aabbccddee").is_none()); // bad hex
        assert!(parse_key(b"123e4567xe89b-12d3-a456-426614174000").is_none());
        assert!(parse_key(b"123e4567-e89b-12d3-a456-42661417400g").is_none());
        assert!(parse_key(b"123e4567-e89b-12d3-a456-4266-1417400").is_none());
        assert!(parse_key(&[b'a'; 17]).is_none());
        assert!(parse_key(&[b'a'; 15]).is_none());
    }
}
