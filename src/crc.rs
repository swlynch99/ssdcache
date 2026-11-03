//! crc32c (Castagnoli) for value integrity on the SSD tier. SSE4.2 when available.

const POLY: u32 = 0x82F6_3B78;

const TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

fn crc32c_sw(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = TABLE[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn crc32c_hw(mut crc: u32, data: &[u8]) -> u32 {
    use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};
    let mut c = crc as u64;
    let (pre, mid, post) = unsafe { data.align_to::<u64>() };
    for &b in pre {
        c = _mm_crc32_u8(c as u32, b) as u64;
    }
    for &w in mid {
        c = _mm_crc32_u64(c, w);
    }
    crc = c as u32;
    for &b in post {
        crc = _mm_crc32_u8(crc, b);
    }
    crc
}

pub fn crc32c(data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("sse4.2") {
            return !unsafe { crc32c_hw(!0, data) };
        }
    }
    !crc32c_sw(!0, data)
}

#[cfg(test)]
mod tests {
    #[test]
    fn known_vector() {
        assert_eq!(super::crc32c(b"123456789"), 0xE306_9283);
        let data: Vec<u8> = (0..100_003u32).map(|i| (i * 31) as u8).collect();
        assert_eq!(super::crc32c(&data), !super::crc32c_sw(!0, &data));
    }
}
