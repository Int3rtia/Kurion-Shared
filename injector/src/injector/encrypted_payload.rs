pub fn r_crypt(data: &mut [u8], key: &[u8]) {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j: u8 = 0;

    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    let mut i: u8 = 0;
    j = 0;
    for byte in data.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        *byte ^= k;
    }
}

pub fn d_hex_payload(hex: &str, original_size: usize, key: &[u8]) -> Result<Vec<u8>, String> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    if hex.is_empty() {
        return Err("No embedded payload".to_string());
    }

    let hex_bytes = hex.as_bytes();
    let compressed_len = hex_bytes.len() / 2;
    let mut encrypted = Vec::with_capacity(compressed_len);
    for chunk in hex_bytes.chunks(2) {
        if chunk.len() < 2 { break; }
        let hi = h_nibble(chunk[0]).ok_or("bad hex")?;
        let lo = h_nibble(chunk[1]).ok_or("bad hex")?;
        encrypted.push((hi << 4) | lo);
    }

    r_crypt(&mut encrypted, key);

    let mut decoder = ZlibDecoder::new(&encrypted[..]);
    let mut output = Vec::with_capacity(original_size);
    decoder.read_to_end(&mut output)
        .map_err(|e| format!("zlib decompress failed: {}", e))?;

    Ok(output)
}

#[inline(always)]
fn h_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
