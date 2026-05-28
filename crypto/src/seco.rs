use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use flate2::read::GzDecoder;
use sha2::{Sha256, Digest};
use std::io::Read;

const HEADER_LEN: usize = 224;
const CHECKSUM_LEN: usize = 32;
const METADATA_LEN: usize = 256;
const METADATA_OFFSET: usize = HEADER_LEN + CHECKSUM_LEN;
const BLOB_OFFSET: usize = METADATA_OFFSET + METADATA_LEN;

pub fn d_seco(file_data: &[u8], password: &str) -> Result<String, String> {
    if file_data.len() < BLOB_OFFSET + 5 {
        return Err("File too small".into());
    }

    if &file_data[0..4] != b"SECO" {
        return Err("Invalid magic".into());
    }

    let md = &file_data[METADATA_OFFSET..METADATA_OFFSET + METADATA_LEN];
    let salt = &md[0..32];
    let n = u32::from_be_bytes(md[32..36].try_into().unwrap());
    let r = u32::from_be_bytes(md[36..40].try_into().unwrap());
    let p = u32::from_be_bytes(md[40..44].try_into().unwrap());
    let blobkey_iv = &md[76..88];
    let blobkey_tag = &md[88..104];
    let enc_blobkey = &md[104..136];
    let blob_iv = &md[136..148];
    let blob_tag = &md[148..164];

    let blob_len = u32::from_be_bytes(
        file_data[BLOB_OFFSET..BLOB_OFFSET + 4].try_into().unwrap(),
    ) as usize;
    if file_data.len() < BLOB_OFFSET + 4 + blob_len {
        return Err("File truncated".into());
    }
    let blob_data = &file_data[BLOB_OFFSET + 4..BLOB_OFFSET + 4 + blob_len];

    let checksum = &file_data[HEADER_LEN..HEADER_LEN + CHECKSUM_LEN];
    let computed = Sha256::digest(&file_data[METADATA_OFFSET..BLOB_OFFSET + 4 + blob_len]);
    if computed.as_slice() != checksum {
        return Err("Checksum mismatch".into());
    }

    let log_n = (n as f64).log2() as u8;
    let params = scrypt::Params::new(log_n, r, p, 32)
        .map_err(|e| format!("scrypt params: {}", e))?;
    let mut derived_key = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut derived_key)
        .map_err(|e| format!("scrypt KDF: {}", e))?;

    let cipher1 = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|_| "AES key init failed".to_string())?;
    let mut ct1 = enc_blobkey.to_vec();
    ct1.extend_from_slice(blobkey_tag);
    let blob_key = cipher1
        .decrypt(Nonce::from_slice(blobkey_iv), ct1.as_ref())
        .map_err(|_| "Wrong password or corrupted file".to_string())?;

    let cipher2 = Aes256Gcm::new_from_slice(&blob_key)
        .map_err(|_| "Blob key init failed".to_string())?;
    let mut ct2 = blob_data.to_vec();
    ct2.extend_from_slice(blob_tag);
    let plaintext = cipher2
        .decrypt(Nonce::from_slice(blob_iv), ct2.as_ref())
        .map_err(|_| "Blob decryption failed".to_string())?;

    let gzip_data = if plaintext.len() >= 2 && plaintext[0] == 0x1f && plaintext[1] == 0x8b {
        &plaintext[..]
    } else if plaintext.len() >= 4 {
        let gz_len = u32::from_be_bytes(plaintext[0..4].try_into().unwrap()) as usize;
        if plaintext.len() < 4 + gz_len {
            return Err("Gzip length exceeds buffer".into());
        }
        &plaintext[4..4 + gz_len]
    } else {
        return Err("Unexpected plaintext format".into());
    };

    let mut decoder = GzDecoder::new(gzip_data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| format!("gunzip: {}", e))?;

    e_mnemonic(&decompressed)
}

fn e_mnemonic(data: &[u8]) -> Result<String, String> {
    if let Ok(text) = std::str::from_utf8(data) {
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.len() == 12 || words.len() == 24 {
            return Ok(words.join(" "));
        }
        if let Some(mnemonic) = f_bip39_sequence(text) {
            return Ok(mnemonic);
        }
    }
    for offset in 0..data.len().min(64) {
        if let Ok(text) = std::str::from_utf8(&data[offset..]) {
            if let Some(mnemonic) = f_bip39_sequence(text) {
                return Ok(mnemonic);
            }
        }
    }
    Err("Could not extract mnemonic from decrypted data".into())
}

fn f_bip39_sequence(text: &str) -> Option<String> {
    let words: Vec<&str> = text
        .split_whitespace()
        .filter(|w| w.chars().all(|c| c.is_ascii_lowercase()))
        .collect();
    for window_size in [24, 12] {
        if words.len() >= window_size {
            for window in words.windows(window_size) {
                let candidate = window.join(" ");
                if candidate.len() > 20 {
                    return Some(candidate);
                }
            }
        }
    }
    None
}
