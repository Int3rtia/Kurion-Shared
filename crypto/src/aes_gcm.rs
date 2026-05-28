use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

pub struct AesGcm;

impl AesGcm {
    pub fn decrypt(key: &[u8], encrypted_data: &[u8]) -> Option<Vec<u8>> {
        const PREFIX_LEN: usize = 3;
        const IV_LEN: usize = 12;
        const TAG_LEN: usize = 16;
        const OVERHEAD: usize = PREFIX_LEN + IV_LEN + TAG_LEN;

        if encrypted_data.len() < OVERHEAD {
            return None;
        }

        let prefix = &encrypted_data[..PREFIX_LEN];
        if prefix != b"v10" && prefix != b"v20" {
            return None;
        }

        let iv = &encrypted_data[PREFIX_LEN..PREFIX_LEN + IV_LEN];
        let ciphertext_with_tag = &encrypted_data[PREFIX_LEN + IV_LEN..];

        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        let nonce = Nonce::from_slice(iv);

        cipher.decrypt(nonce, ciphertext_with_tag).ok()
    }
}
