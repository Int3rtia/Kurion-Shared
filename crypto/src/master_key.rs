use std::path::Path;
use std::fs::File;
use std::io::Read;
use serde_json::Value;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

pub fn g_encrypted_key_by_name(local_state_path: &Path, key_name: &str) -> Result<Vec<u8>, String> {
    let mut file = File::open(local_state_path).map_err(|e| format!("Cannot open Local State: {}", e))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| format!("Cannot read Local State: {}", e))?;

    let v: Value = serde_json::from_str(&contents).map_err(|e| format!("Malformed JSON: {}", e))?;

    let key_val = v.get("os_crypt")
        .and_then(|os_crypt| os_crypt.get(key_name))
        .and_then(|v| v.as_str());

    if let Some(b64_key) = key_val {
        let decoded = BASE64.decode(b64_key).map_err(|e| format!("Invalid base64: {}", e))?;
        if decoded.len() < 5 {
             return Err("Invalid key data (too small)".to_string());
        }
        Ok(decoded[4..].to_vec())
    } else {
        Err(format!("Key not found: {}", key_name))
    }
}

pub fn g_legacy_key(local_state_path: &Path) -> Result<Vec<u8>, String> {
    let mut file = File::open(local_state_path).map_err(|e| format!("Cannot open Local State: {}", e))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| format!("Cannot read Local State: {}", e))?;

    let v: Value = serde_json::from_str(&contents).map_err(|e| format!("Malformed JSON: {}", e))?;

    let key_val = v.get("os_crypt")
        .and_then(|os_crypt| os_crypt.get("encrypted_key"))
        .and_then(|v| v.as_str());

    if let Some(b64_key) = key_val {
        let decoded = BASE64.decode(b64_key).map_err(|e| format!("Invalid base64: {}", e))?;

        if decoded.len() > 5 && &decoded[..5] == b"DPAPI" {
            Ok(decoded[5..].to_vec())
        } else {
            Ok(decoded)
        }
    } else {
         Err("os_crypt.encrypted_key not found".to_string())
    }
}
