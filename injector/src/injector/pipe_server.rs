use kurion_core::common::t_wide;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, GetLastError};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, ConnectNamedPipe, PIPE_TYPE_MESSAGE, PIPE_READMODE_MESSAGE,
    PIPE_WAIT,
};
use windows::Win32::Storage::FileSystem::{ReadFile, PIPE_ACCESS_DUPLEX};
pub struct PipeServer {
    name: String,
    handle: HANDLE,
}

impl PipeServer {
    pub fn new(_browser_type: &str) -> Self {
        let name = crate::deobf(crate::BS_PIPE_NAME);
        Self {
            name,
            handle: INVALID_HANDLE_VALUE,
        }
    }

    pub fn create(&mut self) -> Result<(), String> {
        let name_wide = t_wide(&self.name);

        unsafe {
            let handle = CreateNamedPipeW(
                PCWSTR(name_wide.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                None,
            );

            if handle == INVALID_HANDLE_VALUE {
                return Err(format!("CreateNamedPipeW failed: {:?}", GetLastError()));
            }

            self.handle = handle;
        }
        Ok(())
    }

    pub fn g_name(&self) -> &str {
        &self.name
    }

    pub fn w_for_client(&self) -> Result<(), String> {
        if self.handle == INVALID_HANDLE_VALUE {
            return Err("Pipe not created".to_string());
        }

        unsafe {
            match ConnectNamedPipe(self.handle, None) {
                Ok(()) => {}
                Err(e) => {
                    if (e.code().0 & 0xFFFF) != 535 {
                         return Err(format!("ConnectNamedPipe failed: {:?}", e));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn r_message(&self) -> Result<String, String> {
         if self.handle == INVALID_HANDLE_VALUE {
            return Err("Pipe not created".to_string());
        }

        let mut buffer = [0u8; 1024];
        let mut bytes_read = 0;

        unsafe {
            let res = ReadFile(
                self.handle,
                Some(&mut buffer),
                Some(&mut bytes_read),
                None
            );

            if res.is_err() || bytes_read == 0 {
                return Err("Failed to read from pipe".to_string());
            }
        }

        let msg = String::from_utf8_lossy(&buffer[..bytes_read as usize]).to_string();
        Ok(msg)
    }

    pub fn s_message(&self, msg: &[u8]) -> Result<(), String> {
        if self.handle == INVALID_HANDLE_VALUE {
            return Err("Pipe not created".to_string());
        }

        let mut written = 0;
        unsafe {
            let res = windows::Win32::Storage::FileSystem::WriteFile(
                self.handle,
                Some(msg),
                Some(&mut written),
                None
            );

            if res.is_err() {
                 return Err(format!("WriteFile failed: {}", res.unwrap_err()));
            }
        }
        Ok(())
    }

}

impl Drop for PipeServer {
    fn drop(&mut self) {
         if self.handle != INVALID_HANDLE_VALUE {
            unsafe { let _ = CloseHandle(self.handle); }
        }
    }
}
