use windows::Win32::Foundation::{HANDLE, BOOL};
use windows::core::{PCWSTR, PWSTR, PCSTR};
use windows::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOW};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use std::ffi::CString;

pub type CreateProcessWFn = unsafe extern "system" fn(
    PCWSTR,
    PWSTR,
    *const std::ffi::c_void,
    *const std::ffi::c_void,
    BOOL,
    u32,
    *const std::ffi::c_void,
    PCWSTR,
    *const STARTUPINFOW,
    *mut PROCESS_INFORMATION,
) -> BOOL;

pub type TerminateProcessFn = unsafe extern "system" fn(HANDLE, u32) -> BOOL;

pub unsafe fn r_create_process_w() -> Option<CreateProcessWFn> {
    use obfstr::obfstr;
    let kernel32_str = l_name_kernel32();
    let kernel32_w = kurion_core::common::t_wide(&kernel32_str);
    let h_module = GetModuleHandleW(PCWSTR(kernel32_w.as_ptr())).ok()?;

    let proc_name = CString::new(obfstr!("CreateProcessW")).ok()?;
    let proc_addr = GetProcAddress(h_module, PCSTR(proc_name.as_ptr() as *const u8));

    match proc_addr {
        Some(addr) => Some(std::mem::transmute(addr)),
        None => None
    }
}

pub unsafe fn r_terminate_process() -> Option<TerminateProcessFn> {
    use obfstr::obfstr;
    let kernel32_str = l_name_kernel32();
    let kernel32_w = kurion_core::common::t_wide(&kernel32_str);
    let h_module = GetModuleHandleW(PCWSTR(kernel32_w.as_ptr())).ok()?;

    let proc_name = CString::new(obfstr!("TerminateProcess")).ok()?;
    let proc_addr = GetProcAddress(h_module, PCSTR(proc_name.as_ptr() as *const u8));

    match proc_addr {
        Some(addr) => Some(std::mem::transmute(addr)),
        None => None
    }
}

fn l_name_kernel32() -> String {
    use obfstr::obfstr;
    obfstr!("kernel32.dll").to_string()
}
