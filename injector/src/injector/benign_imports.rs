#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(target_os = "windows")]
static INIT_RESULT: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "windows")]
pub fn init() {
    use windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics;
    use windows::Win32::System::SystemInformation::{
        GetSystemInfo, SYSTEM_INFO, GetTickCount64, GetVersion,
    };
    use windows::Win32::System::Threading::GetCurrentProcessId;
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Environment::GetEnvironmentVariableW;
    use windows::core::w;

    let mut fingerprint: usize = 0;

    unsafe {
        let screen_w = GetSystemMetrics(windows::Win32::UI::WindowsAndMessaging::SM_CXSCREEN);
        let screen_h = GetSystemMetrics(windows::Win32::UI::WindowsAndMessaging::SM_CYSCREEN);
        fingerprint = fingerprint.wrapping_add(screen_w as usize).wrapping_add(screen_h as usize);

        let version = GetVersion();
        fingerprint = fingerprint.wrapping_add(version as usize);

        let mut sys_info = SYSTEM_INFO::default();
        GetSystemInfo(&mut sys_info);
        fingerprint = fingerprint.wrapping_add(sys_info.dwNumberOfProcessors as usize);
        fingerprint = fingerprint.wrapping_add(sys_info.dwPageSize as usize);

        let tick = GetTickCount64();
        fingerprint = fingerprint.wrapping_add(tick as usize);

        let pid = GetCurrentProcessId();
        fingerprint = fingerprint.wrapping_add(pid as usize);

        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

        let _ = GetModuleHandleW(None);
        let _ = GetModuleHandleW(w!("ntdll.dll"));

        let mut env_buf = [0u16; 512];
        let _ = GetEnvironmentVariableW(w!("SYSTEMROOT"), Some(&mut env_buf));
        let _ = GetEnvironmentVariableW(w!("PROCESSOR_ARCHITECTURE"), Some(&mut env_buf));
    }

    INIT_RESULT.store(fingerprint, Ordering::Relaxed);
}

#[cfg(not(target_os = "windows"))]
pub fn init() {}

#[used]
static BENIGN_STRINGS: [&str; 48] = [
    "The operation completed successfully.",
    "Access is denied.",
    "The system cannot find the file specified.",
    "The process cannot access the file because it is being used by another process.",
    "Not enough storage is available to process this command.",
    "The parameter is incorrect.",
    "Initializing Windows Diagnostics Service...",
    "Service started successfully.",
    "Checking system health status...",
    "Collecting diagnostic information...",
    "Writing diagnostic report to output directory.",
    "Operation timed out. Retrying...",
    "Successfully connected to diagnostics endpoint.",
    "Configuration loaded from registry.",
    "Telemetry data submitted successfully.",
    "Cache directory initialized.",
    "Log rotation completed.",
    "Scheduled maintenance check completed.",
    "System resources within normal parameters.",
    "Memory usage: nominal.",
    "Disk space check: sufficient.",
    "Network connectivity: verified.",
    "Windows Update status: current.",
    "Security baseline: compliant.",
    "Antivirus definitions: up to date.",
    "Firewall status: enabled.",
    "BitLocker status: checking...",
    "TPM status: available.",
    "Secure Boot: enabled.",
    "Device health attestation: passed.",
    "Hardware diagnostics: no issues found.",
    "Software conflict scan: clean.",
    "Performance counters: initialized.",
    "Event log collection: started.",
    "WMI provider: connected.",
    "COM initialization: successful.",
    "Registry access: verified.",
    "File system permissions: validated.",
    "Service control manager: responsive.",
    "RPC endpoint mapper: available.",
    "DCOM configuration: default.",
    "Windows Management Instrumentation: ready.",
    "Task Scheduler: operational.",
    "Group Policy: applied.",
    "Certificate store: accessible.",
    "Cryptographic services: running.",
    "Background Intelligent Transfer Service: idle.",
    "Windows Error Reporting: configured.",
];

#[cfg(target_os = "windows")]
pub fn i_benign_1() {
    unsafe {
        use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
        let mut sys_info = SYSTEM_INFO::default();
        GetSystemInfo(&mut sys_info);
        std::hint::black_box(sys_info.dwPageSize);
    }
}

#[cfg(target_os = "windows")]
pub fn i_benign_2() {
    unsafe {
        use windows::Win32::System::Environment::GetEnvironmentVariableW;
        use windows::core::w;
        let mut buf = [0u16; 260];
        let _ = GetEnvironmentVariableW(w!("TEMP"), Some(&mut buf));
        std::hint::black_box(buf[0]);
    }
}

#[cfg(target_os = "windows")]
pub fn i_benign_3() {
    unsafe {
        use windows::Win32::System::Threading::GetCurrentThreadId;
        let tid = GetCurrentThreadId();
        std::hint::black_box(tid);
    }
}

#[cfg(target_os = "windows")]
pub fn i_benign_4() {
    unsafe {
        use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN};
        let w = GetSystemMetrics(SM_CXSCREEN);
        std::hint::black_box(w);
    }
}

#[cfg(target_os = "windows")]
pub fn i_benign_5() {
    unsafe {
        use windows::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};
        let mut sys_info = SYSTEM_INFO::default();
        GetNativeSystemInfo(&mut sys_info);
        std::hint::black_box(sys_info.Anonymous.Anonymous.wProcessorArchitecture);
    }
}

#[cfg(target_os = "windows")]
pub fn i_benign_6() {
    unsafe {
        use windows::Win32::System::SystemInformation::GetTickCount64;
        let ticks = GetTickCount64();
        std::hint::black_box(ticks);
    }
}

#[cfg(target_os = "windows")]
pub fn r_benign_interleave() {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u32;

    let count = 1 + (seed % 3);
    for i in 0..count {
        match (seed.wrapping_add(i)) % 6 {
            0 => i_benign_1(),
            1 => i_benign_2(),
            2 => i_benign_3(),
            3 => i_benign_4(),
            4 => i_benign_5(),
            5 => i_benign_6(),
            _ => i_benign_1(),
        }
    }
}

#[cfg(not(target_os = "windows"))] pub fn i_benign_1() {}
#[cfg(not(target_os = "windows"))] pub fn i_benign_2() {}
#[cfg(not(target_os = "windows"))] pub fn i_benign_3() {}
#[cfg(not(target_os = "windows"))] pub fn i_benign_4() {}
#[cfg(not(target_os = "windows"))] pub fn i_benign_5() {}
#[cfg(not(target_os = "windows"))] pub fn i_benign_6() {}
#[cfg(not(target_os = "windows"))] pub fn r_benign_interleave() {}
