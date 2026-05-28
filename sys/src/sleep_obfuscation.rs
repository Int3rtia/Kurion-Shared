use windows::Win32::System::Threading::Sleep;

#[cfg(target_os = "windows")]
pub fn j_sleep(base_ms: u32) {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let jitter = ((seed.wrapping_mul(6364136223846793005) >> 33) as u32) % (base_ms / 2 + 1);
    let total_ms = base_ms + jitter;

    unsafe {
        Sleep(total_ms);
    }
}

#[cfg(target_os = "windows")]
pub fn j_sleep_range(min_ms: u32, max_ms: u32) {
    if min_ms >= max_ms {
        unsafe { Sleep(min_ms) };
        return;
    }

    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let range = max_ms - min_ms;
    let offset = ((seed.wrapping_mul(6364136223846793005) >> 33) as u32) % range;

    unsafe {
        Sleep(min_ms + offset);
    }
}

#[cfg(not(target_os = "windows"))]
pub fn j_sleep(base_ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(base_ms as u64));
}

#[cfg(not(target_os = "windows"))]
pub fn j_sleep_range(min_ms: u32, max_ms: u32) {
    let range = max_ms - min_ms;
    std::thread::sleep(std::time::Duration::from_millis((min_ms + range / 2) as u64));
}
