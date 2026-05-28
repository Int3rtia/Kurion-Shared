pub type Byte = u8;

pub type Bytes = Vec<Byte>;

pub const TIMEOUT_MS: u32 = 60000;

pub fn t_utf8(s: &std::ffi::OsStr) -> String {
    s.to_string_lossy().into_owned()
}

#[cfg(windows)]
pub fn t_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(not(windows))]
pub fn t_wide(_s: &str) -> Vec<u16> {
    Vec::new()
}
