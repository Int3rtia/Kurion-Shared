use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_TOTAL_SIZE_BYTES: u64 = 100 * 1024 * 1024;
const MAX_FILES: usize = 100;
const MAX_DEPTH: usize = 10;

const SKIP_DIRS: [&str; 6] = [ // bigass dirs would take it a long time
    "system32",
    "program files",
    "programdata",
    "$recycle.bin",
    "appdata",
    "windows",
];

#[derive(Clone)]
struct KeywordPattern {
    original: String,
    pattern: PatternType,
}

#[derive(Clone)]
enum PatternType {
    Contains(String),
    Wildcard(String),
}

impl KeywordPattern {
    fn f_keyword(keyword: &str) -> Option<Self> {
        let trimmed = keyword.trim();
        if trimmed.is_empty() {
            return None;
        }

        let lowered = trimmed.to_lowercase();
        let pattern = if lowered.contains('*') {
            PatternType::Wildcard(lowered)
        } else {
            PatternType::Contains(lowered)
        };

        Some(Self {
            original: trimmed.to_string(),
            pattern,
        })
    }

    fn matches(&self, filename_lower: &str) -> bool {
        let stem = filename_lower
            .rfind('.')
            .map(|i| &filename_lower[..i])
            .unwrap_or(filename_lower);

        match &self.pattern {
            PatternType::Contains(k) => stem == k,
            PatternType::Wildcard(pat) => w_match(stem, pat),
        }
    }
}

#[derive(Clone)]
struct FoundFile {
    path: PathBuf,
    keyword: String,
    drive_letter: char,
}

fn w_match(text: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let starts_with_star = pattern.starts_with('*');
    let ends_with_star = pattern.ends_with('*');
    let parts: Vec<&str> = pattern.split('*').filter(|s| !s.is_empty()).collect();

    if parts.is_empty() {
        return true;
    }

    let mut pos = 0usize;

    if !starts_with_star {
        if !text.starts_with(parts[0]) {
            return false;
        }
        pos = parts[0].len();
    }

    let mut idx = if !starts_with_star { 1 } else { 0 };
    while idx < parts.len() {
        let is_last = idx == parts.len() - 1;
        if is_last && !ends_with_star {
            return text[pos..].ends_with(parts[idx]);
        }

        if let Some(found_at) = text[pos..].find(parts[idx]) {
            pos += found_at + parts[idx].len();
            idx += 1;
        } else {
            return false;
        }
    }

    true
}

fn s_skip_dir_name(name: &str) -> bool {
    SKIP_DIRS.iter().any(|n| n == &name)
}

#[cfg(target_os = "windows")]
fn i_hidden_or_system(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;

    let attrs = meta.file_attributes();
    (attrs & FILE_ATTRIBUTE_HIDDEN) != 0 || (attrs & FILE_ATTRIBUTE_SYSTEM) != 0
}

#[cfg(not(target_os = "windows"))]
fn i_hidden_or_system(_meta: &std::fs::Metadata) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn i_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

#[cfg(not(target_os = "windows"))]
fn i_reparse_point(_meta: &std::fs::Metadata) -> bool {
    false
}

fn e_drive_letter(path: &Path) -> Option<char> {
    path.to_string_lossy()
        .chars()
        .next()
        .filter(|c| c.is_ascii_alphabetic())
}

struct SearchLimits {
    file_count: AtomicUsize,
    total_size: AtomicU64,
}

impl SearchLimits {
    fn new() -> Self {
        Self {
            file_count: AtomicUsize::new(0),
            total_size: AtomicU64::new(0),
        }
    }

    fn t_add(&self, size: u64) -> bool {
        let current_count = self.file_count.load(Ordering::Relaxed);
        if current_count >= MAX_FILES {
            return false;
        }
        let current_size = self.total_size.load(Ordering::Relaxed);
        if current_size + size > MAX_TOTAL_SIZE_BYTES {
            return false;
        }
        self.file_count.fetch_add(1, Ordering::Relaxed);
        self.total_size.fetch_add(size, Ordering::Relaxed);
        true
    }

    fn i_full(&self) -> bool {
        self.file_count.load(Ordering::Relaxed) >= MAX_FILES
            || self.total_size.load(Ordering::Relaxed) >= MAX_TOTAL_SIZE_BYTES
    }
}

fn s_directory_parallel(
    dir: &Path,
    patterns: &[KeywordPattern],
    drive_letter: char,
    depth: usize,
    limits: &SearchLimits,
) -> Vec<FoundFile> {
    if depth > MAX_DEPTH || limits.i_full() {
        return Vec::new();
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut found = Vec::new();
    let mut subdirs = Vec::new();

    for entry in entries.flatten() {
        if limits.i_full() {
            break;
        }

        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        if file_type.is_symlink() {
            continue;
        }

        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if i_reparse_point(&meta) || i_hidden_or_system(&meta) {
            continue;
        }

        if file_type.is_dir() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if s_skip_dir_name(&name) {
                continue;
            }
            subdirs.push(path);
            continue;
        }

        if file_type.is_file() {
            let size = meta.len();
            if size > MAX_FILE_SIZE_BYTES {
                continue;
            }

            let file_name = entry.file_name().to_string_lossy().to_lowercase();
            
            if !file_name.ends_with(".txt") {
                continue;
            }

            for pattern in patterns {
                if pattern.matches(&file_name) {
                    if limits.t_add(size) {
                        found.push(FoundFile {
                            path: path.clone(),
                            keyword: pattern.original.clone(),
                            drive_letter,
                        });
                    }
                    break;
                }
            }
        }
    }

    if !limits.i_full() {
        let nested: Vec<Vec<FoundFile>> = subdirs
            .into_par_iter()
            .map(|subdir| s_directory_parallel(&subdir, patterns, drive_letter, depth + 1, limits))
            .collect();

        for mut chunk in nested {
            found.append(&mut chunk);
        }
    }

    found
}

#[cfg(target_os = "windows")]
fn l_mounted_drives() -> Vec<PathBuf> {
    (b'A'..=b'Z')
        .map(|letter| PathBuf::from(format!("{}:\\", letter as char)))
        .filter(|drive| drive.exists())
        .collect()
}

#[cfg(not(target_os = "windows"))]
fn l_mounted_drives() -> Vec<PathBuf> {
    Vec::new()
}

fn c_found_files(output_dir: &Path, files: &[FoundFile]) {
    let search_dir = output_dir.join("FileSearch");

    for file in files {
        let dest_dir = search_dir
            .join(&file.keyword)
            .join(file.drive_letter.to_string());

        if fs::create_dir_all(&dest_dir).is_err() {
            continue;
        }

        if let Some(file_name) = file.path.file_name() {
            let mut dest_path = dest_dir.join(file_name);

            if dest_path.exists() {
                let stem = file_name.to_string_lossy();
                let ext = file.path.extension().map(|e| e.to_string_lossy().to_string());
                let mut counter = 1;
                loop {
                    let new_name = if let Some(ref ext) = ext {
                        let base = stem.trim_end_matches(&format!(".{}", ext));
                        format!("{}_{}.{}", base, counter, ext)
                    } else {
                        format!("{}_{}", stem, counter)
                    };
                    dest_path = dest_dir.join(&new_name);
                    if !dest_path.exists() {
                        break;
                    }
                    counter += 1;
                }
            }

            let _ = fs::copy(&file.path, &dest_path);
        }
    }
}

pub fn s_files_by_keyword(keywords: &[&str], output_dir: &Path) -> Vec<String> {
    let patterns: Vec<KeywordPattern> = keywords
        .iter()
        .filter_map(|k| KeywordPattern::f_keyword(k))
        .collect();

    if patterns.is_empty() {
        return Vec::new();
    }

    let drives = l_mounted_drives();
    let limits = SearchLimits::new();

    let found: Vec<FoundFile> = drives
        .iter()
        .flat_map(|drive| {
            let drive_letter = e_drive_letter(drive).unwrap_or('C');
            s_directory_parallel(drive, &patterns, drive_letter, 0, &limits)
        })
        .collect();

    c_found_files(output_dir, &found);

    found
        .iter()
        .map(|f| f.path.to_string_lossy().to_string())
        .collect()
}
