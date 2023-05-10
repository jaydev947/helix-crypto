use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

pub(crate) fn get_files(source: &str) -> Vec<PathBuf> {
    let walker = WalkDir::new(source);
    let paths = walker
        .into_iter()
        .map(|e| e.unwrap())
        .filter(|e| !is_hidden(e))
        .filter(|e| !is_helix(e))
        .filter(|e| !is_helix_runnable(e))
        .filter(|e| e.metadata().unwrap().is_file())
        .map(|e| e.into_path());
    Vec::from_iter(paths)
}

fn is_helix(entry: &DirEntry) -> bool {
    entry.path().to_str().unwrap().contains(".helix")
}

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with("."))
        .unwrap_or(false)
}

fn is_helix_runnable(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.eq("helix.exe"))
        .unwrap_or(false)
}

#[test]
fn get_source_files_test() {
    let paths = get_files("./src");
    for path in paths {
        println!("{}", path.display())
    }
}
