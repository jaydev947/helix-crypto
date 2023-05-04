use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

pub(super) fn get_files(source: &str) -> Vec<PathBuf> {
    let helix = Path::new(source).join(".helix");
    let walker = WalkDir::new(source);
    let paths = walker
        .into_iter()
        .map(|e| e.unwrap())
        .filter(|e| !is_hidden(e))
        .filter(|e| !is_helix(e, &helix))
        .filter(|e| e.metadata().unwrap().is_file())
        .map(|e| e.into_path());
    Vec::from_iter(paths)
}

fn is_helix(entry: &DirEntry, helix: &Path) -> bool {
    let starts = entry.path().starts_with(helix);
    starts
}

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with("."))
        .unwrap_or(false)
}

#[test]
fn get_source_files_test() {
    let paths = get_files("./src");
    for path in paths {
        println!("{}", path.display())
    }
}
