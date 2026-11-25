//! Finding input files that are ready to process.
//!
//! A file is ready once two consecutive scans saw the same size and modification time, so a
//! file still being uploaded is left alone. (On Windows, a file another process still has open
//! for writing is also left alone when processing would start: see `process::ProcessError`.)
//! Temp-file patterns used by SFTP clients, dotfiles and (on Windows) hidden or system files
//! are never picked up.

use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    time::SystemTime,
};

/// Suffixes of files that are still being written by common transfer tools.
const IGNORED_SUFFIXES: &[&str] = &[".part", ".filepart", ".tmp", ".crdownload", ".partial"];

/// Remembers what the previous scan of one folder saw.
#[derive(Debug, Default)]
pub struct Scanner {
    previous: HashMap<PathBuf, (u64, Option<SystemTime>)>,
}

impl Scanner {
    /// Scan `dir` and return the files that have not changed since the previous scan,
    /// sorted by name so processing order is predictable.
    pub fn scan(&mut self, dir: &Path) -> io::Result<Vec<PathBuf>> {
        let mut current = HashMap::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            // Directories (processed/, failed/) and symlinks are skipped: `file_type` does not
            // follow symlinks, so a link pointing elsewhere is never read through.
            if !entry.file_type()?.is_file() || is_ignored(&entry.file_name().to_string_lossy()) {
                continue;
            }
            let meta = entry.metadata()?;
            if crate::platform::is_hidden(&meta) {
                continue;
            }
            current.insert(entry.path(), (meta.len(), meta.modified().ok()));
        }

        let mut ready: Vec<PathBuf> = current
            .iter()
            .filter(|(path, state)| self.previous.get(*path) == Some(state))
            .map(|(path, _)| path.clone())
            .collect();
        ready.sort();
        self.previous = current;
        Ok(ready)
    }

    /// Forget a file, e.g. after it was moved away, so a new file with the same name has to
    /// settle again.
    pub fn forget(&mut self, path: &Path) {
        self.previous.remove(path);
    }
}

pub fn is_ignored(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    name.starts_with('.')
        || IGNORED_SUFFIXES
            .iter()
            .any(|suffix| lower.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_must_settle_for_one_scan() {
        let dir = tempfile::tempdir().unwrap();
        let mut scanner = Scanner::default();
        let file = dir.path().join("data.csv");
        fs::write(&file, "a").unwrap();
        assert!(
            scanner.scan(dir.path()).unwrap().is_empty(),
            "first sighting"
        );
        assert_eq!(scanner.scan(dir.path()).unwrap(), vec![file.clone()]);

        fs::write(&file, "ab").unwrap();
        assert!(
            scanner.scan(dir.path()).unwrap().is_empty(),
            "grew since last scan"
        );
        assert_eq!(scanner.scan(dir.path()).unwrap(), vec![file.clone()]);

        scanner.forget(&file);
        assert!(scanner.scan(dir.path()).unwrap().is_empty(), "forgotten");
    }

    #[test]
    fn ignores_temp_files_dotfiles_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "upload.csv.part",
            "x.filepart",
            ".hidden",
            "y.TMP",
            "z.crdownload",
        ] {
            fs::write(dir.path().join(name), "x").unwrap();
        }
        fs::create_dir(dir.path().join("processed")).unwrap();
        let mut scanner = Scanner::default();
        scanner.scan(dir.path()).unwrap();
        assert!(scanner.scan(dir.path()).unwrap().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn ignores_hidden_and_system_files() {
        let dir = tempfile::tempdir().unwrap();
        for (name, flag) in [("Thumbs.db", "+h"), ("desktop.ini", "+s")] {
            let path = dir.path().join(name);
            fs::write(&path, "x").unwrap();
            let status = std::process::Command::new("attrib")
                .arg(flag)
                .arg(&path)
                .status()
                .unwrap();
            assert!(status.success());
        }
        let mut scanner = Scanner::default();
        scanner.scan(dir.path()).unwrap();
        assert!(scanner.scan(dir.path()).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn ignores_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link.csv")).unwrap();
        let mut scanner = Scanner::default();
        scanner.scan(dir.path()).unwrap();
        assert!(scanner.scan(dir.path()).unwrap().is_empty());
    }
}
