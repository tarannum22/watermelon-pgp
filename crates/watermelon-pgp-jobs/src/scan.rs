//! Finding input files that are ready to process.
//!
//! A file is ready once two consecutive scans saw the same size and modification time, so a
//! file still being uploaded is left alone. On Windows it must also not be open in another
//! process, which catches an upload that stalls with the file still open. Temp-file patterns
//! used by SFTP clients, dotfiles and (on Windows) hidden or system files are never picked up.

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
            if is_hidden(&meta) {
                continue;
            }
            current.insert(entry.path(), (meta.len(), meta.modified().ok()));
        }

        let mut ready: Vec<PathBuf> = current
            .iter()
            .filter(|(path, state)| self.previous.get(*path) == Some(state) && !in_use(path))
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

/// Windows: whether another process has `path` open, as an SFTP server does while it is
/// still receiving the file. Opening it with no sharing allowed fails while any other handle
/// exists. Unix has no reliable equivalent, so there it is always `false` and the settle check
/// alone decides.
pub fn in_use(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        /// ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION.
        const IN_USE: [i32; 2] = [32, 33];
        match fs::OpenOptions::new().read(true).share_mode(0).open(path) {
            Ok(_) => false,
            Err(e) => e.raw_os_error().is_some_and(|code| IN_USE.contains(&code)),
        }
    }
    #[cfg(unix)]
    {
        let _ = path;
        false
    }
}

/// Windows: files marked hidden or system, such as `Thumbs.db` and `desktop.ini`.
fn is_hidden(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        /// FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM.
        const HIDDEN_OR_SYSTEM: u32 = 0x2 | 0x4;
        meta.file_attributes() & HIDDEN_OR_SYSTEM != 0
    }
    #[cfg(unix)]
    {
        let _ = meta;
        false
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

    #[cfg(windows)]
    #[test]
    fn leaves_files_open_elsewhere_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("upload.csv");
        // Like an SFTP server that has stopped writing but not closed the file.
        let held = fs::File::create(&file).unwrap();
        assert!(in_use(&file));
        let mut scanner = Scanner::default();
        scanner.scan(dir.path()).unwrap();
        assert!(scanner.scan(dir.path()).unwrap().is_empty(), "still open");
        drop(held);
        assert!(!in_use(&file));
        assert_eq!(scanner.scan(dir.path()).unwrap(), vec![file]);
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
