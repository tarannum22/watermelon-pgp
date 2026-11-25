//! The file operations jobs do differently on Windows, where an SFTP server can hold a file
//! open, files carry a hidden attribute, and renames replace existing files.

use std::{
    fs::{self, File},
    io,
    path::Path,
};

/// Open an input file for processing. On Windows, other processes can still read it while we
/// do, but not write or delete it; and the open fails ([`is_in_use`]) while another process
/// has it open for writing, such as an SFTP server still receiving it.
pub fn open_input(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
        options.share_mode(FILE_SHARE_READ);
    }
    options.open(path)
}

/// Whether an error from [`open_input`] means another process has the file open in a way that
/// excludes us. Never on Unix, which has no mandatory locking.
pub fn is_in_use(error: &io::Error) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION};
        error.raw_os_error().is_some_and(|code| {
            [ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION].contains(&(code as u32))
        })
    }
    #[cfg(not(windows))]
    {
        let _ = error;
        false
    }
}

/// Windows: files marked hidden or system, such as `Thumbs.db` and `desktop.ini`.
pub fn is_hidden(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM,
        };
        meta.file_attributes() & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0
    }
    #[cfg(not(windows))]
    {
        let _ = meta;
        false
    }
}

/// Move `from` to `to`, also across filesystems, failing with `AlreadyExists` instead of
/// replacing an existing `to`. The copy across filesystems is durable before the source is
/// removed.
///
/// On Windows this is one atomic call (MoveFileExW without the replace flag). On Unix the
/// check and the rename are separate steps.
pub fn move_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_COPY_ALLOWED, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let wide =
            |path: &Path| -> Vec<u16> { path.as_os_str().encode_wide().chain([0]).collect() };
        let (from, to) = (wide(from), wide(to));
        // SAFETY: both are NUL-terminated wide strings that outlive the call.
        let moved = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        if fs::symlink_metadata(to).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} already exists", to.display()),
            ));
        }
        match fs::rename(from, to) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
                fs::copy(from, to)?;
                File::open(to)?.sync_all()?;
                fs::remove_file(from)
            }
            Err(e) => Err(e),
        }
    }
}

/// Characters a bare file name from a request must not contain to stay inside the folder it
/// is joined to. On Windows that includes `:`: `C:name` is relative to drive C: and replaces
/// the folder in `Path::join`, and `name:stream` is an alternate data stream.
pub const NOT_IN_A_FILE_NAME: &[char] = if cfg!(windows) {
    &['/', '\\', ':']
} else {
    &['/', '\\']
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn move_no_replace_refuses_an_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let (from, to) = (dir.path().join("a"), dir.path().join("b"));
        fs::write(&from, "new").unwrap();
        fs::write(&to, "existing").unwrap();
        let err = move_no_replace(&from, &to).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
        assert_eq!(fs::read(&to).unwrap(), b"existing");
        assert!(from.exists());

        fs::remove_file(&to).unwrap();
        move_no_replace(&from, &to).unwrap();
        assert_eq!(fs::read(&to).unwrap(), b"new");
        assert!(!from.exists());
    }

    #[cfg(windows)]
    #[test]
    fn a_file_open_for_writing_elsewhere_is_in_use() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upload.csv");
        // Like an SFTP server that has stopped writing but not closed the file.
        let held = File::create(&path).unwrap();
        let err = open_input(&path).unwrap_err();
        assert!(is_in_use(&err), "{err}");
        drop(held);
        open_input(&path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn others_can_read_but_not_change_an_input_being_processed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.csv");
        fs::write(&path, "x").unwrap();
        let _ours = open_input(&path).unwrap();
        fs::read(&path).unwrap();
        let err = fs::OpenOptions::new().append(true).open(&path).unwrap_err();
        assert!(is_in_use(&err), "{err}");
        assert!(fs::remove_file(&path).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn hidden_and_system_files() {
        let dir = tempfile::tempdir().unwrap();
        for (name, flag) in [
            ("Thumbs.db", "+h"),
            ("desktop.ini", "+s"),
            ("plain.csv", "-h"),
        ] {
            let path = dir.path().join(name);
            fs::write(&path, "x").unwrap();
            let status = std::process::Command::new("attrib")
                .arg(flag)
                .arg(&path)
                .status()
                .unwrap();
            assert!(status.success());
            let meta = fs::metadata(&path).unwrap();
            assert_eq!(is_hidden(&meta), name != "plain.csv", "{name}");
        }
    }
}
