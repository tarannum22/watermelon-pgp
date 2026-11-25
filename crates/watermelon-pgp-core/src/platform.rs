//! The few operations whose behaviour differs between operating systems.
//!
//! "Private" means only the current user can access it: mode `0600`/`0700` on Unix, an
//! access list that allows only the current user on Windows (see [`windows`]).

use std::{io, io::Write, path::Path};

#[cfg(windows)]
mod windows;

/// Create a new file at `path` that only the current user can read and write.
/// Fails if the file already exists.
pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    #[cfg(windows)]
    let mut file = windows::create_private_file(path)?;
    #[cfg(not(windows))]
    let mut file = {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)?
    };
    file.write_all(contents)?;
    file.sync_all()
}

/// Create `path` (and missing parents) as a directory only the current user can enter.
/// An existing directory is left as it is.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    #[cfg(windows)]
    return windows::create_private_dir(path);
    #[cfg(not(windows))]
    {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)
    }
}

/// Create the data directory, or make sure an existing one is private where that matters.
///
/// On Unix an existing directory is left as it is: SQLite gives its `-wal` and `-shm` files
/// the database file's mode. On Windows those files take their access from the directory,
/// and the defaults (`C:\ProgramData` lets every local user read) would expose them, so an
/// existing directory that others can access is made private. That covers everything created
/// in it from then on; files already inside keep any access set on them explicitly.
pub fn secure_data_dir(path: &Path) -> io::Result<()> {
    create_private_dir(path)?;
    #[cfg(windows)]
    if windows::is_readable_by_others(path)? {
        windows::make_private(path)?;
    }
    Ok(())
}

/// Restrict an existing file to the current user.
pub fn make_private(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(windows)]
    {
        windows::make_private(path)
    }
}

/// Whether users other than the owner can access `path`. Root on Unix, and LocalSystem and
/// Administrators on Windows, don't count: they can access any file.
pub fn is_readable_by_others(path: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(std::fs::metadata(path)?.permissions().mode() & 0o077 != 0)
    }
    #[cfg(windows)]
    {
        windows::is_readable_by_others(path)
    }
}

/// How to restrict `path` to the current user, for error messages: "restrict it with `…`".
pub fn how_to_restrict(path: &Path) -> String {
    #[cfg(windows)]
    {
        windows::how_to_restrict(path)
    }
    #[cfg(unix)]
    {
        format!("restrict it with `chmod 600 '{}'`", path.display())
    }
}

#[cfg(test)]
pub(crate) mod testing {
    /// Give someone other than the current user read access to `path`, the way a default
    /// umask (Unix) or `C:\ProgramData` (Windows) does. On a directory, files created inside
    /// it later get that access too (Windows only: Unix has no inheritance).
    pub fn grant_others_read(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if path.is_dir() { 0o755 } else { 0o644 };
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(windows)]
        super::windows::testing::grant_users_read(path);
    }

    /// Windows: give someone else access only to what is created inside `dir` from now on.
    #[cfg(windows)]
    pub fn grant_others_read_to_new_items(dir: &std::path::Path) {
        super::windows::testing::grant_users_read_to_new_items(dir);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{testing::grant_others_read, *};

    #[test]
    fn private_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_private_file(&path, b"x").unwrap();
        assert!(!is_readable_by_others(&path).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"x");
        assert!(
            write_private_file(&path, b"y").is_err(),
            "must never overwrite"
        );
    }

    #[test]
    fn detects_and_fixes_access_by_others() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared");
        fs::write(&path, b"x").unwrap();
        grant_others_read(&path);
        assert!(is_readable_by_others(&path).unwrap());
        make_private(&path).unwrap();
        assert!(!is_readable_by_others(&path).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"x", "still readable by us");
    }

    #[test]
    fn private_dir_with_missing_parents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b");
        create_private_dir(&path).unwrap();
        assert!(path.is_dir());
        assert!(!is_readable_by_others(&dir.path().join("a")).unwrap());
        assert!(!is_readable_by_others(&path).unwrap());
        create_private_dir(&path).unwrap();
    }

    /// The case that matters on Windows: a parent that lets everyone read, like
    /// `C:\ProgramData`, must not leak into private files and directories.
    #[cfg(windows)]
    #[test]
    fn private_inside_a_shared_parent() {
        let shared = tempfile::tempdir().unwrap();
        grant_others_read(shared.path());
        let plain = shared.path().join("plain");
        fs::write(&plain, b"x").unwrap();
        assert!(
            is_readable_by_others(&plain).unwrap(),
            "inherits the parent"
        );

        let file = shared.path().join("file");
        write_private_file(&file, b"x").unwrap();
        assert!(!is_readable_by_others(&file).unwrap());

        let dir = shared.path().join("dir");
        create_private_dir(&dir).unwrap();
        assert!(!is_readable_by_others(&dir).unwrap());
        let inside = dir.join("db-wal");
        fs::write(&inside, b"x").unwrap();
        assert!(!is_readable_by_others(&inside).unwrap(), "inherits privacy");
    }

    /// An entry that only covers new files still exposes SQLite's -wal and -shm files.
    #[cfg(windows)]
    #[test]
    fn counts_access_to_new_items_in_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        create_private_dir(&data).unwrap();
        assert!(!is_readable_by_others(&data).unwrap());
        super::testing::grant_others_read_to_new_items(&data);
        assert!(is_readable_by_others(&data).unwrap());
        secure_data_dir(&data).unwrap();
        assert!(!is_readable_by_others(&data).unwrap());
    }

    /// The advice names the accounts to remove when access was granted on the file itself.
    #[cfg(windows)]
    #[test]
    fn how_to_restrict_lists_explicit_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        write_private_file(&path, b"x").unwrap();
        grant_others_read(&path);
        let advice = how_to_restrict(&path);
        assert!(advice.contains("/inheritance:r /grant:r"), "{advice}");
        assert!(advice.contains("/remove \"BUILTIN\\Users\""), "{advice}");
    }

    #[cfg(windows)]
    #[test]
    fn secure_data_dir_restricts_an_existing_shared_dir() {
        let shared = tempfile::tempdir().unwrap();
        grant_others_read(shared.path());
        let data = shared.path().join("data");
        fs::create_dir(&data).unwrap();
        let existing = data.join("existing");
        fs::write(&existing, b"x").unwrap();
        assert!(is_readable_by_others(&data).unwrap());

        secure_data_dir(&data).unwrap();
        assert!(!is_readable_by_others(&data).unwrap());
        assert!(
            !is_readable_by_others(&existing).unwrap(),
            "applied to contents"
        );
        let created = data.join("watermelon.db-wal");
        fs::write(&created, b"x").unwrap();
        assert!(!is_readable_by_others(&created).unwrap());
    }
}
