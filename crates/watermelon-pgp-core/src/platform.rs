//! The few operations whose behaviour differs between operating systems.
//!
//! "Private" means only the current user can access it: mode `0600`/`0700` on Unix, an
//! access list that allows only the current user on Windows (see [`windows`]). On Windows,
//! [`set_owner_and_restrict_to`] makes files private to another account instead (a service's).

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
/// in it from then on; files already inside keep any access set on them explicitly. A
/// directory owned by an account that isn't trusted is refused: its owner could change the
/// access list back.
pub fn secure_data_dir(path: &Path) -> io::Result<()> {
    create_private_dir(path)?;
    #[cfg(windows)]
    if windows::is_readable_by_others(path)? {
        windows::make_private(path)?;
        if windows::is_readable_by_others(path)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "data directory {}: {}",
                    path.display(),
                    windows::how_to_restrict(path)
                ),
            ));
        }
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

/// Windows: make `account` (`DOMAIN\name`, e.g. `NT SERVICE\watermelonpgp`) the owner of
/// `path` and replace its access list, so that only `account`, LocalSystem and Administrators
/// can access `path` and, for a directory, everything inside it, including files created there
/// later. Administrators keep access so that they can still run commands against a service's
/// data directory. Needs an elevated administrator.
#[cfg(windows)]
pub fn set_owner_and_restrict_to(path: &Path, account: &str) -> io::Result<()> {
    windows::set_owner_and_restrict_to(path, account)
}

/// Windows: add an entry to `path`'s access list allowing `account` to read it (and write it,
/// with `write`). The owner and the other entries stay as they are.
#[cfg(windows)]
pub fn allow_account(path: &Path, account: &str, write: bool) -> io::Result<()> {
    windows::allow_account(path, account, write)
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

/// Whether two folder paths name the same folder as written. Windows paths are
/// case-insensitive, and `/` and `\` are the same separator there. Doesn't resolve links,
/// short names, or a drive path and a UNC path to the same place.
pub fn same_folder(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    {
        let folded = |path: &Path| -> Vec<String> {
            path.components()
                .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
                .collect()
        };
        folded(a) == folded(b)
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

/// Example job folders in this platform's path style, for the job form and error messages.
pub struct FolderExamples {
    pub input: &'static str,
    pub output: &'static str,
    pub processed: &'static str,
    pub failed: &'static str,
    /// Appended to "must be an absolute path".
    pub absolute_path_hint: &'static str,
}

#[cfg(windows)]
pub const FOLDER_EXAMPLES: FolderExamples = FolderExamples {
    input: r"D:\sftp\acme\outbound",
    output: r"D:\sftp\acme\upload",
    processed: r"<input>\processed",
    failed: r"<input>\failed",
    absolute_path_hint: r" (like D:\sftp\acme\in or \\server\share\acme\in)",
};
#[cfg(not(windows))]
pub const FOLDER_EXAMPLES: FolderExamples = FolderExamples {
    input: "/srv/sftp/acme/outbound",
    output: "/srv/sftp/acme/upload",
    processed: "<input>/processed",
    failed: "<input>/failed",
    absolute_path_hint: "",
};

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
    const LOCAL_SERVICE: &str = "S-1-5-19";
    #[cfg(windows)]
    const SYSTEM: &str = "S-1-5-18";
    #[cfg(windows)]
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    #[cfg(windows)]
    /// A service account (`S-1-5-80-…`) that exists on every Windows.
    const TRUSTED_INSTALLER: &str = "NT SERVICE\\TrustedInstaller";

    /// What `service install` does to the data directory: the service account owns it, and
    /// only it, LocalSystem and Administrators can access it and what is inside.
    #[cfg(windows)]
    #[test]
    fn set_owner_and_restrict_to_a_service_account() {
        let shared = tempfile::tempdir().unwrap();
        grant_others_read(shared.path());
        let data = shared.path().join("data");
        create_private_dir(&data).unwrap();
        let key = data.join("master.key");
        write_private_file(&key, b"x").unwrap();
        let sub = data.join("sub");
        fs::create_dir(&sub).unwrap();

        set_owner_and_restrict_to(&data, TRUSTED_INSTALLER).unwrap();
        let (service, _) = super::windows::testing::owner_and_allowed(&data);
        assert!(service.starts_with("S-1-5-80-"), "{service}");
        let mut expected = [SYSTEM, ADMINISTRATORS, service.as_str()];
        expected.sort();
        for path in [&data, &key, &sub] {
            let (owner, allowed) = super::windows::testing::owner_and_allowed(path);
            assert_eq!(owner, service, "{}", path.display());
            assert_eq!(allowed, expected, "{}", path.display());
            assert!(!is_readable_by_others(path).unwrap(), "{}", path.display());
        }
        // Created later by someone else (an administrator's CLI): same access, inherited.
        let later = data.join("watermelonpgp.db-wal");
        fs::write(&later, b"x").unwrap();
        let (_, allowed) = super::windows::testing::owner_and_allowed(&later);
        assert_eq!(allowed, expected);
        assert_eq!(fs::read(&key).unwrap(), b"x", "administrators keep access");
    }

    /// An owner that isn't the current user, a trusted account or a service can change the
    /// access list, so it counts as access by others, like a Unix group or other bit.
    #[cfg(windows)]
    #[test]
    fn an_untrusted_owner_counts_as_access_by_others() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master.key");
        write_private_file(&key, b"x").unwrap();
        set_owner_and_restrict_to(&key, "NT AUTHORITY\\LOCAL SERVICE").unwrap();
        let (owner, allowed) = super::windows::testing::owner_and_allowed(&key);
        assert_eq!(owner, LOCAL_SERVICE);
        assert_eq!(allowed, [SYSTEM, LOCAL_SERVICE, ADMINISTRATORS]);
        assert!(is_readable_by_others(&key).unwrap());
        assert!(
            how_to_restrict(&key).contains("/setowner"),
            "{}",
            how_to_restrict(&key)
        );

        // `init` refuses such a data directory rather than make it look private.
        let data = dir.path().join("data");
        fs::create_dir(&data).unwrap();
        set_owner_and_restrict_to(&data, "NT AUTHORITY\\LOCAL SERVICE").unwrap();
        let err = secure_data_dir(&data).unwrap_err();
        assert!(err.to_string().contains("/setowner"), "{err}");
    }

    #[cfg(windows)]
    #[test]
    fn allow_account_keeps_the_other_entries() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        write_private_file(&cert, b"x").unwrap();
        let (owner, before) = super::windows::testing::owner_and_allowed(&cert);
        allow_account(&cert, "NT AUTHORITY\\LOCAL SERVICE", false).unwrap();
        let (owner_after, after) = super::windows::testing::owner_and_allowed(&cert);
        assert_eq!(owner_after, owner);
        let mut expected = before.clone();
        expected.push(LOCAL_SERVICE.to_owned());
        expected.sort();
        assert_eq!(after, expected);
    }

    #[cfg(windows)]
    #[test]
    fn an_unknown_account_fails() {
        let dir = tempfile::tempdir().unwrap();
        let unknown = "NT SERVICE\\no-such-watermelon-service";
        assert!(set_owner_and_restrict_to(dir.path(), unknown).is_err());
        assert!(allow_account(dir.path(), unknown, false).is_err());
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
        let created = data.join("watermelonpgp.db-wal");
        fs::write(&created, b"x").unwrap();
        assert!(!is_readable_by_others(&created).unwrap());
    }
}
