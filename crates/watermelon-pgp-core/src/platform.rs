//! The few operations whose behaviour differs between operating systems.

use std::{fs, io, io::Write, path::Path};

/// Create a new file at `path` that only the current user can read and write.
/// Fails if the file already exists.
pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// Create `path` (and missing parents) as a directory only the current user can enter.
/// An existing directory is left as it is.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Restrict an existing file to the current user.
pub fn make_private(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Whether users other than the owner can access `path`.
pub fn is_readable_by_others(path: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(fs::metadata(path)?.permissions().mode() & 0o077 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(false)
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
