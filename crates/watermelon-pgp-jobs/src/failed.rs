//! Files a job could not process: listing them and putting them back for another attempt.

use std::{
    fs, io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use watermelon_pgp_core::{audit::Actor, jobs::Job, vault::Vault};

use crate::process;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedFile {
    pub name: String,
    pub size: u64,
    pub modified: Option<SystemTime>,
}

/// Regular files in the job's failed folder, oldest first. A missing folder means none.
pub fn list(job: &Job) -> io::Result<Vec<FailedFile>> {
    let entries = match fs::read_dir(&job.spec.failed_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;
        if !meta.file_type().is_file() {
            continue;
        }
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        files.push(FailedFile {
            name,
            size: meta.len(),
            modified: meta.modified().ok(),
        });
    }
    files.sort_by(|a, b| a.modified.cmp(&b.modified).then(a.name.cmp(&b.name)));
    Ok(files)
}

/// Move a failed file back into the input folder, where the next pass picks it up again.
pub fn retry(vault: &Vault, actor: Actor, job: &Job, name: &str) -> Result<PathBuf, String> {
    if !is_plain_name(name) {
        return Err(format!("invalid file name {name:?}"));
    }
    let source = job.spec.failed_dir.join(name);
    let meta = fs::symlink_metadata(&source).map_err(|e| format!("{name}: {e}"))?;
    if !meta.file_type().is_file() {
        return Err(format!("{name} is not a regular file"));
    }
    if exists(&job.spec.input_dir.join(name)) {
        return Err(format!(
            "{name} already exists in the input folder {}",
            job.spec.input_dir.display()
        ));
    }
    let target = process::move_into(&source, &job.spec.input_dir)
        .map_err(|e| format!("moving {name} back: {e}"))?;
    vault
        .record_retry(actor, job, name)
        .map_err(|e| e.to_string())?;
    Ok(target)
}

/// A bare file name that stays inside the folder it's joined to.
fn is_plain_name(name: &str) -> bool {
    !(name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(crate::platform::NOT_IN_A_FILE_NAME))
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_names_can_be_retried() {
        for name in ["", ".", "..", "../x", "a/b", "a\\b"] {
            assert!(!is_plain_name(name), "{name:?}");
        }
        assert!(is_plain_name("report.csv.pgp"));
        // Drive-relative and alternate-data-stream names would leave the failed folder.
        assert_eq!(is_plain_name("C:secret.txt"), !cfg!(windows));
        assert_eq!(is_plain_name("report.csv:stream"), !cfg!(windows));
    }

    #[cfg(windows)]
    #[test]
    fn drive_relative_names_replace_the_folder_in_join() {
        // Why `:` is refused: joining keeps nothing of the failed folder.
        assert_eq!(
            Path::new(r"D:\sftp\failed").join("C:secret.txt"),
            Path::new("C:secret.txt")
        );
    }
}
