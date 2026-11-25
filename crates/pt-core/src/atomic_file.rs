//! Atomic replacement of small state files that several pt processes share.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Atomically replace the file at `path` with `contents`.
///
/// Concurrent pt processes (and threads) can write the same per-user state
/// file. Each call stages its bytes in a sibling with a per-call name, created
/// exclusively, and renames that sibling over `path`. No writer can truncate,
/// publish or rename away another writer's staged bytes: the last rename wins,
/// and readers see either the previous file or a complete new one. When writing
/// or the rename fails, the call removes its own staged file, which was never
/// published. The parent directory must already exist.
pub(crate) fn replace(path: &Path, contents: &[u8]) -> io::Result<()> {
    let staged = staging_path(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)?;
    let written = file.write_all(contents).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written.and_then(|()| fs::rename(&staged, path)) {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    Ok(())
}

/// `.<name>.<pid>.<uuid>.tmp` next to `path`. The random part keeps threads of
/// one process apart; exclusive creation, not the name, enforces that no two
/// writers share a staged file.
fn staging_path(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "state file path has no file name",
        )
    })?;
    let mut staged = OsString::from(".");
    staged.push(name);
    staged.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    Ok(path.with_file_name(staged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn staged_leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn concurrent_replacements_of_one_file_all_succeed_and_leave_a_complete_file() {
        const WRITERS: usize = 8;
        const ROUNDS: usize = 25;
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("state.json"));
        let payloads: Vec<Vec<u8>> = (0..WRITERS)
            .map(|writer| {
                serde_json::to_vec_pretty(&serde_json::json!({
                    "writer": writer,
                    "padding": "x".repeat(16 * 1024 + writer),
                }))
                .unwrap()
            })
            .collect();
        let payloads = Arc::new(payloads);
        let barrier = Arc::new(Barrier::new(WRITERS));
        let handles: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let (path, payloads, barrier) = (
                    Arc::clone(&path),
                    Arc::clone(&payloads),
                    Arc::clone(&barrier),
                );
                std::thread::spawn(move || {
                    barrier.wait();
                    (0..ROUNDS)
                        .map(|_| replace(&path, &payloads[writer]))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in handles {
            for result in handle.join().unwrap() {
                result.expect("every concurrent replacement succeeds");
            }
        }
        let published = fs::read(path.as_path()).unwrap();
        assert!(
            payloads.contains(&published),
            "the published file is one writer's complete payload"
        );
        assert!(staged_leftovers(dir.path()).is_empty());
    }

    #[test]
    fn failed_rename_removes_the_staged_file_and_keeps_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("kept"), b"kept").unwrap();
        assert!(replace(&path, b"{}").is_err());
        assert_eq!(fs::read(path.join("kept")).unwrap(), b"kept");
        assert!(staged_leftovers(dir.path()).is_empty());
    }

    #[test]
    fn staged_name_is_a_hidden_sibling() {
        let path = Path::new("/state/dir/pending.json");
        let staged = staging_path(path).unwrap();
        assert_eq!(staged.parent(), path.parent());
        let name = staged.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(".pending.json."));
        assert!(name.ends_with(".tmp"));
        assert_ne!(staged, staging_path(path).unwrap());
        assert!(staging_path(Path::new("/")).is_err());
    }
}
