use std::ffi::CStr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use nix::fcntl::{OFlag, open};
use nix::sys::stat::{Mode, SFlag, fstat};
use thiserror::Error;

/// An owned descriptor that has been verified to refer to a directory.
///
/// Keeping the descriptor open binds later execution to the same directory object even if a
/// pathname used to open it is renamed or replaced.
#[derive(Debug)]
pub struct WorkingDirectoryFd {
    fd: OwnedFd,
}

impl WorkingDirectoryFd {
    /// Opens a directory descriptor for transfer to the privileged executor.
    pub fn open(path: &CStr) -> Result<Self, WorkingDirectoryError> {
        let fd = open(
            path,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(WorkingDirectoryError::Open)?;
        Self::try_from(fd)
    }

    /// Borrows the directory descriptor for transfer to another process.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Transfers ownership while preserving the verified directory-object identity.
    pub fn into_owned_fd(self) -> OwnedFd {
        self.fd
    }
}

impl AsFd for WorkingDirectoryFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl TryFrom<OwnedFd> for WorkingDirectoryFd {
    type Error = WorkingDirectoryError;

    fn try_from(fd: OwnedFd) -> Result<Self, Self::Error> {
        let metadata = fstat(&fd).map_err(WorkingDirectoryError::Stat)?;
        if SFlag::from_bits_truncate(metadata.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
            return Err(WorkingDirectoryError::NotDirectory);
        }
        Ok(Self { fd })
    }
}

/// Failure to open or validate the working-directory descriptor.
#[derive(Debug, Error)]
pub enum WorkingDirectoryError {
    #[error("failed to open working directory: {0}")]
    Open(nix::errno::Errno),
    #[error("failed to inspect working-directory descriptor: {0}")]
    Stat(nix::errno::Errno),
    #[error("working-directory descriptor does not refer to a directory")]
    NotDirectory,
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn accepts_directory_and_rejects_regular_file() {
        let directory = File::open("/").unwrap();
        assert!(WorkingDirectoryFd::try_from(OwnedFd::from(directory)).is_ok());

        let file = tempfile::tempfile().unwrap();
        assert!(matches!(
            WorkingDirectoryFd::try_from(OwnedFd::from(file)),
            Err(WorkingDirectoryError::NotDirectory)
        ));
    }

    #[test]
    fn opens_execute_only_directory() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("execute-only");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o111)).unwrap();
        let path = std::ffi::CString::new(directory.as_os_str().as_bytes()).unwrap();

        let opened = WorkingDirectoryFd::open(&path).unwrap();
        assert!(fstat(opened.as_fd()).unwrap().st_mode & libc::S_IFMT == libc::S_IFDIR);
    }

    #[test]
    fn opened_descriptor_survives_path_rename() {
        let parent = tempfile::tempdir().unwrap();
        let original = parent.path().join("original");
        let renamed = parent.path().join("renamed");
        std::fs::create_dir(&original).unwrap();
        let path = std::ffi::CString::new(original.as_os_str().as_bytes()).unwrap();
        let directory = WorkingDirectoryFd::open(&path).unwrap();
        std::fs::rename(&original, &renamed).unwrap();

        assert!(fstat(directory.as_fd()).unwrap().st_mode & libc::S_IFMT == libc::S_IFDIR);
        assert!(!original.exists());
        assert!(renamed.exists());
    }
}
