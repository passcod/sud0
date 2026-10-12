use std::ffi::CStr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use nix::fcntl::{OFlag, open};
use nix::sys::stat::{Mode, SFlag, fstat};
use thiserror::Error;

/// An owned descriptor that has been verified to refer to a directory.
///
/// Keeping the descriptor open binds later execution to the same directory object even if a
/// pathname used to open it is renamed or replaced.
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
        Ok(Self { fd })
    }

    /// Returns the kernel's current UTF-8 pathname for this exact opened directory object.
    pub fn display_path(&self) -> Result<String, WorkingDirectoryError> {
        let link = format!("/proc/self/fd/{}", self.fd.as_raw_fd());
        std::fs::read_link(link)
            .map_err(WorkingDirectoryError::DisplayPath)?
            .into_os_string()
            .into_string()
            .map_err(|_| WorkingDirectoryError::DisplayPathNotUtf8)
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
    #[error("failed to obtain working-directory display path: {0}")]
    DisplayPath(std::io::Error),
    #[error("working-directory display path is not valid UTF-8")]
    DisplayPathNotUtf8,
    #[error("working-directory descriptor does not refer to a directory")]
    NotDirectory,
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

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
    fn display_path_tracks_the_opened_directory_across_rename() {
        let parent = tempfile::tempdir().unwrap();
        let original = parent.path().join("original");
        let renamed = parent.path().join("renamed");
        std::fs::create_dir(&original).unwrap();
        let path = CString::new(original.as_os_str().as_bytes()).unwrap();
        let directory = WorkingDirectoryFd::open(&path).unwrap();
        assert_eq!(
            directory.display_path().unwrap(),
            original.to_str().unwrap()
        );

        std::fs::rename(&original, &renamed).unwrap();
        assert_eq!(directory.display_path().unwrap(), renamed.to_str().unwrap());
    }
}
