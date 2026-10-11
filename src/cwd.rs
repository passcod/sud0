use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;

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

    /// Returns kernel-derived identity for this exact directory object.
    pub fn identity(&self) -> Result<WorkingDirectoryIdentity, WorkingDirectoryError> {
        let mut metadata = MaybeUninit::<libc::statx>::zeroed();
        // SAFETY: `metadata` points to writable storage for `statx`; an empty pathname plus
        // `AT_EMPTY_PATH` asks the kernel to inspect the valid borrowed directory descriptor.
        let result = unsafe {
            libc::statx(
                self.fd.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT,
                libc::STATX_TYPE | libc::STATX_INO | libc::STATX_MNT_ID,
                metadata.as_mut_ptr(),
            )
        };
        if result == -1 {
            return Err(WorkingDirectoryError::Identity(
                std::io::Error::last_os_error(),
            ));
        }
        // SAFETY: successful `statx` initialized the output structure.
        let metadata = unsafe { metadata.assume_init() };
        Ok(WorkingDirectoryIdentity {
            mount_id: metadata.stx_mnt_id,
            inode: metadata.stx_ino,
        })
    }

    /// Returns the kernel's current pathname for this exact opened directory object.
    pub fn display_path(&self) -> Result<Vec<u8>, WorkingDirectoryError> {
        let link = format!("/proc/self/fd/{}", self.fd.as_raw_fd());
        let path = std::fs::read_link(link).map_err(WorkingDirectoryError::DisplayPath)?;
        let bytes = path.into_os_string().into_vec();
        CString::new(bytes.clone()).map_err(|_| WorkingDirectoryError::DisplayPathNul)?;
        Ok(bytes)
    }

    /// Transfers ownership while preserving the verified directory-object identity.
    pub fn into_owned_fd(self) -> OwnedFd {
        self.fd
    }
}

/// Kernel-derived identity for an opened working directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkingDirectoryIdentity {
    mount_id: u64,
    inode: u64,
}

impl WorkingDirectoryIdentity {
    #[cfg(test)]
    pub(crate) const fn new_for_test(mount_id: u64, inode: u64) -> Self {
        Self { mount_id, inode }
    }

    pub const fn mount_id(self) -> u64 {
        self.mount_id
    }

    pub const fn inode(self) -> u64 {
        self.inode
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
    #[error("failed to identify working-directory descriptor: {0}")]
    Identity(std::io::Error),
    #[error("failed to obtain working-directory display path: {0}")]
    DisplayPath(std::io::Error),
    #[error("working-directory display path contains a NUL byte")]
    DisplayPathNul,
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
    fn display_path_is_derived_from_the_open_descriptor() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("opened");
        std::fs::create_dir(&directory).unwrap();
        let path = CString::new(directory.as_os_str().as_bytes()).unwrap();
        let opened = WorkingDirectoryFd::open(&path).unwrap();
        assert_eq!(
            opened.display_path().unwrap(),
            directory.as_os_str().as_bytes()
        );
    }

    #[test]
    fn identity_is_stable_for_the_same_directory_object() {
        let directory =
            WorkingDirectoryFd::try_from(OwnedFd::from(File::open("/").unwrap())).unwrap();
        let identity = directory.identity().unwrap();
        assert_ne!(identity.inode(), 0);
        assert_eq!(directory.identity().unwrap(), identity);
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
