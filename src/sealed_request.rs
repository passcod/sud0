use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt;

use nix::fcntl::{FcntlArg, SealFlag, fcntl};
use nix::sys::memfd::{MFdFlags, memfd_create};
use nix::sys::stat::{SFlag, fstat};
use thiserror::Error;

use crate::FrozenRequest;
use crate::constants::MAX_ENCODED_REQUEST_BYTES;
use crate::error::ProtocolError;

const MEMFD_NAME: &str = "sud0-request";
const REQUIRED_SEALS: SealFlag = SealFlag::F_SEAL_WRITE
    .union(SealFlag::F_SEAL_SHRINK)
    .union(SealFlag::F_SEAL_GROW)
    .union(SealFlag::F_SEAL_SEAL);

/// An owned descriptor whose contents are a verified frozen request protected by all mandatory
/// Linux file seals.
///
/// The type establishes immutability of the file contents and size. It deliberately does not claim
/// that a descriptor received by the executor can be proven to originate from `memfd_create(2)`.
#[derive(Debug)]
pub struct SealedRequestFd {
    file: File,
}

impl SealedRequestFd {
    /// Encodes `request` into a new close-on-exec sealable memfd and seals it permanently.
    pub fn create(request: &FrozenRequest) -> Result<Self, SealedRequestError> {
        let encoded = request.encode()?;
        let fd = memfd_create(
            MEMFD_NAME,
            MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
        )
        .map_err(SealedRequestError::Create)?;
        let file = File::from(fd);

        file.write_all_at(&encoded, 0)
            .map_err(SealedRequestError::Write)?;
        fcntl(&file, FcntlArg::F_ADD_SEALS(REQUIRED_SEALS)).map_err(SealedRequestError::Seal)?;

        let actual_seals = get_seals(&file)?;
        if !actual_seals.contains(REQUIRED_SEALS) {
            return Err(SealedRequestError::MissingSeals {
                actual: actual_seals,
            });
        }

        Ok(Self { file })
    }

    /// Borrows the sealed descriptor for transfer to another process.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }

    /// Transfers ownership while retaining the kernel-enforced seals.
    pub fn into_owned_fd(self) -> OwnedFd {
        self.file.into()
    }
}

impl AsFd for SealedRequestFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

/// Validates and decodes a sealed request object.
///
/// Acceptance is based on observable descriptor properties and seals, not a claim about whether the
/// object was originally created by `memfd_create(2)`.
pub fn decode_sealed_request(file: &File) -> Result<FrozenRequest, SealedRequestError> {
    let flags = fcntl(file, FcntlArg::F_GETFL).map_err(SealedRequestError::GetFlags)?;
    if flags & libc::O_ACCMODE == libc::O_WRONLY || flags & libc::O_PATH != 0 {
        return Err(SealedRequestError::NotReadable);
    }

    let metadata = fstat(file).map_err(SealedRequestError::Stat)?;
    if SFlag::from_bits_truncate(metadata.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG {
        return Err(SealedRequestError::NotRegular);
    }
    let size = usize::try_from(metadata.st_size)
        .map_err(|_| SealedRequestError::InvalidSize(metadata.st_size))?;
    if size > MAX_ENCODED_REQUEST_BYTES {
        return Err(SealedRequestError::TooLarge {
            actual: size,
            maximum: MAX_ENCODED_REQUEST_BYTES,
        });
    }

    let actual_seals = get_seals(file)?;
    if !actual_seals.contains(REQUIRED_SEALS) {
        return Err(SealedRequestError::MissingSeals {
            actual: actual_seals,
        });
    }

    let mut encoded = vec![0; size];
    file.read_exact_at(&mut encoded, 0)
        .map_err(SealedRequestError::Read)?;
    FrozenRequest::decode(&encoded).map_err(SealedRequestError::Decode)
}

fn get_seals(file: &File) -> Result<SealFlag, SealedRequestError> {
    let bits = fcntl(file, FcntlArg::F_GET_SEALS).map_err(SealedRequestError::GetSeals)?;
    Ok(SealFlag::from_bits_retain(bits))
}

/// Failure to create or consume an immutable request descriptor.
#[derive(Debug, Error)]
pub enum SealedRequestError {
    #[error("failed to encode frozen request: {0}")]
    Encode(#[from] ProtocolError),
    #[error("failed to create request descriptor: {0}")]
    Create(nix::errno::Errno),
    #[error("failed to write request descriptor: {0}")]
    Write(io::Error),
    #[error("failed to seal request descriptor: {0}")]
    Seal(nix::errno::Errno),
    #[error("failed to inspect request descriptor flags: {0}")]
    GetFlags(nix::errno::Errno),
    #[error("request descriptor is not readable")]
    NotReadable,
    #[error("failed to inspect request descriptor metadata: {0}")]
    Stat(nix::errno::Errno),
    #[error("request descriptor is not a regular file")]
    NotRegular,
    #[error("request descriptor has invalid size {0}")]
    InvalidSize(i64),
    #[error("request descriptor has {actual} bytes; the maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("failed to inspect request descriptor seals: {0}")]
    GetSeals(nix::errno::Errno),
    #[error("request descriptor lacks mandatory seals (actual bits: 0x{actual:x})")]
    MissingSeals { actual: SealFlag },
    #[error("failed to read request descriptor: {0}")]
    Read(io::Error),
    #[error("failed to decode request descriptor: {0}")]
    Decode(ProtocolError),
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};
    use std::os::fd::AsRawFd;

    use super::*;
    use crate::IoMode;

    fn request() -> FrozenRequest {
        FrozenRequest::new(
            vec!["/usr/bin/printf".to_owned(), "héllo".to_owned()],
            vec![("TERM".to_owned(), "xterm-256color".to_owned())],
            IoMode::Pipe,
        )
        .unwrap()
    }

    fn unsealed_file(bytes: &[u8]) -> File {
        let fd = memfd_create(
            "sud0-request-test",
            MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
        )
        .unwrap();
        let mut file = File::from(fd);
        file.write_all(bytes).unwrap();
        file
    }

    #[test]
    fn creates_permanently_sealed_round_trip_request() {
        let request = request();
        let sealed = SealedRequestFd::create(&request).unwrap();
        let file = File::from(sealed.into_owned_fd());

        assert_eq!(decode_sealed_request(&file).unwrap(), request);
        let seals = get_seals(&file).unwrap();
        assert!(seals.contains(REQUIRED_SEALS));
        assert_ne!(file.as_raw_fd(), -1);
    }

    #[test]
    fn rejects_missing_mandatory_seals() {
        let file = unsealed_file(&request().encode().unwrap());
        assert!(matches!(
            decode_sealed_request(&file),
            Err(SealedRequestError::MissingSeals { .. })
        ));

        fcntl(
            &file,
            FcntlArg::F_ADD_SEALS(SealFlag::F_SEAL_WRITE | SealFlag::F_SEAL_SHRINK),
        )
        .unwrap();
        assert!(matches!(
            decode_sealed_request(&file),
            Err(SealedRequestError::MissingSeals { .. })
        ));
    }

    #[test]
    fn accepts_extra_seals() {
        let file = unsealed_file(&request().encode().unwrap());
        fcntl(
            &file,
            FcntlArg::F_ADD_SEALS(REQUIRED_SEALS | SealFlag::F_SEAL_FUTURE_WRITE),
        )
        .unwrap();
        assert_eq!(decode_sealed_request(&file).unwrap(), request());
    }

    #[test]
    fn rejects_sealed_malformed_protocol() {
        let file = unsealed_file(b"not a frozen request");
        fcntl(&file, FcntlArg::F_ADD_SEALS(REQUIRED_SEALS)).unwrap();
        assert!(matches!(
            decode_sealed_request(&file),
            Err(SealedRequestError::Decode(_))
        ));
    }

    #[test]
    fn reads_from_offset_zero_without_changing_or_trusting_cursor() {
        let request = request();
        let sealed = SealedRequestFd::create(&request).unwrap();
        let mut file = File::from(sealed.into_owned_fd());
        file.seek(io::SeekFrom::End(0)).unwrap();

        assert_eq!(decode_sealed_request(&file).unwrap(), request);
        assert_eq!(
            file.stream_position().unwrap(),
            file.metadata().unwrap().len()
        );
    }
}
