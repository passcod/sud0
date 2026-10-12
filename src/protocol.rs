use serde::{Deserialize, Serialize};

use crate::constants::{MAX_ENCODED_REQUEST_BYTES, PROTOCOL_VERSION};
use crate::error::ProtocolError;
use crate::request::{FrozenRequest, IoMode};

#[derive(Serialize, Deserialize)]
struct WireRequest {
    version: u8,
    argv: Vec<String>,
    environment: Vec<(String, String)>,
    io_mode: IoMode,
}

impl FrozenRequest {
    /// Encodes this request in the private Postcard wire format.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let wire = WireRequest {
            version: PROTOCOL_VERSION,
            argv: self.argv().to_vec(),
            environment: self.environment().to_vec(),
            io_mode: self.io_mode(),
        };
        let encoded = postcard::to_allocvec(&wire).map_err(ProtocolError::Encode)?;
        if encoded.len() > MAX_ENCODED_REQUEST_BYTES {
            return Err(ProtocolError::EncodedRequestTooLarge {
                actual: encoded.len(),
                maximum: MAX_ENCODED_REQUEST_BYTES,
            });
        }
        Ok(encoded)
    }

    /// Decodes bounded Postcard data and reconstructs validated request state.
    pub fn decode(encoded: &[u8]) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_ENCODED_REQUEST_BYTES {
            return Err(ProtocolError::EncodedRequestTooLarge {
                actual: encoded.len(),
                maximum: MAX_ENCODED_REQUEST_BYTES,
            });
        }
        let (wire, remainder): (WireRequest, _) =
            postcard::take_from_bytes(encoded).map_err(ProtocolError::Decode)?;
        if !remainder.is_empty() {
            return Err(ProtocolError::TrailingData);
        }
        if wire.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(wire.version));
        }
        FrozenRequest::new(wire.argv, wire.environment, wire.io_mode).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> FrozenRequest {
        FrozenRequest::new(
            vec!["/usr/bin/printf".to_owned(), "héllo".to_owned()],
            vec![("LANG".to_owned(), "C.UTF-8".to_owned())],
            IoMode::Pipe,
        )
        .unwrap()
    }

    #[test]
    fn round_trip_preserves_validated_request() {
        let request = request();
        assert_eq!(
            FrozenRequest::decode(&request.encode().unwrap()).unwrap(),
            request
        );
    }

    #[test]
    fn rejects_malformed_trailing_and_wrong_version_data() {
        assert!(matches!(
            FrozenRequest::decode(&[0xff]),
            Err(ProtocolError::Decode(_))
        ));
        let encoded = request().encode().unwrap();
        assert!(matches!(
            FrozenRequest::decode(&encoded[..encoded.len() - 1]),
            Err(ProtocolError::Decode(_))
        ));
        assert!(matches!(
            FrozenRequest::decode(&vec![0; MAX_ENCODED_REQUEST_BYTES + 1]),
            Err(ProtocolError::EncodedRequestTooLarge { .. })
        ));

        let mut trailing = request().encode().unwrap();
        trailing.push(0);
        assert!(matches!(
            FrozenRequest::decode(&trailing),
            Err(ProtocolError::TrailingData)
        ));

        let wrong_version = postcard::to_allocvec(&WireRequest {
            version: PROTOCOL_VERSION + 1,
            argv: vec!["true".to_owned()],
            environment: vec![],
            io_mode: IoMode::Pipe,
        })
        .unwrap();
        assert!(matches!(
            FrozenRequest::decode(&wrong_version),
            Err(ProtocolError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn decoded_values_still_pass_request_validation() {
        let invalid = postcard::to_allocvec(&WireRequest {
            version: PROTOCOL_VERSION,
            argv: vec![String::new()],
            environment: vec![],
            io_mode: IoMode::Pipe,
        })
        .unwrap();
        assert!(matches!(
            FrozenRequest::decode(&invalid),
            Err(ProtocolError::InvalidRequest(
                crate::RequestError::EmptyProgram
            ))
        ));
    }
}
