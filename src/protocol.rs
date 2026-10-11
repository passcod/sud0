use crate::constants::{
    DIGEST_BYTES, MAX_ARGUMENT_BYTES, MAX_ARGUMENTS, MAX_CWD_BYTES, MAX_ENCODED_REQUEST_BYTES,
    MAX_ENVIRONMENT_NAME_BYTES, MAX_ENVIRONMENT_VALUE_BYTES, MAX_ENVIRONMENT_VARIABLES,
    MAX_REQUEST_DATA_BYTES, PROTOCOL_MAGIC, PROTOCOL_VERSION,
};
use crate::error::ProtocolError;
use crate::request::{FrozenRequest, RequestOptions};

const HEADER_BYTES: usize = PROTOCOL_MAGIC.len() + 2 + 4 + DIGEST_BYTES;
const ABSENT_FIELD: u32 = u32::MAX;

impl FrozenRequest {
    /// Encodes this request in the canonical, digest-bearing wire format.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let payload = encode_payload(self)?;
        let encoded_len = HEADER_BYTES
            .checked_add(payload.len())
            .ok_or(ProtocolError::LengthOverflow)?;
        if encoded_len > MAX_ENCODED_REQUEST_BYTES {
            return Err(ProtocolError::EncodedRequestTooLarge {
                actual: encoded_len,
                maximum: MAX_ENCODED_REQUEST_BYTES,
            });
        }

        let mut encoded = Vec::with_capacity(encoded_len);
        encoded.extend_from_slice(PROTOCOL_MAGIC);
        encoded.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        put_length(&mut encoded, payload.len())?;
        encoded.extend_from_slice(self.execution_digest());
        encoded.extend_from_slice(&payload);
        Ok(encoded)
    }

    /// Decodes, bounds-checks, validates, and verifies a canonical wire-format request.
    pub fn decode(encoded: &[u8]) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_ENCODED_REQUEST_BYTES {
            return Err(ProtocolError::EncodedRequestTooLarge {
                actual: encoded.len(),
                maximum: MAX_ENCODED_REQUEST_BYTES,
            });
        }

        let mut reader = Reader::new(encoded);
        if reader.take(PROTOCOL_MAGIC.len(), "protocol magic")? != PROTOCOL_MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        let version = reader.read_u16("protocol version")?;
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion { version });
        }
        let payload_len = reader.read_u32("payload length")? as usize;
        let expected_digest: [u8; DIGEST_BYTES] = reader
            .take(DIGEST_BYTES, "execution digest")?
            .try_into()
            .expect("digest length is fixed");
        if payload_len != reader.remaining() {
            return Err(ProtocolError::InvalidPayloadLength {
                declared: payload_len,
                actual: reader.remaining(),
            });
        }

        let payload_bytes = reader.take(payload_len, "payload")?;
        let mut payload = Reader::new(payload_bytes);
        let flags = payload.read_u8("request options")?;
        let options = RequestOptions::from_flags(flags)?;

        let mut data_budget = DataBudget::new();
        let argument_count = payload.read_count("argument count", MAX_ARGUMENTS)?;
        let mut argv = Vec::with_capacity(argument_count);
        for index in 0..argument_count {
            argv.push(payload.read_bytes(
                Field::Argument(index),
                MAX_ARGUMENT_BYTES,
                &mut data_budget,
            )?);
        }

        let working_directory = payload.read_optional_bytes(
            Field::WorkingDirectory,
            MAX_CWD_BYTES,
            &mut data_budget,
        )?;

        let environment_count =
            payload.read_count("environment variable count", MAX_ENVIRONMENT_VARIABLES)?;
        let mut environment = Vec::with_capacity(environment_count);
        for index in 0..environment_count {
            let name = payload.read_bytes(
                Field::EnvironmentName(index),
                MAX_ENVIRONMENT_NAME_BYTES,
                &mut data_budget,
            )?;
            let value = payload.read_bytes(
                Field::EnvironmentValue(index),
                MAX_ENVIRONMENT_VALUE_BYTES,
                &mut data_budget,
            )?;
            environment.push((name, value));
        }
        if payload.remaining() != 0 {
            return Err(ProtocolError::TrailingPayload);
        }

        let request = FrozenRequest::new(argv, working_directory, environment, options)?;
        if encode_payload(&request)? != payload_bytes {
            return Err(ProtocolError::NonCanonicalPayload);
        }
        if request.execution_digest() != &expected_digest {
            return Err(ProtocolError::DigestMismatch);
        }
        Ok(request)
    }
}

pub(crate) fn encode_payload(request: &FrozenRequest) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Vec::new();
    payload.push(request.options().flags());
    put_length(&mut payload, request.argv().len())?;
    for argument in request.argv() {
        put_bytes(&mut payload, argument)?;
    }
    match request.working_directory() {
        Some(working_directory) => put_bytes(&mut payload, working_directory)?,
        None => payload.extend_from_slice(&ABSENT_FIELD.to_be_bytes()),
    }
    put_length(&mut payload, request.environment().len())?;
    for variable in request.environment() {
        put_bytes(&mut payload, variable.name())?;
        put_bytes(&mut payload, variable.value())?;
    }
    Ok(payload)
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ProtocolError> {
    put_length(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_length(output: &mut Vec<u8>, length: usize) -> Result<(), ProtocolError> {
    let length =
        u32::try_from(length).map_err(|_| ProtocolError::LengthNotRepresentable { length })?;
    output.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

struct DataBudget {
    consumed: usize,
}

impl DataBudget {
    const fn new() -> Self {
        Self { consumed: 0 }
    }

    fn charge(&mut self, length: usize) -> Result<(), ProtocolError> {
        let consumed = self
            .consumed
            .checked_add(length)
            .ok_or(ProtocolError::LengthOverflow)?;
        if consumed > MAX_REQUEST_DATA_BYTES {
            return Err(crate::error::RequestError::RequestTooLarge {
                actual: consumed,
                maximum: MAX_REQUEST_DATA_BYTES,
            }
            .into());
        }
        self.consumed = consumed;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Field {
    Argument(usize),
    WorkingDirectory,
    EnvironmentName(usize),
    EnvironmentValue(usize),
}

impl Field {
    const fn label(self) -> &'static str {
        match self {
            Self::Argument(_) => "command argument",
            Self::WorkingDirectory => "working directory",
            Self::EnvironmentName(_) => "environment variable name",
            Self::EnvironmentValue(_) => "environment variable value",
        }
    }

    fn length_error(self, actual: usize, maximum: usize) -> crate::error::RequestError {
        match self {
            Self::Argument(index) => crate::error::RequestError::ArgumentTooLong {
                index,
                actual,
                maximum,
            },
            Self::WorkingDirectory => {
                crate::error::RequestError::WorkingDirectoryTooLong { actual, maximum }
            }
            Self::EnvironmentName(index) => crate::error::RequestError::EnvironmentNameTooLong {
                index,
                actual,
                maximum,
            },
            Self::EnvironmentValue(index) => crate::error::RequestError::EnvironmentValueTooLong {
                index,
                actual,
                maximum,
            },
        }
    }
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ProtocolError::LengthOverflow)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(ProtocolError::Truncated { field })?;
        self.position = end;
        Ok(bytes)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, ProtocolError> {
        Ok(self.take(1, field)?[0])
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(
            self.take(2, field)?.try_into().expect("length is fixed"),
        ))
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(
            self.take(4, field)?.try_into().expect("length is fixed"),
        ))
    }

    fn read_count(&mut self, field: &'static str, maximum: usize) -> Result<usize, ProtocolError> {
        let count = self.read_u32(field)? as usize;
        if count > maximum {
            return Err(match field {
                "argument count" => crate::error::RequestError::TooManyArguments {
                    actual: count,
                    maximum,
                },
                _ => crate::error::RequestError::TooManyEnvironmentVariables {
                    actual: count,
                    maximum,
                },
            }
            .into());
        }
        Ok(count)
    }

    fn read_bytes(
        &mut self,
        field: Field,
        maximum: usize,
        data_budget: &mut DataBudget,
    ) -> Result<Vec<u8>, ProtocolError> {
        let length = self.read_u32(field.label())? as usize;
        if length > maximum {
            return Err(field.length_error(length, maximum).into());
        }
        data_budget.charge(length)?;
        Ok(self.take(length, field.label())?.to_vec())
    }

    fn read_optional_bytes(
        &mut self,
        field: Field,
        maximum: usize,
        data_budget: &mut DataBudget,
    ) -> Result<Option<Vec<u8>>, ProtocolError> {
        let length = self.read_u32(field.label())?;
        if length == ABSENT_FIELD {
            return Ok(None);
        }
        let length = length as usize;
        if length > maximum {
            return Err(field.length_error(length, maximum).into());
        }
        data_budget.charge(length)?;
        Ok(Some(self.take(length, field.label())?.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::*;
    use crate::request::IoMode;

    fn request() -> FrozenRequest {
        FrozenRequest::new(
            vec![b"/usr/bin/printf".to_vec(), vec![b'%', b's', 0xff]],
            Some(vec![b'/', b't', b'm', b'p', 0xfe]),
            vec![
                (b"LANG".to_vec(), b"C.UTF-8".to_vec()),
                (b"RAW".to_vec(), vec![0xff, b'x']),
            ],
            RequestOptions::for_io_mode(IoMode::Pipe),
        )
        .unwrap()
    }

    #[test]
    fn round_trip_preserves_non_utf8_bytes() {
        let request = request();
        let decoded = FrozenRequest::decode(&request.encode().unwrap()).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn encoding_is_canonical_across_environment_input_order() {
        let left = FrozenRequest::new(
            vec![b"true".to_vec()],
            None,
            vec![
                (b"Z".to_vec(), b"2".to_vec()),
                (b"A".to_vec(), b"1".to_vec()),
            ],
            RequestOptions::for_io_mode(IoMode::Pty),
        )
        .unwrap();
        let right = FrozenRequest::new(
            vec![b"true".to_vec()],
            None,
            vec![
                (b"A".to_vec(), b"1".to_vec()),
                (b"Z".to_vec(), b"2".to_vec()),
            ],
            RequestOptions::for_io_mode(IoMode::Pty),
        )
        .unwrap();
        assert_eq!(left.encode().unwrap(), right.encode().unwrap());
        assert_eq!(left.execution_digest(), right.execution_digest());
    }

    #[test]
    fn corruption_is_detected_by_digest() {
        let mut encoded = request().encode().unwrap();
        *encoded.last_mut().unwrap() ^= 1;
        assert_eq!(
            FrozenRequest::decode(&encoded),
            Err(ProtocolError::DigestMismatch)
        );
    }

    #[test]
    fn rejects_bad_magic_version_length_and_truncation() {
        let encoded = request().encode().unwrap();

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            FrozenRequest::decode(&bad_magic),
            Err(ProtocolError::InvalidMagic)
        );

        let mut bad_version = encoded.clone();
        bad_version[PROTOCOL_MAGIC.len() + 1] = 2;
        assert_eq!(
            FrozenRequest::decode(&bad_version),
            Err(ProtocolError::UnsupportedVersion { version: 2 })
        );

        let mut bad_length = encoded.clone();
        let offset = PROTOCOL_MAGIC.len() + 2;
        bad_length[offset..offset + 4].copy_from_slice(&0_u32.to_be_bytes());
        assert!(matches!(
            FrozenRequest::decode(&bad_length),
            Err(ProtocolError::InvalidPayloadLength { .. })
        ));

        for length in 0..encoded.len() {
            assert!(FrozenRequest::decode(&encoded[..length]).is_err());
        }
    }

    #[test]
    fn checks_count_before_allocating_elements() {
        let request = request();
        let mut encoded = request.encode().unwrap();
        let payload_offset = HEADER_BYTES;
        encoded[payload_offset + 1..payload_offset + 5]
            .copy_from_slice(&((MAX_ARGUMENTS as u32) + 1).to_be_bytes());
        assert!(matches!(
            FrozenRequest::decode(&encoded),
            Err(ProtocolError::InvalidRequest(
                crate::error::RequestError::TooManyArguments { .. }
            ))
        ));
    }

    #[test]
    fn checks_aggregate_data_limit_before_copying_excess_field() {
        let field = vec![b'x'; MAX_ARGUMENT_BYTES];
        let argument_count = MAX_REQUEST_DATA_BYTES / MAX_ARGUMENT_BYTES;
        let mut payload = vec![RequestOptions::for_io_mode(IoMode::Pipe).flags()];
        put_length(&mut payload, argument_count).unwrap();
        for _ in 0..argument_count {
            put_bytes(&mut payload, &field).unwrap();
        }
        put_bytes(&mut payload, b"/").unwrap();
        put_length(&mut payload, 0).unwrap();

        let mut encoded = Vec::new();
        encoded.extend_from_slice(PROTOCOL_MAGIC);
        encoded.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        put_length(&mut encoded, payload.len()).unwrap();
        encoded.extend_from_slice(&[0; DIGEST_BYTES]);
        encoded.extend_from_slice(&payload);

        assert!(matches!(
            FrozenRequest::decode(&encoded),
            Err(ProtocolError::InvalidRequest(
                crate::error::RequestError::RequestTooLarge { .. }
            ))
        ));
    }

    #[test]
    fn every_execution_field_contributes_to_digest() {
        let baseline = request();
        let changed_argv = FrozenRequest::new(
            vec![b"/usr/bin/printf".to_vec(), b"changed".to_vec()],
            baseline.working_directory().map(<[u8]>::to_vec),
            baseline
                .environment()
                .iter()
                .map(|variable| (variable.name().to_vec(), variable.value().to_vec()))
                .collect(),
            baseline.options(),
        )
        .unwrap();
        let changed_cwd = FrozenRequest::new(
            baseline.argv().to_vec(),
            Some(b"/elsewhere".to_vec()),
            baseline
                .environment()
                .iter()
                .map(|variable| (variable.name().to_vec(), variable.value().to_vec()))
                .collect(),
            baseline.options(),
        )
        .unwrap();
        let changed_environment = FrozenRequest::new(
            baseline.argv().to_vec(),
            baseline.working_directory().map(<[u8]>::to_vec),
            vec![(b"LANG".to_vec(), b"different".to_vec())],
            baseline.options(),
        )
        .unwrap();
        let changed_options = FrozenRequest::new(
            baseline.argv().to_vec(),
            baseline.working_directory().map(<[u8]>::to_vec),
            baseline
                .environment()
                .iter()
                .map(|variable| (variable.name().to_vec(), variable.value().to_vec()))
                .collect(),
            RequestOptions::for_io_mode(IoMode::Pty),
        )
        .unwrap();

        for changed in [
            changed_argv,
            changed_cwd,
            changed_environment,
            changed_options,
        ] {
            assert_ne!(baseline.execution_digest(), changed.execution_digest());
        }
    }

    fn safe_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
        vec(1_u8..=255, 0..=max)
    }

    proptest! {
        #[test]
        fn arbitrary_valid_requests_round_trip(
            program in safe_bytes(32).prop_filter("program is nonempty", |bytes| !bytes.is_empty()),
            arguments in vec(safe_bytes(32), 0..8),
            cwd in prop::option::of(safe_bytes(32).prop_filter("cwd is nonempty", |bytes| !bytes.is_empty())),
            values in vec(safe_bytes(32), 0..8),
            pty in any::<bool>(),
        ) {
            let mut argv = vec![program];
            argv.extend(arguments);
            let environment = values
                .into_iter()
                .enumerate()
                .map(|(index, value)| (format!("VAR_{index}").into_bytes(), value))
                .collect();
            let mode = if pty { IoMode::Pty } else { IoMode::Pipe };
            let request = FrozenRequest::new(
                argv,
                cwd,
                environment,
                RequestOptions::for_io_mode(mode),
            ).unwrap();

            let encoded = request.encode().unwrap();
            prop_assert_eq!(FrozenRequest::decode(&encoded).unwrap(), request);
        }

        #[test]
        fn decoder_never_panics_on_arbitrary_input(input in vec(any::<u8>(), 0..4096)) {
            let _ = FrozenRequest::decode(&input);
        }
    }
}
