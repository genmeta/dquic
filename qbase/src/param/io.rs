use std::{fmt::Debug, time::Duration};

use bytes::Bytes;
use nom::{Parser, multi::length_data};

use crate::{
    cid::{ConnectionId, WriteConnectionId},
    error::QuicError,
    param::{
        core::{ParameterId, ParameterValue, ParameterValueType, Parameters, ServerParameters},
        error::Error,
        preferred_address::{PreferredAddress, WirtePreferredAddress, be_preferred_address},
    },
    role::{IntoRole, RequiredParameters, Role},
    token::{ResetToken, WriteResetToken, be_reset_token},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly
/// to write the parameter id.
pub trait WriteParameterId: bytes::BufMut {
    /// Write the parameter id to the buffer.
    fn put_parameter_id(&mut self, param_id: ParameterId);
}

impl<T: bytes::BufMut> WriteParameterId for T {
    fn put_parameter_id(&mut self, param_id: ParameterId) {
        self.put_varint(&VarInt::from(param_id));
    }
}

pub fn be_raw_parameter(input: &[u8]) -> nom::IResult<&[u8], (VarInt, &[u8])> {
    let (remain, param_id) = crate::varint::be_varint(input)?;
    let (remain, data) = length_data(be_varint).parse(remain)?;
    Ok((remain, (param_id, data)))
}

pub fn be_parameter_value(input: &[u8], id: ParameterId) -> nom::IResult<&[u8], ParameterValue> {
    use nom::combinator::map;

    match id.value_type() {
        ParameterValueType::VarInt => map(be_varint, ParameterValue::VarInt).parse(input),
        ParameterValueType::Boolean => Ok((input, ParameterValue::True)),
        ParameterValueType::Bytes => {
            Ok((&[], ParameterValue::Bytes(Bytes::copy_from_slice(input))))
        }
        ParameterValueType::Duration => {
            map(be_varint, |v| Duration::from_millis(v.into_u64()).into()).parse(input)
        }
        ParameterValueType::ResetToken => {
            map(be_reset_token, ParameterValue::ResetToken).parse(input)
        }
        ParameterValueType::ConnectionId => Ok((
            &[],
            ParameterValue::ConnectionId(ConnectionId::from_slice(input)),
        )),
        ParameterValueType::PreferredAddress => {
            map(be_preferred_address, ParameterValue::PreferredAddress).parse(input)
        }
    }
}

// A trait for writing parameters to the buffer.
pub trait WriteParameter {
    fn put_bytes_parameter(&mut self, id: ParameterId, bytes: &Bytes);

    fn put_cid_parameter(&mut self, id: ParameterId, cid: &ConnectionId);

    fn put_duration_parameter(&mut self, id: ParameterId, dur: &Duration) {
        let value = VarInt::from_u128(dur.as_millis()).expect("Duration too large");
        self.put_varint_parameter(id, &value);
    }

    fn put_bool_parameter(&mut self, id: ParameterId);

    fn put_preferred_address_parameter(&mut self, id: ParameterId, addr: &PreferredAddress);

    fn put_reset_token_parameter(&mut self, id: ParameterId, token: &ResetToken);

    fn put_varint_parameter(&mut self, id: ParameterId, value: &VarInt);

    fn put_parameter(&mut self, id: ParameterId, value: &ParameterValue) {
        match value {
            ParameterValue::Bytes(bytes) => self.put_bytes_parameter(id, bytes),
            ParameterValue::ConnectionId(cid) => self.put_cid_parameter(id, cid),
            ParameterValue::Duration(dur) => self.put_duration_parameter(id, dur),
            ParameterValue::True => self.put_bool_parameter(id),
            ParameterValue::PreferredAddress(addr) => {
                self.put_preferred_address_parameter(id, addr)
            }
            ParameterValue::ResetToken(token) => self.put_reset_token_parameter(id, token),
            ParameterValue::VarInt(varint) => self.put_varint_parameter(id, varint),
        }
    }
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly
/// to write parameters.
impl<T: bytes::BufMut> WriteParameter for T {
    fn put_bytes_parameter(&mut self, id: ParameterId, bytes: &Bytes) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::try_from(bytes.len()).expect("param too large"));
        self.put_slice(bytes);
    }

    fn put_cid_parameter(&mut self, id: ParameterId, cid: &ConnectionId) {
        self.put_parameter_id(id);
        self.put_connection_id(cid);
    }

    fn put_bool_parameter(&mut self, id: ParameterId) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::from_u32(0));
    }

    fn put_preferred_address_parameter(&mut self, id: ParameterId, addr: &PreferredAddress) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::try_from(addr.encoding_size()).expect("param too large"));
        self.put_preferred_address(addr);
    }

    fn put_reset_token_parameter(&mut self, id: ParameterId, token: &ResetToken) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::try_from(token.encoding_size()).expect("param too large"));
        self.put_reset_token(token);
    }

    fn put_varint_parameter(&mut self, id: ParameterId, value: &VarInt) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::try_from(value.encoding_size()).expect("param too large"));
        self.put_varint(value);
    }
}

pub trait WriteParameters<Role> {
    fn put_parameters(&mut self, params: &Parameters<Role>);
}

impl<Role, T: bytes::BufMut> WriteParameters<Role> for T {
    fn put_parameters(&mut self, params: &Parameters<Role>) {
        for (id, value) in &params.map {
            self.put_parameter(*id, value);
        }
    }
}

fn handle_nom_error<F: Debug, E: Debug>(input: &[u8], nom_error: nom::Err<F, E>) -> Error {
    assert!(
        matches!(nom_error, nom::Err::Incomplete(..)),
        "Only incomplete errors should occur, but {nom_error:?} happened for input: {input:?}"
    );
    Error::IncompleteParameterId(format!("incomplete parameter data for input: {input:?}"))
}

impl<R: IntoRole + RequiredParameters + Default> Parameters<R> {
    pub fn parse_from_bytes(mut buf: &[u8]) -> Result<Self, QuicError> {
        let mut parameters = Self::default();
        while !buf.is_empty() {
            let (param_id, param_value);
            (buf, (param_id, param_value)) =
                be_raw_parameter(buf).map_err(|nom_error| handle_nom_error(buf, nom_error))?;

            let param_id = match ParameterId::try_from(param_id) {
                Ok(param_id) => param_id,
                Err(unknown @ Error::UnknownParameterId(..)) => {
                    tracing::debug!(target: "dquic", %unknown, "ignore unknown transport parameter");
                    continue; // Ignore unknown parameters
                }
                Err(e) => return Err(e.into()),
            };

            ParameterId::belong_to(param_id, R::into_role())?;
            let (remain, param_value) = be_parameter_value(param_value, param_id)
                .map_err(|nom_error| handle_nom_error(param_value, nom_error))?;
            assert!(remain.is_empty(), "Parameter value should consume all data");

            parameters.set(param_id, param_value)?;
        }
        for id in R::required_parameters() {
            if !parameters.contains(id) {
                return Err(Error::LackParameterId(R::into_role(), id).into());
            }
        }
        Ok(parameters)
    }
}

impl ServerParameters {
    pub fn try_from_remembered_bytes(mut buf: &[u8]) -> Result<Self, QuicError> {
        let mut parameters = Self::new();
        while !buf.is_empty() {
            let (param_id, param_value);
            (buf, (param_id, param_value)) =
                be_raw_parameter(buf).map_err(|nom_error| handle_nom_error(buf, nom_error))?;

            let param_id = match ParameterId::try_from(param_id) {
                Ok(param_id) => param_id,
                Err(unknown @ Error::UnknownParameterId(..)) => {
                    tracing::debug!(target: "dquic", %unknown, "ignore unknown transport parameter");
                    continue; // Ignore unknown parameters
                }
                Err(e) => return Err(e.into()),
            };

            ParameterId::belong_to(param_id, Role::Server)?;
            let (remain, param_value) = be_parameter_value(param_value, param_id)
                .map_err(|nom_error| handle_nom_error(param_value, nom_error))?;
            assert!(remain.is_empty(), "Parameter value should consume all data");

            parameters.set(param_id, param_value)?;
        }
        Ok(parameters)
    }
}
