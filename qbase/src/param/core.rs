use std::{collections::HashMap, marker::PhantomData, time::Duration};

use bytes::Bytes;
use derive_more::{From, TryIntoError};

use super::{error::Error, preferred_address::PreferredAddress};
use crate::{
    cid::ConnectionId,
    role::*,
    token::ResetToken,
    varint::{VARINT_MAX, VarInt},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterValueType {
    VarInt,
    Boolean,
    Bytes,
    Duration,
    ResetToken,
    ConnectionId,
    PreferredAddress,
}

#[derive(Debug, Clone, PartialEq, From)]
pub enum ParameterValue {
    Bytes(Bytes),
    False,
    True,
    VarInt(VarInt),
    Duration(Duration),
    ConnectionId(ConnectionId),
    ResetToken(ResetToken),
    PreferredAddress(PreferredAddress),
}

impl ParameterValue {
    pub fn value_type(&self) -> ParameterValueType {
        match self {
            ParameterValue::VarInt(_) => ParameterValueType::VarInt,
            ParameterValue::False | ParameterValue::True => ParameterValueType::Boolean,
            ParameterValue::Bytes(_) => ParameterValueType::Bytes,
            ParameterValue::Duration(_) => ParameterValueType::Duration,
            ParameterValue::ConnectionId(_) => ParameterValueType::ConnectionId,
            ParameterValue::ResetToken(_) => ParameterValueType::ResetToken,
            ParameterValue::PreferredAddress(_) => ParameterValueType::PreferredAddress,
        }
    }
}

impl From<u32> for ParameterValue {
    fn from(value: u32) -> Self {
        ParameterValue::VarInt(VarInt::from_u32(value))
    }
}

impl From<bool> for ParameterValue {
    fn from(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }
}

impl From<String> for ParameterValue {
    fn from(value: String) -> Self {
        ParameterValue::Bytes(Bytes::from(Vec::from(value)))
    }
}

impl TryFrom<ParameterValue> for Duration {
    type Error = TryIntoError<ParameterValue>;

    #[inline]
    fn try_from(value: ParameterValue) -> Result<Self, TryIntoError<ParameterValue>> {
        match value {
            ParameterValue::Duration(v) => Ok(v),
            _ => Err(TryIntoError::new(value, "Duration", "Duration")),
        }
    }
}

impl TryFrom<ParameterValue> for ConnectionId {
    type Error = TryIntoError<ParameterValue>;

    #[inline]
    fn try_from(value: ParameterValue) -> Result<Self, TryIntoError<ParameterValue>> {
        match value {
            ParameterValue::ConnectionId(v) => Ok(v),
            _ => Err(TryIntoError::new(value, "ConnectionId", "ConnectionId")),
        }
    }
}

impl TryFrom<ParameterValue> for VarInt {
    type Error = TryIntoError<ParameterValue>;

    #[inline]
    fn try_from(value: ParameterValue) -> Result<Self, TryIntoError<ParameterValue>> {
        match value {
            ParameterValue::VarInt(v) => Ok(v),
            _ => Err(TryIntoError::new(value, "VarInt", "VarInt")),
        }
    }
}

impl TryFrom<ParameterValue> for u64 {
    type Error = <VarInt as TryFrom<ParameterValue>>::Error;

    #[inline]
    fn try_from(value: ParameterValue) -> Result<Self, Self::Error> {
        VarInt::try_from(value).map(|value| value.into_u64())
    }
}

impl TryFrom<ParameterValue> for PreferredAddress {
    type Error = TryIntoError<ParameterValue>;

    #[inline]
    fn try_from(value: ParameterValue) -> Result<Self, TryIntoError<ParameterValue>> {
        match value {
            ParameterValue::PreferredAddress(v) => Ok(v),
            _ => Err(TryIntoError::new(
                value,
                "PreferredAddress",
                "PreferredAddress",
            )),
        }
    }
}

impl TryFrom<ParameterValue> for Bytes {
    type Error = TryIntoError<ParameterValue>;

    #[inline]
    fn try_from(value: ParameterValue) -> Result<Self, TryIntoError<ParameterValue>> {
        match value {
            ParameterValue::Bytes(v) => Ok(v),
            _ => Err(TryIntoError::new(value, "Bytes", "Bytes")),
        }
    }
}

impl TryFrom<ParameterValue> for bool {
    type Error = TryIntoError<ParameterValue>;

    #[inline]
    fn try_from(value: ParameterValue) -> Result<Self, Self::Error> {
        match value {
            ParameterValue::False => Ok(false),
            ParameterValue::True => Ok(true),
            _ => Err(TryIntoError::new(value, "Enabled", "bool")),
        }
    }
}

impl TryFrom<ParameterValue> for ResetToken {
    type Error = TryIntoError<ParameterValue>;

    #[inline]
    fn try_from(value: ParameterValue) -> Result<Self, TryIntoError<ParameterValue>> {
        match value {
            ParameterValue::ResetToken(v) => Ok(v),
            _ => Err(TryIntoError::new(value, "ResetToken", "ResetToken")),
        }
    }
}

impl TryFrom<ParameterValue> for String {
    type Error = <Bytes as TryFrom<ParameterValue>>::Error;

    #[inline]
    fn try_from(value: ParameterValue) -> Result<Self, Self::Error> {
        Bytes::try_from(value).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[repr(u64)]
// qmacro::TransportParameter
#[derive(qmacro::ParameterId, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParameterId {
    #[param(value_type = ConnectionId)]
    OriginalDestinationConnectionId = 0x0000,
    #[param(value_type = Duration, default = Duration::ZERO)]
    MaxIdleTimeout = 0x0001,
    #[param(value_type = ResetToken)]
    StatelessResetToken = 0x0002,
    #[param(value_type = VarInt, default = 65527u32, bound = 1200..=65527)]
    MaxUdpPayloadSize = 0x0003,
    #[param(value_type = VarInt, default = 0u32)]
    InitialMaxData = 0x0004,
    #[param(value_type = VarInt, default = 0u32)]
    InitialMaxStreamDataBidiLocal = 0x0005,
    #[param(value_type = VarInt, default = 0u32)]
    InitialMaxStreamDataBidiRemote = 0x0006,
    #[param(value_type = VarInt, default = 0u32)]
    InitialMaxStreamDataUni = 0x0007,
    #[param(value_type = VarInt, default = 0u32)]
    InitialMaxStreamsBidi = 0x0008,
    #[param(value_type = VarInt, default = 0u32)]
    InitialMaxStreamsUni = 0x0009,
    #[param(value_type = VarInt, default = 3u32, bound = 0..=20)]
    AckDelayExponent = 0x000a,
    #[param(value_type = Duration, default = Duration::from_millis(25))]
    MaxAckDelay = 0x000b,
    #[param(value_type = Boolean, default = false)]
    DisableActiveMigration = 0x000c,
    #[param(value_type = PreferredAddress)]
    PreferredAddress = 0x000d,
    #[param(value_type = VarInt, default = 2u32, bound = 2..=VARINT_MAX)]
    ActiveConnectionIdLimit = 0x000e,
    #[param(value_type = ConnectionId)]
    InitialSourceConnectionId = 0x000f,
    #[param(value_type = ConnectionId)]
    RetrySourceConnectionId = 0x0010,
    #[param(value_type = VarInt, default = 0u32)]
    MaxDatagramFrameSize = 0x0020,
    #[param(value_type = Boolean, default = false)]
    GreaseQuicBit = 0x2ab2,
    /// Genemta extension parameter.
    #[param(value_type = Bytes)]
    ClientName = 0xffee,
}

impl ParameterId {
    pub fn belong_to(self, role: Role) -> Result<(), Error> {
        match self {
            ParameterId::OriginalDestinationConnectionId
            | ParameterId::StatelessResetToken
            | ParameterId::PreferredAddress
            | ParameterId::RetrySourceConnectionId
                if role != Role::Server =>
            {
                Err(Error::InvalidParameterId(self, role))
            }
            ParameterId::ClientName if role != Role::Client => {
                Err(Error::InvalidParameterId(self, role))
            }
            _ => Ok(()),
        }
    }
}

impl std::fmt::LowerHex for ParameterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", VarInt::from(*self).into_u64())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Parameters<Role> {
    pub(super) map: HashMap<ParameterId, ParameterValue>,
    _role: PhantomData<Role>,
}

impl<Role> Parameters<Role> {
    /// Explicitly configured parameters, without synthesizing default values.
    pub fn iter(&self) -> impl Iterator<Item = (&ParameterId, &ParameterValue)> {
        self.map.iter()
    }

    /// Return an explicitly configured value or the protocol default.
    /// Use [`Self::try_get`] for parameters that are genuinely optional.
    pub fn get<V>(&self, id: ParameterId) -> V
    where
        V: TryFrom<ParameterValue>,
    {
        self.try_get(id)
            .unwrap_or_else(|| panic!("{id:?} has neither a configured value nor a default"))
    }

    /// Return an optional parameter, still applying its protocol default when one exists.
    pub fn try_get<V>(&self, id: ParameterId) -> Option<V>
    where
        V: TryFrom<ParameterValue>,
    {
        self.map
            .get(&id)
            .cloned()
            .or_else(|| id.default_value())
            .and_then(|value| value.try_into().ok())
    }

    pub fn contains(&self, id: ParameterId) -> bool {
        self.map.contains_key(&id)
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl<R: IntoRole + Default> Parameters<R> {
    /// An empty parameter set whose missing values use protocol defaults.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            _role: PhantomData,
        }
    }

    pub fn set(&mut self, id: ParameterId, value: impl Into<ParameterValue>) -> Result<(), Error> {
        let role: Role = R::into_role();
        id.belong_to(role)?;
        let value = value.into();
        id.validate(&value)?;
        self.map.insert(id, value);
        Ok(())
    }
}

pub type ClientParameters = Parameters<Client>;
pub type ServerParameters = Parameters<Server>;

impl Default for ClientParameters {
    fn default() -> Self {
        let mut params = Self::new();

        for (id, value) in [
            (ParameterId::InitialMaxStreamsBidi, 100u32),
            (ParameterId::InitialMaxStreamsUni, 100u32),
            (ParameterId::InitialMaxData, 1u32 << 20),
            (ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 20),
            (ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 20),
            (ParameterId::InitialMaxStreamDataUni, 1u32 << 20),
            (ParameterId::ActiveConnectionIdLimit, 10u32),
        ] {
            params.set(id, value).expect("unreachable");
        }

        params
            .set(ParameterId::MaxIdleTimeout, Duration::from_secs(20))
            .expect("unreachable");

        params
    }
}

impl Default for ServerParameters {
    fn default() -> Self {
        let mut params = Self::new();

        for (id, value) in [
            (ParameterId::InitialMaxStreamsBidi, 100u32),
            (ParameterId::InitialMaxStreamsUni, 100u32),
            (ParameterId::InitialMaxData, 1u32 << 20),
            (ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 20),
            (ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 20),
            (ParameterId::InitialMaxStreamDataUni, 1u32 << 20),
            (ParameterId::ActiveConnectionIdLimit, 10u32),
        ] {
            params.set(id, value).expect("unreachable");
        }
        params
            .set(ParameterId::MaxIdleTimeout, Duration::from_secs(30))
            .expect("unreachable");

        params
    }
}

impl ServerParameters {
    #[inline]
    pub fn is_0rtt_accepted(&self, server_params: &ServerParameters) -> bool {
        [
            ParameterId::InitialMaxData,
            ParameterId::InitialMaxStreamDataBidiLocal,
            ParameterId::InitialMaxStreamDataBidiRemote,
            ParameterId::InitialMaxStreamDataUni,
            ParameterId::InitialMaxStreamsBidi,
            ParameterId::InitialMaxStreamsUni,
            ParameterId::ActiveConnectionIdLimit,
            ParameterId::MaxDatagramFrameSize,
        ]
        .into_iter()
        .all(|id| self.get::<VarInt>(id) <= server_params.get::<VarInt>(id))
    }
}
