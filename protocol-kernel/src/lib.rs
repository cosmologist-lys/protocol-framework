pub mod bridge;
pub mod core;
pub mod utils;

// Re-export protocol-base types
pub use protocol_base::{ProtocolError, ProtocolResult};

pub use crate::bridge::{JniRequest, JniResponse, ReportField};
pub use crate::core::{
    cache::ProtocolCache,
    parts::{
        placeholder::PlaceHolder,
        raw_capsule::RawCapsule,
        raw_chamber::RawChamber,
        rawfield::Rawfield,
        traits::{
            AutoDecoding, AutoDecodingParam, AutoEncoding, AutoEncodingParam, Cmd, ProtocolConfig,
            Transport,
        },
        transport_carrier::TransportCarrier,
        transport_pair::TransportPair,
    },
    reader::Reader,
    type_converter::{
        FieldCompareDecoder, FieldConvertDecoder, FieldEnumDecoder, FieldTranslator, FieldType,
        TryFromBytes,
    },
    writer::Writer,
    DirectionEnum, MsgTypeEnum, Symbol, RW,
};
pub use crate::utils::{generate_rand, hex_util, math_util, timestamp_util, to_pinyin};
