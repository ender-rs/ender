use std::{mem::transmute_copy, str::FromStr};

use fastbuf::{ReadBuf, WriteBuf};
use packetize::{Decode, Encode};
use serde::{de::Visitor, Deserialize, Serialize};

use crate::var_int::VarInt;

#[derive(Debug, Clone, Copy)]
pub enum ProtocolVersion {
    Mc1_21_1 = 767,
}

impl Serialize for ProtocolVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i32(*self as i32)
    }
}

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(unsafe { transmute_copy(&deserializer.deserialize_i32(I32Visitor)?) })
    }
}

pub struct I32Visitor;
impl Visitor<'_> for I32Visitor {
    type Value = i32;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an integer")
    }

    fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v)
    }
}

impl ToString for ProtocolVersion {
    fn to_string(&self) -> String {
        match self {
            ProtocolVersion::Mc1_21_1 => String::from_str("1.21.1").unwrap(),
        }
    }
}

impl Encode for ProtocolVersion {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        VarInt::from(*self as i32).encode(buf)?;
        Ok(())
    }
}

impl Decode for ProtocolVersion {
    fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        Ok(unsafe { transmute_copy(&VarInt::decode(buf)?) })
    }
}
