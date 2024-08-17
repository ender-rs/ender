use arrayvec::ArrayVec;
use fastbuf::{ReadBuf, WriteBuf};
use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    array_capacitor::VarStringCap, net::protocol_version::ProtocolVersion, player_name::PlayerName,
};

#[derive(Debug, Encode, Decode)]
pub struct StatusRequestC2s;

#[derive(Debug)]
pub struct StatusResponseS2c {
    pub status: Status,
}

#[derive(Debug, Encode, Decode)]
pub struct PingRequestC2s {
    pub payload: i64,
}

#[derive(Debug, Encode, Decode)]
pub struct PingResponseS2c {
    pub payload: i64,
}
impl Decode for StatusResponseS2c {
    fn decode(_buf: &mut impl ReadBuf) -> Result<Self, ()> {
        todo!()
    }
}

impl Encode for StatusResponseS2c {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        let string = match simd_json::serde::to_string(&self.status) {
            Ok(v) => v,
            Err(_) => Err(())?,
        };
        dbg!(&string);
        VarStringCap::<32767>(string).encode(buf)?;
        Ok(())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Status {
    pub version: Version,
    pub players: Players,
    pub description: Option<Description>,
    pub favicon: Option<String>,
    #[serde(rename = "enforcesSecureChat")]
    pub enforce_sercure_chat: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Description {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Players {
    pub max: i32,
    pub online: i32,
    pub sample: ArrayVec<Sample, 10>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Sample {
    pub name: PlayerName,
    pub id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Version {
    pub name: String,
    pub protocol: ProtocolVersion,
}
