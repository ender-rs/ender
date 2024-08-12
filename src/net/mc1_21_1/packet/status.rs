use std::str::FromStr;

use arrayvec::{ArrayString, ArrayVec};
use packetize::{Decode, Encode, Packet};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    net::{
        protocol_version::ProtocolVersion,
        server::{ConnectionId, Server},
    },
    player_name::PlayerName,
    var_string::VarString,
};

#[derive(Debug, Encode, Decode)]
pub struct StatusRequestC2s;

pub fn handle_status_request(
    server: &mut Server,
    connection_id: ConnectionId,
    status_request: &StatusRequestC2s,
) -> Result<(), ()> {
    dbg!(status_request);
    server.send_packet(
        connection_id,
        &StatusResponseS2c {
            status: Status {
                version: Version {
                    name: ProtocolVersion::Mc1_21_1.to_string(),
                    protocol: ProtocolVersion::Mc1_21_1,
                },
                players: Players {
                    max: 100,
                    online: 0,
                    sample: {
                        let mut vec = ArrayVec::new();
                        let value = Sample {
                            name: VarString::from_str("Notch").unwrap().into(),
                            id: Uuid::nil(),
                        };
                        unsafe { vec.push_unchecked(value) };
                        vec
                    },
                },
                description: Some(Description {
                    text: String::from_str("Hello ender").unwrap(),
                }),
                favicon: None,
                enforce_sercure_chat: false,
            },
        }
        .into(),
    )?;
    server.flush_write_buffer(connection_id);
    println!("HI");
    Ok(())
}

#[derive(Debug)]
pub struct StatusResponseS2c {
    status: Status,
}

impl Decode for StatusResponseS2c {
    fn decode(buf: &mut impl fastbuf::ReadBuf) -> Result<Self, ()> {
        todo!()
    }
}

impl Encode for StatusResponseS2c {
    fn encode(&self, buf: &mut impl fastbuf::WriteBuf) -> Result<(), ()> {
        let string = match simd_json::serde::to_string(&self.status) {
            Ok(v) => v,
            Err(err) => Err(())?,
        };
        dbg!(&string);
        VarString(ArrayString::<32767>::from_str(string.as_str()).map_err(|_| ())?).encode(buf)?;
        Ok(())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Status {
    version: Version,
    players: Players,
    description: Option<Description>,
    favicon: Option<String>,
    #[serde(rename = "enforcesSecureChat")]
    enforce_sercure_chat: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Description {
    text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Players {
    max: i32,
    online: i32,
    sample: ArrayVec<Sample, 10>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Sample {
    name: PlayerName,
    id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Version {
    name: String,
    protocol: ProtocolVersion,
}

pub fn handle_status_response(
    server: &mut Server,
    connection_id: ConnectionId,
    status_response: StatusResponseS2c,
) {
    dbg!(status_response);
}
