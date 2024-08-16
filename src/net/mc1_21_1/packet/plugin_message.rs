use std::{cmp::min, fmt::Debug};

use arrayvec::ArrayVec;
use derive_more::derive::{Deref, DerefMut};
use packetize::{Decode, Encode};

use crate::{
    identifier::Identifier,
    net::login_server::{ConnectionId, LoginServer},
};

#[derive(Debug)]
pub struct PluginMessage {
    channel: Identifier,
    data: ArrayVec<u8, 32767>,
}

#[derive(Deref, DerefMut, Encode, Decode, Debug)]
pub struct PluginMessageConfC2s(pub PluginMessage);

#[derive(Deref, DerefMut, Encode, Decode, Debug)]
pub struct PluginMessagePlayC2s(pub PluginMessage);

#[derive(Deref, DerefMut, Encode, Decode, Debug)]
pub struct PluginMessageConfS2c(pub PluginMessage);

#[derive(Deref, DerefMut, Encode, Decode, Debug)]
pub struct PluginMessagePlayS2c(pub PluginMessage);

impl Encode for PluginMessage {
    fn encode(&self, _buf: &mut impl fastbuf::WriteBuf) -> Result<(), ()> {
        todo!()
    }
}

impl Decode for PluginMessage {
    fn decode(buf: &mut impl fastbuf::ReadBuf) -> Result<Self, ()> {
        let channel = Identifier::decode(buf)?;
        let mut data = ArrayVec::new();
        let buf = buf.read(buf.remaining());
        unsafe { data.set_len(buf.len()) };
        data.as_mut_slice().copy_from_slice(buf);
        Ok(PluginMessage { channel, data })
    }
}

pub fn handle_plugin_message(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    plugin_message: &PluginMessage,
) -> Result<(), ()> {
    println!("{plugin_message:?}");
    Ok(())
}
