use std::fmt::Debug;

use derive_more::derive::{Deref, DerefMut};
use packetize::{Decode, Encode};

use crate::{
    array_capacitor::VecCap,
    identifier::Identifier,
    net::{connection::ConnectionId, game_server::GameServer},
};

#[derive(Debug)]
pub struct PluginMessage {
    pub channel: Identifier,
    pub data: VecCap<u8, 1048576>,
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
    fn encode(&self, buf: &mut impl fastbuf::WriteBuf) -> Result<(), ()> {
        self.channel.encode(buf)?;
        self.data.as_slice().encode(buf)?;
        Ok(())
    }
}

impl Decode for PluginMessage {
    fn decode(buf: &mut impl fastbuf::ReadBuf) -> Result<Self, ()> {
        let channel = Identifier::decode(buf)?;
        let mut data = Vec::with_capacity(buf.remaining());
        let buf = buf.read(buf.remaining());
        unsafe { data.set_len(buf.len()) };
        data.as_mut_slice().copy_from_slice(buf);
        let data = data.into();
        Ok(PluginMessage { channel, data })
    }
}

pub fn handle_plugin_message(
    server: &mut GameServer,
    connection_id: ConnectionId,
    plugin_message: &PluginMessage,
) -> Result<(), ()> {
    println!("{plugin_message:?}");
    Ok(())
}
