use derive_more::derive::{Deref, DerefMut};
use packetize::{Decode, Encode};

use crate::{
    net::login_server::{ConnectionId, LoginServer},
    var_string::VarString32767,
};

#[derive(Debug, Encode, Decode, Deref, DerefMut)]
pub struct KnownPacksS2c(KnownPacks);

#[derive(Debug, Encode, Decode, Deref, DerefMut)]
pub struct KnownPacksC2s(KnownPacks);

#[derive(Debug, Encode, Decode)]
pub struct KnownPacks {
    known_packs: Vec<KnownPack>,
}

#[derive(Debug, Encode, Decode)]
pub struct KnownPack {
    namespace: Box<VarString32767>,
    id: Box<VarString32767>,
    version: Box<VarString32767>,
}

pub fn handle_known_packs(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    known_packs: &KnownPacks,
) -> Result<(), ()> {
    Ok(())
}
