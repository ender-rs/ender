use derive_more::derive::{Deref, DerefMut};
use packetize::{Decode, Encode};

use crate::var_array::VarStringCap32767;

#[derive(Debug, Encode, Decode, Deref, DerefMut)]
pub struct KnownPacksS2c(pub KnownPacks);

#[derive(Debug, Encode, Decode, Deref, DerefMut)]
pub struct KnownPacksC2s(pub KnownPacks);

#[derive(Debug, Encode, Decode)]
pub struct KnownPacks {
    pub known_packs: Vec<KnownPack>,
}

#[derive(Debug, Encode, Decode)]
pub struct KnownPack {
    pub namespace: VarStringCap32767,
    pub id: VarStringCap32767,
    pub version: VarStringCap32767,
}
