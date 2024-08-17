use derive_more::derive::{Deref, DerefMut};
use packetize::{Decode, Encode};

use crate::array_capacitor::VarStringCap32767;

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
    namespace: Box<VarStringCap32767>,
    id: Box<VarStringCap32767>,
    version: Box<VarStringCap32767>,
}
