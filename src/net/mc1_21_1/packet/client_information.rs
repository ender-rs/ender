use bitflags::{bitflags, Flags};
use packetize::{Decode, Encode};

use crate::{
    net::login_server::{ConnectionId, LoginServer},
    var_string::VarString,
};

#[derive(Debug, Encode, Decode)]
pub struct ClientInformationC2s {
    locale: VarString<16>,
    view_distance: u8,
    chat_mode: ChatMode,
    chat_colors: bool,
    display_skin_parts: DisplaySkinParts,
    main_hand: MainHand,
    enable_text_filtering: bool,
    allow_server_listings: bool,
}

bitflags! {
    #[derive(Debug)]
    pub struct DisplaySkinParts: u8 {
        const Cape = 0x01;
        const Jacket = 0x02;
        const LeftSleeve = 0x04;
        const RightSleeve = 0x08;
        const LeftPantsLeg = 0x10;
        const RightPantsLeg = 0x20;
        const Hat = 0x40;
        const _Unused = 0x80;
    }
}

impl Encode for DisplaySkinParts {
    fn encode(&self, buf: &mut impl fastbuf::WriteBuf) -> Result<(), ()> {
        self.bits().encode(buf)
    }
}

impl Decode for DisplaySkinParts {
    fn decode(buf: &mut impl fastbuf::ReadBuf) -> Result<Self, ()> {
        Ok(DisplaySkinParts::from_bits(u8::decode(buf)?).ok_or(())?)
    }
}

#[derive(Debug, Encode, Decode)]
pub enum MainHand {
    Left = 0,
    Right = 1,
}

#[derive(Debug, Encode, Decode)]
pub enum ChatMode {
    Enabled = 0,
    CommandOnly = 1,
    Hidden = 2,
}

pub fn handle_client_information(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    client_information: &ClientInformationC2s,
) -> Result<(), ()> {
    dbg!(client_information);
    Ok(())
}
