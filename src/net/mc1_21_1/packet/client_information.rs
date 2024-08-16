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
    display_skin_parts: u8,
    main_hand: MainHand,
    enable_text_filtering: bool,
    allow_server_listings: bool,
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
