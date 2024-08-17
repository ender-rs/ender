use kanal::{unbounded, unbounded_async};
use server::net::{game_server::GameServer, login_server::LoginServer};

fn main() {
    let (sender, receiver) = unbounded();
    let mut login_server = LoginServer::new(sender);
    let mut game_server = GameServer::new(receiver);
    std::thread::spawn(move || game_server.start_loop());
    login_server.start_loop()
}
