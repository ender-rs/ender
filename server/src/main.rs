use kanal::unbounded_async;
use server::net::{game_server::GameServer, login_server::LoginServer};

fn main() {
    let (sender, receiver) = unbounded_async();
    let mut game_server = GameServer::new(receiver);
    let mut login_server = LoginServer::new(sender);
    std::thread::spawn(move || game_server.start_loop());
    login_server.start_loop()
}
