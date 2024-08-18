use kanal::{unbounded, unbounded_async};
use server::net::{game_server::GameServer, login_server::LoginServer};

fn main() {
    let (sender, receiver) = unbounded();
    let mut login_server = LoginServer::new(sender);
    let mut game_server = GameServer::new(receiver);
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || game_server.start_loop())
        .unwrap();

    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || login_server.start_loop())
        .unwrap()
        .join()
        .unwrap();
}
