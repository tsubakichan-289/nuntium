mod client;
mod command;
mod config;
mod file_io;
mod ipv6;
mod message_io;
mod packet;
mod path_manager;
mod server;
mod tun;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let first_arg = args.get(1).map(|s| s.as_str()).unwrap_or("");
    match first_arg {
        "client" => {
            println!("Running as client...");
            client::run_client();
        }
        "server" => {
            println!("Running as server...");
            server::run_server();
        }
        _ => {
            println!("Usage: {} [client|server]", args[0]);
            std::process::exit(1);
        }
    }
}
