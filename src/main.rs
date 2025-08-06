mod aes;
mod client;
mod command;
mod config;
mod ipv6;
mod message_io;
mod packet;
mod path_manager;
mod server;
mod shared_keys;
mod tun;

use env_logger::Env;
use log::{error, info};

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("error")).init();

    let args = std::env::args().collect::<Vec<_>>();
    let first_arg = args.get(1).map(|s| s.as_str()).unwrap_or("");
    match first_arg {
        "client" => {
            info!("Running as client...");
            if let Err(e) = client::run_client() {
                error!("Client error: {}", e);
            }
        }
        "server" => {
            info!("Running as server...");
            if let Err(e) = server::run_server() {
                error!("Server error: {}", e);
            }
        }
        _ => {
            error!("Usage: {} [client|server]", args[0]);
            std::process::exit(1);
        }
    }
}
