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
mod tun_writer;

use env_logger::Env;
use log::{error, info};

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("error")).init();

    // Avoid collecting all CLI arguments; only fetch the first argument if present.
    let first_arg = std::env::args().nth(1).unwrap_or_default();
    match first_arg.as_str() {
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
            let program = std::env::args().next().unwrap_or_else(|| "nuntium".into());
            error!("Usage: {} [client|server]", program);
            std::process::exit(1);
        }
    }
}
