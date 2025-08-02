mod command;
mod path_manager;
mod config;
mod message_io;
mod ipv6;
mod client;
mod server;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let first_arg = args.get(1).map(|s| s.as_str()).unwrap_or("");
    match first_arg {
        "client" => {
            println!("Running as client...");
        }
        "server" => {
            println!("Running as server...");
        }
        _ => {
            println!("Usage: {} [client|server]", args[0]);

            println!("config file: {}", path_manager::CONFIG_FILE);
            if let Ok(config) = config::load_config() {
                println!("Loaded config: {:?}", config);
            } else {
                println!("Failed to load config.");
            }

            std::process::exit(1);
        }
    }
}
