use clap::Parser;
use nuntium::modes::{run_client, run_server, run_client_tun, run_server_tun};

#[derive(Parser)]
struct Args {
    /// Operating mode: 'client', 'server', 'client-tun', or 'server-tun'
    #[arg(long)]
    mode: String,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    match args.mode.as_str() {
        "client" => run_client(),
        "server" => run_server(),
        "client-tun" => run_client_tun(),
        "server-tun" => run_server_tun(),
        other => {
            eprintln!("unknown mode: {other}");
            std::process::exit(1);
        }
    }
}
