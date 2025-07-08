use clap::Parser;
use nuntium::modes::{run_client, run_server};

#[derive(Parser)]
struct Args {
    /// Operating mode: 'client' or 'server'
    #[arg(long)]
    mode: String,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    match args.mode.as_str() {
        "client" => run_client(),
        "server" => run_server(),
        other => {
            eprintln!("unknown mode: {other}");
            std::process::exit(1);
        }
    }
}
