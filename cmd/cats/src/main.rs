use clap::Parser;

fn main() {
    let cli = cats_cli::Cli::parse();
    if let Err(e) = cats_cli::run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
