use clap::Parser;

fn main() {
    let cli = cats_cli::Cli::parse();
    let result = cats_cli::run(cli);
    let exit_code = cats_cli::process_exit_code(&result);
    if let Err(error) = result {
        eprintln!("error: {error:#}");
        std::process::exit(exit_code);
    }
}
