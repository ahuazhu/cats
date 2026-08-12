fn main() {
    if let Err(error) = cats_node_agent::vmm_launcher::run() {
        eprintln!("cats-vmm-launcher: {error:#}");
        std::process::exit(1);
    }
}
