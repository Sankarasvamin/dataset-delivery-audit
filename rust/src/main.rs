use dataset_delivery_audit::{scan, write_jsonl};
use std::env;
use std::path::Path;

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 || args[1] != "scan" || args[2] != "--root" || args[4] != "--output" {
        return Err("usage: dataset-delivery-audit scan --root ROOT --output FILE".into());
    }
    let output = Path::new(&args[5]);
    if let Some(parent) = output.parent() { std::fs::create_dir_all(parent).map_err(|error| error.to_string())?; }
    write_jsonl(output, &scan(Path::new(&args[3]))?)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

