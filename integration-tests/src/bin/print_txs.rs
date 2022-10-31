use std::env;
use integration_tests::{fuzzer::convert_to_proto};
use env_logger::Env;
use std::fs::metadata;
use std::fs;
use log::{info, error};


#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 1 {
        panic!("usage: cargo run --bin print_txs PATH");
    }
    let filepath = args[1].clone();
    let md = metadata(&filepath);
    let path = match md {
        Ok(path) => path,
        Err(error) => panic!("Path does not exist: {:?}", error),
    };  
    if path.is_dir() {
        error!("Path is dir please provide a file");
    } else if path.is_file() {
        info!("Processing file: {}", filepath);
        let data = fs::read(&filepath).expect("Unable to read file");
        match convert_to_proto(&data) {
            Some(proto) => {
                println!("{:?}", proto);
            },
            None => (),
        }
    }
}
