fn main() {
    let Err(error) = sud0::executor::run();
    eprintln!("sud0-exec: {error}");
    std::process::exit(1);
}
