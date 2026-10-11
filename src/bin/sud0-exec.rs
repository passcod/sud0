fn main() {
    // SAFETY: This is the first operation of the fixed synchronous binary. It has created no
    // threads, Rust descriptor owners, callbacks, or signal handlers. The deployment contract
    // starts this process with only standard descriptors plus uniquely inherited activation
    // descriptors 3 and 4, whose exact count and names `run` validates before claiming ownership.
    let Err(error) = unsafe { sud0::executor::run() };
    eprintln!("sud0-exec: {error}");
    std::process::exit(1);
}
