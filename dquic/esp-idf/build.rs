fn main() {
    embuild::espidf::sysenv::output();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    println!("cargo:rustc-env=DQUIC_TEST_UNIX_TIME={now}");
}
