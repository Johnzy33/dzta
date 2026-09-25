use dzta_arch_detector::PlatformInfo;


fn main() {
    println!("Starting arch detector...");

    let info = PlatformInfo::new();

    let enclave = info.detect_enclave();

    println!("{:#?}\n Available Enclave: {:?}", info, enclave);

    println!("Press Enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}