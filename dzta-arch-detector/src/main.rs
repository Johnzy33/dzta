use dzta_arch_detector::PlatformInfo;


fn main() {
    println!("Starting arch detector...");

    let info = PlatformInfo::new();

    println!("{:#?}", info);

    println!("Press Enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}