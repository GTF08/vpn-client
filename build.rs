fn main() {
    println!("cargo:rustc-link-search=native=target\\debug");
    println!("cargo:rustc-link-search=native=target\\release");
    println!("cargo:rustc-link-search=native=target\\x86_64-pc-windows-gnu\\release");
    println!("cargo:rustc-link-lib=dylib=tunnel_lib");
}