#[cfg(target_os = "windows")]
extern crate embed_resource;

fn main() {
    #[cfg(target_os = "windows")]
    println!("cargo:rustc-link-search=native=target\\debug");
    #[cfg(target_os = "windows")]
    println!("cargo:rustc-link-search=native=target\\release");
    #[cfg(target_os = "windows")]
    println!("cargo:rustc-link-search=native=target\\x86_64-pc-windows-gnu\\release");
    #[cfg(target_os = "windows")]
    println!("cargo:rustc-link-lib=dylib=tunnel_lib");

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    println!("cargo:rustc-link-search=native=target/debug");
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    println!("cargo:rustc-link-search=native=target/release");
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    println!("cargo:rustc-link-search=native=target/x86_64-pc-windows-gnu/release");
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    println!("cargo:rustc-link-lib=dylib=tunnel_lib");

    #[cfg(target_os = "windows")]
    embed_resource::compile("app-manifest.rc");
}