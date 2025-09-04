//use tunnel_lib;
use std::process;
use std::ffi::CString;
use std::os::raw::c_char;


#[link(name = "tunnel_lib", kind = "dylib")]
unsafe extern "C" {
    fn start_vpn(
        server_pubkey_path: *const c_char,
        server_addr: *const std::os::raw::c_char,
        server_port: *const std::os::raw::c_char,
        username: *const std::os::raw::c_char,
        password: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
}



fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
        if args.len() != 6 {
            eprintln!("Usage: {} <server_pubkey_filepath> <server_addr> <server_port> <username> <password>", args[0]);
            process::exit(1);
        }
    let server_pubkey_filepath = &args[1];
    let server_addr = &args[2];
    let server_port = &args[3];
    let username = &args[4];
    let password = &args[5];
    

    let server_pubkey_filepath_c = CString::new(server_pubkey_filepath.as_str()).unwrap();
    let server_addr_c = CString::new(server_addr.as_str()).unwrap();
    let server_port_c = CString::new(server_port.as_str()).unwrap();
    let username_c = CString::new(username.as_str()).unwrap();
    let password_c = CString::new(password.as_str()).unwrap();

    let result = unsafe {
        start_vpn(
            server_pubkey_filepath_c.as_ptr() as *const c_char,
            server_addr_c.as_ptr() as *const c_char,
            server_port_c.as_ptr() as *const c_char,
            username_c.as_ptr() as *const c_char,
            password_c.as_ptr() as *const c_char,
        )
    };
    
    if result == 0 {
        Ok(())
    } else {
        Err(format!("VPN failed to start, code {result}"))
    }
}
