use std::ffi::{c_char, c_int, c_void};



#[link(name = "tunnel_lib", kind = "dylib")]
unsafe extern "C" {
    pub fn vpn_init(
        server_pubkey_path: *const c_char,
        server_addr: *const c_char,
        server_port: *const c_char,
        username: *const c_char,
        password: *const c_char,
    ) -> *mut c_void;
    pub fn vpn_negotiate(vpn_client_ptr: *mut c_void) -> c_int;
    pub fn vpn_create_tun(vpn_client_ptr: *mut c_void) -> c_int;
    pub fn vpn_loop(vpn_client_ptr: *mut c_void) -> c_int;
    pub fn vpn_disconnect(vpn_client_ptr: *mut c_void);
    pub fn vpn_cleanup(vpn_client_ptr: *mut c_void);
}