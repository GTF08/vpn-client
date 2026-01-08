#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use std::ffi::{c_char, c_int, c_void, CStr};

#[cfg(target_os = "android")]
use jni::{objects::{JClass, JObject, JString, JValue}, sys::{jint, jlong}, JNIEnv};
#[cfg(target_os = "android")]
use std::os::unix::io::{AsRawFd};


use log::{error, info};
#[cfg(target_os = "android")]
use android_logger;

use crate::vpnclient::VPNClient;

mod messages;
mod diffie_hellman;
mod tunnel;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
mod desktop_routemanager;
mod sock_ops;
mod key_management;
mod vpnclient;
mod bufferpool;
mod tasks;

const LOG_FILE: &'static str = "vpn.log";



#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
 pub extern "C" fn init_rust_logger() -> c_int {
    use std::fs;
    use chrono::Local;
    use fern::Dispatch;
    use log::{info, LevelFilter};

    let _ = fs::create_dir_all("logs");
    let logfile = match fern::log_file(format!("logs/{LOG_FILE}")) {
        Ok(file) => file,
        Err(_e) => return -1,
    };
    let init_result = Dispatch::new()
        .format(|out, message, record| {
            

            out.finish(format_args!(
                "{} [{}] {}: {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.target(),
                message
            ))
        })
        .level(LevelFilter::Debug) // Уровень логирования по умолчанию
        .chain(logfile) // Логи в файл
        //.chain(std::io::stdout()) // Логи в консоль
        .apply();
    if let Err(_e) = init_result {
        return -1;
    }
    info!("Logger initialized");
    return 1;
}

#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn vpn_init(
    server_pubkey_path: *const c_char,
    server_addr: *const c_char,
    server_port: *const c_char,
    username: *const c_char,
    password: *const c_char,
) -> *mut c_void {
    use std::net::Ipv4Addr;

    
    let server_pubkey_path = unsafe { CStr::from_ptr(server_pubkey_path).to_string_lossy().into_owned() };
    let server_addr = unsafe { CStr::from_ptr(server_addr).to_string_lossy().into_owned() };
    let server_port = unsafe { CStr::from_ptr(server_port).to_string_lossy().into_owned() };
    let username = unsafe { CStr::from_ptr(username).to_string_lossy().into_owned() };
    let password = unsafe { CStr::from_ptr(password).to_string_lossy().into_owned() };
    info!("Creating client with pubkey path: {}, server address {}:{}", 
        server_pubkey_path,
        server_addr,
        server_port
    );
    let runtime = tokio::runtime::Builder::
        new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
   let server_addr: Ipv4Addr = match server_addr.parse::<std::net::Ipv4Addr>() {
        Ok(ipv4) => {
            info!("Parsed IP {} as {}", server_addr, ipv4.to_bits());
            ipv4
        },
        Err(e) => {
            error!("Failed to parse server address '{}': {}", server_addr, e);
            return std::ptr::null_mut();
        },
    };
    let server_port : u16 = match server_port.parse() {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse server port as u16. Error: {e}");
            return std::ptr::null_mut();
        },
    };
    let vpn_client_box = Box::new(
        VPNClient::new(server_pubkey_path, server_addr, server_port, username, password, runtime)
    );
    
    Box::into_raw(vpn_client_box) as *mut c_void
}



#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn vpn_negotiate(vpn_client_ptr: *mut c_void) -> c_int {

    if vpn_client_ptr.is_null() {
        error!("Client pointer is null");
        return -1;
    }
    let vpn_client = unsafe{ &mut *(vpn_client_ptr as *mut VPNClient)};
    //let mut vpn_client = unsafe { Box::from_raw(vpn_client_ptr as *mut VPNClient) };

    match vpn_client.negotiate() {
        Ok(_) => 1,
        Err(e) => {
            error!("Negotiation failed. {}", e);
            -1
        },
    }
}


#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn vpn_create_tun(vpn_client_ptr: *mut c_void) -> c_int {
    if vpn_client_ptr.is_null() {
        error!("Client pointer is null");
        return -1;
    }
    let vpn_client = unsafe{ &mut *(vpn_client_ptr as *mut VPNClient)};
    //let mut vpn_client = unsafe { Box::from_raw(vpn_client_ptr as *mut VPNClient) };

    match vpn_client.create_tun() {
        Ok(_) => 1,
        Err(e) => {
            error!("Tunnel creation failed. {}", e);
            -1
        },
    }
}


#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn vpn_loop(vpn_client_ptr: *mut c_void) -> c_int {
    if vpn_client_ptr.is_null() {
        error!("Client pointer is null");
        return -1;
    }
    let vpn_client = unsafe{ &mut *(vpn_client_ptr as *mut VPNClient)};

    match vpn_client.vpn_loop() {
        Ok(_) => return 1,
        Err(e) => {
            error!("VPN loop error: {}", e);
            return -1;
        },
    }
}


#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn vpn_disconnect(vpn_client_ptr: *mut c_void) {
    if vpn_client_ptr.is_null() {
        error!("Client pointer is null");
        return;
    }
    let vpn_client = unsafe { &mut *(vpn_client_ptr as *mut VPNClient) };
    if let Some(tx) = vpn_client.termination_signal_tx.take() {
        let _ = tx.send(());
    }
}

#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn vpn_cleanup(vpn_client_ptr: *mut c_void) {
    let client_box = unsafe { Box::from_raw(vpn_client_ptr as *mut VPNClient) };
    client_box.tokio_runtime.shutdown_background();
}

#[derive(Debug)]
pub struct TunnelConfig {
    pub ip: String,
    pub netmask: String,
    pub gateway: String,
    pub dns: String,
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_sucksonecvpn_VpnClient_vpnInit(
    mut env: JNIEnv,
    _class: JClass,
    server_pubkey_path: JString,
    server_addr: JString,
    server_port: JString,
    username: JString,
    password: JString,
) -> jlong {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Trace)
            .with_tag("SuckVPN"),
    );
    let server_pubkey_path: String = env.get_string(&server_pubkey_path)
        .unwrap().into();
    let server_addr: String = env.get_string(&server_addr)
        .unwrap().into();
    let server_port: String = env.get_string(&server_port)
        .unwrap().into();
    let username: String = env.get_string(&username)
        .unwrap().into();
    let password: String = env.get_string(&password)
        .unwrap().into();

    let runtime = tokio::runtime::Builder::
        new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    Box::into_raw(Box::new(VPNClient::new(server_pubkey_path, server_addr, server_port, username, password, runtime))) as jlong
}


#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_sucksonecvpn_VpnClient_vpnNegotiate(
    mut env: JNIEnv,
    _class: JClass,
    vpn_client_ptr: jlong,
    tunnel_settings_obj: JObject,
) -> jint {
    if vpn_client_ptr == 0 {
        return -1;
    }
    let vpn_client = unsafe{ &mut *(vpn_client_ptr as *mut VPNClient)};
    //let mut vpn_client = unsafe { Box::from_raw(vpn_client_ptr as *mut VPNClient) };

    let negot_result = vpn_client.negotiate();
    if let Err(e) = negot_result {
        error!("Negotiation error: {}", e);
        return -1;
    }


    // let tunnel_config_class = match env.find_class("com/example/sucksonecvpn/model/TunnelConfig") {
    //     Ok(class) => class,
    //     Err(e) => {
    //         error!("Failed to find tunnel settings java class: {}", e);
    //         return -1;
    //     }
    // };

    let ip_java_string = match env.new_string(&vpn_client.tunnel_settings.as_ref().unwrap().ip_string) {
        Ok(jstring) => jstring,
        Err(e) => {
            error!("Failed to create java string for ip address: {}", e);
            return -1;
        }
    };
    if let Err(e) = env.set_field(&tunnel_settings_obj, "ip", "Ljava/lang/String;", 
        jni::objects::JValueGen::Object(&ip_java_string)) 
    {
        error!("Failed to set ip field of tunnelConfig object: {}", e);
        return -1;
    }
    
    let netmask_java_string = match env.new_string(&vpn_client.tunnel_settings.as_ref().unwrap().netmask_string) {
        Ok(jstring) => jstring,
        Err(e) => {
            error!("Failed to create java string for netmask: {}", e);
            return -1;
        }
    };
    if let Err(e) = env.set_field(&tunnel_settings_obj, "netmask", "Ljava/lang/String;", 
        jni::objects::JValueGen::Object(&netmask_java_string)) 
    {
        error!("Failed to set netmask field of tunnelConfig object: {}", e);
        return -1;
    }
    

    // let tun_settings = TunnelSettingsPkt::decrypt(&tun_settings_encrypted, &cipher)?;
    // Ok((tun_settings, cipher))
    return 1;
}

#[cfg(target_os = "android")]
fn java_protect_socket(
    mut env: JNIEnv,
    vpn_service_object: JObject,
    socket_fd: i32
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    env.call_method(vpn_service_object, "protect", "(I)Z", &[JValue::Int(socket_fd)])?;
    Ok(())
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_sucksonecvpn_VpnClient_vpnCreateTun(
    env: JNIEnv,
    _class: JClass,
    vpn_client_ptr: jlong,
    vpn_service_object: JObject,
    tun_fd: jint,
) -> jint {
    if vpn_client_ptr == 0 {
        return -1;
    }
    let vpn_client = unsafe{ &mut *(vpn_client_ptr as *mut VPNClient)};
    //let mut vpn_client = unsafe { Box::from_raw(vpn_client_ptr as *mut VPNClient) };

    if let Err(e) = java_protect_socket(env, vpn_service_object, vpn_client.udp_socket.as_ref().unwrap().as_raw_fd()) {
        error!("Failed to protect socket {e}");
        return -1;  
    }

    match vpn_client.create_tun(tun_fd) {
        Ok(_) => 1,
        Err(e) => {
            error!("Failed to create tunnel: {}", e);
            return -1;         
        },
    }
}


#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_sucksonecvpn_VpnClient_vpnLoop(
    env: JNIEnv,
    _class: JClass,
    vpn_client_ptr: jlong,
) -> jint {
    if vpn_client_ptr == 0 {
        
        return -1;
    }
    let vpn_client = unsafe{ &mut *(vpn_client_ptr as *mut VPNClient)};

    match vpn_client.vpn_loop() {
        Ok(_) => return 1,
        Err(e) => {
            error!("VPN loop error: {}", e);
            return -1;
        },
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_sucksonecvpn_VpnClient_vpnDisconnect(
    env: JNIEnv,
    _class: JClass,
    vpn_client_ptr: jlong,
) {
    if vpn_client_ptr == 0 {
        return;
    }
    
    let vpn_client = unsafe { &mut *(vpn_client_ptr as *mut VPNClient) };
    if let Some(tx) = vpn_client.termination_signal_tx.take() {
        let _ = tx.send(());
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_sucksonecvpn_VpnClient_vpnCleanup(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
) {
    if client_ptr == 0 {
        return;
    }
    
    let _client = unsafe { Box::from_raw(client_ptr as *mut VPNClient) };
    _client.tokio_runtime.shutdown_background();
}