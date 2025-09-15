#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use std::ffi::{c_char, c_int, c_void, CStr};

#[cfg(target_os = "android")]
use jni::{JNIEnv, sys::{jint}, objects::{JObject, JString, JValue}};

use ed25519_dalek::Signature;
use packet::ip;
use rand::rngs::OsRng;
use rand::Rng;
use sha2::Digest;


use tokio::net::{UdpSocket};
use aes_gcm_siv::{
    aead::{AeadMut, KeyInit}, AeadCore, Aes256GcmSiv, Nonce // Or `Aes128Gcm`
};
use tun_rs::{AsyncDevice, PACKET_INFORMATION_LENGTH};
use x25519_dalek::PublicKey;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use crate::desktop_routemanager::RouteManager;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use crate::desktop_routemanager::DesktopRouteManager;
use crate::key_management::load_verifying_key;
use crate::sock_ops::{sock_read, sock_write};
use crate::tunnel::create_tunnel;


use crate::messages::PacketType;
use crate::{diffie_hellman::generate_keypair, messages::{AuthData, TunnelSettingsPkt, CryptoSupported, DHKeyPacket, EncryptedMessage}};

mod messages;
mod diffie_hellman;
mod tunnel;
mod desktop_routemanager;
mod sock_ops;
mod key_management;

const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(10);


pub struct VPNClient {
    pub server_pubkey_path: String,
    pub server_addr: String,
    pub server_port: String,
    pub username: String,
    pub password: String,
    pub tokio_runtime: tokio::runtime::Runtime,
    pub tunnel_settings: Option<TunnelSettingsPkt>,
    pub cipher: Option<Aes256GcmSiv>,
    pub dev: Option<AsyncDevice>,
    pub udp_socket: Option<UdpSocket>,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub route_manager: Option<DesktopRouteManager>,
    pub termination_signal_tx: Option<tokio::sync::oneshot::Sender<()>>
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

    let server_pubkey_path = unsafe { CStr::from_ptr(server_pubkey_path).to_string_lossy().into_owned() };
    let server_addr = unsafe { CStr::from_ptr(server_addr).to_string_lossy().into_owned() };
    let server_port = unsafe { CStr::from_ptr(server_port).to_string_lossy().into_owned() };
    let username = unsafe { CStr::from_ptr(username).to_string_lossy().into_owned() };
    let password = unsafe { CStr::from_ptr(password).to_string_lossy().into_owned() };

    let runtime = tokio::runtime::Builder::
        new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let vpn_client_box = Box::new(
        VPNClient {
            server_pubkey_path: server_pubkey_path,
            server_addr: server_addr,
            server_port: server_port,
            username: username,
            password: password,
            tokio_runtime: runtime,
            tunnel_settings: None,
            cipher: None,
            dev: None,
            udp_socket: None,
            route_manager: None,
            termination_signal_tx: None
        }
    );

    Box::into_raw(vpn_client_box) as *mut c_void
}



#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn vpn_negotiate(vpn_client_ptr: *mut c_void) -> c_int {
    if vpn_client_ptr.is_null() {
        return -1;
    }
    let vpn_client = unsafe{ &mut *(vpn_client_ptr as *mut VPNClient)};
    //let mut vpn_client = unsafe { Box::from_raw(vpn_client_ptr as *mut VPNClient) };

    let server_pubkey = match load_verifying_key(&vpn_client.server_pubkey_path) {
        Ok(spk) => spk,
        Err(e) => {
            return -1;
        },
    };

    let _guard = vpn_client.tokio_runtime.enter();

    let udp_socket_result = vpn_client.tokio_runtime.block_on(
        async {
            UdpSocket::bind("0.0.0.0:0").await
        }
    );
    let udp_socket = match udp_socket_result {
        Ok(socket) => socket,
        Err(e) => {
            return -1;
        },
    };

    let udp_socket_connect_result = vpn_client.tokio_runtime.block_on(
        async {
            udp_socket.connect(format!("{}:{}", vpn_client.server_addr, vpn_client.server_port)).await
        }
    );
    if let Err(e) = udp_socket_connect_result {
        return -1;
    }

    let mut udp_buffer = vec![0u8; 1500];
    //1. send pubkey to server
    let (secret, public) = generate_keypair();

    let client_nonce: u128 = rand::thread_rng().r#gen();
    let dh_key_pkt = PacketType::Handshake(
        DHKeyPacket {
            pub_key: public.to_bytes().to_vec(),
            nonce: client_nonce
        }
    );
    
    let send_pubkey_result = vpn_client.tokio_runtime.block_on(
        async {
            tokio::time::timeout(tokio::time::Duration::from_secs(5), sock_write(&udp_socket, dh_key_pkt))
                .await
        }
    );
    
    match send_pubkey_result {
        Ok(Ok(_)) => {},
        Ok(Err(e)) => {
            return -1;
        },
        Err(e) => {
            return -1;
        }
    }

    //2. read server pubkey
    let server_pubkey_recv_result = vpn_client.tokio_runtime.block_on(async {
        tokio::time::timeout(tokio::time::Duration::from_secs(5), sock_read(&udp_socket, &mut udp_buffer))
            .await
    });
    
    let other_pubkey_pkt: PacketType = match server_pubkey_recv_result {
        Ok(Ok(pkt)) => pkt,
        Ok(Err(e)) => {
            return -1;
        }
        Err(e) => {
            return -1;
        },
    };
    
    let other_pubkey_pkt = match other_pubkey_pkt {
        PacketType::HandshakeResponse(dhkey_response_packet) => {
            dhkey_response_packet
        },
        _ => {
            return -1;
        }
    };

    let signature = match Signature::from_slice(&other_pubkey_pkt.signature) {
        Ok(s) => s,
        Err(e) => {
            return -1;
        },
    };

    if let Err(e) = server_pubkey.verify_strict(&other_pubkey_pkt.pub_key, &signature) {
        
        return -1;
    }

    let sized_key_array: [u8; 32] = match other_pubkey_pkt.pub_key.try_into() {
        Ok(good) => good,
        Err(_e) => {
            
            return -1;
        }
    };
    let other_pubkey = PublicKey::from(sized_key_array);

    let shared_key = secret.diffie_hellman(&other_pubkey);
    let cipher = Aes256GcmSiv::new(shared_key.as_bytes().into());

    //3. send authdata to server, encrypted
    let auth_data = AuthData {
        username: vpn_client.username.clone(),
        password: hex::encode(sha2::Sha512::digest(vpn_client.password.clone())),
        client_nonce: client_nonce,
        server_nonce: other_pubkey_pkt.nonce
    };
    let encrypted_authdata = match auth_data.encrypt(&cipher) {
        Ok(encrypted) => encrypted,
        Err(e) => {
            
            return -1
        }
    };
    let auth_pkt = PacketType::AuthPacket(encrypted_authdata);
    
    let auth_data_send_result = vpn_client.tokio_runtime.block_on(
        async {
            tokio::time::timeout(tokio::time::Duration::from_secs(5),sock_write(&udp_socket, auth_pkt))
                .await
        }
    );
    match auth_data_send_result {
        Ok(Ok(_)) => {},
        Ok(Err(e)) => {
            
            return -1;
        },
        Err(e) => {
            
            return -1;
        }
    }

    //4. read ip address from server
    let tun_settings_encrypted_pkt_read_result =
        vpn_client.tokio_runtime.block_on(async {
            tokio::time::timeout(tokio::time::Duration::from_secs(5),sock_read(&udp_socket, &mut udp_buffer))
                .await
        });

    let tun_settings_encrypted_pkt: PacketType = match tun_settings_encrypted_pkt_read_result {
        Ok(Ok(pkt)) => pkt,
        Ok(Err(e)) => {
            
            return -1;
        },
        Err(e) => {
            
            return -1;
        }
    };

    let tun_settings_encrypted = match tun_settings_encrypted_pkt {
        PacketType::TunnelSettings(encrypted_message) => {
            encrypted_message
        },
        _ => {
            
            return -1;
        }
    } ;
    let tun_settings = match TunnelSettingsPkt::decrypt(&tun_settings_encrypted, &cipher) {
        Ok(decrypted) => decrypted,
        Err(e) => {
            
            return -1;
        }
    };
    vpn_client.tunnel_settings = Some(tun_settings);
    vpn_client.cipher = Some(cipher);
    vpn_client.udp_socket = Some(udp_socket);
    // let tun_settings = TunnelSettingsPkt::decrypt(&tun_settings_encrypted, &cipher)?;
    // Ok((tun_settings, cipher))
    return 1;
}


#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn vpn_create_tun(vpn_client_ptr: *mut c_void) -> c_int {
    if vpn_client_ptr.is_null() {
        
        return -1;
    }
    let vpn_client = unsafe{ &mut *(vpn_client_ptr as *mut VPNClient)};
    //let mut vpn_client = unsafe { Box::from_raw(vpn_client_ptr as *mut VPNClient) };

    let _guard = vpn_client.tokio_runtime.enter();

    let dev_create_result = vpn_client.tokio_runtime.block_on(async {
         create_tunnel(
        &vpn_client.tunnel_settings.as_ref().unwrap().ip_string, 
        &vpn_client.tunnel_settings.as_ref().unwrap().netmask_string, 
        &vpn_client.tunnel_settings.as_ref().unwrap().gateway_string
        ).await
    });
   
    let dev = match dev_create_result {
        Ok(dev) => dev,
        Err(e) => {
            
            return -1;
        },
    };

    let tun_index = match dev.if_index() {
        Ok(id) => id,
        Err(e) => {
            
            return -1;
        },
    };

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    let route_guard = {
        let guard = DesktopRouteManager::new(
            tun_index, 
            vpn_client.server_addr.clone(),
            vpn_client.tunnel_settings.as_ref().unwrap().gateway_string.clone()
        );
        if let Err(e) = guard.add_default_route() {
            
            return -1;
        }
        guard
    };

    vpn_client.dev = Some(dev);
    vpn_client.route_manager = Some(route_guard);

    return 1;
}


#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn vpn_loop(vpn_client_ptr: *mut c_void) -> c_int {
    use std::{sync::Arc};

    if vpn_client_ptr.is_null() {
        
        return -1;
    }
    let vpn_client = unsafe{ &mut *(vpn_client_ptr as *mut VPNClient)};

    let (term_tx, mut term_rx) = tokio::sync::oneshot::channel::<()>();
    vpn_client.termination_signal_tx = Some(term_tx);
    //vpn_client.termination_signal_tx = Some(term_tx);
    //let mut vpn_client = unsafe { Box::from_raw(vpn_client_ptr as *mut VPNClient) };
    let tun_buffer_size = vpn_client.dev.as_ref().unwrap().mtu().unwrap() as usize + PACKET_INFORMATION_LENGTH;
    let dev = match vpn_client.dev.take() {
        Some(dev) => dev,
        None => {
            return -1;
        }
    };

    let (tun_writer, tun_reader) = (Arc::new(&dev), Arc::new(&dev));
    //let (mut tun_writer, mut tun_reader) = dev.unwrap().split().unwrap();

    let mut udp_buffer = vec![0u8; 1500];
    let mut tun_buf = vec![0u8; tun_buffer_size];

    let mut lastseen = tokio::time::Instant::now();

    let _guard = vpn_client.tokio_runtime.enter();
    
    let loop_result = vpn_client.tokio_runtime.block_on(
        async {
            while tokio::time::Instant::now() - lastseen < CONNECTION_TIMEOUT {
                tokio::select! {
                    encrypted_read_result = sock_read(&vpn_client.udp_socket.as_ref().unwrap(), &mut udp_buffer) => {
                        lastseen = tokio::time::Instant::now();
                        match encrypted_read_result {
                            Ok(pkt_type) => {
                                match pkt_type {
                                    PacketType::EncryptedPkt(encrypted_message) => {
                                        let decrypted =  match vpn_client.cipher.as_mut().unwrap().decrypt(&Nonce::from_slice(&encrypted_message.nonce), &encrypted_message.ciphertext[..]) {
                                            Ok(dec) => dec,
                                            Err(e) => {
                                                
                                                continue;
                                            },
                                        };
                                        match ip::Packet::new(&decrypted) {
                                            Ok(_pkt) => {
                                                tun_writer.send(&decrypted).await?;
                                            }
                                            Err(e) => {
                                                //return Err::<(), Box<dyn std::error::Error + Sync + Send>>(Box::new(e));
                                            }
                                        }
                                    },
                                    _ => {
                                        
                                        continue
                                    }
                                }
                            },
                            Err(e) => {
                                eprintln!("SOCK ERROR {e}");
                            }
                        }
                    },
                    device_read_result = tun_reader.recv(&mut tun_buf) => {
                        match device_read_result {
                            Ok(n) => {
                                if n == 0 {
                                    return Err::<(), Box<dyn std::error::Error + Send + Sync>>("Tun interface closed".into()); // EOF
                                }
                                let bytes = &tun_buf[..n];
                                let nonce = Aes256GcmSiv::generate_nonce(&mut OsRng);
                                let ciphertext = vpn_client.cipher.as_mut().unwrap().encrypt(&nonce, bytes)
                                    .map_err(|e| format!("{e}"))?;
                                let encrypted_msg = EncryptedMessage {
                                    ciphertext,
                                    nonce: nonce.to_vec(),
                                };
                                let enc_pkt = PacketType::EncryptedPkt(
                                    encrypted_msg
                                );
                                sock_write(&vpn_client.udp_socket.as_mut().unwrap(), enc_pkt).await?;
                            },
                            Err(e) => {
                                eprintln!("TUN READ ERROR {e}");
                                return Err(Box::new(e));
                            }
                        }
                    },
                    _ = &mut term_rx => {
                        return Ok(());
                    }
                    
                }
            }
            eprintln!("Connection timed out");
            return Err("Connection timed out".into());
        }
    );
    if let Err(e) = loop_result {
        
        return -1;
    }
    return 1;
}


#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn vpn_disconnect(vpn_client_ptr: *mut c_void) {
    if vpn_client_ptr.is_null() {
        
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


#[cfg(target_os = "android")]
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_VpnClient_VpnService_startVpn<'local>(
    mut env: &mut JNIEnv<'local>,
    _: JObject,
    vpn_builder: &mut JObject<'local>,
    server_addr: JString<'local>,
    server_port: JString<'local>,
    username: JString<'local>,
    password: JString<'local>
) -> jint {
    let server_addr: String = env.get_string(&server_addr).unwrap().into();
    let server_port: String = env.get_string(&server_port).unwrap().into();
    let username: String = env.get_string(&username).unwrap().into();
    let password: String = env.get_string(&password).unwrap().into();

    let tokio_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            
            -1
        })
        .unwrap();

     let udp_socket_result = tokio_runtime.block_on(
        async {
            UdpSocket::bind("0.0.0.0:0").await
        }
    );
    let udp_socket = match udp_socket_result {
        Ok(socket) => socket,
        Err(e) => {
            
            return -1;
        },
    };

    let udp_socket_connect_result = tokio_runtime.block_on(
        async {
            udp_socket.connect(format!("{server_addr}:{server_port}")).await
        }
    );
    if let Err(e) = udp_socket_connect_result {
        
        return -1;
    }


    let negotioation_result = tokio_runtime.block_on(async {
        vpn_negotiation(&udp_socket, username, password).await
    });
    let (tunnel_settings, cipher) = match negotioation_result {
        Ok((tunnel_settings, cipher)) => (tunnel_settings, cipher),
        Err(e) => {
            
            return -1;
        },
    };

    let tun_fd = match configure_android_vpn(env, vpn_builder, tunnel_settings) {
        Ok(fd) => fd,
        Err(e) => {
            
            return -1;
        },
    };

    let dev_create_result = tokio_runtime.block_on(async {
         create_tunnel(
            tun_fd
        ).await
    });

    let dev = match dev_create_result {
        Ok(dev) => dev,
        Err(e) => {
            
            return -1;
        },
    };

    let result = tokio_runtime.block_on(async {
        vpn_main_loop(dev, &udp_socket, cipher).await
    });
    
    // Run your VPN logic (will need to be adapted)
    match result {
        Ok(_) => 0,
        Err(e) => {
            
            -1
        }
    }

}

#[cfg(target_os = "android")]
fn configure_android_vpn<'local>(
    env: &mut JNIEnv<'local>,
    vpn_builder: &mut JObject<'local>,
    tunnel_settings: TunnelSettingsPkt
) -> Result<jint, Box<dyn std::error::Error + Send + Sync>> {
    let builder_class = env.find_class("android/net/VpnService$Builder").unwrap();
    
    let java_ip = env.new_string(tunnel_settings.ip_string)?;
    env.call_method(
        &vpn_builder, 
        "addAddress", 
        "(Ljava/lang/String;I)Landroid/net/VpnService$Builder;",
    &[
        JValue::from(&JObject::from(java_ip)),
        JValue::from(tunnel_settings.netmask_string.parse::<i32>()?),
    ])
    ?;
    
    let gateway_str = env.new_string(tunnel_settings.gateway_string)?;
    //let add_route = env.get_method_id(builder_class, "addRoute", "(Ljava/lang/String;I)Landroid/net/VpnService$Builder;").unwrap();
    env.call_method(
        &vpn_builder,
        "addRoute",
             "(Ljava/lang/String;I)Landroid/net/VpnService$Builder;",
        &[
            JValue::from(&JObject::from(gateway_str)),
            JValue::from(0), // Default route
        ],
    )?; 

    let dns_str = env.new_string("8.8.8.8")?;
    env.call_method(
        &vpn_builder,
        "addDnsServer",
        "(Ljava/lang/String;)Landroid/net/VpnService$Builder;",
        &[JValue::from(&JObject::from(dns_str))],
    )?;


    let pfd = env.call_method(
        &vpn_builder,
        "establish",
        "()Landroid/os/ParcelFileDescriptor;",
        &[],
    )?.l()?;

    let pfd_class = env.find_class("android/os/ParcelFileDescriptor")?;
    let tun_fd = env.call_method(
        pfd,
        "getFd",
        "()I",
        &[],
    )?.i()?;
    
    Ok(tun_fd)
}

// #[cfg(not(target_os = "android"))]
// #[unsafe(no_mangle)]
// pub extern "C" fn start_vpn(
//     server_pubkey_path: *const c_char,
//     server_addr: *const c_char,
//     server_port: *const c_char,
//     username: *const c_char,
//     password: *const c_char,
// ) -> c_int {
//     // Convert C strings to Rust strings
//     let server_pubkey_path = unsafe { CStr::from_ptr(server_pubkey_path).to_string_lossy().into_owned() };
//     let server_addr = unsafe { CStr::from_ptr(server_addr).to_string_lossy().into_owned() };
//     let server_port = unsafe { CStr::from_ptr(server_port).to_string_lossy().into_owned() };
//     let username = unsafe { CStr::from_ptr(username).to_string_lossy().into_owned() };
//     let password = unsafe { CStr::from_ptr(password).to_string_lossy().into_owned() };
    
//     let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
//         .enable_all()
//         .build()
//         .map_err(|e| {
            
//             -1
//         })
//         .unwrap();
    
//     let udp_socket_result = tokio_runtime.block_on(
//         async {
//             UdpSocket::bind("0.0.0.0:0").await
//         }
//     );
//     let udp_socket = match udp_socket_result {
//         Ok(socket) => socket,
//         Err(e) => {
            
//             return -1;
//         },
//     };

//     let udp_socket_connect_result = tokio_runtime.block_on(
//         async {
//             udp_socket.connect(format!("{server_addr}:{server_port}")).await
//         }
//     );
//     if let Err(e) = udp_socket_connect_result {
        
//         return -1;
//     }


//     let negotioation_result = tokio_runtime.block_on(async {
//         vpn_negotiation(server_pubkey_path, &udp_socket, username, password).await
//     });
//     let (tunnel_settings, cipher) = match negotioation_result {
//         Ok((tunnel_settings, cipher)) => (tunnel_settings, cipher),
//         Err(e) => {
            
//             return -1;
//         },
//     };
//     println!("SUCCESSFUL NEGOTIATION");

//     let dev_create_result = tokio_runtime.block_on(async {
//          create_tunnel(
//         &tunnel_settings.ip_string, 
//         &tunnel_settings.netmask_string, 
//         &tunnel_settings.gateway_string
//         ).await
//     });
   
//     let dev = match dev_create_result {
//         Ok(dev) => dev,
//         Err(e) => {
            
//             return -1;
//         },
//     };

//     let tun_index = match dev.tun_index() {
//         Ok(id) => id,
//         Err(e) => {
            
//             return -1;
//         },
//     };
//     println!("CONNECTED");
//     println!("CREATED TUN INTERFACE");

    
//     #[cfg(not(target_os = "android"))]
//     let _route_guard = {
//         let guard = DesktopRouteManager::new(
//             tun_index, 
//             server_addr,
//             tunnel_settings.gateway_string
//         );
//         if let Err(e) = guard.add_default_route() {
            
//             return -1;
//         }
//         guard
//     };
    
//     let result = tokio_runtime.block_on(async {
//         vpn_main_loop(dev, &udp_socket, cipher).await
//     });
    
//     // Run your VPN logic (will need to be adapted)
//     match result {
//         Ok(_) => 0,
//         Err(e) => {
            
//             -1
//         }
//     }
// }


// async fn vpn_negotiation(
//     server_pubkey_path: String,
//     udp_socket: &UdpSocket,
//     username: String,
//     password: String,
// ) -> Result<(TunnelSettingsPkt, Aes256GcmSiv), Box<dyn std::error::Error + Send + Sync>>  {
//         // Your existing logic, but using the provided TUN FD instead of creating one
//     // ...
//     //let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
//     //udp_socket.connect(format!("{server_addr}:{server_port}")).await?;

//     //let transport = Framed::new(stream, LengthDelimitedCodec::new());
//     //let (stream, response) = connect_async().await.unwrap();

//     let server_pubkey = load_verifying_key(&server_pubkey_path)?;

//     let mut udp_buffer = vec![0u8; 1500];
//     //1. send pubkey to server
//     let (secret, public) = generate_keypair();

//     let client_nonce: u128 = rand::thread_rng().r#gen();
//     let dh_key_pkt = PacketType::Handshake(
//         DHKeyPacket {
//             pub_key: public.to_bytes().to_vec(),
//             nonce: client_nonce
//         }
//     );
    
//     tokio::time::timeout(tokio::time::Duration::from_secs(5), sock_write(&udp_socket, dh_key_pkt))
//         .await
//         .map_err(|e| {
            
//             e
//         })??;
    


//     //2. read server pubkey
//     let other_pubkey_pkt: PacketType = 
//         tokio::time::timeout(tokio::time::Duration::from_secs(5), sock_read(&udp_socket, &mut udp_buffer))
//         .await
//         .map_err(|e| {
            
//             e
//         })??;
    
//     let other_pubkey_pkt = match other_pubkey_pkt {
//         PacketType::HandshakeResponse(dhkey_response_packet) => {
//             dhkey_response_packet
//         },
//         _ => return Err("Server sent wrong data to client: Expected Handshake packet".into())
//     };

//     server_pubkey.verify_strict(&other_pubkey_pkt.pub_key, &Signature::from_slice(&other_pubkey_pkt.signature)?)?;

//     let sized_key_array: [u8; 32] = other_pubkey_pkt.pub_key.try_into().unwrap();
//     let other_pubkey = PublicKey::from(sized_key_array);

//     let shared_key = secret.diffie_hellman(&other_pubkey);
//     let cipher = Aes256GcmSiv::new(shared_key.as_bytes().into());

//     //3. send authdata to server, encrypted
//     let auth_data = AuthData {
//         username: username,
//         password: hex::encode(sha2::Sha512::digest(password)),
//         client_nonce: client_nonce,
//         server_nonce: other_pubkey_pkt.nonce
//     };
//     let encrypted_authdata = auth_data.encrypt(&cipher)?;
//     let auth_pkt = PacketType::AuthPacket(encrypted_authdata);
    
//     tokio::time::timeout(tokio::time::Duration::from_secs(5),sock_write(&udp_socket, auth_pkt))
//         .await
//         .map_err(|e| {
            
//             e
//         })??;

//     //4. read ip address from server
//     let tun_settings_encrypted_pkt: PacketType = 
//         tokio::time::timeout(tokio::time::Duration::from_secs(5),sock_read(&udp_socket, &mut udp_buffer))
//         .await
//         .map_err(|e| {
            
//             e
//         })?
//         .map_err(|e| {
            
//             e
//         })?;
//     let tun_settings_encrypted = match tun_settings_encrypted_pkt {
//         PacketType::TunnelSettings(encrypted_message) => {
//             encrypted_message
//         },
//         _ => {
            
//             return Err("Server sent wrong data to client: Expected Tunnel Settings packet".into());
//         }
//     } ;
//     let tun_settings = TunnelSettingsPkt::decrypt(&tun_settings_encrypted, &cipher)?;
//     Ok((tun_settings, cipher))
// }


// async fn vpn_main_loop(
//     dev: AsyncDevice,
//     udp_socket: &UdpSocket,
//     mut cipher: Aes256GcmSiv,
// ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//     let tun_buffer_size = dev.mtu()? as usize + tun::PACKET_INFORMATION_LENGTH;
    
//     let (mut tun_writer, mut tun_reader) = dev.split()?;


//     let mut udp_buffer = vec![0u8; 1500];
//     let mut tun_buf = vec![0u8; tun_buffer_size];

//     let mut lastseen = tokio::time::Instant::now();
//     while tokio::time::Instant::now() - lastseen < CONNECTION_TIMEOUT {
//         tokio::select! {
//             encrypted_read_result = sock_read(&udp_socket, &mut udp_buffer) => {
//                 lastseen = tokio::time::Instant::now();
//                 match encrypted_read_result {
//                     Ok(pkt_type) => {
//                         match pkt_type {
//                             PacketType::EncryptedPkt(encrypted_message) => {
//                                 let decrypted =  match cipher.decrypt(&Nonce::from_slice(&encrypted_message.nonce), &encrypted_message.ciphertext[..]) {
//                                     Ok(dec) => dec,
//                                     Err(e) => {
                                        
//                                         continue;
//                                     },
//                                 };
//                                 match ip::Packet::new(&decrypted) {
//                                     Ok(_pkt) => {
//                                         tun_writer.write_all(&decrypted).await?;
//                                     }
//                                     Err(e) => {
//                                         return Err(Box::new(e));
//                                     }
//                                 }
//                             },
//                             _ => {
                                
//                                 continue
//                             }
//                         }
//                     },
//                     Err(e) => {
                        
//                         return Err(e);
//                     }
//                 }
//             },
//             device_read_result = tun_reader.read(&mut tun_buf) => {
//                 match device_read_result {
//                     Ok(n) => {
//                         if n == 0 {
//                             return Err("Tun interface closed".into()); // EOF
//                         }
//                         let bytes = &tun_buf[..n];
//                         let nonce = Aes256GcmSiv::generate_nonce(&mut OsRng);
//                         let ciphertext = cipher.encrypt(&nonce, bytes)
//                             .map_err(|e| format!("{e}"))?;
//                         let encrypted_msg = EncryptedMessage {
//                             ciphertext,
//                             nonce: nonce.to_vec(),
//                         };
//                         let enc_pkt = PacketType::EncryptedPkt(
//                             encrypted_msg
//                         );
//                         sock_write(&udp_socket, enc_pkt).await?;
//                     },
//                     Err(e) => {
//                         return Err(Box::new(e));
//                     }
//                 }
//             }
            
//         }
//     };
//     return Err("Connection timed out".into());
// }