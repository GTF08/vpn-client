#[cfg(not(target_os = "android"))]
use std::os::raw::{c_char, c_int};
#[cfg(not(target_os = "android"))]
use std::ffi::CStr;

use ed25519_dalek::Signature;
use packet::ip;
use rand::rngs::OsRng;
use rand::Rng;
use sha2::Digest;

//use futures::io::{AsyncReadExt, AsyncWriteExt};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tun::{AbstractDevice, AsyncDevice};
use tokio::net::{UdpSocket};
use aes_gcm_siv::{
    aead::{AeadMut, KeyInit}, AeadCore, Aes256GcmSiv, Nonce // Or `Aes128Gcm`
};
use x25519_dalek::PublicKey;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use crate::desktop_routemanager::RouteManager;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use crate::desktop_routemanager::DesktopRouteManager;
use crate::key_management::load_verifying_key;
use crate::sock_ops::{sock_read, sock_write};
use crate::tunnel::create_tunnel;
#[cfg(target_os = "android")]
use jni::{JNIEnv, sys::{jint}, objects::{JObject, JString, JValue}};

use crate::messages::PacketType;
use crate::{diffie_hellman::generate_keypair, messages::{AuthData, TunnelSettingsPkt, CryptoSupported, DHKeyPacket, EncryptedMessage}};

mod messages;
mod diffie_hellman;
mod tunnel;
mod desktop_routemanager;
mod sock_ops;
mod key_management;

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
            eprintln!("Failed to create Tokio runtime: {}", e);
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
            eprintln!("Socket error: {e}");
            return -1;
        },
    };

    let udp_socket_connect_result = tokio_runtime.block_on(
        async {
            udp_socket.connect(format!("{server_addr}:{server_port}")).await
        }
    );
    if let Err(e) = udp_socket_connect_result {
        eprintln!("Socket connect error: {e}");
        return -1;
    }


    let negotioation_result = tokio_runtime.block_on(async {
        vpn_negotiation(&udp_socket, username, password).await
    });
    let (tunnel_settings, cipher) = match negotioation_result {
        Ok((tunnel_settings, cipher)) => (tunnel_settings, cipher),
        Err(e) => {
            eprintln!("Negotiation error: {e}");
            return -1;
        },
    };

    let tun_fd = match configure_android_vpn(env, vpn_builder, tunnel_settings) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("Failed to configure android VPN Service {e}");
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
            eprintln!("Tun device error: {e}");
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
            eprintln!("VPN error: {}", e);
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

#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn start_vpn(
    server_pubkey_path: *const c_char,
    server_addr: *const c_char,
    server_port: *const c_char,
    username: *const c_char,
    password: *const c_char,
) -> c_int {
    // Convert C strings to Rust strings
    let server_pubkey_path = unsafe { CStr::from_ptr(server_pubkey_path).to_string_lossy().into_owned() };
    let server_addr = unsafe { CStr::from_ptr(server_addr).to_string_lossy().into_owned() };
    let server_port = unsafe { CStr::from_ptr(server_port).to_string_lossy().into_owned() };
    let username = unsafe { CStr::from_ptr(username).to_string_lossy().into_owned() };
    let password = unsafe { CStr::from_ptr(password).to_string_lossy().into_owned() };
    
    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            eprintln!("Failed to create Tokio runtime: {}", e);
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
            eprintln!("Socket error: {e}");
            return -1;
        },
    };

    let udp_socket_connect_result = tokio_runtime.block_on(
        async {
            udp_socket.connect(format!("{server_addr}:{server_port}")).await
        }
    );
    if let Err(e) = udp_socket_connect_result {
        eprintln!("Socket connect error: {e}");
        return -1;
    }


    let negotioation_result = tokio_runtime.block_on(async {
        vpn_negotiation(server_pubkey_path, &udp_socket, username, password).await
    });
    let (tunnel_settings, cipher) = match negotioation_result {
        Ok((tunnel_settings, cipher)) => (tunnel_settings, cipher),
        Err(e) => {
            eprintln!("Negotiation error: {e}");
            return -1;
        },
    };
    println!("SUCCESSFUL NEGOTIATION");

    let dev_create_result = tokio_runtime.block_on(async {
         create_tunnel(
        &tunnel_settings.ip_string, 
        &tunnel_settings.netmask_string, 
        &tunnel_settings.gateway_string
        ).await
    });
   
    let dev = match dev_create_result {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("Tun device error: {e}");
            return -1;
        },
    };

    let tun_index = match dev.tun_index() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Failed to get tun device index: {e}");
            return -1;
        },
    };
    println!("CONNECTED");
    println!("CREATED TUN INTERFACE");

    
    #[cfg(not(target_os = "android"))]
    let _route_guard = {
        let guard = DesktopRouteManager::new(tun_index, tunnel_settings.gateway_string);
        if let Err(e) = guard.add_default_route() {
            eprintln!("Failed to add default route: {e}");
            return -1;
        }
        guard
    };
    
    let result = tokio_runtime.block_on(async {
        vpn_main_loop(dev, &udp_socket, cipher).await
    });
    
    // Run your VPN logic (will need to be adapted)
    match result {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("VPN error: {}", e);
            -1
        }
    }
}


async fn vpn_negotiation(
    server_pubkey_path: String,
    udp_socket: &UdpSocket,
    username: String,
    password: String,
) -> Result<(TunnelSettingsPkt, Aes256GcmSiv), Box<dyn std::error::Error + Send + Sync>>  {
        // Your existing logic, but using the provided TUN FD instead of creating one
    // ...
    //let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    //udp_socket.connect(format!("{server_addr}:{server_port}")).await?;

    //let transport = Framed::new(stream, LengthDelimitedCodec::new());
    //let (stream, response) = connect_async().await.unwrap();

    let server_pubkey = load_verifying_key(&server_pubkey_path)?;

    let mut udp_buffer = vec![0u8; 65536];
    //1. send pubkey to server
    let (secret, public) = generate_keypair();

    let client_nonce: u128 = rand::thread_rng().r#gen();
    let dh_key_pkt = PacketType::Handshake(
        DHKeyPacket {
            pub_key: public.to_bytes().to_vec(),
            nonce: client_nonce
        }
    );
    
    tokio::time::timeout(tokio::time::Duration::from_secs(5), sock_write(&udp_socket, dh_key_pkt))
        .await
        .map_err(|e| {
            eprintln!("Timeout during sending public key to server");
            e
        })??;
    


    //2. read server pubkey
    let other_pubkey_pkt: PacketType = 
        tokio::time::timeout(tokio::time::Duration::from_secs(5), sock_read(&udp_socket, &mut udp_buffer))
        .await
        .map_err(|e| {
            eprintln!("Timeout during reading public key from server");
            e
        })??;
    
    let other_pubkey_pkt = match other_pubkey_pkt {
        PacketType::HandshakeResponse(dhkey_response_packet) => {
            dhkey_response_packet
        },
        _ => return Err("Server sent wrong data to client: Expected Handshake packet".into())
    };

    server_pubkey.verify_strict(&other_pubkey_pkt.pub_key, &Signature::from_slice(&other_pubkey_pkt.signature)?)?;

    let sized_key_array: [u8; 32] = other_pubkey_pkt.pub_key.try_into().unwrap();
    let other_pubkey = PublicKey::from(sized_key_array);

    let shared_key = secret.diffie_hellman(&other_pubkey);
    let cipher = Aes256GcmSiv::new(shared_key.as_bytes().into());

    //3. send authdata to server, encrypted
    let auth_data = AuthData {
        username: username,
        password: hex::encode(sha2::Sha512::digest(password)),
        client_nonce: client_nonce,
        server_nonce: other_pubkey_pkt.nonce
    };
    let encrypted_authdata = auth_data.encrypt(&cipher)?;
    let auth_pkt = PacketType::AuthPacket(encrypted_authdata);
    
    tokio::time::timeout(tokio::time::Duration::from_secs(5),sock_write(&udp_socket, auth_pkt))
        .await
        .map_err(|e| {
            eprintln!("Timeout during sending auth data to server");
            e
        })??;

    //4. read ip address from server
    let tun_settings_encrypted_pkt: PacketType = 
        tokio::time::timeout(tokio::time::Duration::from_secs(5),sock_read(&udp_socket, &mut udp_buffer))
        .await
        .map_err(|e| {
            eprintln!("Timeout during reading tunnel settings from server");
            e
        })?
        .map_err(|e| {
            eprintln!("Failed to login to server");
            e
        })?;
    let tun_settings_encrypted = match tun_settings_encrypted_pkt {
        PacketType::TunnelSettings(encrypted_message) => {
            encrypted_message
        },
        _ => {
            eprintln!("Server sent wrong data to client: Expected Tunnel Settings packet");
            return Err("Server sent wrong data to client: Expected Tunnel Settings packet".into());
        }
    } ;
    let tun_settings = TunnelSettingsPkt::decrypt(&tun_settings_encrypted, &cipher)?;
    Ok((tun_settings, cipher))
}


async fn vpn_main_loop(
    dev: AsyncDevice,
    udp_socket: &UdpSocket,
    mut cipher: Aes256GcmSiv,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tun_buffer_size = dev.mtu()? as usize + tun::PACKET_INFORMATION_LENGTH;
    
    let (mut tun_writer, mut tun_reader) = dev.split()?;

    let mut udp_buffer = vec![0u8; 65536];
    let mut tun_buf = vec![0u8; tun_buffer_size];
    loop {
        tokio::select! {
            encrypted_read_result = sock_read(&udp_socket, &mut udp_buffer) => {
                match encrypted_read_result {
                    Ok(pkt_type) => {
                        match pkt_type {
                            PacketType::EncryptedPkt(encrypted_message) => {
                                let decrypted =  match cipher.decrypt(&Nonce::from_slice(&encrypted_message.nonce), &encrypted_message.ciphertext[..]) {
                                    Ok(dec) => dec,
                                    Err(e) => {
                                        eprintln!("{}", e);
                                        continue;
                                    },
                                };
                                match ip::Packet::new(&decrypted) {
                                    Ok(_pkt) => {
                                        tun_writer.write_all(&decrypted).await?;
                                    }
                                    Err(e) => {
                                        return Err(Box::new(e));
                                    }
                                }
                            },
                            _ => {
                                eprintln!("Server sent wrong data to client: Expected EncryptedPkt packet");
                                continue
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("{e}");
                        return Err(e);
                    }
                }
            },
            device_read_result = tun_reader.read(&mut tun_buf) => {
                match device_read_result {
                    Ok(n) => {
                        if n == 0 {
                            break Ok(()); // EOF
                        }
                        let bytes = &tun_buf[..n];
                        let nonce = Aes256GcmSiv::generate_nonce(&mut OsRng);
                        let ciphertext = cipher.encrypt(&nonce, bytes)
                            .map_err(|e| format!("{e}"))?;
                        let encrypted_msg = EncryptedMessage {
                            ciphertext,
                            nonce: nonce.to_vec(),
                        };
                        let enc_pkt = PacketType::EncryptedPkt(
                            encrypted_msg
                        );
                        sock_write(&udp_socket, enc_pkt).await?;
                    },
                    Err(e) => {
                        return Err(Box::new(e));
                    }
                }
            }
            
        }
    }
}