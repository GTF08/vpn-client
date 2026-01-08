
use std::net::Ipv4Addr;
use std::{sync::Arc};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use ed25519_dalek::Signature;

use rand::Rng;

use sha2::Digest;
use tokio::net::UdpSocket;
use tun_rs::{AsyncDevice};
use x25519_dalek::PublicKey;

use tokio_util::sync::CancellationToken;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use crate::desktop_routemanager::{RouteManager, DesktopRouteManager};


use crate::messages::{
    authdata::AuthPacket, 
    traits::{Decryptable, Encryptable}, 
    handshake::HandshakePacket,
    handshake_response::HandshakeResponsePacket,
    tunnel_settings::{TunnelSettingsPacketEncrypted}
};

use crate::tunnel::{create_tunnel};
use crate::{
    diffie_hellman::generate_keypair, 
    key_management::load_verifying_key,
    sock_ops::{sock_read, sock_write},
    bufferpool::BytesPool,
    tasks::{tun_read_task, sock_read_task}
};

const BUFFER_COUNT: usize = 64;
pub const BUFFER_SIZE: usize = 1500;

//const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(10);
struct TunnelSettings {
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr
}

pub struct VPNClient {
    pub server_pubkey_path: String,
    pub server_addr: Ipv4Addr,
    pub server_port: u16,
    pub username: String,
    pub password: String,
    pub tokio_runtime: tokio::runtime::Runtime,
    tunnel_settings: Option<TunnelSettings>,
    pub cipher: Option<ChaCha20Poly1305>,
    bufferpool: Arc<BytesPool>,
    pub dev: Option<AsyncDevice>,
    pub udp_socket: Option<UdpSocket>,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub route_manager: Option<DesktopRouteManager>,
    pub termination_signal_tx: Option<tokio::sync::oneshot::Sender<()>>
}


impl VPNClient {
    pub fn new(
        server_pubkey_path: String,
        server_addr: Ipv4Addr,
        server_port: u16,
        username: String,
        password: String,
        tokio_runtime: tokio::runtime::Runtime
    ) -> Self {
        VPNClient {
            server_pubkey_path: server_pubkey_path,
            server_addr: server_addr,
            server_port: server_port,
            username: username,
            password: password,
            tokio_runtime: tokio_runtime,
            tunnel_settings: None,
            cipher: None,
            bufferpool: Arc::new(BytesPool::new(BUFFER_COUNT, BUFFER_SIZE)),
            dev: None,
            udp_socket: None,
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            route_manager: None,
            termination_signal_tx: None
        }
    }

    
    fn handle_tunnel_settings_pkt(&mut self, enc_tun_set: TunnelSettingsPacketEncrypted) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tunnel_settings_decrypted =  match enc_tun_set.decrypt(&self.cipher.as_ref().unwrap()) {
            Ok(dec) => dec,
            Err(e) => {
                return Err(e.to_string().into());
            },
        };

        let ip_slice = tunnel_settings_decrypted.get_ip_bytes();
        let netmask_slice = tunnel_settings_decrypted.get_netmask_bytes();
        let gateway_slice = tunnel_settings_decrypted.get_gateway_bytes();
        self.tunnel_settings = Some(TunnelSettings {
            ip:         Ipv4Addr::new(ip_slice[0], ip_slice[1], ip_slice[2], ip_slice[3]),
            netmask:    Ipv4Addr::new(netmask_slice[0], netmask_slice[1], netmask_slice[2], netmask_slice[3]),
            gateway:    Ipv4Addr::new(gateway_slice[0], gateway_slice[1], gateway_slice[2], gateway_slice[3]),
            // ip: u32::from_be_bytes(buffer[PKT_TUNNEL_SETTINGS_IP_RANGE].try_into().unwrap()),
            // netmask: u32::from_be_bytes(buffer[PKT_TUNNEL_SETTINGS_NETMASK_RANGE].try_into().unwrap()),
            // gateway: u32::from_be_bytes(buffer[PKT_TUNNEL_SETTINGS_GATEWAY_RANGE].try_into().unwrap()), 
        });

        Ok(())
    }

    pub fn negotiate(&mut self) -> Result<(), Box<dyn std::error::Error + Send+ Sync>> {
        let server_pubkey = match load_verifying_key(&self.server_pubkey_path) {
            Ok(spk) => spk,
            Err(e) => {
                return Err(format!("Failed to load verifying key {e}").into());
            },
        };

        let _guard = self.tokio_runtime.enter();

        let udp_socket_result = self.tokio_runtime.block_on(
            async {
                UdpSocket::bind("0.0.0.0:0").await
            }
        );
        let udp_socket = match udp_socket_result {
            Ok(socket) => socket,
            Err(e) => {
                return Err(format!("Failed to create socket: {e}").into());
            },
        };

        let udp_socket_connect_result = self.tokio_runtime.block_on(
            async {
                log::info!("Connecting to {}:{}", self.server_addr, self.server_port);
                udp_socket.connect(format!("{}:{}", self.server_addr, self.server_port)).await
            }
        );
        if let Err(e) = udp_socket_connect_result {
            return Err(format!("Failed to connect socket: {e}").into());
        }

        //let mut buffer = vec![0u8; 1500];
        //let mut buffer = BytesMut::zeroed(2048);
        let buffer = self.bufferpool.acquire().unwrap();


        //1. send pubkey to server
        let (secret, public) = generate_keypair();

        let client_nonce: u128 = rand::thread_rng().r#gen();

        
        let handshake_buffer_pkt = HandshakePacket::new(
            buffer,
            public,
            client_nonce
        );
        log::info!("Writing handshake data...");

        let send_pubkey_result = self.tokio_runtime.block_on(
            async {
                tokio::time::timeout(tokio::time::Duration::from_secs(5), sock_write(&udp_socket, &handshake_buffer_pkt.data()))
                    .await
            }
        );

        
        match send_pubkey_result {
            Ok(Ok(_)) => {},
            Ok(Err(e)) => {
                return Err(format!("Failed to send pubkey to server. Error: {e}").into());
            },
            Err(e) => {
                return Err(format!("Timeout during sending pubkey to server. Error: {e}").into());
            }
        }

        //2. read server pubkey
        log::info!("Reading handshake response...");
        let mut buffer_handle = handshake_buffer_pkt.clear_release();
        
        
        let server_pubkey_recv_result = self.tokio_runtime.block_on(async {
            tokio::time::timeout(tokio::time::Duration::from_secs(5), 
            sock_read(&udp_socket, buffer_handle.data_mut()))
                .await
        });
        let handshake_response_pkt = HandshakeResponsePacket::from_recieved(buffer_handle);

        let read_count = match server_pubkey_recv_result {
            Ok(Ok(n)) => {
                n
            },
            Ok(Err(e)) => {
                return Err(format!("Failed to receive server pubkey: {e}").into());
            }
            Err(e) => {
                return Err(format!("Timeout during reading server pubkey: {e}").into());
            }
        };

        if !HandshakeResponsePacket::is_valid_buffer_size(read_count) {
            return Err(format!("invalid handshake response packet size: {}", read_count).into())
        }

        

        if !handshake_response_pkt.is_valid_type() {
            log::debug!("{:?}", handshake_response_pkt.data());
            return Err(format!("Recieved wrong packet from server, expected HandshakeResponsePacket").into());
        }
        
        let other_pubkey_bytes = handshake_response_pkt.get_key_bytes();
        let other_nonce_bytes = handshake_response_pkt.get_server_nonce().to_owned();
        let signature_bytes = handshake_response_pkt.get_signature_bytes();

        let signature = match Signature::from_slice(signature_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(format!("Failed to construct signature from data received from server. Error: {e}").into());
            },
        };

        if let Err(e) = server_pubkey.verify_strict(&other_pubkey_bytes, &signature) {
            return Err(format!("Server key signature verification failed. Possible MITM attack!. Error: {e}").into());
        }

        let sized_key_array: [u8; 32] = match other_pubkey_bytes.try_into() {
            Ok(good) => good,
            Err(_e) => {
                return Err(format!("Failed to construct server key byte array from data received").into());
            }
        };

        let other_pubkey = PublicKey::from(sized_key_array);

        let shared_key = secret.diffie_hellman(&other_pubkey);
        
        self.cipher = Some(ChaCha20Poly1305::new(shared_key.as_bytes().into()));

        //3. send authdata to server, encrypted
        log::info!("Writing auth data...");
        let buffer_handle = handshake_response_pkt.clear_release();
        let auth_pkt_handle = AuthPacket::new(
            buffer_handle,
            &self.username.as_bytes(),
            &sha2::Sha512::digest(self.password.clone()),
            &client_nonce.to_be_bytes(), 
            &other_nonce_bytes
        );
        

        log::info!("Encrypting auth data...");
        let enc_auth_pkt_handle = match auth_pkt_handle.encrypt(self.cipher.as_ref().unwrap()) {
            Ok(enc) => enc,
            Err(e) => {
                return Err(format!("Failed to encrypt auth data: {e}").into());
            },
        };

        let auth_data_send_result = self.tokio_runtime.block_on(
            async {
                tokio::time::timeout(tokio::time::Duration::from_secs(5),sock_write(&udp_socket, &enc_auth_pkt_handle.data()))
                    .await
            }
        );
        match auth_data_send_result {
            Ok(Ok(_)) => {},
            Ok(Err(e)) => {
                return Err(format!("Failed to send authdata to server: {e}").into());
            },
            Err(e) => {
                return Err(format!("Timeout during sending authdata to server: {e}").into());
            }
        }

        let buffer_handle = enc_auth_pkt_handle.clear_release();
        let mut tun_settings_encrypted = TunnelSettingsPacketEncrypted::new(buffer_handle);

        //4. read ip address from server
        log::info!("Reading tunnel settings...");
        let tun_settings_encrypted_pkt_read_result =
            self.tokio_runtime.block_on(async {
                tokio::time::timeout(tokio::time::Duration::from_secs(5),sock_read(&udp_socket, tun_settings_encrypted.data_mut()))
                    .await
            });
        
        let read_count =  match tun_settings_encrypted_pkt_read_result {
            Ok(Ok(pkt_size)) => pkt_size,
            Ok(Err(e)) => {
                return Err(format!("Failed to read tunnel setting from server: {e}").into());
            },
            Err(e) => {
                return Err(format!("Timeout during receiving tunnel settings from server: {e}").into());
            }
        };
        
        if !TunnelSettingsPacketEncrypted::is_valid_buffer_size(read_count) {
            return Err(format!("Invalid tunnel settings encrypted size: {}", read_count).into());
        }

        if !tun_settings_encrypted.is_valid_type() {
            return Err(format!("Invalid tunnel settings encrypted type").into());
        }

        self.handle_tunnel_settings_pkt(tun_settings_encrypted)?;


        self.udp_socket = Some(udp_socket);
        
        Ok(())
    }

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub fn create_tun(&mut self) -> Result<(), Box<dyn std::error::Error + Send+ Sync>> {
        let _guard = self.tokio_runtime.enter();

        let dev_create_result = self.tokio_runtime.block_on(async {
            create_tunnel(
            &self.tunnel_settings.as_ref().unwrap().ip, 
            &self.tunnel_settings.as_ref().unwrap().netmask, 
            &self.tunnel_settings.as_ref().unwrap().gateway
            ).await
        });
    
        let dev = match dev_create_result {
            Ok(dev) => dev,
            Err(e) => {
                return Err(format!("Failed to create tun device: {e}").into());
            },
        };

        let tun_index = match dev.if_index() {
            Ok(id) => id,
            Err(e) => {
                return Err(format!("Failed to get tun interface index: {e}").into());
            },
        };

        
        let route_guard = {
            let guard = DesktopRouteManager::new(
                tun_index, 
                self.server_addr,
                self.tunnel_settings.as_ref().unwrap().gateway.clone()
            );
            if let Err(e) = guard.add_default_route() {
                return Err(format!("Failed to add default route: {e}").into());
            }
            guard
        };

        self.route_manager = Some(route_guard);
        self.dev = Some(dev);
        

        Ok(())
    }

    #[cfg(target_os = "android")]
    pub fn create_tun(&mut self, tun_fd: i32) -> Result<(), Box<dyn std::error::Error + Send+ Sync>> {
        let _guard = self.tokio_runtime.enter();

        let dev_create_result = self.tokio_runtime.block_on(async {
            create_tunnel(
                tun_fd
            ).await
        });
    
        let dev = match dev_create_result {
            Ok(dev) => dev,
            Err(e) => {
                return Err(format!("Failed to create tun device: {e}").into());
            },
        };

        self.dev = Some(dev);
        
        Ok(())
    }

    // async fn start_encryption_task(&mut self) {
    //     tokio::task::spawn(async {})
    // }

    fn handle_task_result(
        &self,
        result: Result<Result<(), Box<dyn std::error::Error + Send + Sync>>, tokio::task::JoinError>,
        task_name: &str
    ) {
        match result {
            Ok(Ok(())) => {
                log::info!("{} finished", task_name);

            },
            Ok(Err(e)) => {
                log::error!("{} failed: {}", task_name, e);
            },
            Err(join_err) => if join_err.is_cancelled() {
                log::info!("{} was cancelled", task_name);
            }
            Err(join_err) => {
                log::error!("{} panicked: {}", task_name, join_err);
            }
        }
    }

    pub fn vpn_loop(&mut self) -> Result<(), Box<dyn std::error::Error + Send+ Sync>> {
        let cancel_token = CancellationToken::new();
        let (term_tx, mut term_rx) = tokio::sync::oneshot::channel::<()>();
        //let (task_shutdown_tx, task_shutdown_rx) = tokio::sync::broadcast::channel(1);

        self.termination_signal_tx = Some(term_tx);
        
        
        //let tun_buffer_size = MTU as usize + PACKET_INFORMATION_LENGTH;
        let dev = match self.dev.take() {
            Some(dev) => dev,
            None => {
                return Err("Tunnel is None. Cant enter VPN loop".into());
            }
        };

        let tun_dev_arc = Arc::new(dev);

        let _guard = self.tokio_runtime.enter();

        let buffer_pool_arc = &self.bufferpool;
        let cipher_arc = Arc::new(self.cipher.take().unwrap());
        let udp_socket_arc = Arc::new(self.udp_socket.take().unwrap());

        let shutdown_timeout = tokio::time::Duration::from_secs(5);
        
        self.tokio_runtime.block_on(
            async {
                let cancel_token1 = cancel_token.clone();
                let mut tun_read_handle = tokio::spawn(
                    tun_read_task(
                    buffer_pool_arc.clone(),
                    tun_dev_arc.clone(),
                    cipher_arc.clone(),
                    udp_socket_arc.clone(),
                    cancel_token1
                    )
                );
                let cancel_token2 = cancel_token.clone();
                let mut sock_read_handle = tokio::spawn(
                sock_read_task(buffer_pool_arc.clone(), 
                        tun_dev_arc, 
                        cipher_arc, 
                        udp_socket_arc, 
                        cancel_token2
                    )
                );
           
                tokio::select! {
                     _ = &mut term_rx => {
                        log::info!("Termination signal received");
                        cancel_token.cancel();
                    },
                    res = &mut tun_read_handle => {
                        self.handle_task_result(res, "tun_read_task");
                    },
                    res = &mut sock_read_handle => {
                        self.handle_task_result(res, "sock_read_task");
                    }
                }
                tokio::select! {
                    _ = async {
                        let _ = tokio::join!(&mut tun_read_handle, &mut sock_read_handle);
                        log::info!("All tasks completed");
                    } => {}
                    _ = tokio::time::sleep(shutdown_timeout) => {
                        log::warn!("Timeout waiting for tasks, aborting");
                        tun_read_handle.abort();
                        sock_read_handle.abort();
                    }
                }
        });
        
        Ok(())
    }
}