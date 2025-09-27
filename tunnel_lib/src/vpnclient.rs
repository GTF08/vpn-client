use std::{sync::Arc};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use ed25519_dalek::Signature;
use log::error;
use packet::ip;
use rand::rngs::OsRng;
use rand::Rng;
use sha2::Digest;
use tokio::net::UdpSocket;
use tun_rs::{AsyncDevice, PACKET_INFORMATION_LENGTH};
use x25519_dalek::PublicKey;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use crate::desktop_routemanager::{RouteManager, DesktopRouteManager};

use crate::tunnel::{create_tunnel, MTU};
use crate::{
    diffie_hellman::generate_keypair, 
    key_management::load_verifying_key, 
    messages::{AuthData, CryptoSupported, DHKeyPacket, PacketType, TunnelSettingsPkt, EncryptedMessage}, 
    sock_ops::{sock_read, sock_write}
};

//const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(10);

pub struct VPNClient {
    pub server_pubkey_path: String,
    pub server_addr: String,
    pub server_port: String,
    pub username: String,
    pub password: String,
    pub tokio_runtime: tokio::runtime::Runtime,
    pub tunnel_settings: Option<TunnelSettingsPkt>,
    pub cipher: Option<ChaCha20Poly1305>,
    pub dev: Option<AsyncDevice>,
    pub udp_socket: Option<UdpSocket>,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub route_manager: Option<DesktopRouteManager>,
    pub termination_signal_tx: Option<tokio::sync::oneshot::Sender<()>>
}


impl VPNClient {
    pub fn new(
        server_pubkey_path: String,
        server_addr: String,
        server_port: String,
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
            dev: None,
            udp_socket: None,
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            route_manager: None,
            termination_signal_tx: None
        }
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
                udp_socket.connect(format!("{}:{}", self.server_addr, self.server_port)).await
            }
        );
        if let Err(e) = udp_socket_connect_result {
            return Err(format!("Failed to connect socket: {e}").into());
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
        
        let send_pubkey_result = self.tokio_runtime.block_on(
            async {
                tokio::time::timeout(tokio::time::Duration::from_secs(5), sock_write(&udp_socket, dh_key_pkt))
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
        let server_pubkey_recv_result = self.tokio_runtime.block_on(async {
            tokio::time::timeout(tokio::time::Duration::from_secs(5), sock_read(&udp_socket, &mut udp_buffer))
                .await
        });
        
        let other_pubkey_pkt: PacketType = match server_pubkey_recv_result {
            Ok(Ok(pkt)) => pkt,
            Ok(Err(e)) => {
                return Err(format!("Failed to receive server pubkey: {e}").into());
            }
            Err(e) => {
                return Err(format!("Timeout during reading server pubkey: {e}").into());
            },
        };
        
        let other_pubkey_pkt = match other_pubkey_pkt {
            PacketType::HandshakeResponse(dhkey_response_packet) => {
                dhkey_response_packet
            },
            _ => {
                return Err(format!("Recieved wrong packet from server, expected HandshakeResponsePacket").into());
            }
        };

        let signature = match Signature::from_slice(&other_pubkey_pkt.signature) {
            Ok(s) => s,
            Err(e) => {
                return Err(format!("Failed to construct signature from data received from server. Error: {e}").into());
            },
        };

        if let Err(e) = server_pubkey.verify_strict(&other_pubkey_pkt.pub_key, &signature) {
            return Err(format!("Server key signature verification failed. Possible MITM attack!. Error: {e}").into());
        }

        let sized_key_array: [u8; 32] = match other_pubkey_pkt.pub_key.try_into() {
            Ok(good) => good,
            Err(e) => {
                return Err(format!("Failed to construct server key byte array from data received").into());
            }
        };
        let other_pubkey = PublicKey::from(sized_key_array);

        let shared_key = secret.diffie_hellman(&other_pubkey);
        let cipher = ChaCha20Poly1305::new(shared_key.as_bytes().into());

        //3. send authdata to server, encrypted
        let auth_data = AuthData {
            username: self.username.clone(),
            password: hex::encode(sha2::Sha512::digest(self.password.clone())),
            client_nonce: client_nonce,
            server_nonce: other_pubkey_pkt.nonce
        };
        let encrypted_authdata = match auth_data.encrypt(&cipher) {
            Ok(encrypted) => encrypted,
            Err(e) => {
                return Err(format!("Failed to encrypt authdata: {e}").into());
            }
        };
        let auth_pkt = PacketType::AuthPacket(encrypted_authdata);
        
        let auth_data_send_result = self.tokio_runtime.block_on(
            async {
                tokio::time::timeout(tokio::time::Duration::from_secs(5),sock_write(&udp_socket, auth_pkt))
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

        //4. read ip address from server
        let tun_settings_encrypted_pkt_read_result =
            self.tokio_runtime.block_on(async {
                tokio::time::timeout(tokio::time::Duration::from_secs(5),sock_read(&udp_socket, &mut udp_buffer))
                    .await
            });

        let tun_settings_encrypted_pkt: PacketType = match tun_settings_encrypted_pkt_read_result {
            Ok(Ok(pkt)) => pkt,
            Ok(Err(e)) => {
                return Err(format!("Failed to read tunnel setting from server: {e}").into());
            },
            Err(e) => {
                return Err(format!("Timeout during receiving tunnel settings from server: {e}").into());
            }
        };

        let tun_settings_encrypted = match tun_settings_encrypted_pkt {
            PacketType::TunnelSettings(encrypted_message) => {
                encrypted_message
            },
            _ => {
                return Err(format!("Received wrong packet from server. Expected TunnelSettings").into());
            }
        } ;
        let tun_settings = match TunnelSettingsPkt::decrypt(&tun_settings_encrypted, &cipher) {
            Ok(decrypted) => decrypted,
            Err(e) => {
                return Err(format!("Failed to decrypt tunnel settings: {e}").into());
            }
        };
        self.tunnel_settings = Some(tun_settings);
        self.cipher = Some(cipher);
        self.udp_socket = Some(udp_socket);
        
        Ok(())
    }

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub fn create_tun(&mut self) -> Result<(), Box<dyn std::error::Error + Send+ Sync>> {
        let _guard = self.tokio_runtime.enter();

        let dev_create_result = self.tokio_runtime.block_on(async {
            create_tunnel(
            &self.tunnel_settings.as_ref().unwrap().ip_string, 
            &self.tunnel_settings.as_ref().unwrap().netmask_string, 
            &self.tunnel_settings.as_ref().unwrap().gateway_string
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
                self.server_addr.clone(),
                self.tunnel_settings.as_ref().unwrap().gateway_string.clone()
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

    pub fn vpn_loop(&mut self) -> Result<(), Box<dyn std::error::Error + Send+ Sync>> {
        let (term_tx, mut term_rx) = tokio::sync::oneshot::channel::<()>();
        
        self.termination_signal_tx = Some(term_tx);
        
        let tun_buffer_size = MTU as usize + PACKET_INFORMATION_LENGTH;
        let dev = match self.dev.take() {
            Some(dev) => dev,
            None => {
                return Err("Tunnel is None. Cant enter VPN loop".into());
            }
        };

        let (tun_writer, tun_reader) = (Arc::new(&dev), Arc::new(&dev));
        //let (mut tun_writer, mut tun_reader) = dev.unwrap().split().unwrap();

        let mut udp_buffer = vec![0u8; 1500];
        let mut tun_buf = vec![0u8; tun_buffer_size];

        let mut lastseen = tokio::time::Instant::now();

        let _guard = self.tokio_runtime.enter();
        
        let loop_result = self.tokio_runtime.block_on(
            async {
                //while tokio::time::Instant::now() - lastseen < CONNECTION_TIMEOUT {
                loop {
                    use chacha20poly1305::{aead::Aead, AeadCore, Nonce};

                    tokio::select! {
                        encrypted_read_result = sock_read(&self.udp_socket.as_ref().unwrap(), &mut udp_buffer) => {
                            lastseen = tokio::time::Instant::now();
                            match encrypted_read_result {
                                Ok(pkt_type) => {
                                    match pkt_type {
                                        PacketType::EncryptedPkt(encrypted_message) => {
                                            let decrypted =  match self.cipher.as_mut().unwrap().decrypt(&Nonce::from_slice(&encrypted_message.nonce), &encrypted_message.ciphertext[..]) {
                                                Ok(dec) => dec,
                                                Err(e) => {
                                                    error!("Failed to decrypt packet: {}", e);
                                                    continue;
                                                },
                                            };
                                            match ip::Packet::new(&decrypted) {
                                                Ok(_pkt) => {
                                                    tun_writer.send(&decrypted).await?;
                                                }
                                                Err(e) => {
                                                    error!("Packet error: {}", e);
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
                                    error!("Socket error: {}", e);
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
                                    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                                    let ciphertext = match self.cipher.as_mut().unwrap().encrypt(&nonce, bytes) {
                                        Ok(ciphertext) => ciphertext,
                                        Err(e) => {
                                            error!("Failed to encrypt packet: {}", e);
                                            continue;
                                        }
                                    };
                                    let encrypted_msg = EncryptedMessage {
                                        ciphertext,
                                        nonce: nonce.to_vec(),
                                    };
                                    let enc_pkt = PacketType::EncryptedPkt(
                                        encrypted_msg
                                    );
                                    sock_write(&self.udp_socket.as_mut().unwrap(), enc_pkt).await?;
                                },
                                Err(e) => {
                                    return Err(format!("Tunnel read error: {e}").into());
                                }
                            }
                        },
                        _ = &mut term_rx => {
                            return Ok(());
                        }
                        
                    }
                }
                return Err("Connection timed out".into());
            }
        );
        loop_result
    }
}