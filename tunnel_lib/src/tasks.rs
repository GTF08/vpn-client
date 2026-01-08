use chacha20poly1305::ChaCha20Poly1305;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tun_rs::{AsyncDevice};
use std::sync::Arc;
use tokio::sync::broadcast::Receiver;

use log::error;

use crate::bufferpool::BytesPool;
//use crate::messages::{Decryptable, DecryptedBuffer, DecryptedPacket, Encryptable, EncryptedBuffer, EncryptedPacket};

use crate::messages::constants::ENCRYPTED_PACKET_HEADER_SIZE;
use crate::messages::decrypted::{DecryptedPacket};
use crate::messages::encrypted::EncryptedPacket;
use crate::messages::traits::{Decryptable as _, Encryptable};
use crate::sock_ops::{sock_read, sock_write};
use crate::vpnclient::BUFFER_SIZE;

    
pub async fn tun_read_task(
    bufferpool: Arc<BytesPool>, 
    tun_reader: Arc<AsyncDevice>,
    cipher: Arc<ChaCha20Poly1305>,
    udp_socket: Arc<UdpSocket>,
    cancel_token: CancellationToken
) 
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> 
{
    log::info!("tun read task started");
    loop {
        if cancel_token.is_cancelled() {
            log::debug!("Cancellation token recieved");
            break;
        }

        let mut buf_handle = match bufferpool.acquire() {
            Some(mut handle) => {
                //resize because tun reader expects initialized data
                handle.data_mut().resize(BUFFER_SIZE, 0);
                handle
            },
            None => {
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                continue;
            }
        };

        let read_count = tokio::select! {
            _ = cancel_token.cancelled() => {
                break;
            },
            res = tun_reader.recv(&mut buf_handle.data_mut()[ENCRYPTED_PACKET_HEADER_SIZE..]) => {
                res?
            }
        };

        //let read_count = tun_reader.recv(&mut buf_handle.data_mut()[ENCRYPTED_PACKET_HEADER_SIZE..]).await?;
     
        let size_with_header = ENCRYPTED_PACKET_HEADER_SIZE + read_count;
        buf_handle.data_mut().resize(size_with_header, 0);

        if read_count == 0 {
            return Err::<(), Box<dyn std::error::Error + Send + Sync>>("Tun interface closed".into()); // EOF
        }

        let decrypted_pkt_handle = DecryptedPacket::new(buf_handle);

        let encrypted_pkt_handle = match decrypted_pkt_handle.encrypt(&cipher) {
            Ok(enc) => enc,
            Err(e) => {
                error!("Failed to encrypt packet: {}", e);
                continue;
            }
        };

        tokio::select! {
            _ = cancel_token.cancelled() => {
                break;
            },
            res = sock_write(&udp_socket, &encrypted_pkt_handle.data()) => {
                res?;
            }
        }
        //dec_pkt_handle.
    }
    log::info!("tun read task finished");
    Ok(())
}

pub async fn sock_read_task(
    bufferpool: Arc<BytesPool>, 
    tun_writer: Arc<AsyncDevice>,
    cipher: Arc<ChaCha20Poly1305>,
    udp_socket: Arc<UdpSocket>,
    cancel_token: CancellationToken
)
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> 
{

    log::info!("sock read task started");
    loop {
        if cancel_token.is_cancelled() {
            log::debug!("Cancellation token recieved");
            break;
        }

        let mut buf_handle = match bufferpool.acquire() {
            Some(handle) => {
                handle
            },
            None => {
                tokio::time::sleep(tokio::time::Duration::from_micros(1)).await;
                continue;
            }
        };

        let encrypted_read_result = tokio::select! {
            _ = cancel_token.cancelled() => {
                break;
            },
            res = sock_read(&udp_socket, buf_handle.data_mut()) => {
                res
            }
        };

        let encrypted_pkt_handle = match encrypted_read_result {
            Ok(read_count) => {
                if read_count == 0 {
                    return Err("Socket connection got closed!".into());
                }

                let encrypted_pkt_handle = EncryptedPacket::new(buf_handle);

                if !encrypted_pkt_handle.is_valid_type() {
                    error!("Invalid packet type {}. Expected encrypted type", encrypted_pkt_handle.data()[0]);
                    continue;
                }   
                encrypted_pkt_handle
            },
            Err(e) => {
                error!("Socket error: {}", e);
                continue;
            },
        };



        match encrypted_pkt_handle.decrypt(&cipher) {
            Ok(dec) => {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        break;
                    },
                    res = tun_writer.send(&dec.data()[ENCRYPTED_PACKET_HEADER_SIZE..]) => {
                        res?;
                    }
                }
            },
            Err(e) => {
                error!("Failed to decrypt packet: {}", e);
                continue;
            },
        };

    }
    log::info!("sock read task finished");
    Ok(())
}