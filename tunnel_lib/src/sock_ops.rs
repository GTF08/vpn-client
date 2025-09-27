use tokio::net::UdpSocket;

use crate::messages::PacketType;

pub async fn sock_read(
    //read: &mut (impl AsyncReadExt + std::marker::Unpin),
    udp_socket: &UdpSocket,
    mut buf: &mut [u8]
    //on_binary_data_recieved: F
) -> Result<PacketType, Box<dyn std::error::Error + Send + Sync>> 
{

    match udp_socket.recv(&mut buf).await {
        Ok(n) => {
            let deserialized: (PacketType, usize) = bincode::decode_from_slice(&buf[..n], bincode::config::standard())?;
            return Ok(deserialized.0)
        },
        Err(e) => {
            return Err(Box::new(e))
        },
    }
}


pub async fn sock_write(
    udp_socket: &UdpSocket,
    data: PacketType,
)  -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    // while let Some((msg, addr)) = consumer.recv().await {
    //     let bytes = bincode::encode_to_vec(msg, bincode::config::standard())?;
    //     write.send_to(&bytes, addr).await?;
    // }
    // Ok(())
    let bytes = bincode::encode_to_vec(data, bincode::config::standard())?;
        //.map_err(|e| {println!("{e}"); format!("{e}")})?;

    udp_socket.send(&bytes).await?;
    Ok(())
}