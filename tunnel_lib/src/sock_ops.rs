use tokio::net::UdpSocket;

pub async fn sock_read(
    //read: &mut (impl AsyncReadExt + std::marker::Unpin),
    udp_socket: &UdpSocket,
    buf: &mut bytes::BytesMut
    //on_binary_data_recieved: F
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> 
{
    
    match udp_socket.recv_buf(buf).await {
        Ok(n) => {
            //let deserialized: (PacketType, usize) = bincode::decode_from_slice(&buf[..n], bincode::config::standard())?;
            return Ok(n)
        },
        Err(e) => {
            return Err(Box::new(e))
        },
    }
}


pub async fn sock_write(
    udp_socket: &UdpSocket,
    data: &bytes::BytesMut,
)  -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    // while let Some((msg, addr)) = consumer.recv().await {
    //     let bytes = bincode::encode_to_vec(msg, bincode::config::standard())?;
    //     write.send_to(&bytes, addr).await?;
    // }
    // Ok(())
        //.map_err(|e| {println!("{e}"); format!("{e}")})?;

    udp_socket.send(&data).await?;
    Ok(())
}