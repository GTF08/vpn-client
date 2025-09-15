// #[cfg(target_os = "windows")]
// use futures::io::{AsyncRead, AsyncWrite};
// #[cfg(target_os = "windows")]
// use std::{net::Ipv4Addr, str::FromStr};
// #[cfg(target_os = "windows")]
// use wintun_bindings::AsyncSession;
// #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
// use tokio::io::{AsyncRead, AsyncWrite};
//#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]

use tun_rs::{DeviceBuilder, AsyncDevice};

#[cfg(target_os = "android")]
use std::os::raw::{c_int};

// pub async fn create_tunnel(
//     tun_ip: &str,
//     tun_netmask: &str,
//     tun_gateway: &str,
//     tun_fd: Option<c_int>
// ) -> Result<AsyncDevice, Box<dyn std::error::Error + Send + Sync>> {
//     #[cfg(target_os = "android")]
//     return tunnel_android(tun_fd.unwrap()).await;
//     #[cfg(target_os = "linux")]
//     return tunnel_linux(tun_ip, tun_netmask, tun_gateway).await;
//     #[cfg(target_os = "macos")]
//     return tunnel_macos(tun_ip, tun_netmask, tun_gateway).await;
//     #[cfg(target_os = "windows")]
//     return tunnel_windows(tun_ip, tun_netmask, tun_gateway).await;
// }

#[cfg(target_os = "windows")]
pub async fn create_tunnel(tun_ip: &str, tun_netmask: &str, tun_gateway: &str) 
-> Result<AsyncDevice, Box<dyn std::error::Error + Send + Sync>> 
{
    let dev = DeviceBuilder::new()
        .name("sucktun0")
        .ipv4(tun_ip, tun_netmask, Some(tun_gateway))
        .mtu(1400u16)
        .build_async()
        .unwrap();
    // let mut config = tun::Configuration::default();
    // config
    //     .address(tun_ip)
    //     .netmask(tun_netmask)
    //     .destination(tun_gateway)
    //     .mtu(1400u16)
    //     .up();

    //let dev = tun::create_as_async(&config)?;

    Ok(dev)
}

#[cfg(target_os = "android")]
pub async fn create_tunnel(tun_fd: c_int) 
-> Result<AsyncDevice, Box<dyn std::error::Error + Send + Sync>> 
{
    let mut config = tun::Configuration::default();
    config.mtu(1400u16);
    config.raw_fd(tun_fd);
    let mut dev = tun::create_as_async(&config).unwrap();
    Ok(dev)
}

#[cfg(target_os = "macos")]
pub async fn create_tunnel(tun_ip: &str, tun_netmask: &str, tun_gateway: &str) 
-> Result<AsyncDevice, Box<dyn std::error::Error + Send + Sync>> 
{
    let dev = DeviceBuilder::new()
        .ipv4(tun_ip, tun_netmask, Some(tun_gateway))
        .mtu(1400u16)
        .build_async()
        .unwrap();

    Ok(dev)
}



#[cfg(target_os = "linux")]
pub async fn create_tunnel(tun_ip: &str, tun_netmask: &str, tun_gateway: &str) 
-> Result<(impl AsyncRead, impl AsyncWrite, Option<i32>), Box<dyn std::error::Error + Send + Sync>> 
{
    use tun::{AbstractDevice, Configuration};

    let mut config = Configuration::default();

    config
        .address(tun_ip)
        .netmask(tun_netmask)
        .destination(tun_gateway)
        .mtu(1400u16)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        #[allow(deprecated)]
        config.packet_information(true);
        config.ensure_root_privileges(true);
    });

    #[cfg(target_os = "windows")]
    config.platform_config(|config| {
        config.device_guid(9099482345783245345344_u128);
    });
    let dev = tun::create_as_async(&config)?;


    Ok(dev)
}