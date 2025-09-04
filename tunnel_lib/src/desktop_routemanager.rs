use std::process::Command;
use std::io;

#[cfg(not(target_os = "android"))]
pub trait RouteManager {
    fn add_default_route(&self) -> io::Result<()>;
    fn remove_default_route(&self) -> io::Result<()>;
}

#[cfg(not(target_os = "android"))]
pub struct DesktopRouteManager {
    tun_index: i32,
    gateway: String
}

#[cfg(not(target_os = "android"))]
impl DesktopRouteManager {
    pub fn new(tun_index: i32, gateway: String) -> Self {
        Self { tun_index, gateway}
    }
}

#[cfg(not(target_os = "android"))]
impl Drop for DesktopRouteManager {
    fn drop(&mut self) {
        let _ = self.remove_default_route();
    }
}

#[cfg(not(target_os = "android"))]
impl RouteManager for DesktopRouteManager {
    fn add_default_route(&self) -> io::Result<()> {
        #[cfg(target_os = "windows")]
        {
            // Windows route command
            let output = Command::new("route")
                .args(&["add", "0.0.0.0", "mask", "0.0.0.0", &self.gateway, "if", &self.tun_index.to_string(), "metric", "1"])
                .output()?;
            
            if !output.status.success() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to add route: {}", String::from_utf8_lossy(&output.stderr))
                ));
            }
        }
        
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            // Linux/macOS route command
            let output = Command::new("route")
                .args(&["add", "-net", "0.0.0.0", "netmask", "0.0.0.0", &self.gateway])
                .output()?;
            
            if !output.status.success() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to add route: {}", String::from_utf8_lossy(&output.stderr))
                ));
            }
        }
        println!("ADDED DEFAULT ROUTE VIA {}", self.gateway);
        Ok(())
    }
    
    fn remove_default_route(&self) -> io::Result<()> {
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("route")
                .args(&["delete", "0.0.0.0", 
                        "mask", "0.0.0.0",
                        &self.gateway, "if", &self.tun_index.to_string()
                ])
                .output()?;
            
            if !output.status.success() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to remove route: {}", String::from_utf8_lossy(&output.stderr))
                ));
            }
        }
        
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let output = Command::new("route")
                .args(&["delete", "-net", "0.0.0.0", "netmask", "0.0.0.0", "gw", &self.gateway])
                .output()?;
            
            if !output.status.success() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to remove route: {}", String::from_utf8_lossy(&output.stderr))
                ));
            }
        }
        println!("REMOVED DEFAULT ROUTE VIA {}", self.gateway);
        Ok(())
    }
}