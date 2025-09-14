use std::process::Command;

#[cfg(not(target_os = "android"))]
use std::io::Write;
#[cfg(not(target_os = "android"))]
use std::fs::File;
#[cfg(not(target_os = "android"))]
use std::fs::read_to_string;

const ROUTE_REVERT_FILE: &str = "route_revert.cfg";

#[cfg(not(target_os = "android"))]
pub trait RouteManager {
    fn add_route(&self, destination: &str, gateway: &str) -> Result<(), Box<dyn std::error::Error>>;
    fn add_default_route(&self) -> Result<(), Box<dyn std::error::Error>>;
    fn cleanup(&self) -> Result<(), Box<dyn std::error::Error>>;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn get_default_gateway() -> Result<String, Box<dyn std::error::Error>> {
        #[cfg(target_os = "linux")]
        let output = Command::new("ip")
            .arg("route show default | awk '{print $3}'")
            .output()?;
        #[cfg(target_os = "macos")]
        let output = Command::new("ip")
            .arg("r | grep default | grep -v link |awk {print $3}")
            .output()?;
        if !output.status.success() {
            return Ok(String::from_utf8(output.stdout)?.trim().to_string());
        }
        let std_err = String::from_utf8(output.stderr)?;
        return Err(format!("Failed to get default gateway: {}", std_err).into());
    }
}

#[cfg(not(target_os = "android"))]
pub struct DesktopRouteManager {
    tun_index: i32,
    server_pub_ip: String,
    server_gateway: String,
}

#[cfg(not(target_os = "android"))]
impl DesktopRouteManager {
    pub fn new(
        tun_index: i32, 
        server_pub_ip: String,
        server_gateway: String
    ) -> Self {
        Self { 
            tun_index, 
            server_pub_ip,
            server_gateway: server_gateway
        }
    }
}

#[cfg(not(target_os = "android"))]
impl Drop for DesktopRouteManager {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(not(target_os = "android"))]
impl RouteManager for DesktopRouteManager {
    fn add_route(&self, destination: &str, gateway: &str) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(target_os = "windows")]
        Command::new("cmd")
            .args(&["/C", &format!("route add {} mask 255.255.255.255 {}", destination, gateway)])
            .status()?;
        #[cfg(target_os = "linux")] 
        Command::new("sh")
            .arg("-c")
            .arg(&format!("ip route add {} via {}", destination, gateway))
            .status()?;
        #[cfg(target_os = "macos")] 
         Command::new("sh")
            .arg("-c")
            .arg(&format!("route add {} {}", destination, gateway))
            .status()?;
        Ok(())
    }
    fn add_default_route(&self) -> Result<(), Box<(dyn std::error::Error + 'static)>> {
        let mut file = File::create(ROUTE_REVERT_FILE)?;
        
        #[cfg(target_os = "windows")]
        {
            // Windows route command
            Command::new("route")
                .args(&["add", "0.0.0.0", "mask", "0.0.0.0", &self.server_gateway, "if", &self.tun_index.to_string(), "metric", "1"])
                .status()?;
            writeln!(file, "route delete 0.0.0.0 mask 0.0.0.0 {} if {}", &self.server_gateway, &self.tun_index.to_string())?;
        }
        
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let old_gateway = DesktopRouteManager::get_default_gateway()?;
            println!("{}", old_gateway);
            // Linux/macOS route command
            //Add route to server
            println!("EXEC route add {} {}", &self.server_pub_ip, &old_gateway);
            Command::new("route")
                .args(&["add", &self.server_pub_ip, &old_gateway ])
                .status()?;
            
            //Command to delete server route
            writeln!(file, "route delete {} {}", &self.server_pub_ip, &old_gateway);

            //Delete default route
            println!("EXEC route delete default");
            Command::new("route")
                .args(&["delete", "default"])
                .status()?;
            //Command to recover default route
            writeln!(file, "route add default {}", &old_gateway);

            //Add default route via tun
            println!("EXEC route add default {}", &self.server_gateway);
            let output = Command::new("route")
                .args(&["add", "default", &self.server_gateway ])
                .status()?;

            //delete default route via tun
            writeln!(file, "route delete default {}", &self.server_gateway);
            
        }
        println!("ADDED DEFAULT ROUTE VIA {}", self.server_gateway);
        Ok(())
    }
    
    
    // fn remove_default_route(&self) -> Result<(), Box<(dyn std::error::Error + 'static)>> {
    //     #[cfg(target_os = "windows")]
    //     {
    //         let output = Command::new("route")
    //             .args(&["delete", "0.0.0.0", 
    //                     "mask", "0.0.0.0",
    //                     &self.server_gateway, "if", &self.tun_index.to_string()
    //             ])
    //             .output()?;
            
    //         if !output.status.success() {
    //             return Err(std::io::Error::new(
    //                 std::io::ErrorKind::Other,
    //                 format!("Failed to remove route: {}", String::from_utf8_lossy(&output.stderr))
    //             ).into());
    //         }
    //     }
        
    //     #[cfg(any(target_os = "linux", target_os = "macos"))]
    //     {
    //         if std::path::Path::new(ROUTE_REVERT_FILE).exists() {
                

    //             for line in read_to_string(ROUTE_REVERT_FILE).unwrap().lines() {
    //                 let output = Command::new("sh")
    //                     .arg("-c")
    //                     .arg(line)
    //                     .output()?;
    //                 if !output.status.success() {
    //                     eprintln!("Failed to cleanup routes with command: {line}")
    //                 }
    //             }
    //         }
    //     }
    //     println!("REMOVED DEFAULT ROUTE VIA {}", self.server_gateway);
    //     Ok(())
    // }
    
    fn cleanup(&self) -> Result<(), Box<dyn std::error::Error>> {
        if std::path::Path::new(ROUTE_REVERT_FILE).exists() {
            for line in read_to_string(ROUTE_REVERT_FILE).unwrap().lines() {
                #[cfg(target_os = "windows")]
                let output = Command::new("cmd")
                    .arg("/C")
                    .arg(line)
                    .output()?;

                #[cfg(any(target_os = "linux", target_os = "macos"))]
                let output = Command::new(line)
                    .output()?;
                if !output.status.success() {
                    eprintln!("Failed to cleanup routes with command: {line}")
                }
            }
        }
        Ok(())
    }
}