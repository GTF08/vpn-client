use ed25519_dalek::{SignatureError, VerifyingKey};
use std::fs::File;
use std::io::{Read};

pub fn load_verifying_key(path: &str) -> Result<VerifyingKey, Box<dyn std::error::Error + Sync + Send>> {
    let mut file = File::open(path)?;
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)?;
    
    let verifying_key = VerifyingKey::from_bytes(&bytes)
        .map_err(|e: SignatureError| format!("Invalid public key: {}", e))?;
    
    Ok(verifying_key)
}