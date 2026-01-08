use crate::{bufferpool::BufferHandle, messages::{constants::PKT_TYPE_ENCRYPTED_PKT, encrypted::EncryptedPacket, traits::Encryptable}};


pub struct DecryptedPacket {
    pub(super) buffer_handle: BufferHandle
}

impl DecryptedPacket {
    pub fn new(buffer_handle: BufferHandle) -> Self {
        Self{
            buffer_handle
        }
    }

    pub fn data(&self) -> &bytes::BytesMut {
        self.buffer_handle.data()
    }

    pub fn data_mut(&mut self) -> &mut bytes::BytesMut {
        self.buffer_handle.data_mut()
    }
}

impl From<EncryptedPacket> for DecryptedPacket {
    fn from(value: EncryptedPacket) -> Self {
        DecryptedPacket::new(value.buffer_handle)
    }
}

impl Encryptable for DecryptedPacket {
    type EncryptedType = EncryptedPacket;
    const PKT_TYPE: u8 = PKT_TYPE_ENCRYPTED_PKT;
     
    fn get_buffer_mut(&mut self) -> &mut bytes::BytesMut {
        self.buffer_handle.data_mut()
    }

}


// Реализуем AsMut<[u8]> для BufferHandle
impl AsMut<[u8]> for DecryptedPacket{
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer_handle.data_mut().as_mut()
    }
}

// Реализуем AsRef<[u8]> для BufferHandle
impl AsRef<[u8]> for DecryptedPacket {
    fn as_ref(&self) -> &[u8] {
        &self.buffer_handle.data()
    }
}