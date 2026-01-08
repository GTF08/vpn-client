use crate::{bufferpool::BufferHandle, messages::{constants::{PKT_TYPE_ENCRYPTED_PKT}, decrypted::DecryptedPacket, traits::Decryptable}};


pub struct EncryptedPacket {
    pub(super) buffer_handle: BufferHandle,
}

impl EncryptedPacket {
    pub fn new(buffer_handle: BufferHandle) -> Self {
        Self {
            buffer_handle,
        }
    }

    pub fn data(&self) -> &bytes::BytesMut {
        self.buffer_handle.data()
    }

    pub fn data_mut(&mut self) -> &mut bytes::BytesMut {
        self.buffer_handle.data_mut()
    }

    pub fn is_valid_type(&self) -> bool {
        self.buffer_handle.data()[0] == PKT_TYPE_ENCRYPTED_PKT
    }
}

impl Decryptable for EncryptedPacket {
    type DecryptedType = DecryptedPacket;
    
    fn get_buffer_mut(&mut self) -> &mut bytes::BytesMut {
        self.buffer_handle.data_mut()
    }

}

impl From<DecryptedPacket> for EncryptedPacket {
    fn from(value: DecryptedPacket) -> Self {
        return EncryptedPacket::new(value.buffer_handle)
    }
}