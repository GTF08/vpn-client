use bytes::BytesMut;
use std::sync::{Arc, Mutex};

pub struct BytesPool {
    buffers: Mutex<Vec<BytesMut>>,    // Защищённый Mutex
    free_list: Mutex<Vec<usize>>,     // Отдельный Mutex
    buffer_size: usize,
}

impl BytesPool {
    pub fn new(count: usize, buffer_size: usize) -> Self {
        let buffers = (0..count)
            .map(|_| BytesMut::with_capacity(buffer_size))
            .collect();
        
        let buffers = Mutex::new(buffers);
        let free_list = Mutex::new((0..count).collect());
        
        Self { buffers, free_list, buffer_size }
    }
    
    pub fn acquire(self: &Arc<Self>) -> Option<BufferHandle> {
        // 1. Берём свободный индекс
        let idx = {
            let mut free = self.free_list.lock().unwrap();
            free.pop()?
        };
        
        // 2. Забираем буфер
        let buf = {
            let mut buffers = self.buffers.lock().unwrap();
            std::mem::take(&mut buffers[idx])
        };
        
        Some(BufferHandle::new(Arc::clone(self), idx, buf))
    }
    
    // pub fn acquire_blocking(&self) -> (usize, BytesMut) {
    //     loop {
    //         if let Some(result) = self.acquire() {
    //             return result;
    //         }
    //         std::thread::yield_now();
    //     }
    // }
    
    fn release(&self, idx: usize, mut buf: BytesMut) {
        // Очищаем буфер
        buf.clear();
        
        // Возвращаем в пул
        {
            let mut buffers = self.buffers.lock().unwrap();
            buffers[idx] = buf;
        }
        
        // Помечаем как свободный
        {
            let mut free = self.free_list.lock().unwrap();
            free.push(idx);
        }
    }
}

// RAII Handle
pub struct BufferHandle {
    pool: Arc<BytesPool>,
    idx: usize,
    buf: BytesMut,
}

impl BufferHandle {
    pub fn new(pool: Arc<BytesPool>, idx: usize, buf: BytesMut) -> Self {
        Self { pool, idx, buf }
    }

    pub fn data(&self) -> &BytesMut {
        &self.buf
    }
    
    pub fn data_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }
}

impl Drop for BufferHandle {
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.buf);
        self.pool.release(self.idx, buf);
    }
}