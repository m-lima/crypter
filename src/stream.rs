#![allow(clippy::missing_errors_doc)]

pub const DEFAULT_CHUNK: usize = 128 * 1024;
pub type DefautEncryptor<Out> = Encryptor<Out, DEFAULT_CHUNK>;
pub type DefautDecryptor<Out> = Decryptor<Out, DEFAULT_CHUNK>;

const TAG_LEN: usize = std::mem::size_of::<aes_gcm_siv::Tag>();

pub struct Encryptor<Out, const CHUNK: usize>
where
    Out: std::io::Write,
{
    stream: Option<aead::stream::EncryptorLE31<aes_gcm_siv::Aes256GcmSiv>>,
    buffer: aead::arrayvec::ArrayVec<u8, CHUNK>,
    output: Out,
}

impl<Out, const CHUNK: usize> Encryptor<Out, CHUNK>
where
    Out: std::io::Write,
{
    const MAX_CAP: usize = CHUNK - TAG_LEN;

    pub fn new<Key>(key: Key, mut output: Out) -> std::io::Result<Self>
    where
        Key: AsRef<[u8]>,
    {
        use aes_gcm_siv::aead::KeyInit;

        let key = super::normalize_key(key.as_ref());
        let nonce = make_nonce();

        output.write_all(&nonce)?;

        let stream = Some(aead::stream::EncryptorLE31::from_aead(
            aes_gcm_siv::Aes256GcmSiv::new(&key),
            nonce.as_slice().into(),
        ));
        let buffer = aead::arrayvec::ArrayVec::new();

        Ok(Self {
            stream,
            buffer,
            output,
        })
    }

    pub fn finish(mut self) -> std::io::Result<()> {
        self.finish_inner()
    }

    fn fill_buffer(&mut self, buf: &[u8]) -> std::io::Result<()> {
        use aead::Buffer;

        self.buffer
            .extend_from_slice(buf)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::OutOfMemory, err.to_string()))
    }

    fn flush_block(&mut self) -> std::io::Result<()> {
        // SAFETY: The option is only removed on drop
        unsafe {
            self.stream
                .as_mut()
                .unwrap_unchecked()
                .encrypt_next_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
        }

        self.output.write_all(&self.buffer)?;
        self.buffer.clear();
        Ok(())
    }

    fn finish_inner(&mut self) -> std::io::Result<()> {
        // SAFETY: The option is only removed on drop
        unsafe {
            self.stream
                .take()
                .unwrap_unchecked()
                .encrypt_last_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
        }

        self.output.write_all(&self.buffer)?;
        self.output.flush()
    }
}

impl<Out, const CHUNK: usize> std::io::Write for Encryptor<Out, CHUNK>
where
    Out: std::io::Write,
{
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        let mut sent = 0;
        let mut capacity = Self::MAX_CAP.saturating_sub(self.buffer.len());

        while buf.len() > capacity {
            self.fill_buffer(&buf[..capacity])?;
            self.flush_block()?;

            buf = &buf[capacity..];
            sent += capacity;
            capacity = Self::MAX_CAP;
        }

        self.fill_buffer(buf)?;

        Ok(sent + self.buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buffer.len() == Self::MAX_CAP {
            self.flush_block()?;
        }
        self.output.flush()
    }
}

impl<Out, const CHUNK: usize> Drop for Encryptor<Out, CHUNK>
where
    Out: std::io::Write,
{
    fn drop(&mut self) {
        if self.stream.is_some() {
            drop(self.finish_inner());
        }
    }
}

pub struct Decryptor<In, const CHUNK: usize>
where
    In: std::io::Read,
{
    stream: Option<aead::stream::DecryptorLE31<aes_gcm_siv::Aes256GcmSiv>>,
    buffer: aead::arrayvec::ArrayVec<u8, CHUNK>,
    cursor: usize,
    input: In,
}

impl<In, const CHUNK: usize> Decryptor<In, CHUNK>
where
    In: std::io::Read,
{
    pub fn new<Key>(key: Key, mut input: In) -> std::io::Result<Self>
    where
        Key: AsRef<[u8]>,
    {
        use aead::KeyInit;

        let key = super::normalize_key(key.as_ref());

        let mut nonce = [0; 8];
        input.read_exact(&mut nonce)?;

        let stream = Some(aead::stream::DecryptorLE31::from_aead(
            aes_gcm_siv::Aes256GcmSiv::new(&key),
            nonce.as_slice().into(),
        ));
        let buffer = aead::arrayvec::ArrayVec::new();

        Ok(Self {
            stream,
            buffer,
            cursor: 0,
            input,
        })
    }

    fn fill_buf(&mut self) -> std::io::Result<()> {
        unsafe { self.buffer.set_len(CHUNK) };
        let mut read = 0;
        while read < CHUNK {
            read += {
                let bytes = self.input.read(&mut self.buffer[read..])?;
                if bytes == 0 {
                    break;
                }
                bytes
            };
        }
        unsafe { self.buffer.set_len(read) };
        self.cursor = 0;
        Ok(())
    }

    unsafe fn decrypt(&mut self) -> std::io::Result<()> {
        if self.buffer.len() < CHUNK {
            self.stream
                .take()
                .unwrap_unchecked()
                .decrypt_last_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
        } else {
            self.stream
                .as_mut()
                .unwrap_unchecked()
                .decrypt_next_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
        }

        Ok(())
    }
}

impl<In, const CHUNK: usize> std::io::Read for Decryptor<In, CHUNK>
where
    In: std::io::Read,
{
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read = 0;
        while !buf.is_empty() {
            let buf_size = self.buffer.len() - self.cursor;
            if buf_size > 0 {
                let len = buf_size.min(buf.len());
                buf[..len].copy_from_slice(&self.buffer[self.cursor..self.cursor + len]);
                self.cursor += len;
                buf = &mut buf[len..];
                read += len;

                continue;
            }

            if self.stream.is_none() {
                break;
            }
            self.fill_buf()?;
            // SAFETY: The presence of `self.stream` was checked above
            unsafe {
                self.decrypt()?;
            }
        }
        Ok(read)
    }
}

fn make_nonce() -> [u8; 8] {
    let mut nonce = [0; 8];
    aes_gcm_siv::aead::rand_core::RngCore::fill_bytes(&mut aes_gcm_siv::aead::OsRng, &mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn tag_len() {
        assert_eq!(TAG_LEN, 16);
    }

    #[test]
    fn round_trip() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| (u8::MIN..u8::MAX))
            .collect::<Vec<_>>();

        let mut transient = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));
        let mut output = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));

        let mut encryptor = DefautEncryptor::new([], &mut transient).unwrap();
        encryptor.write_all(input.as_slice()).unwrap();
        encryptor.finish().unwrap();
        assert_ne!(input, transient);

        let mut decryptor = DefautDecryptor::new([], transient.as_slice()).unwrap();
        decryptor.read_to_end(&mut output).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_with_drop() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| (u8::MIN..u8::MAX))
            .collect::<Vec<_>>();

        let mut transient = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));
        let mut output = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));

        {
            let mut encryptor = DefautEncryptor::new([], &mut transient).unwrap();
            encryptor.write_all(input.as_slice()).unwrap();
        }
        assert_ne!(input, transient);

        let mut decryptor = DefautDecryptor::new([], transient.as_slice()).unwrap();
        decryptor.read_to_end(&mut output).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn different_block_size() {
        const CHUNK: usize = 8 * 1024;

        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| (u8::MIN..u8::MAX))
            .collect::<Vec<_>>();

        let mut transient = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));
        let mut output = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));

        let mut encryptor = DefautEncryptor::new([], &mut transient).unwrap();
        encryptor.write_all(input.as_slice()).unwrap();
        encryptor.finish().unwrap();
        assert_ne!(input, transient);

        let mut decryptor = Decryptor::<_, CHUNK>::new([], transient.as_slice()).unwrap();
        let err = decryptor.read_to_end(&mut output).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert_eq!(err.to_string(), "aead::Error");
    }
}
