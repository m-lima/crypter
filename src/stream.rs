//! Stream support for AES-GCM-SIV 256-bits encrypting and decrypting in chunks.
//!
//! The chunks are counted and used when generating the nonce of the next chunk. Therefore, it is
//! important that the [`Encrypter`] and [`Decrypter`] use the same chunk size so the nonces can be
//! in sync. Decryption will fail otherwise.
//!
//! # Examples
//!
//! ## Encrypting
//!
//! ```no_run
//! # fn get_key() -> &'static [u8] { &[] }
//! use std::io::{BufRead, Write};
//!
//! let key = get_key();
//! let mut encrypter = crypter::stream::Encrypter::new(key, std::io::stdout())
//!     .expect("Failed to write to stdout");
//! let reader = std::io::BufReader::new(std::io::stdin());
//!
//! for line in reader.lines() {
//!     let line = line.expect("Failed to read from stdin");
//!     encrypter
//!         .write_all(line.as_bytes())
//!         .expect("Failed to encrypt stream");
//! }
//! ```
//!
//! ## Decrypting
//!
//! ```no_run
//! # fn get_key() -> &'static [u8] { &[] }
//! use std::io::BufRead;
//!
//! let key = get_key();
//! let decrypter = crypter::stream::Decrypter::new(key, std::io::stdin())
//!     .expect("Failed to read from stdin");
//! let reader = std::io::BufReader::new(decrypter);
//!
//! for line in reader.lines() {
//!     let line = line.expect("Failed to read from stdin");
//!     println!("{line}");
//! }
//! ```

/// The default chunk size for encryption. That is, 512 KiB
pub const DEFAULT_CHUNK: usize = 512 * 1024;

/// A streaming AES-GCM-SIV 256-bits encrypter.
///
/// Implements the [`Write`](std::io::Write) trait to provide streaming, while internally keeping a
/// buffer of the chunk to encrypt as a single message.
///
/// It will auto-finalize on drop, but will fail silently in that case. To get any errors that may
/// happen while finalizing, explicitly call [`finish`](Encrypter::finish)
///
/// **Note:** The size of the chunk used must match the chunk size used by the [`Decrypter`]. The decryption
/// will fail if there is a mismatch.
///
/// # Examples
///
/// ```no_run
/// # fn get_key() -> &'static [u8] { &[] }
/// use std::io::{BufRead, Write};
///
/// let key = get_key();
/// let mut encrypter = crypter::stream::Encrypter::new(key, std::io::stdout())
///     .expect("Failed to write to stdout");
/// let reader = std::io::BufReader::new(std::io::stdin());
///
/// for line in reader.lines() {
///     let line = line.expect("Failed to read from stdin");
///     encrypter
///         .write_all(line.as_bytes())
///         .expect("Failed to encrypt stream");
/// }
/// ```
pub struct Encrypter<Out>
where
    Out: std::io::Write,
{
    stream: Option<aead::stream::EncryptorLE31<aes_gcm_siv::Aes256GcmSiv>>,
    buffer: Vec<u8>,
    output: Out,
    plain_capacity: usize,
}

impl<Out> Encrypter<Out>
where
    Out: std::io::Write,
{
    /// Creates a new [`Encrypter`] using the writer `output` and a default chunk size [`DEFAULT_CHUNK`]
    /// encrypted with the cryptographic key `key`.
    ///
    /// **Note:** There is no derivation of the key. It is simply hashed to allow variable lenghts.
    /// It is assumed that all security precautions were taken with the `key` before calling this function.
    ///
    /// # Errors
    ///
    /// When initializing, the [`Encrypter`] will write a few bytes to `output`. If any error happens at
    /// that stage, this function will fail.
    pub fn new<Key>(key: Key, output: Out) -> std::io::Result<Self>
    where
        Key: AsRef<[u8]>,
    {
        Self::with_chunk(key, output, DEFAULT_CHUNK)
    }

    /// Creates a new [`Encrypter`] using the writer `output` and a chunk size `chunk` encrypted with
    /// the cryptographic key `key`.
    ///
    /// **Note:** There is no derivation of the key. It is simply hashed to allow variable lenghts.
    /// It is assumed that all security precautions were taken with the `key` before calling this function.
    ///
    /// # Errors
    ///
    /// When initializing, the [`Encrypter`] will write a few bytes to `output`. If any error happens at
    /// that stage, this function will fail.
    ///
    /// # Panics
    ///
    /// If the value of `chunk` is less than 32.
    pub fn with_chunk<Key>(key: Key, mut output: Out, chunk: usize) -> std::io::Result<Self>
    where
        Key: AsRef<[u8]>,
    {
        use aes_gcm_siv::aead::KeyInit;

        assert!(chunk >= 32);

        let key = super::normalize_key(key.as_ref());
        let nonce = make_nonce();

        output.write_all(&nonce)?;

        let stream = Some(aead::stream::EncryptorLE31::from_aead(
            aes_gcm_siv::Aes256GcmSiv::new(&key),
            nonce.as_slice().into(),
        ));
        let buffer = Vec::with_capacity(chunk);
        let plain_capacity = buffer.capacity() - std::mem::size_of::<aes_gcm_siv::Tag>();

        Ok(Self {
            stream,
            buffer,
            output,
            plain_capacity,
        })
    }

    /// Finalizes the stream by encrypting any reamining bytes and setting the `last` flag,
    /// flushing the output, and dropping this [`Encrypter`].
    ///
    /// If the plain text message matches exactly with the chunk division, an empty chunk will be
    /// sent to signal the end of the stream. The chunk division is 16 bytes smaller than the chunk
    /// size to accommodate the AES-GCM-SIV tag.
    ///
    /// This function will be called on [`drop()`](std::mem::drop) if not explicitly called.
    /// Though, if called on [`drop()`](std::mem::drop), any errors will be ignored.
    ///
    /// # Errors
    ///
    /// The function may fail while encrypting any buffered bytes and flushing the encrypted message.
    pub fn finish(mut self) -> std::io::Result<()> {
        self.finish_inner()
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
        let mut stream = unsafe { self.stream.take().unwrap_unchecked() };

        if self.buffer.len() == self.plain_capacity {
            stream
                .encrypt_next_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;

            self.output.write_all(&self.buffer)?;
            self.buffer.clear();
        }

        stream
            .encrypt_last_in_place(b"", &mut self.buffer)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;

        self.output.write_all(&self.buffer)?;
        self.output.flush()
    }

    /// # Safety
    ///
    /// The capacity of `self.buffer` must accommodate `buf.len()`
    unsafe fn fill_buf(&mut self, buf: &[u8]) {
        let len = self.buffer.len();
        self.buffer.set_len(len + buf.len());
        self.buffer[len..].copy_from_slice(buf);
    }
}

impl<Out> std::io::Write for Encrypter<Out>
where
    Out: std::io::Write,
{
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        let mut sent = 0;
        let mut rem_cap = self.plain_capacity.saturating_sub(self.buffer.len());

        while buf.len() > rem_cap {
            // SAFETY: The length was check before entering the loop
            unsafe { self.fill_buf(&buf[..rem_cap]) };
            self.flush_block()?;

            buf = &buf[rem_cap..];
            sent += rem_cap;
            rem_cap = self.plain_capacity;
        }

        // SAFETY: The length was checked by the loop before reaching here
        unsafe { self.fill_buf(buf) };
        Ok(sent + buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buffer.len() == self.plain_capacity {
            self.flush_block()?;
        }
        self.output.flush()
    }
}

impl<Out> Drop for Encrypter<Out>
where
    Out: std::io::Write,
{
    fn drop(&mut self) {
        if self.stream.is_some() {
            drop(self.finish_inner());
        }
    }
}

/// A streaming AES-GCM-SIV 256-bits decrypter.
///
/// Implements the [`Read`](std::io::Read) trait to provide streaming, while internally keeping a
/// buffer of the chunk to decrypt as a single message.
///
/// **Note:** The size of the chunk used must match the chunk size used by the [`Encrypter`]. The decryption
/// will fail if there is a mismatch.
///
/// # Examples
///
/// ```no_run
/// # fn get_key() -> &'static [u8] { &[] }
/// use std::io::BufRead;
///
/// let key = get_key();
/// let decrypter = crypter::stream::Decrypter::new(key, std::io::stdin())
///     .expect("Failed to read from stdin");
/// let reader = std::io::BufReader::new(decrypter);
///
/// for line in reader.lines() {
///     let line = line.expect("Failed to read from stdin");
///     println!("{line}");
/// }
/// ```
pub struct Decrypter<In>
where
    In: std::io::Read,
{
    stream: Option<aead::stream::DecryptorLE31<aes_gcm_siv::Aes256GcmSiv>>,
    buffer: Vec<u8>,
    cursor: usize,
    input: In,
}

impl<In> Decrypter<In>
where
    In: std::io::Read,
{
    /// Creates a new [`Decrypter`] using the reader `input` and a default size [`DEFAULT_CHUNK`] decrypted
    /// with the cryptographic key `key`.
    ///
    /// **Note:** There is no derivation of the key. It is simply hashed to allow variable lenghts.
    /// It is assumed that all security precautions were taken with the `key` before calling this function.
    ///
    /// # Errors
    ///
    /// When initializing, the [`Decrypter`] will read the first few bytes of `input`. If any error
    /// happens at that stage, this function will fail.
    pub fn new<Key>(key: Key, input: In) -> std::io::Result<Self>
    where
        Key: AsRef<[u8]>,
    {
        Self::with_chunk(key, input, DEFAULT_CHUNK)
    }

    /// Creates a new [`Decrypter`] using the reader `input` and a chunk size `chunk` decrypted
    /// with the cryptographic key `key`.
    ///
    /// **Note:** There is no derivation of the key. It is simply hashed to allow variable lenghts.
    /// It is assumed that all security precautions were taken with the `key` before calling this function.
    ///
    /// # Errors
    ///
    /// When initializing, the [`Decrypter`] will read the first few bytes of `input`. If any error
    /// happens at that stage, this function will fail.
    ///
    /// # Panics
    ///
    /// If the value of `chunk` is less than 32.
    pub fn with_chunk<Key>(key: Key, mut input: In, chunk: usize) -> std::io::Result<Self>
    where
        Key: AsRef<[u8]>,
    {
        use aead::KeyInit;

        assert!(chunk >= 32);

        let key = super::normalize_key(key.as_ref());

        let mut nonce = [0; 8];
        input.read_exact(&mut nonce)?;

        let stream = Some(aead::stream::DecryptorLE31::from_aead(
            aes_gcm_siv::Aes256GcmSiv::new(&key),
            nonce.as_slice().into(),
        ));
        let buffer = Vec::with_capacity(chunk);

        Ok(Self {
            stream,
            buffer,
            cursor: 0,
            input,
        })
    }

    fn fill_buf(&mut self) -> std::io::Result<()> {
        // SAFETY: The unused length will be truncated after reading
        unsafe { self.buffer.set_len(self.buffer.capacity()) };
        let mut read = 0;
        while read < self.buffer.capacity() {
            read += {
                let bytes = self.input.read(&mut self.buffer[read..])?;
                if bytes == 0 {
                    break;
                }
                bytes
            };
        }
        // SAFETY: Truncating the length to ensure safety from the previous `set_len`
        unsafe { self.buffer.set_len(read) };
        self.cursor = 0;
        Ok(())
    }

    /// # Safety
    ///
    /// The presence of `self.stream` must be guaranteed
    unsafe fn decrypt(&mut self) -> std::io::Result<()> {
        if self.buffer.len() < self.buffer.capacity() {
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

impl<In> std::io::Read for Decrypter<In>
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
            unsafe { self.decrypt() }?;
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
        assert_eq!(std::mem::size_of::<aes_gcm_siv::Tag>(), 16);
    }

    #[test]
    fn round_trip() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| (u8::MIN..u8::MAX))
            .collect::<Vec<_>>();

        let mut transient = Vec::with_capacity(input.len());
        let mut output = Vec::with_capacity(input.len());

        let mut encrypter = Encrypter::new([], &mut transient).unwrap();
        encrypter.write_all(input.as_slice()).unwrap();
        encrypter.finish().unwrap();
        assert_ne!(input, transient);

        let mut decrypter = Decrypter::new([], transient.as_slice()).unwrap();
        decrypter.read_to_end(&mut output).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_with_drop() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| (u8::MIN..u8::MAX))
            .collect::<Vec<_>>();

        let mut transient = Vec::with_capacity(input.len());
        let mut output = Vec::with_capacity(input.len());

        {
            let mut encrypter = Encrypter::new([], &mut transient).unwrap();
            encrypter.write_all(input.as_slice()).unwrap();
        }
        assert_ne!(input, transient);

        let mut decrypter = Decrypter::new([], transient.as_slice()).unwrap();
        decrypter.read_to_end(&mut output).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn different_block_size() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| (u8::MIN..u8::MAX))
            .collect::<Vec<_>>();

        let mut transient = Vec::with_capacity(input.len());
        let mut output = Vec::with_capacity(input.len());

        let mut encrypter = Encrypter::with_chunk([], &mut transient, 256).unwrap();
        encrypter.write_all(input.as_slice()).unwrap();
        encrypter.finish().unwrap();
        assert_ne!(input, transient);

        let mut decrypter = Decrypter::with_chunk([], transient.as_slice(), 128).unwrap();
        let err = decrypter.read_to_end(&mut output).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert_eq!(err.to_string(), "aead::Error");
    }

    #[test]
    fn variable_chunk() {
        for chunk in [64, 240, 256, 272, 512, 1024, 16 * 1024 * 1024] {
            for chunk in chunk - 1..=chunk + 1 {
                if let Err(err) = std::thread::spawn(move || {
                    let input = (u8::MIN..=u8::MAX)
                        .flat_map(|_| (u8::MIN..u8::MAX))
                        .collect::<Vec<_>>();

                    let mut transient = Vec::with_capacity(input.len());
                    let mut output = Vec::with_capacity(input.len());

                    eprintln!("Chunk {chunk}");
                    let mut encrypter = Encrypter::with_chunk([], &mut transient, chunk).unwrap();
                    encrypter.write_all(input.as_slice()).unwrap();
                    encrypter.finish().unwrap();
                    assert_ne!(input, transient);

                    let mut decrypter =
                        Decrypter::with_chunk([], transient.as_slice(), chunk).unwrap();
                    decrypter.read_to_end(&mut output).unwrap();
                    assert_eq!(input, output);
                })
                .join()
                {
                    panic!("Chunk {chunk}: {err:?}");
                }
            }
        }
    }

    #[test]
    fn minimum_chunk() {
        for chunk in 0..64 {
            let result = std::thread::spawn(move || {
                let mut buffer = Vec::new();
                let _ = Encrypter::with_chunk([], &mut buffer, chunk).unwrap();
            })
            .join();
            if chunk < 32 {
                assert!(result.is_err(), "Chunk {chunk}: Expected error");
            } else if let Err(err) = result {
                panic!("Chunk {chunk}: {err:?}");
            }
        }
    }
}
