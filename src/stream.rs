//! Stream support for AES-GCM-SIV 256-bits encrypting and decrypting in chunks.
//!
//! The chunks are counted as used when generating the nonce of the next chunk. Therefore, it is
//! important that the [`Encrypter`] and [`Decrypter`] use the same chunk size.
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
//! let mut encrypter = crypter::stream::DefautEncrypter::new(key, std::io::stdout())
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
//! let decrypter = crypter::stream::DefautDecrypter::new(key, std::io::stdin())
//!     .expect("Failed to read from stdin");
//! let reader = std::io::BufReader::new(decrypter);
//!
//! for line in reader.lines() {
//!     let line = line.expect("Failed to read from stdin");
//!     println!("{line}");
//! }
//! ```

/// The default chunk size for encryption. That is, 128 KiB
pub const DEFAULT_CHUNK: usize = 128 * 1024;
/// Alias to an [`Encrypter`] using the [`DEFAULT_CHUNK`]
pub type DefautEncrypter<Out> = Encrypter<Out, DEFAULT_CHUNK>;
/// Alias to a [`Decrypter`] using the [`DEFAULT_CHUNK`]
pub type DefautDecrypter<Out> = Decrypter<Out, DEFAULT_CHUNK>;

const TAG_LEN: usize = std::mem::size_of::<aes_gcm_siv::Tag>();

/// A streaming AES-GCM-SIV 256-bits encrypter.
///
/// It uses the [`Write`](std::io::Write) trait to provide streaming, while internally keeping a
/// buffer of `CHUNK` bytes in length to encrypt as a single message.
///
/// It will auto-finalize on drop, but will fail silently in that case. To get any errors that may
/// happen while finalizing, explicitly call [`finish`](Encrypter::finish)
///
/// There is a buffer of `CHUNK` size bytes that is encrypted as a single message. This size should
/// match the size used by a [`Decrypter`].
///
/// # Examples
///
/// ```no_run
/// # fn get_key() -> &'static [u8] { &[] }
/// use std::io::{BufRead, Write};
///
/// let key = get_key();
/// let mut encrypter = crypter::stream::DefautEncrypter::new(key, std::io::stdout())
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
pub struct Encrypter<Out, const CHUNK: usize>
where
    Out: std::io::Write,
{
    stream: Option<aead::stream::EncryptorLE31<aes_gcm_siv::Aes256GcmSiv>>,
    buffer: Vec<u8>,
    output: Out,
}

impl<Out, const CHUNK: usize> Encrypter<Out, CHUNK>
where
    Out: std::io::Write,
{
    const MAX_CAP: usize = CHUNK - TAG_LEN;

    /// Creates a new [`Encrypter`] using the writer `output` and chunk size `CHUNK`.
    ///
    /// **Note:** There is no derivation of the key. It is simply hashed to allow variable lenghts.
    /// It is assumed that all security precautions were taken with the `key` before calling this function.
    ///
    /// # Errors
    ///
    /// When initializing, the [`Encrypter`] will write a few bytes to `output`. If any error happens at
    /// that stage, this function will fail.
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
        let buffer = Vec::with_capacity(CHUNK);

        Ok(Self {
            stream,
            buffer,
            output,
        })
    }

    /// Finalizes the stream by encrypting any reamining bytes and setting the `last` flag,
    /// flushing the output, and dropping this [`Encrypter`].
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

impl<Out, const CHUNK: usize> std::io::Write for Encrypter<Out, CHUNK>
where
    Out: std::io::Write,
{
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        let mut sent = 0;
        let mut capacity = Self::MAX_CAP.saturating_sub(self.buffer.len());

        while buf.len() > capacity {
            self.buffer.extend_from_slice(&buf[..capacity]);
            self.flush_block()?;

            buf = &buf[capacity..];
            sent += capacity;
            capacity = Self::MAX_CAP;
        }

        self.buffer.extend_from_slice(buf);

        Ok(sent + self.buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buffer.len() == Self::MAX_CAP {
            self.flush_block()?;
        }
        self.output.flush()
    }
}

impl<Out, const CHUNK: usize> Drop for Encrypter<Out, CHUNK>
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
/// It uses the [`Read`](std::io::Read) trait to provide streaming, while internally keeping a
/// buffer of `CHUNK` bytes in length to decrypt as a single message.
///
/// There is a buffer of `CHUNK` size bytes that is encrypted as a single message. This size should
/// match the size used by a [`Encrypter`].
///
/// # Examples
///
/// ```no_run
/// # fn get_key() -> &'static [u8] { &[] }
/// use std::io::BufRead;
///
/// let key = get_key();
/// let decrypter = crypter::stream::DefautDecrypter::new(key, std::io::stdin())
///     .expect("Failed to read from stdin");
/// let reader = std::io::BufReader::new(decrypter);
///
/// for line in reader.lines() {
///     let line = line.expect("Failed to read from stdin");
///     println!("{line}");
/// }
/// ```
pub struct Decrypter<In, const CHUNK: usize>
where
    In: std::io::Read,
{
    stream: Option<aead::stream::DecryptorLE31<aes_gcm_siv::Aes256GcmSiv>>,
    buffer: Vec<u8>,
    cursor: usize,
    input: In,
}

impl<In, const CHUNK: usize> Decrypter<In, CHUNK>
where
    In: std::io::Read,
{
    /// Creates a new [`Decrypter`] using the reader `input` and chunk size `CHUNK`. The chunk
    /// buffer will be kept on the stack.
    ///
    /// **Note:** There is no derivation of the key. It is simply hashed to allow variable lenghts.
    /// It is assumed that all security precautions were taken with the `key` before calling this function.
    ///
    /// # Errors
    ///
    /// When initializing, the [`Decrypter`] will read the first few bytes of `input`. If any error
    /// happens at that stage, this function will fail.
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
        let buffer = Vec::with_capacity(CHUNK);

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

impl<In, const CHUNK: usize> std::io::Read for Decrypter<In, CHUNK>
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

        let mut encrypter = DefautEncrypter::new([], &mut transient).unwrap();
        encrypter.write_all(input.as_slice()).unwrap();
        encrypter.finish().unwrap();
        assert_ne!(input, transient);

        let mut decrypter = DefautDecrypter::new([], transient.as_slice()).unwrap();
        decrypter.read_to_end(&mut output).unwrap();
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
            let mut encrypter = DefautEncrypter::new([], &mut transient).unwrap();
            encrypter.write_all(input.as_slice()).unwrap();
        }
        assert_ne!(input, transient);

        let mut decrypter = DefautDecrypter::new([], transient.as_slice()).unwrap();
        decrypter.read_to_end(&mut output).unwrap();
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

        let mut encrypter = DefautEncrypter::new([], &mut transient).unwrap();
        encrypter.write_all(input.as_slice()).unwrap();
        encrypter.finish().unwrap();
        assert_ne!(input, transient);

        let mut decrypter = Decrypter::<_, CHUNK>::new([], transient.as_slice()).unwrap();
        let err = decrypter.read_to_end(&mut output).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert_eq!(err.to_string(), "aead::Error");
    }
}
