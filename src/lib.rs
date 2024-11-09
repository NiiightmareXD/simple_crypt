//! # Simple Crypt
//!
//! `simple_crypt` is a high-level library to encrypt and decrypt data
//!
//! For encryption it uses [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) and [Argon2](https://en.wikipedia.org/wiki/Argon2)
//!
//! ## Usage
//!
//! add this to Cargo.toml:
//!
//! ```toml
//! simple_crypt = "*"
//! ```
//!
//! ## Examples
//!
//! ```no_run
//! // Encrypting
//!
//! use simple_crypt::encrypt;
//! let encrypted_data = encrypt(b"example text", b"example password").expect("Failed to encrypt");
//!
//! // Decrypting
//!
//! use simple_crypt::decrypt;
//! let data = decrypt(&encrypted_data, b"example password").expect("Failed to decrypt");
//! ```
//!
//! And there are other functions to encrypt files or folders see the [documentation](https://docs.rs/simple_crypt)
//!
//! [Documentation](https://docs.rs/simple_crypt)
//! [Repository](https://github.com/NiiightmareXD/simple_crypt)
//!

use std::{fs, io, path::Path};

use argon2::Config;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, rand_core::RngCore, Aead, OsRng},
    AeadCore, ChaCha20Poly1305, KeyInit, Nonce,
};
use log::{info, trace};
use serde_derive::{Deserialize, Serialize};
use tar::{Archive, Builder};
use thiserror::Error;

#[derive(Serialize, Deserialize)]
struct PrecryptorFile {
    data: Vec<u8>,
    nonce: [u8; 12],
    salt: [u8; 32],
}
#[derive(Error, Debug)]
pub enum EncryptError {
    #[error("failed to generate key from password")]
    Hashing(argon2::Error),
    #[error("error running chacha20poly1305 on data")]
    Cipher(chacha20poly1305::Error),
    #[error("error serializing data to binary format")]
    Serialize(bincode::Error),
}
/// Encrypts some data and returns the result
///
/// # Examples
///
/// ```no_run
/// use simple_crypt::encrypt;
///
/// let encrypted_data = encrypt(b"example text", b"example password").expect("Failed to encrypt");
/// // and now you can write it to a file:
/// // fs::write("encrypted_text.txt", encrypted_data).expect("Failed to write to file");
/// ```
///
pub fn encrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>, EncryptError> {
    trace!("Generating salt");
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let config = Config {
        hash_length: 32,
        ..Default::default()
    };

    trace!("Generating key");
    let password = argon2::hash_raw(password, &salt, &config).map_err(EncryptError::Hashing)?;
    let key = GenericArray::from_slice(&password);
    let cipher = ChaCha20Poly1305::new(key);

    trace!("Generating nonce");
    let nonce = ChaCha20Poly1305::generate_nonce(OsRng);

    info!("Encrypting");
    let ciphertext = cipher
        .encrypt(&nonce, data.as_ref())
        .map_err(EncryptError::Cipher)?;
    let file = PrecryptorFile {
        data: ciphertext,
        nonce: nonce.into(),
        salt,
    };

    trace!("Encoding");
    let encoded: Vec<u8> = bincode::serialize(&file).map_err(EncryptError::Serialize)?;

    Ok(encoded)
}
#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("failed to generate decryption key from password")]
    Hashing(argon2::Error),
    #[error("failed to deserialize encrypted file from binary format")]
    Deserialize(bincode::Error),
    #[error("error decrypting with chacha20poly1305 (possibly invalid password)")]
    Cipher(chacha20poly1305::Error),
}
/// Decrypts some data and returns the result
///
/// # Examples
///
/// ```no_run
/// use simple_crypt::{encrypt, decrypt};
///
/// let encrypted_data = encrypt(b"example text", b"example password").expect("Failed to encrypt");
///
/// let data = decrypt(&encrypted_data, b"example passowrd").expect("Failed to decrypt");
/// // and now you can print it to stdout:
/// // println!("data: {}", String::from_utf8(data.clone()).expect("Data is not a utf8 string"));
/// // or you can write it to a file:
/// // fs::write("text.txt", data).expect("Failed to write to file");
/// ```
///
pub fn decrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>, DecryptError> {
    trace!("Decoding");
    let decoded: PrecryptorFile = bincode::deserialize(data).map_err(DecryptError::Deserialize)?;

    let config = Config {
        hash_length: 32,
        ..Default::default()
    };

    trace!("Generating key");
    let password =
        argon2::hash_raw(password, &decoded.salt, &config).map_err(DecryptError::Hashing)?;

    let key = GenericArray::from_slice(&password);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&decoded.nonce);

    info!("Decrypting");
    let text = cipher
        .decrypt(nonce, decoded.data.as_ref())
        .map_err(DecryptError::Cipher)?;
    Ok(text)
}
#[derive(Error, Debug)]
pub enum FsEncryptError {
    #[error("error writing data to file system")]
    Fs(io::Error),
    #[error("error encrypting file contents")]
    Encrypt(EncryptError),
}
/// Encrypts file data and outputs it to the specified output file
///
/// # Examples
///
/// ```no_run
/// use simple_crypt::encrypt_file;
/// use std::path::Path;
///
/// encrypt_file(Path::new("example.txt"), Path::new("encrypted_example.txt"), b"example passwprd").expect("Failed to encrypt the file");
/// // Now the encrypted_example.txt is encrypted
/// ```
///
pub fn encrypt_file(
    path: &Path,
    output_path: &Path,
    password: &[u8],
) -> Result<(), FsEncryptError> {
    trace!("Reading file");
    let data = fs::read(path).map_err(FsEncryptError::Fs)?;
    let encrypted_data = encrypt(&data, password).map_err(FsEncryptError::Encrypt)?;
    trace!("Writing to file");
    fs::write(output_path, encrypted_data).map_err(FsEncryptError::Fs)?;
    Ok(())
}

/// Decrypts file data and output it to the specified output file
///
/// # Examples
///
/// ```no_run
/// use simple_crypt::decrypt_file;
/// use std::path::Path;
///
/// decrypt_file(Path::new("encrypted_example.txt"), Path::new("example.txt"), b"example passwprd").expect("Failed to decrypt the file");
/// // Now the example.txt is decrypted
/// ```
///
#[derive(Error, Debug)]
pub enum FsDecryptError {
    #[error("error writing encrypted data to file system")]
    Fs(io::Error),
    #[error("error decrypting file contents")]
    Decrypt(DecryptError),
}
pub fn decrypt_file(
    path: &Path,
    output_path: &Path,
    password: &[u8],
) -> Result<(), FsDecryptError> {
    trace!("Reading file");
    let encrypted_data = fs::read(path).map_err(FsDecryptError::Fs)?;
    let data = decrypt(&encrypted_data, password).map_err(FsDecryptError::Decrypt)?;
    trace!("Writing to file");
    fs::write(output_path, data).map_err(FsDecryptError::Fs)?;
    Ok(())
}
#[derive(Error, Debug)]
pub enum EncryptDirectoryError {
    #[error("error creating archive to encrypt")]
    Archive(io::Error),
    #[error("no filename found for path")]
    NoFilename,
    #[error("error encrypting archive contents")]
    Encrypt(EncryptError),
    #[error("error writing encrypted archive to file")]
    Fs(io::Error),
}
/// Encrypts a directory and outputs it to the specified output file
///
/// note: the output is a file but when you decrypt it, it will be a directory again it's simply an encrypted tar file
///
/// # Examples
///
/// ```no_run
/// use simple_crypt::encrypt_directory;
/// use std::path::Path;
///
/// encrypt_directory(Path::new("example"), Path::new("example.dir"), b"example password").expect("Failed to encrypt directory");
/// // Now the example.dir is encrypted
/// ```
///
pub fn encrypt_directory(
    path: &Path,
    output_path: &Path,
    password: &[u8],
) -> Result<(), EncryptDirectoryError> {
    let mut archive_output = Vec::new();
    let mut archive = Builder::new(&mut archive_output);

    trace!("Adding folder to file");
    archive
        .append_dir_all(
            path.file_name().ok_or(EncryptDirectoryError::NoFilename)?,
            path,
        )
        .map_err(EncryptDirectoryError::Archive)?;

    let data = archive
        .into_inner()
        .map_err(EncryptDirectoryError::Archive)?;
    let encrypted_data = encrypt(data, password).map_err(EncryptDirectoryError::Encrypt)?;
    trace!("Writing to file");
    fs::write(output_path, encrypted_data).map_err(EncryptDirectoryError::Fs)?;
    Ok(())
}
#[derive(Error, Debug)]
pub enum DecryptDirectoryError {
    #[error("error reading encrypted data")]
    Fs(io::Error),
    #[error("error decrypting archive")]
    Decrypt(DecryptError),
    #[error("error unpacking archive")]
    Archive(io::Error),
}
/// Decrypts a directory and extracts it to the specified output directory
///
/// note: the encrypted directory is a file but when its decrypted it will be a directory and the output path is not what the folder name should be its where to extract the file
///
/// # Examples
///
/// ```no_run
/// use simple_crypt::decrypt_directory;
/// use std::path::Path;
///
/// decrypt_directory(Path::new("example.dir"), Path::new("example"), b"example password").expect("Failed to decrypt directory");
/// // Now the example.txt is decrypted
/// ```
///
pub fn decrypt_directory(
    path: &Path,
    output_path: &Path,
    password: &[u8],
) -> Result<(), DecryptDirectoryError> {
    trace!("Reading from file");
    let encrypted_data = fs::read(path).map_err(DecryptDirectoryError::Fs)?;
    let data = decrypt(&encrypted_data, password).map_err(DecryptDirectoryError::Decrypt)?;

    let mut archive: Archive<&[u8]> = Archive::new(data.as_ref());

    trace!("Extracting file");
    archive
        .unpack(output_path)
        .map_err(DecryptDirectoryError::Archive)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data() {
        let encrypted_data = encrypt(b"test", b"test").expect("Failed to encrypt");
        let data = decrypt(&encrypted_data, b"test").expect("Failed to decrypt");
        assert_eq!(data, b"test");
    }

    #[test]
    fn file() {
        fs::write("test.txt", "test").expect("Failed to write to file");
        encrypt_file(Path::new("test.txt"), Path::new("test.txt"), b"test")
            .expect("Failed to encrypt the file");
        decrypt_file(Path::new("test.txt"), Path::new("test.txt"), b"test")
            .expect("Failed to decrypt the file");
        let data = fs::read("test.txt").expect("Failed to read file");
        assert_eq!(data, b"test");
        fs::remove_file("test.txt").expect("Failed to remove the test file");
    }

    #[test]
    fn directory() {
        fs::create_dir("test").expect("Failed to create directory");
        fs::write("test/test.txt", "test").expect("Failed to write to file");
        encrypt_directory(Path::new("test"), Path::new("test.dir"), b"test")
            .expect("Failed to encrypt directory");
        fs::remove_dir_all("test").expect("Failed to remove test directory");
        decrypt_directory(Path::new("test.dir"), Path::new("."), b"test")
            .expect("Failed to decrypt directory");
        fs::remove_file("test.dir").expect("Failed to remove file");
        fs::remove_dir_all("test").expect("Failed to remove test directory");
    }
}
