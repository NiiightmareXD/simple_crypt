//! # Simple Crypt
//!
//! `simple_crypt` is a high-level library to encrypt and decrypt data
//!
//! For encryption it uses [AES-GCM-SIV-256](https://en.wikipedia.org/wiki/AES-GCM-SIV) and [Argon2](https://en.wikipedia.org/wiki/Argon2)
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

use std::{
    fs::{self, File},
    path::Path,
};

use anyhow::{anyhow, Context, Result};
use argon2::Config;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, rand_core::RngCore, Aead, OsRng},
    AeadCore, ChaCha20Poly1305, KeyInit, Nonce,
};
use log::{info, trace};
use serde_derive::{Deserialize, Serialize};
use tar::{Archive, Builder};

#[derive(Serialize, Deserialize)]
struct PrecryptorFile {
    data: Vec<u8>,
    nonce: [u8; 12],
    salt: [u8; 32],
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
pub fn encrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    trace!("Generating salt");
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let config = Config {
        hash_length: 32,
        ..Default::default()
    };

    trace!("Generating key");
    let password = argon2::hash_raw(password, &salt, &config)
        .with_context(|| "Failed to generate key from password")?;
    let key = GenericArray::from_slice(&password);
    let cipher = ChaCha20Poly1305::new(&key);

    trace!("Generating nonce");
    let nonce = ChaCha20Poly1305::generate_nonce(OsRng);

    info!("Encrypting");
    let ciphertext = match cipher.encrypt(&nonce, data.as_ref()) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return Err(anyhow!("Failed to encrypt data -> invalid password")),
    };

    let file = PrecryptorFile {
        data: ciphertext,
        nonce: nonce.into(),
        salt,
    };

    trace!("Encoding");
    let encoded: Vec<u8> = bincode::serialize(&file).with_context(|| "Failed to decode data")?;

    Ok(encoded)
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
pub fn decrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    trace!("Decoding");
    let decoded: PrecryptorFile =
        bincode::deserialize(data).with_context(|| "Failed to decode data")?;

    let config = Config {
        hash_length: 32,
        ..Default::default()
    };

    trace!("Generating key");
    let password = argon2::hash_raw(password, &decoded.salt, &config)
        .with_context(|| "Failed to generate key from password")?;

    let key = GenericArray::from_slice(&password);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(&decoded.nonce);

    info!("Decrypting");
    let text = match cipher.decrypt(&nonce, decoded.data.as_ref()) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return Err(anyhow!("Failed to encrypt data -> invalid password")),
    };

    Ok(text)
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
pub fn encrypt_file(path: &Path, output_path: &Path, password: &[u8]) -> Result<()> {
    trace!("Reading file");
    let data = fs::read(path).with_context(|| "Failed to read the file")?;
    let encrypted_data = encrypt(&data, password).with_context(|| "Failed to encrypt data")?;
    trace!("Writing to file");
    fs::write(output_path, encrypted_data).with_context(|| "Failed to write to file")?;
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
pub fn decrypt_file(path: &Path, output_path: &Path, password: &[u8]) -> Result<()> {
    trace!("Reading file");
    let encrypted_data = fs::read(path).with_context(|| "Failed to read the file")?;
    let data = decrypt(&encrypted_data, password).with_context(|| "Failed to decrypt data")?;
    trace!("Writing to file");
    fs::write(output_path, data).with_context(|| "Failed to write to file")?;
    Ok(())
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
pub fn encrypt_directory(path: &Path, output_path: &Path, password: &[u8]) -> Result<()> {
    trace!("Creating temporarily file");
    let file = File::create(format!("{}.tmp", output_path.display()))
        .with_context(|| "Failed to create file")?;
    let mut archive = Builder::new(file);

    trace!("Adding folder to file");
    archive
        .append_dir_all(
            path.file_name().with_context(|| "Failed to get filename")?,
            path,
        )
        .with_context(|| "Failed to add the folder to the file")?;

    trace!("Finishing writing to file");
    archive
        .finish()
        .with_context(|| "Failed to finish writing the archive")?;

    trace!("Reading from temporarily file");
    let data = fs::read(format!("{}.tmp", output_path.display()))
        .with_context(|| "Failed to read the file")?;

    trace!("Removing temporarily file");
    fs::remove_file(format!("{}.tmp", output_path.display()))
        .with_context(|| "Failed to remove the temporarily file")?;

    let encrypted_data = encrypt(&data, password).with_context(|| "Failed to encrypt data")?;

    trace!("Writing to file");
    fs::write(output_path, encrypted_data).with_context(|| "Failed to write to file")?;
    Ok(())
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
pub fn decrypt_directory(path: &Path, output_path: &Path, password: &[u8]) -> Result<()> {
    trace!("Reading from file");
    let encrypted_data = fs::read(path).with_context(|| "Failed to read the file")?;
    let data = decrypt(&encrypted_data, password).with_context(|| "Failed to decrypt data")?;

    trace!("Writing to temporarily file");
    fs::write(format!("{}.tmp", output_path.display()), data)
        .with_context(|| "Failed to write to file")?;

    trace!("Opening file");
    let file = File::open(format!("{}.tmp", output_path.display()))
        .with_context(|| "Failed to open file")?;
    let mut archive = Archive::new(file);

    trace!("Extracting file");
    archive
        .unpack(output_path)
        .with_context(|| "Failed to extract directory from file")?;

    trace!("Removing temporarily file");
    fs::remove_file(format!("{}.tmp", output_path.display()))
        .with_context(|| "Failed to remove the temporarily file")?;
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
