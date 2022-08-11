//! # Simple Crypt
//!
//! `simple_crypt` is a high level library to encrypt and decrypt data
//!
//! For security it uses aes-gcm-siv-256 and argon2
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
//! ```rusr
//! // Encrypting
//!
//! use simple_crypt::encrypt;
//! let encrypted_data = encrypt(b"example text", "example passowrd").expect("Failed to encrypt");
//!
//! // Decrypting
//!
//! use simple_crypt::decrypt;
//! let data = decrypt(&encrypted_data, "example passowrd").expect("Failed to decrypt");
//! ```
//!
//! [Documentation](https://docs.rs/simple-crypt)
//! [Repository](https://github.com/NiiightmareXD/simple_crypt)
//!

use aes_gcm_siv::{
    aead::{generic_array::GenericArray, rand_core::RngCore, Aead, OsRng},
    Aes256GcmSiv, KeyInit, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::Config;
use log::{info, trace};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct PrecryptorFile {
    data: Vec<u8>,
    nonce: [u8; 12],
    salt: [u8; 32],
}

/// Encrypts some data and return the result
///
/// # Examples
///
/// ```rust
/// use simple_crypt::encrypt;
///
/// let encrypted_data = encrypt(b"example text", b"example passowrd").expect("Failed to encrypt");
/// // and now you can write it to a file:
/// // fs::write("test.enc", encrypted_data).expect("Failed to write to file");
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
    let cipher = Aes256GcmSiv::new(key);

    trace!("Generating nonce");
    let mut nonce_rand = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_rand);
    let nonce = Nonce::from_slice(&nonce_rand);

    info!("Encrypting");
    let ciphertext = match cipher.encrypt(nonce, data.as_ref()) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return Err(anyhow!("Failed to encrypt data -> invalid password")),
    };

    let file = PrecryptorFile {
        data: ciphertext,
        nonce: nonce_rand,
        salt,
    };

    trace!("Encoding");
    let encoded: Vec<u8> = bincode::serialize(&file).with_context(|| "Failed to decode data")?;

    Ok(encoded)
}

/// Decrypts some data and return the result
///
/// # Examples
///
/// ```rust
/// use simple_crypt::{encrypt, decrypt};
///
/// let encrypted_data = encrypt(b"example text", b"example passowrd").expect("Failed to encrypt");
///
/// let data = decrypt(&encrypted_data, b"example passowrd").expect("Failed to decrypt");
/// // and now you can print it to stdout:
/// // println!("data: {}", String::from_utf8(data.clone()).expect("Data is not a utf8 string"));
/// // or you can write it to a file:
/// // fs::write("test.txt", data).expect("Failed to write to file");
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
    let cipher = Aes256GcmSiv::new(key);
    let nonce = Nonce::from_slice(&decoded.nonce);

    info!("Decrypting");
    let text = match cipher.decrypt(nonce, decoded.data.as_ref()) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return Err(anyhow!("Failed to encrypt data -> invalid password")),
    };

    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let encrypted_data =
            encrypt(b"example text", b"example passowrd").expect("Failed to encrypt");
        let data = decrypt(&encrypted_data, b"example passowrd").expect("Failed to decrypt");
        assert_eq!(data, b"example text");
    }
}
