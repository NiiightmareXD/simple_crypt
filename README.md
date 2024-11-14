# Simple Crypt

A simple and high-level rust library to encrypt and decrypt texts, files, folders and any data with it
For encryption, it uses [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) and [Argon2](https://en.wikipedia.org/wiki/Argon2)

## Usage

add this package to your Cargo.toml by running: `cargo add simple_crypt`

## Examples

Encrypting

```rust
let encrypted_data = encrypt(b"example text", b"example passowrd").expect("Failed to encrypt");
```

Decrypting

```rust
let data = decrypt(&encrypted_data, b"example passowrd").expect("Failed to decrypt");
```

And there are other functions to encrypt files or folders see the [documentation](https://docs.rs/simple_crypt)

Go to [Documentation](https://docs.rs/simple_crypt) | [Repository](https://github.com/NiiightmareXD/simple_crypt)
