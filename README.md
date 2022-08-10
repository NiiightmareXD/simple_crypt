# simple-crypt

A simple and high level library to encrypt and decrypt text, files and any data with it

## Usage

add this to Cargo.toml:

```toml
simple-crypt = "0.1.4"
```

## Examples

Encrypting

```rust
let encrypted_data = encrypt(b"example text", "example passowrd").expect("Failed to encrypt");
```

Decrypting

```rust
let data = decrypt(&encrypted_data, "example passowrd").expect("Failed to decrypt");
```

Go to [Documentation](https://docs.rs/simple-crypt) | [Repository](https://github.com/NiiightmareXD/simple_crypt)
