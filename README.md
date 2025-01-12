# Secure Message Exchange

This repository is a small project designed to familiarize myself with the basics of secure message exchange. It demonstrates core concepts like message encryption, decryption, and secure transmission using Rust. **Disclaimer: This implementation is far from perfect and should not be considered a role model for any production environment. It is intended solely for educational purposes.**


## Features

- **Message Transmission**: Send and receive messages over a TCP connection.
- **Message Encryption**: Encrypt messages using RSA public/private key pairs.
- **Message Decryption**: Decrypt received messages securely.
- **Metadata Handling**: Includes message size headers for proper parsing.

## Dependencies

This project uses the following external crates:

- [`clap`](https://crates.io/crates/clap): For parsing command-line arguments.
- [`rsa`](https://crates.io/crates/rsa): For RSA encryption and decryption.
- [`tokio`](https://crates.io/crates/tokio): For asynchronous networking.

## Code Structure

- `cryptography`: Contains helper functions for RSA encryption and decryption.
- `msg_handler`: Manages sending and receiving messages, including handling size headers and interfacing with the `cryptography` module.
- `main.rs`: The entry point of the application.

## How It Works

1. **Setup**:
   - A public/private RSA key pair is used for encrypting and decrypting messages.
   - The `TcpListener` and `TcpStream` from the `tokio` crate handle networking.

2. **Sending a Message**:
   - The message is encrypted using the recipient's public key.
   - A size header is prepended to the encrypted message.
   - The complete message is transmitted over the network.

3. **Receiving a Message**:
   - The size header is read first to allocate the correct buffer.
   - The encrypted message is read and then decrypted using the private key.
