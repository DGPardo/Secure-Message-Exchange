mod cryptography;
mod msg_handler;

use clap::Parser;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpListener, TcpStream,
};

use msg_handler::{encrypt_and_send_msg, receive_and_decrypt_msg, receive_msg, send_msg};

#[derive(Parser)]
#[command(name = "SecureChat")]
#[command(version = "1.0")]
#[command(about = "Does awesome things", long_about = None)]
struct Cli {
    #[arg(long, required = true)]
    alias: String,
    #[arg(long, required = true)]
    address: String,
    #[arg(long, required = false, default_value = "8080")]
    port: u16,
}

/// This is a basic CLI application that allows to connect to another user
/// to send and receive secure messages from all the participants.
#[tokio::main]
async fn main() {
    let args = Cli::parse();

    // Generate RSA keypair
    let (private_key, public_key) = cryptography::generate_rsa_keypair(2048);
    println!("Generated RSA keypair");

    // Connect to other client
    let address: Ipv4Addr = args.address.parse().expect("Invalid IP address");

    // Connect to the other client
    // If the connection fails, then the current client will act as a server
    let stream = match TcpStream::connect(SocketAddrV4::new(address, args.port)).await {
        Ok(stream) => stream,
        Err(_) => {
            let listener = match TcpListener::bind(format!("0.0.0.0:{}", args.port).as_str()).await
            {
                Ok(listener) => listener,
                Err(e) => {
                    eprintln!("Failed to bind a TcpListener to the port. Error: {:?}", e);
                    return;
                }
            };
            let (stream, host) = listener.accept().await.unwrap();
            println!(
                "Accepted connection from client {}:{}",
                host.ip(),
                host.port()
            );
            stream
        }
    };

    println!("Connected to client {}:{}", address, args.port);
    let (mut receiver, mut sender) = stream.into_split();

    // Perform the public key exchange
    let remote_public_key = match public_key_exchange(&mut sender, &mut receiver, public_key).await
    {
        Ok(remote_public_key) => remote_public_key,
        Err(e) => {
            eprintln!("Failed to perform the public key exchange. Error: {:?}", e);
            return;
        }
    };

    let remote_alias = match alias_exchange(
        &mut sender,
        &mut receiver,
        &remote_public_key,
        &private_key,
        args.alias,
    )
    .await
    {
        Ok(remote_alias) => remote_alias,
        Err(e) => {
            eprintln!("Failed to perform the alias exchange. Error: {:?}", e);
            return;
        }
    };

    println!("Public key exchange completed");

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let listener_handle = tokio::spawn(msg_handler::listener_handler(
        private_key,
        receiver,
        tx.clone(),
        remote_alias,
    ));
    let sender_handle = tokio::spawn(msg_handler::sender_handle(remote_public_key, sender, rx));

    println!(); println!(); // Adding some space to separate intialization from chat

    tokio::select! {
        _ = listener_handle => {
            eprintln!("Listener handler has exited");
        }
        _ = sender_handle => {
            eprintln!("Sender handler has exited");
        }
    }
}

async fn public_key_exchange(
    writer: &mut OwnedWriteHalf,
    reader: &mut OwnedReadHalf,
    public_key: RsaPublicKey,
) -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
    if let Ok(serialized) = public_key.to_pkcs1_der() {
        // only non-encrypted message that will be sent
        send_msg(writer, serialized.as_bytes()).await?;
    } else {
        eprintln!("Failed to serialize the public key");
        return Err("Failed to serialize the public key".into());
    }

    // Receive the public key from the other user
    let data = receive_msg(reader).await?;
    let remote_public_key = RsaPublicKey::from_pkcs1_der(&data)?;

    Ok(remote_public_key)
}

async fn alias_exchange(
    writer: &mut OwnedWriteHalf,
    reader: &mut OwnedReadHalf,
    remote_public_key: &RsaPublicKey,
    this_private_key: &RsaPrivateKey,
    this_alias: String,
) -> Result<String, Box<dyn std::error::Error>> {
    // Encrypt the alias
    let sender = encrypt_and_send_msg(writer, remote_public_key, this_alias);
    let receiver = receive_and_decrypt_msg(reader, this_private_key);

    let (_, r) = tokio::join!(sender, receiver);

    let remote_alias = r?;
    println!("Connected to user: {}", remote_alias);
    Ok(remote_alias)
}
