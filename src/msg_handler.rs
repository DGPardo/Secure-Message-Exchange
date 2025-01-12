use rsa::{RsaPrivateKey, RsaPublicKey};
use tokio::{
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
};

use crate::cryptography::{decrypt_message, encrypt_message};

pub struct ListenerState {
    /// The private key of the current client
    this_private_key: RsaPrivateKey,
    /// The TCP half used to receive messages
    channel: OwnedReadHalf,
    /// The channel used to send messages to the sender (tokio) task
    to_sender: UnboundedSender<String>,
}

pub struct SenderState {
    /// The public key of the remote client
    remote_public_key: RsaPublicKey,
    /// The TCP half used to send messages
    channel: OwnedWriteHalf,
    /// The channel used to receive messages from the listener (tokio) task
    from_listener: UnboundedReceiver<String>,
}

pub async fn listener_handler(
    this_private_key: RsaPrivateKey,
    channel: OwnedReadHalf,
    to_sender: UnboundedSender<String>,
    remote_alias: String,
) {
    let mut state = ListenerState {
        this_private_key,
        channel,
        to_sender,
    };

    let mut stdout_stdin = tokio::task::JoinSet::new();

    stdout_stdin.spawn(async move {
        loop {
            let stdin = io::stdin();
            let mut reader = BufReader::new(stdin).lines();
            while let Ok(Some(input)) = reader.next_line().await {
                state
                    .to_sender
                    .send(input.trim().to_string())
                    .expect("Failed to send message to sender");
            }
        }
    });

    stdout_stdin.spawn(async move {
        loop {
            let msg = receive_and_decrypt_msg(&mut state.channel, &state.this_private_key)
                .await
                .expect("Failed to receive and decrypt message");
            println!("[{}]: {}", remote_alias, msg);
        }
    });

    stdout_stdin.join_all().await;
}

pub async fn sender_handle(
    remote_public_key: RsaPublicKey,
    channel: OwnedWriteHalf,
    from_listener: UnboundedReceiver<String>,
) {
    let mut state = SenderState {
        remote_public_key,
        channel,
        from_listener,
    };

    loop {
        let message = state
            .from_listener
            .recv()
            .await
            .expect("Failed to gather reply to last received message");
        encrypt_and_send_msg(&mut state.channel, &state.remote_public_key, message)
            .await
            .expect("Failed to send message");
    }
}

pub async fn receive_msg(
    receiver: &mut OwnedReadHalf,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let nbytes = receiver.read_u32_le().await?;
    let mut buffer = vec![0; nbytes as usize];
    receiver.read_exact(&mut buffer).await?;
    Ok(buffer)
}

pub async fn send_msg(
    sender: &mut OwnedWriteHalf,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    sender.write_u32_le(data.len() as u32).await?;
    sender.write_all(data).await?;
    sender.flush().await?;
    Ok(())
}

pub async fn receive_and_decrypt_msg(
    receiver: &mut OwnedReadHalf,
    private_key: &RsaPrivateKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let msg = receive_msg(receiver).await?;
    let msg = decrypt_message(private_key, msg)?;
    Ok(String::from_utf8(msg)?)
}

pub async fn encrypt_and_send_msg(
    sender: &mut OwnedWriteHalf,
    public_key: &RsaPublicKey,
    msg: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let msg = encrypt_message(public_key, msg.as_bytes());
    send_msg(sender, &msg).await?;
    Ok(())
}
