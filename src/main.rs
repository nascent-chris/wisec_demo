use async_channel::{Receiver, Sender};
use futures::channel;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

use anyhow::anyhow;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = cipher
        .encrypt(&nonce, b"plaintext message".as_ref())
        .map_err(|e| anyhow!(e))?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|e| anyhow!(e))?;

    assert_eq!(&plaintext, b"plaintext message");

    tracing::info!("plaintext: {}", std::str::from_utf8(&plaintext)?);
    tracing::info!("ciphertext: {}", hex::encode(ciphertext));

    let txs = (0..10)
        .into_iter()
        .map(|id| {
            let (tx, rx) = async_channel::unbounded();

            Node::new(id, rx).init();

            tx
        })
        .collect::<Vec<_>>();

    loop {
        for tx in txs.iter() {
            tx.send(b"hello".to_vec()).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }

    Ok(())
}

struct Node {
    id: u64,
    recv: Receiver<Vec<u8>>,
}

impl Node {
    pub fn new(id: u64, recv: Receiver<Vec<u8>>) -> Self {
        Self { id, recv }
    }

    pub fn init(&self) {
        let recv = self.recv.clone();
        let id = self.id;
        tokio::spawn(async move {
            loop {
                let msg = recv.recv().await.unwrap();
                tracing::info!("{} received: {}", id, hex::encode(msg));
            }
        });
    }
}
