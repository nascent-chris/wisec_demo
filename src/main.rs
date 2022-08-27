use std::time::SystemTime;

use async_channel::Receiver;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

use anyhow::anyhow;
use chacha20poly1305::consts::U12;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};

const KEY_SIZE: usize = 32;
const KEY: [u8; KEY_SIZE] = [42u8; KEY_SIZE];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // build a list of `Node`s and the corresponding `Sender<_>` objects that we will use to communicate with them
    let txs = (0..5)
        .into_iter()
        .map(|id| {
            let (tx, rx) = async_channel::unbounded();
            // create a new `Node` with the given id and give it the receiving end of the channel
            // then call `.init()` to spawn a task for this node to then live on
            Node::new(id, rx).init();

            // return the `Sender<_>` end of the channel to send messages to this node
            tx
        })
        // Collect all of these `Sender<_>` objects into a a `Vec<Sender<_>>`
        .collect::<Vec<_>>();

    // Create the key for this node
    let cipher = ChaCha20Poly1305::new_from_slice(&KEY).map_err(|e| anyhow!(e))?;
    loop {
        // let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let nonce = generate_nonce(0xFF);

        let msg = b"plaintext message bruv";
        let ciphertext = cipher.encrypt(&nonce.into(), msg.as_ref()).unwrap();
        tracing::info!(
            "ciphertext: {}, nonce: {}",
            hex::encode(&ciphertext),
            hex::encode(&nonce)
        );

        // Send our ciphertext, along with the generated nonce, to all of the nodes
        for tx in txs.iter() {
            tx.send((nonce.into(), ciphertext.to_vec())).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }
}

fn generate_nonce(chip_id: u8) -> Nonce {
    let mut nonce_array = GenericArray::<u8, U12>::default();

    let timestamp_mills = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    let timestamp_bits = timestamp_mills.to_le_bytes();
    // lower 48 bits of timestamp only
    let timestamp_bits = &timestamp_bits[0..6];

    // Next 40 bits are random
    let mut rand_bytes = [0u8; 5];
    OsRng.fill_bytes(&mut rand_bytes);
    // tracing::info!("generating random bytes for nonce {:?}", hex::encode(rand_bytes));

    // Final byte is the chip ID
    let id = chip_id;

    // First 6 bytes is timestamp
    nonce_array[6..12].copy_from_slice(&timestamp_bits);
    // Next 5 bytes is random
    nonce_array[1..6].copy_from_slice(&rand_bytes);
    // Final byte is the chip ID
    nonce_array[0] = id;
    nonce_array
}

struct Node {
    id: u8,
    recv: Receiver<(Nonce, Vec<u8>)>,
}

impl Node {
    pub fn new(id: u8, recv: Receiver<(Nonce, Vec<u8>)>) -> Self {
        Self { id, recv }
    }

    // Consumes the `Node` object and spawns a task for it to listen for and decrypt messages
    // NOTE: Because `init()` takes `self` by ownership and not by reference (e.g. `&self`), this function consumes the `Node` object
    pub fn init(self) {
        // each device has its own copy of the same key
        let cipher = ChaCha20Poly1305::new_from_slice(&KEY).unwrap();

        // spawn a task with this node
        tokio::spawn(async move {
            loop {
                let (nonce, msg) = self.recv.recv().await.unwrap();
                let plaintext = cipher.decrypt(&nonce, msg.as_ref()).unwrap();

                tracing::info!(
                    "id {} got plaintext: {}",
                    self.id,
                    std::str::from_utf8(&plaintext).unwrap()
                );
            }
        });
    }
}
