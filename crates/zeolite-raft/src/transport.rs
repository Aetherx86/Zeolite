//! Authenticated, encrypted TCP transport between cluster members.
//!
//! Every connection is one-way: a node dials each peer to send, and receives on the
//! connections it accepts. Each side holds a pre-shared cluster key. The handshake
//! exchanges fresh nonces and derives one AEAD key per direction, which rules out
//! replaying traffic across sessions and reflecting a frame back to its sender. Frame
//! nonces are a per-direction counter, which rules out replay and reordering inside a
//! session. Both sides prove possession of the key before any Raft message moves.
//!
//! The pre-shared key authenticates cluster membership. It does not bind a connection
//! to one member, so any key holder can claim any configured node id.

use crate::codec;
use crate::core::{Envelope, NodeId};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;

const MAGIC: &[u8; 8] = b"ZEOLITE1";
const HELLO_LEN: usize = 8 + 8 + 32;
const CONFIRM: &[u8] = b"zeolite-confirm";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_INBOUND_CONNECTIONS: usize = 64;
const AEAD_TAG_LEN: usize = 16;

#[derive(Clone)]
pub struct TransportConfig {
    pub id: NodeId,
    pub peers: BTreeMap<NodeId, String>,
    pub key: [u8; 32],
    /// Upper bound on one encrypted frame. Checked before the frame is buffered.
    pub max_frame: usize,
    /// Outbound queue per peer. Raft tolerates loss, so a full queue drops messages
    /// rather than blocking the consensus loop.
    pub queue: usize,
    pub reconnect_delay: Duration,
}

impl TransportConfig {
    pub fn new(id: NodeId, peers: BTreeMap<NodeId, String>, key: [u8; 32]) -> Self {
        TransportConfig {
            id,
            peers,
            key,
            max_frame: 64 << 20,
            queue: 1024,
            reconnect_delay: Duration::from_millis(100),
        }
    }
}

struct Cipher {
    aead: ChaCha20Poly1305,
    counter: u64,
}

impl Cipher {
    fn new(key: [u8; 32]) -> Self {
        Cipher {
            aead: ChaCha20Poly1305::new(Key::from_slice(&key)),
            counter: 0,
        }
    }

    fn nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        n
    }

    fn seal(&mut self, plain: &[u8]) -> io::Result<Vec<u8>> {
        let n = self.nonce();
        self.aead
            .encrypt(Nonce::from_slice(&n), plain)
            .map_err(|_| io::Error::other("frame encryption failed"))
    }

    fn open(&mut self, sealed: &[u8]) -> io::Result<Vec<u8>> {
        let n = self.nonce();
        self.aead
            .decrypt(Nonce::from_slice(&n), sealed)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame failed authentication"))
    }
}

/// Derives the initiator-to-responder and responder-to-initiator keys.
fn derive_keys(
    psk: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    client_id: NodeId,
    server_id: NodeId,
) -> io::Result<([u8; 32], [u8; 32])> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(client_nonce);
    salt[32..].copy_from_slice(server_nonce);
    let hk = Hkdf::<Sha256>::new(Some(&salt), psk);
    let expand = |label: &[u8]| -> io::Result<[u8; 32]> {
        let mut info = Vec::with_capacity(label.len() + 16);
        info.extend_from_slice(label);
        info.extend_from_slice(&client_id.to_le_bytes());
        info.extend_from_slice(&server_id.to_le_bytes());
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm)
            .map_err(|_| io::Error::other("key derivation failed"))?;
        Ok(okm)
    };
    Ok((expand(b"zeolite/raft/c2s")?, expand(b"zeolite/raft/s2c")?))
}

fn hello(id: NodeId, nonce: &[u8; 32]) -> [u8; HELLO_LEN] {
    let mut out = [0u8; HELLO_LEN];
    out[..8].copy_from_slice(MAGIC);
    out[8..16].copy_from_slice(&id.to_le_bytes());
    out[16..48].copy_from_slice(nonce);
    out
}

fn parse_hello(buf: &[u8; HELLO_LEN]) -> io::Result<(NodeId, [u8; 32])> {
    if &buf[..8] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer sent a bad handshake magic",
        ));
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&buf[8..16]);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&buf[16..48]);
    Ok((NodeId::from_le_bytes(id), nonce))
}

fn fresh_nonce() -> io::Result<[u8; 32]> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(nonce)
}

async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    stream.write_all(&buf).await
}

async fn read_frame(stream: &mut TcpStream, max: usize) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let len = u32::from_le_bytes(len) as usize;
    if len > max.saturating_add(AEAD_TAG_LEN) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds the configured limit",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn client_handshake(
    stream: &mut TcpStream,
    id: NodeId,
    expected_peer: NodeId,
    key: &[u8; 32],
) -> io::Result<Cipher> {
    let nonce = fresh_nonce()?;
    stream.write_all(&hello(id, &nonce)).await?;
    let mut reply = [0u8; HELLO_LEN];
    stream.read_exact(&mut reply).await?;
    let (server_id, server_nonce) = parse_hello(&reply)?;
    if server_id != expected_peer {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "connected to an unexpected node id",
        ));
    }
    let (c2s, s2c) = derive_keys(key, &nonce, &server_nonce, id, server_id)?;
    let mut tx = Cipher::new(c2s);
    let mut rx = Cipher::new(s2c);
    write_frame(stream, &tx.seal(CONFIRM)?).await?;
    let confirm = read_frame(stream, CONFIRM.len()).await?;
    if rx.open(&confirm)? != CONFIRM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer failed key confirmation",
        ));
    }
    Ok(tx)
}

async fn server_handshake(
    stream: &mut TcpStream,
    id: NodeId,
    key: &[u8; 32],
    peers: &BTreeMap<NodeId, String>,
) -> io::Result<(NodeId, Cipher)> {
    let mut first = [0u8; HELLO_LEN];
    stream.read_exact(&mut first).await?;
    let (client_id, client_nonce) = parse_hello(&first)?;
    if !peers.contains_key(&client_id) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection from an unknown node id",
        ));
    }
    let nonce = fresh_nonce()?;
    stream.write_all(&hello(id, &nonce)).await?;
    let (c2s, s2c) = derive_keys(key, &client_nonce, &nonce, client_id, id)?;
    let mut rx = Cipher::new(c2s);
    let mut tx = Cipher::new(s2c);
    let confirm = read_frame(stream, CONFIRM.len()).await?;
    if rx.open(&confirm)? != CONFIRM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer failed key confirmation",
        ));
    }
    write_frame(stream, &tx.seal(CONFIRM)?).await?;
    Ok((client_id, rx))
}

async fn serve_connection(
    mut stream: TcpStream,
    cfg: Arc<TransportConfig>,
    inbound: mpsc::Sender<Envelope>,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let (peer, mut rx) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        server_handshake(&mut stream, cfg.id, &cfg.key, &cfg.peers),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))??;

    loop {
        let sealed = read_frame(&mut stream, cfg.max_frame).await?;
        let plain = rx.open(&sealed)?;
        let mut env = codec::decode(&plain)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        // The sender is whoever completed this handshake, not what the frame claims.
        env.from = peer;
        env.to = cfg.id;
        if inbound.send(env).await.is_err() {
            return Ok(());
        }
    }
}

async fn run_dialer(
    peer: NodeId,
    addr: String,
    cfg: Arc<TransportConfig>,
    mut outbound: mpsc::Receiver<Envelope>,
) {
    let mut pending: Option<Envelope> = None;
    loop {
        let connected = async {
            let mut stream = TcpStream::connect(&addr).await?;
            stream.set_nodelay(true)?;
            let tx = tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                client_handshake(&mut stream, cfg.id, peer, &cfg.key),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))??;
            Ok::<_, io::Error>((stream, tx))
        }
        .await;

        let (mut stream, mut tx) = match connected {
            Ok(pair) => pair,
            Err(_) => {
                tokio::time::sleep(cfg.reconnect_delay).await;
                // Messages queued during an outage are stale. Raft retransmits from
                // current state, so draining beats replaying an old backlog.
                while outbound.try_recv().is_ok() {}
                pending = None;
                if outbound.is_closed() {
                    return;
                }
                continue;
            }
        };

        loop {
            let env = match pending.take() {
                Some(env) => env,
                None => match outbound.recv().await {
                    Some(env) => env,
                    None => return,
                },
            };
            let plain = codec::encode(&env);
            if plain.len() > cfg.max_frame {
                continue;
            }
            let sealed = match tx.seal(&plain) {
                Ok(sealed) => sealed,
                Err(_) => break,
            };
            if write_frame(&mut stream, &sealed).await.is_err() {
                pending = Some(env);
                break;
            }
        }
        tokio::time::sleep(cfg.reconnect_delay).await;
    }
}

pub struct Transport {
    senders: BTreeMap<NodeId, mpsc::Sender<Envelope>>,
    tasks: Vec<JoinHandle<()>>,
    local_addr: SocketAddr,
}

impl Transport {
    /// Starts accepting on `listener` and dialing every configured peer.
    pub fn start(
        cfg: TransportConfig,
        listener: TcpListener,
        inbound: mpsc::Sender<Envelope>,
    ) -> io::Result<Transport> {
        let local_addr = listener.local_addr()?;
        let cfg = Arc::new(cfg);
        let mut senders = BTreeMap::new();
        let mut tasks = Vec::new();

        for (peer, addr) in &cfg.peers {
            let (tx, rx) = mpsc::channel(cfg.queue);
            senders.insert(*peer, tx);
            tasks.push(tokio::spawn(run_dialer(
                *peer,
                addr.clone(),
                cfg.clone(),
                rx,
            )));
        }

        let accept_cfg = cfg.clone();
        tasks.push(tokio::spawn(async move {
            let limit = Arc::new(Semaphore::new(MAX_INBOUND_CONNECTIONS));
            loop {
                let Ok(permit) = limit.clone().acquire_owned().await else {
                    return;
                };
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let cfg = accept_cfg.clone();
                let inbound = inbound.clone();
                tokio::spawn(async move {
                    let _ = serve_connection(stream, cfg, inbound).await;
                    drop(permit);
                });
            }
        }));

        Ok(Transport {
            senders,
            tasks,
            local_addr,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Queues a message for delivery. Messages may be dropped; Raft recovers.
    pub fn send(&self, env: Envelope) {
        if let Some(tx) = self.senders.get(&env.to) {
            let _ = tx.try_send(env);
        }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Message;

    async fn pair(
        key_a: [u8; 32],
        key_b: [u8; 32],
    ) -> (Transport, Transport, mpsc::Receiver<Envelope>) {
        let la = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lb = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (aa, ab) = (la.local_addr().unwrap(), lb.local_addr().unwrap());
        let (tx_a, _rx_a) = mpsc::channel(16);
        let (tx_b, rx_b) = mpsc::channel(16);
        let a = Transport::start(
            TransportConfig::new(1, BTreeMap::from([(2, ab.to_string())]), key_a),
            la,
            tx_a,
        )
        .unwrap();
        let b = Transport::start(
            TransportConfig::new(2, BTreeMap::from([(1, aa.to_string())]), key_b),
            lb,
            tx_b,
        )
        .unwrap();
        (a, b, rx_b)
    }

    fn vote() -> Envelope {
        Envelope {
            from: 1,
            to: 2,
            msg: Message::VoteResp {
                term: 42,
                granted: true,
            },
        }
    }

    #[tokio::test]
    async fn delivers_messages_with_a_matching_key() {
        let (a, _b, mut rx) = pair([7; 32], [7; 32]).await;
        let got = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                a.send(vote());
                if let Ok(Some(env)) =
                    tokio::time::timeout(Duration::from_millis(50), rx.recv()).await
                {
                    return env;
                }
            }
        })
        .await
        .expect("message should arrive");
        assert_eq!(got, vote());
    }

    #[tokio::test]
    async fn rejects_a_peer_with_the_wrong_key() {
        let (a, _b, mut rx) = pair([7; 32], [8; 32]).await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(700);
        while tokio::time::Instant::now() < deadline {
            a.send(vote());
            if let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
                panic!("a message crossed a key mismatch");
            }
        }
    }

    #[test]
    fn directional_keys_differ_and_depend_on_every_input() {
        let (a, b) = derive_keys(&[1; 32], &[2; 32], &[3; 32], 1, 2).unwrap();
        assert_ne!(a, b);
        assert_ne!(
            derive_keys(&[9; 32], &[2; 32], &[3; 32], 1, 2).unwrap().0,
            a
        );
        assert_ne!(
            derive_keys(&[1; 32], &[9; 32], &[3; 32], 1, 2).unwrap().0,
            a
        );
        assert_ne!(
            derive_keys(&[1; 32], &[2; 32], &[9; 32], 1, 2).unwrap().0,
            a
        );
        assert_ne!(
            derive_keys(&[1; 32], &[2; 32], &[3; 32], 9, 2).unwrap().0,
            a
        );
    }

    #[test]
    fn replayed_frames_fail_authentication() {
        let mut tx = Cipher::new([5; 32]);
        let mut rx = Cipher::new([5; 32]);
        let frame = tx.seal(b"hello").unwrap();
        assert_eq!(rx.open(&frame).unwrap(), b"hello");
        assert!(
            rx.open(&frame).is_err(),
            "the same frame must not verify twice"
        );
    }

    #[tokio::test]
    async fn oversized_frame_length_is_rejected_before_allocation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            read_frame(&mut s, 1024).await
        });
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        let result = server.await.unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
