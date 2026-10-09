//! Real loopback UDP stress test: one QUIC connection, 1024 streams, 10 MiB each.

use std::{
    collections::HashSet,
    fmt, fs,
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures::{FutureExt, StreamExt, stream};
use qbase::{
    endpoint::Endpoint,
    param::{ClientParameters, ParameterId, ServerParameters},
    role::Role,
};
use qconnection::{ArcConnection, QuicEndpoint, Scopes, ServerRegistry};
use qprotocol::{AddressBook, Dock, UdpSocket};
use qresolve::{EndpointAddr, Family, Resolve, ResolveFuture, Resolver, Source};
use tls_backend::pki_types::pem::PemObject;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    task::JoinSet,
    time::timeout,
};

type Error = Box<dyn std::error::Error + Send + Sync>;
const FILE_SIZE: usize = 10 * 1024 * 1024;
const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug)]
struct LocalResolver(EndpointAddr);

impl fmt::Display for LocalResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("loopback test resolver")
    }
}

impl Resolve for LocalResolver {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        _: &'a str,
        family: Option<Family>,
    ) -> ResolveFuture<'a> {
        async move {
            let matches = name == "localhost" && family != Some(Family::V6);
            Ok(stream::iter(matches.then_some((Source::System, self.0))).boxed())
        }
        .boxed()
    }
}

struct LocalSocket {
    udp: Arc<UdpSocket>,
    addr: SocketAddr,
}

impl LocalSocket {
    fn bind(publish: bool) -> Result<Self, Error> {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0".parse()?)?);
        let socket = Self {
            addr: udp.local_addr()?,
            udp,
        };
        Dock::global().add(socket.udp.clone())?;
        if publish {
            AddressBook::global().insert_inner(&socket.udp, socket.addr.into())?;
        }
        Ok(socket)
    }
}

impl Drop for LocalSocket {
    fn drop(&mut self) {
        AddressBook::global().remove_bound(self.addr);
        Dock::global().remove(&self.udp);
    }
}

struct Listener;

impl Drop for Listener {
    fn drop(&mut self) {
        ServerRegistry::global().remove("localhost");
    }
}

struct TestFile(PathBuf);

impl TestFile {
    fn create() -> Result<Self, Error> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path =
            std::env::temp_dir().join(format!("dquic-transfer-{}-{nonce}.bin", std::process::id()));
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let file = Self(path);
        // Deterministic, position-dependent bytes expose truncation and misplaced chunks.
        let mut state = 0x1234_5678_u32;
        let mut chunk = vec![0; CHUNK_SIZE];
        for _ in 0..FILE_SIZE / CHUNK_SIZE {
            for byte in &mut chunk {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            output.write_all(&chunk)?;
        }
        Ok(file)
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn identity(server: bool) -> Result<Arc<Endpoint>, Error> {
    let (name, cert, key, ocsp): (_, &[u8], &[u8], &[u8]) = if server {
        (
            "localhost",
            include_bytes!("keychain/localhost/server.cert"),
            include_bytes!("keychain/localhost/server.key"),
            include_bytes!("keychain/localhost/server.ocsp"),
        )
    } else {
        (
            "client",
            include_bytes!("keychain/localhost/client.cert"),
            include_bytes!("keychain/localhost/client.key"),
            include_bytes!("keychain/localhost/client.ocsp"),
        )
    };
    Ok(Endpoint::new(
        name,
        vec![qtls::CertificateDer::from_pem_slice(cert)?],
        qtls::PrivateKeyDer::from_pem_slice(key)?,
        ocsp.to_vec(),
    )?)
}

async fn send(connection: &ArcConnection, payload: Arc<[u8]>, count: usize) -> Result<u64, Error> {
    let mut tasks = JoinSet::new();
    for index in 0..count {
        let (_, (mut reader, mut writer)) = connection
            .open_bi_stream()
            .await?
            .ok_or("bidirectional stream IDs exhausted")?;
        let payload = payload.clone();
        tasks.spawn(async move {
            writer.write_u32(index as u32).await?;
            // Each opened stream immediately sends its own file.
            for chunk in payload.chunks(CHUNK_SIZE) {
                writer.write_all(chunk).await?;
            }
            writer.shutdown().await?;
            let received = reader.read_u64().await?;
            if received != payload.len() as u64 || reader.read(&mut [0; 1]).await? != 0 {
                return Err(format!("stream {index}: invalid completion response").into());
            }
            Ok::<_, Error>(received)
        });
    }
    eprintln!("Opened all {count} client streams");
    let mut total = 0;
    while let Some(result) = tasks.join_next().await {
        total += result??;
    }
    Ok(total)
}

async fn receive(
    connection: &ArcConnection,
    payload: Arc<[u8]>,
    count: usize,
    progress: Arc<AtomicU64>,
) -> Result<u64, Error> {
    let headers = Arc::new(AtomicU64::new(0));
    let mut tasks = JoinSet::new();
    let mut stream_ids = HashSet::new();
    for _ in 0..count {
        let (id, (mut reader, mut writer)) = connection.accept_bi_stream().await?;
        assert!(stream_ids.insert(id), "duplicate QUIC stream ID");
        let (payload, progress) = (payload.clone(), progress.clone());
        let headers = headers.clone();
        tasks.spawn(async move {
            let index = reader.read_u32().await? as usize;
            if index >= count {
                return Err(format!("invalid stream index {index}").into());
            }
            let received = headers.fetch_add(1, Ordering::Relaxed) + 1;
            if received.is_multiple_of(128) || received == count as u64 {
                eprintln!("Ready stream headers: {received}/{count}");
            }
            let mut buffer = vec![0; CHUNK_SIZE];
            let mut offset = 0;
            loop {
                let n = reader.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                if offset + n > payload.len() || buffer[..n] != payload[offset..offset + n] {
                    return Err(format!("stream {index}: content mismatch at byte {offset}").into());
                }
                offset += n;
                progress.fetch_add(n as u64, Ordering::Relaxed);
            }
            if offset != payload.len() {
                return Err(format!(
                    "stream {index}: expected {} bytes, received {offset}",
                    payload.len()
                )
                .into());
            }
            writer.write_u64(offset as u64).await?;
            writer.shutdown().await?;
            Ok::<_, Error>((index, offset as u64))
        });
    }
    eprintln!("Accepted all {count} server streams");
    let mut indices = HashSet::new();
    let mut total = 0;
    while let Some(result) = tasks.join_next().await {
        let (index, bytes) = result??;
        assert!(indices.insert(index), "duplicate application stream index");
        total += bytes;
    }
    assert_eq!(indices.len(), count);
    Ok(total)
}

fn env_number(name: &str, default: usize) -> Result<usize, Error> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "10 GiB loopback stress test; run explicitly with --ignored --nocapture"]
async fn local_quic_1024_streams_10mib() -> Result<(), Error> {
    let count = env_number("DQUIC_TEST_STREAMS", 1024)?;
    let seconds = env_number("DQUIC_TEST_TIMEOUT_SECS", 600)?;
    if count == 0 || count > 1024 || seconds == 0 {
        return Err("require 1..=1024 streams and a positive timeout".into());
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .try_init();
    let file = TestFile::create()?;
    // Read the real source file once; all streams share it instead of allocating 10 GiB.
    let payload: Arc<[u8]> = fs::read(&file.0)?.into();
    assert_eq!(payload.len(), FILE_SIZE);
    qtls::RootCerts::set([qtls::CertificateDer::from_pem_slice(include_bytes!(
        "keychain/localhost/ca.cert"
    ))?])?;
    let server_socket = LocalSocket::bind(false)?;
    let client_socket = LocalSocket::bind(true)?;
    Resolver::add(Arc::new(LocalResolver(server_socket.addr.into())));
    let mut server = QuicEndpoint::from(identity(true)?);
    for (id, value) in ServerParameters::default().iter() {
        server.set_parameters(Role::Server, *id, value.clone())?;
    }
    server.set_parameters(
        Role::Server,
        ParameterId::InitialMaxStreamsBidi,
        count as u32,
    )?;
    server.set_parameters(
        Role::Server,
        ParameterId::InitialMaxData,
        16u32 * 1024 * 1024,
    )?;
    server.set_parameters(
        Role::Server,
        ParameterId::InitialMaxStreamDataBidiRemote,
        CHUNK_SIZE as u32,
    )?;
    let mut client = QuicEndpoint::from(identity(false)?);
    for (id, value) in ClientParameters::default().iter() {
        client.set_parameters(Role::Client, *id, value.clone())?;
    }
    let (incoming, mut accepted) = mpsc::unbounded_channel();
    server.listen(Scopes::ALL, move |result| {
        let _ = incoming.send(result);
    })?;
    let _listener = Listener;
    let ((_, _, client_conn), (_, _, server_conn)) = timeout(Duration::from_secs(15), async {
        tokio::try_join!(client.connect("localhost".into()), async {
            Ok(accepted.recv().await.expect("listener stopped"))
        })
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "loopback handshake timed out"))??;
    eprintln!(
        "Connected {} -> {}; {count} streams × 10 MiB = {} MiB",
        client_socket.addr,
        server_socket.addr,
        count * 10
    );
    let expected = count as u64 * FILE_SIZE as u64;
    let progress = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let transfer = async {
        tokio::try_join!(
            send(&client_conn, payload.clone(), count),
            receive(&server_conn, payload, count, progress.clone())
        )
    };
    let report = async {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            eprintln!(
                "Verified {} / {} MiB ({:.1}s)",
                progress.load(Ordering::Relaxed) / 1024 / 1024,
                expected / 1024 / 1024,
                started.elapsed().as_secs_f64()
            );
        }
    };
    let result = tokio::select! {
        result = timeout(Duration::from_secs(seconds as u64), transfer) => result,
        () = report => unreachable!(),
    };
    client_conn.close(0u32.into(), "transfer test finished");
    server_conn.close(0u32.into(), "transfer test finished");
    let (sent, received) = result.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "transfer timed out after {seconds}s: verified {} / {expected} bytes",
                progress.load(Ordering::Relaxed)
            ),
        )
    })??;
    assert_eq!(sent, expected);
    assert_eq!(received, expected);
    assert!(accepted.try_recv().is_err(), "unexpected extra connection");
    let elapsed = started.elapsed().as_secs_f64();
    eprintln!(
        "PASS: {count} streams, {received} bytes verified in {elapsed:.3}s, {:.2} MiB/s",
        received as f64 / 1024.0 / 1024.0 / elapsed
    );
    Ok(())
}
