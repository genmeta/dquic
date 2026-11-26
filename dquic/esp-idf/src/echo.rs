use std::{sync::Arc, time::Duration};

use dquic::{CertificateDer, Dock, Endpoint, ParameterId, PrivateKeyDer, QuicEndpoint, Resolver, Role, RootCerts, Scope, SystemResolver};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    time::timeout,
};

type Error = Box<dyn std::error::Error + Send + Sync>;
const MESSAGE: &[u8] = b"hello from ESP-IDF";

pub async fn run() -> Result<(), Error> {
    RootCerts::set([CertificateDer::from(include_bytes!("../../examples/keychain/ca.der").as_slice())])?;
    let identity = Endpoint::new(
        "localhost",
        vec![CertificateDer::from(include_bytes!("../../examples/keychain/server.der").as_slice())],
        PrivateKeyDer::try_from(include_bytes!("../../examples/keychain/server.key.der").as_slice())?,
        include_bytes!("../../examples/keychain/server.ocsp").to_vec(),
    )?;
    let dock = Dock::global();
    let server_socket = dock.ephemeral_socket("127.0.0.1:0".parse()?)?;
    let client_socket = dock.use_socket("127.0.0.1:0".parse()?)?;
    let server_addr = server_socket.socket().local_addr()?;
    Resolver::add(Arc::new(SystemResolver));
    let mut server = QuicEndpoint::from(identity);
    let mut client = QuicEndpoint::anonymous();
    configure(&mut server, Role::Server)?;
    configure(&mut client, Role::Client)?;
    let (accepted, mut incoming) = mpsc::channel(1);
    server.listen(Scope::Loopback, move |connection| {
        let _ = accepted.try_send(connection);
    })?;
    let result = timeout(Duration::from_secs(30), async {
        let (_, authority, client) = client.connect(format!("localhost:{}", server_addr.port())).await?;
        if authority.name() != "localhost" {
            return Err("unexpected verified peer identity".into());
        }
        let (_, _, server) = incoming.recv().await.ok_or("listener stopped")?;
        println!("PASS: verified QUIC handshake {} -> {server_addr}", client_socket.local_addr()?);
        let request = async {
            let (_, (mut reader, mut writer)) = client.open_bi_stream().await?.ok_or("stream IDs exhausted")?;
            writer.write_all(MESSAGE).await?;
            writer.shutdown().await?;
            let mut reply = [0; MESSAGE.len()];
            reader.read_exact(&mut reply).await?;
            if reply != MESSAGE || reader.read(&mut [0; 1]).await? != 0 {
                return Err("invalid echo or missing FIN".into());
            }
            Ok::<(), Error>(())
        };
        let response = async {
            let (_, (mut reader, mut writer)) = server.accept_bi_stream().await?;
            let mut payload = [0; MESSAGE.len()];
            reader.read_exact(&mut payload).await?;
            if payload != MESSAGE || reader.read(&mut [0; 1]).await? != 0 {
                return Err("invalid request or missing FIN".into());
            }
            writer.write_all(&payload).await?;
            writer.shutdown().await?;
            Ok::<(), Error>(())
        };
        let result = tokio::try_join!(request, response);
        client.close(0u32.into(), "echo complete");
        server.close(0u32.into(), "echo complete");
        result?;
        println!("PASS: bidirectional echo, {} bytes and FIN in both directions", MESSAGE.len());
        Ok::<(), Error>(())
    })
    .await?;
    dquic::qconnection::ServerRegistry::global().remove("localhost");
    result
}

fn configure(endpoint: &mut QuicEndpoint, role: Role) -> Result<(), Error> {
    for (id, value) in [
        (ParameterId::InitialMaxStreamsBidi, 2u32),
        (ParameterId::InitialMaxStreamsUni, 0),
        (ParameterId::InitialMaxData, 8192),
        (ParameterId::InitialMaxStreamDataBidiLocal, 4096),
        (ParameterId::InitialMaxStreamDataBidiRemote, 4096),
        (ParameterId::InitialMaxStreamDataUni, 0),
        (ParameterId::MaxUdpPayloadSize, dquic::qbase::datagram::MAX_DATAGRAM_SIZE as u32),
        (ParameterId::ActiveConnectionIdLimit, 2),
    ] {
        endpoint.set_parameters(role, id, value)?;
    }
    Ok(())
}
