//! Real UDP regression for address discovery, punching, validation and path loss.
//! Keep this in its own test process: Dock, AddressBook and the router are globals.
mod common;

use std::{sync::Arc, time::Duration};

use qbase::{
    cid::{ArcRemoteCids, ConnectionId, GenUniqueCid},
    net::{addr::EndpointAddr, route::Pathway},
    packet::{GetDcid, GetScid},
    param::ParameterId,
    role::Role,
    token::{ArcTokenRegistry, handy::NoopTokenRegistry},
};
use qconnection::{
    ArcConnPhase, ArcConnection, ArcLocalCids, ArcReliableFrames, CidRegistry, CloseReason,
    ConnPhase, InitialPhase, Paths, Scope, ServerRegistry, TlsContext, client_growing,
    server_growing,
};
use qprotocol::{AddressBook, Dock, QuicProtocol, UdpSocket};
use qtransport::{
    StreamReader, StreamWriter,
    packet::channel,
    path::{Path, PathState},
    router::QuicRouter,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{sleep, timeout},
};

const STEP_TIMEOUT: Duration = Duration::from_secs(3);

struct Socket(Arc<UdpSocket>);

impl Socket {
    fn new() -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        Dock::global().add(socket.clone()).unwrap();
        Self(socket)
    }

    fn endpoint(&self) -> EndpointAddr {
        self.0.local_addr().unwrap().into()
    }

    fn publish(&self) {
        AddressBook::global()
            .insert_inner(&self.0, self.endpoint())
            .unwrap();
    }

    fn withdraw(&self) {
        AddressBook::global().remove_bound(self.0.local_addr().unwrap());
        Dock::global().remove(&self.0);
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.withdraw();
    }
}

struct Peer {
    connection: ArcConnection,
    phase: ArcConnPhase,
    paths: Arc<Paths>,
    growing: JoinHandle<CloseReason>,
}

impl Peer {
    async fn lifecycle_status(&mut self) -> String {
        if self.growing.is_finished() {
            format!("{:?}", (&mut self.growing).await)
        } else {
            "running".to_owned()
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        // Test cleanup also runs after a failed stage; none of this drives migration.
        self.connection
            .clone()
            .close(0u32.into(), "migration test finished");
        if let ConnPhase::Mature(phase) = self.phase.get() {
            phase.puncher.abort_transactions();
            phase.puncher.release_temporary_sockets();
            phase.cid_registry.local.clear();
        }
        for path in self.paths.snapshot() {
            self.paths.remove(&path);
        }
        self.growing.abort();
    }
}

/// Use the production lifecycle while retaining read-only access to its paths.
async fn connect(server_socket: &Socket) -> (Peer, Peer) {
    let (accepted, mut incoming) = mpsc::unbounded_channel();
    common::quic_endpoint()
        .listen(Scope::Loopback, move |result| {
            accepted.send(result).unwrap();
        })
        .unwrap();
    let server = ServerRegistry::global().get("localhost").unwrap();
    let (created, mut server_state) = mpsc::unbounded_channel();
    QuicRouter::global().on_incoming(move |packet, pathway, link| {
        let odcid = *packet.dcid();
        let router = QuicRouter::global();
        let (inbox, received) = channel::new();
        let route = router.insert(odcid.into(), inbox.clone());
        let reliable = ArcReliableFrames::with_capacity(0);
        let registry = router.registry_on_issuing_scid(inbox.clone(), reliable.clone());
        let scid = registry.gen_unique_cid();
        let cid_registry = CidRegistry::new(
            Role::Server,
            odcid,
            ArcLocalCids::new(scid, registry),
            ArcRemoteCids::new(2, reliable.clone()),
        );
        let phase = ArcConnPhase::initial(InitialPhase::new(
            (scid, *packet.scid()),
            server
                .tls_server
                .initial_keys(qtls::QuicVersion::V1, odcid.as_ref())
                .unwrap(),
            reliable,
            cid_registry,
        ));
        let paths = Paths::new(Role::Server, phase.clone(), Duration::ZERO, Duration::ZERO);
        assert!(inbox.try_send_initial(packet, pathway, link));
        let tick = qconnection::recv::tick(paths.clone());
        let growing = server_growing(
            received,
            paths.clone(),
            ArcTokenRegistry::with_provider(Arc::new(NoopTokenRegistry)),
        );
        let growing = tokio::spawn(async move {
            let _route = route;
            tokio::join!(growing, tick).0
        });
        created.send((phase, paths, growing)).unwrap();
    });

    let client = common::anonymous_client();
    let odcid = ConnectionId::random_gen(8);
    let reliable = ArcReliableFrames::with_capacity(0);
    let (inbox, received) = channel::new();
    let registry = QuicRouter::global().registry_on_issuing_scid(inbox, reliable.clone());
    let scid = registry.gen_unique_cid();
    let (mut parameters, _) = common::parameters();
    parameters
        .set(ParameterId::InitialSourceConnectionId, scid)
        .unwrap();
    let tls = TlsContext::client(&client, "localhost".try_into().unwrap(), &parameters).unwrap();
    let cid_registry = CidRegistry::new(
        Role::Client,
        odcid,
        ArcLocalCids::new(scid, registry),
        ArcRemoteCids::new(
            parameters.get::<u64>(ParameterId::ActiveConnectionIdLimit),
            reliable.clone(),
        ),
    );
    let phase = ArcConnPhase::initial(InitialPhase::new(
        (scid, odcid),
        client
            .initial_keys(qtls::QuicVersion::V1, odcid.as_ref())
            .unwrap(),
        reliable,
        cid_registry,
    ));
    let paths = Paths::new(Role::Client, phase.clone(), Duration::ZERO, Duration::ZERO);
    let (deliver, connected) = oneshot::channel();
    let tick = qconnection::recv::tick(paths.clone());
    let growing = client_growing(
        format!("localhost:{}", server_socket.0.local_addr().unwrap().port()),
        parameters,
        paths.clone(),
        received,
        tls,
        ArcTokenRegistry::with_sink("localhost".into(), Arc::new(NoopTokenRegistry)),
        move |result| {
            let _ = deliver.send(result);
        },
    );
    let growing = tokio::spawn(async move { tokio::join!(growing, tick).0 });
    let client_connection = timeout(STEP_TIMEOUT, connected)
        .await
        .expect("stage 1: client handshake timed out")
        .unwrap()
        .unwrap()
        .2;
    let server_connection = timeout(STEP_TIMEOUT, incoming.recv())
        .await
        .expect("stage 1: server handshake timed out")
        .unwrap()
        .unwrap()
        .2;
    let (server_phase, server_paths, server_growing) = server_state.recv().await.unwrap();
    (
        Peer {
            connection: client_connection,
            phase,
            paths,
            growing,
        },
        Peer {
            connection: server_connection,
            phase: server_phase,
            paths: server_paths,
            growing: server_growing,
        },
    )
}

async fn wait_for(mut ready: impl FnMut() -> bool) -> bool {
    timeout(STEP_TIMEOUT, async {
        while !ready() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

fn describe(paths: &Paths) -> String {
    paths
        .snapshot()
        .iter()
        .map(|path| {
            format!(
                "{:?}: {:?}, challenge={:?}",
                path.pathway,
                path.state(),
                path.challenge()
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn write_counted(
    writer: &mut StreamWriter,
    bytes: &[u8],
    count: &mut usize,
) -> std::io::Result<()> {
    while *count < bytes.len() {
        let n = AsyncWriteExt::write(writer, &bytes[*count..]).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        *count += n;
    }
    Ok(())
}

async fn read_counted(
    reader: &mut StreamReader,
    bytes: &mut [u8],
    count: &mut usize,
) -> std::io::Result<()> {
    while *count < bytes.len() {
        let n = reader.read(&mut bytes[*count..]).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        *count += n;
    }
    Ok(())
}

async fn echo(
    client: &mut (StreamReader, StreamWriter),
    server: &mut (StreamReader, StreamWriter),
    payload: &[u8],
) -> Result<(), String> {
    let (mut client_written, mut server_read, mut server_written, mut client_read) = (0, 0, 0, 0);
    let result = timeout(STEP_TIMEOUT, async {
        let request = async {
            write_counted(&mut client.1, payload, &mut client_written).await?;
            let mut echoed = vec![0; payload.len()];
            read_counted(&mut client.0, &mut echoed, &mut client_read).await?;
            assert_eq!(echoed, payload);
            Ok::<_, std::io::Error>(())
        };
        let response = async {
            let mut received = vec![0; payload.len()];
            read_counted(&mut server.0, &mut received, &mut server_read).await?;
            assert_eq!(received, payload);
            write_counted(&mut server.1, &received, &mut server_written).await
        };
        tokio::try_join!(request, response)
    })
    .await;
    result.map_err(|_| format!("echo timed out: client wrote {client_written}, server read {server_read}, server wrote {server_written}, client read {client_read} of {} bytes", payload.len()))?
        .map(|_| ()).map_err(|error| error.to_string())
}

#[tokio::test]
async fn added_address_punches_validates_and_keeps_the_stream_alive_after_old_socket_loss() {
    common::use_system_resolver();
    let server_socket = Socket::new();
    let old_socket = Socket::new();
    server_socket.publish();
    old_socket.publish();
    let (mut client, mut server) = connect(&server_socket).await;
    let old_route = Pathway::new(old_socket.endpoint(), server_socket.endpoint());
    assert!(
        wait_for(|| client
            .paths
            .get(&old_route)
            .is_some_and(|p| p.selected() == Path::HANDSHAKED && p.is_validated()))
        .await,
        "stage 1: handshake confirmation missing"
    );
    let old_client_path = client.paths.get(&old_route).unwrap();
    let old_server_path = server.paths.get(&old_route.flip()).unwrap();
    let (_, mut client_stream) = client.connection.open_bi_stream().await.unwrap().unwrap();
    client_stream.1.write_all(b"open").await.unwrap();
    let (_, mut server_stream) = timeout(STEP_TIMEOUT, server.connection.accept_bi_stream())
        .await
        .unwrap()
        .unwrap();
    let mut opening = [0; 4];
    server_stream.0.read_exact(&mut opening).await.unwrap();
    assert_eq!(&opening, b"open");
    echo(&mut client_stream, &mut server_stream, b"before migration")
        .await
        .unwrap();

    // Only publish a new address. The test must not manually wire observe_endpoints,
    // call on_local_added/start_validation, or mark the new Path as validated.
    let new_socket = Socket::new();
    let new_route = Pathway::new(new_socket.endpoint(), server_socket.endpoint());
    new_socket.publish();
    let punched = wait_for(|| {
        client.paths.get(&new_route).is_some() && server.paths.get(&new_route.flip()).is_some()
    })
    .await;
    if !punched {
        panic!(
            "stage 2: publishing the address did not create the punched path\nclient: {}; lifecycle: {}\nserver: {}; lifecycle: {}",
            describe(&client.paths),
            client.lifecycle_status().await,
            describe(&server.paths),
            server.lifecycle_status().await
        );
    }
    assert!(
        wait_for(|| client
            .paths
            .get(&new_route)
            .is_some_and(|p| p.is_validated())
            && server
                .paths
                .get(&new_route.flip())
                .is_some_and(|p| p.is_validated()))
        .await,
        "stage 3: new path validation did not complete\nclient: {}\nserver: {}",
        describe(&client.paths),
        describe(&server.paths)
    );

    // Remove the old socket, not the Path. Its sender must detect the failure itself.
    old_socket.withdraw();
    assert!(
        QuicProtocol::global()
            .find_socket(old_socket.endpoint())
            .is_none()
    );
    assert!(
        Dock::global()
            .find_socket(old_socket.0.local_addr().unwrap())
            .is_none()
    );
    let payload: Vec<_> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    if let Err(error) = echo(&mut client_stream, &mut server_stream, &payload).await {
        panic!(
            "stage 4: {error}\nclient: {}\nserver: {}\nold paths: {:?}/{:?}",
            describe(&client.paths),
            describe(&server.paths),
            old_client_path.state(),
            old_server_path.state()
        );
    }
    assert!(
        wait_for(|| old_client_path.state() == PathState::Retired).await,
        "stage 4: the old client sender did not retire its unusable path"
    );
    assert!(
        client
            .paths
            .get(&new_route)
            .is_some_and(|p| p.is_validated())
    );
    assert!(
        server
            .paths
            .get(&new_route.flip())
            .is_some_and(|p| p.is_validated())
    );
    ServerRegistry::global().remove("localhost");
}
