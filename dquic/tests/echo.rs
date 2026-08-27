use std::{net::SocketAddr, sync::Arc, time::Duration};

use dquic::{
    prelude::{handy::*, *},
    qbase::param::{ClientParameters, ServerParameters},
    qinterface::{bind_uri::BindUri, component::route::QuicRouter, manager::InterfaceManager},
    qresolve::Source,
};
use rustls::pki_types::pem::PemObject;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

mod common;
use common::*;
mod echo_common;
use echo_common::*;

const TEST_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(100);

async fn launch_gated_test_client(
    router: Arc<QuicRouter>,
    parameters: ClientParameters,
    defer_idle_timeout: Duration,
    gate: Arc<NetworkGateFactory>,
    bind_uris: impl IntoIterator<Item = BindUri>,
) -> Arc<QuicClient> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(
        rustls::pki_types::CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
    );
    let builder = QuicClient::builder()
        .with_router(router)
        .with_root_certificates(roots)
        .without_cert()
        .with_parameters(parameters)
        .keep_alive(defer_idle_timeout, TEST_HEARTBEAT_INTERVAL)
        .with_iface_factory(gate)
        .with_iface_manager(Arc::new(InterfaceManager::new()))
        .with_qlog(qlogger());
    Arc::new(builder.bind(bind_uris).await.build())
}

#[test]
fn single_stream() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());
        let connection = client
            .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
            .await?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn signal_big_stream() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());
        let connection = client
            .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
            .await?;
        // Use 16x repeat (~58KB) instead of 1024x (~3.7MB) for CI stability
        send_and_verify_echo(&connection, &TEST_DATA.to_vec().repeat(16)).await?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn empty_stream() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());
        let connection = client
            .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
            .await?;
        send_and_verify_echo(&connection, b"").await?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn shutdown() -> Result<(), BoxError> {
    run(async {
        async fn serve_only_one_stream(listeners: Arc<QuicListeners>) {
            while let Ok((connection, server, pathway, _link)) = listeners.accept().await {
                assert_eq!(server, "localhost");
                tracing::info!(target: "dquic", source = ?pathway.remote(), "accepted new connection");
                tokio::spawn(async move {
                    let (_sid, (reader, writer)) = connection.accept_bi_stream().await?;
                    echo_stream(reader, writer).await;
                    _ = connection.close("Bye bye", 0);
                    Result::<(), BoxError>::Ok(())
                });
            }
        }

        let router = Arc::new(QuicRouter::default());
        let listeners = QuicListeners::builder()
            .with_router(router.clone())
            .without_client_cert_verifier()
            .with_parameters(server_parameters())
            .with_qlog(qlogger())
            .listen(128)?;
        listeners
            .add_server(
                "localhost",
                SERVER_CERT,
                SERVER_KEY,
                [BindUri::from("inet://127.0.0.1:0").alloc_port()],
                None,
            )
            .await?;
        let server_task = serve_only_one_stream(listeners.clone());
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);

        let client = launch_test_client(router, client_parameters());
        let connection = client
            .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
            .await?;
        _ = connection.handshaked().await; // 可有可无

        assert!(
            send_and_verify_echo(&connection, b"").await.is_err()
                || send_and_verify_echo(&connection, b"").await.is_err()
        );

        connection.terminated().await;
        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn application_close_then_drop_does_not_strand_connection() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());
        let connection = client
            .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
            .await?;

        send_and_verify_echo(&connection, TEST_DATA).await?;
        connection.close("client done", 0)?;
        drop(connection);

        tokio::time::sleep(Duration::from_millis(100)).await;
        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn idle_timeout() -> Result<(), BoxError> {
    run(async {
        fn server_parameters() -> ServerParameters {
            let mut params = handy::server_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_secs(1))
                .expect("unreachable");

            params
        }

        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);

        let client = launch_test_client(router, client_parameters());
        let connection = client
            .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
            .await?;
        connection.terminated().await;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn keep_alive_extends_path_idle_then_stops_at_defer_deadline() -> Result<(), BoxError> {
    run(async {
        const MAX_IDLE: Duration = Duration::from_secs(1);
        const DEFER_IDLE: Duration = Duration::from_secs(3);

        fn client_parameters() -> ClientParameters {
            let mut params = handy::client_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, MAX_IDLE)
                .expect("unreachable");
            params
        }

        fn server_parameters() -> ServerParameters {
            let mut params = handy::server_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, MAX_IDLE)
                .expect("unreachable");
            params
        }

        let router = Arc::new(QuicRouter::default());
        let listeners = QuicListeners::builder()
            .with_router(router.clone())
            .without_client_cert_verifier()
            .with_parameters(server_parameters())
            .keep_alive(DEFER_IDLE, TEST_HEARTBEAT_INTERVAL)
            .with_qlog(qlogger())
            .listen(128)?;
        listeners
            .add_server(
                "localhost",
                SERVER_CERT,
                SERVER_KEY,
                [BindUri::from("inet://127.0.0.1:0").alloc_port()],
                None,
            )
            .await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(serve_echo(listeners.clone())));

        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(
            rustls::pki_types::CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
        );
        let client = Arc::new(
            QuicClient::builder()
                .with_router(router)
                .with_root_certificates(roots)
                .without_cert()
                .with_parameters(client_parameters())
                .keep_alive(DEFER_IDLE, TEST_HEARTBEAT_INTERVAL)
                .bind([BindUri::from("inet://127.0.0.1:0").alloc_port()])
                .await
                .with_qlog(qlogger())
                .build(),
        );
        let connection = client
            .connected_to_with_source(
                "localhost",
                [(Source::System, get_server_addr(&listeners).into())],
            )
            .await?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        let effective_idle = connection
            .path_context()?
            .max_pto_duration()
            .map(|pto| pto.saturating_mul(3))
            .unwrap_or_default()
            .max(MAX_IDLE);
        tokio::time::sleep(effective_idle + Duration::from_millis(100)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), connection.terminated())
                .await
                .is_err(),
            "periodic path PINGs must keep the path idle timer alive"
        );
        send_and_verify_echo(&connection, TEST_DATA).await?;

        tokio::time::timeout(
            DEFER_IDLE + effective_idle + Duration::from_secs(2),
            async {
                connection.terminated().await;
            },
        )
        .await
        .expect("connection must close after the KeepAlive window and path idle timeout");

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn established_connection_times_out_after_network_disappears() -> Result<(), BoxError> {
    run(async {
        const MAX_IDLE: Duration = Duration::from_millis(400);
        const DEFER_IDLE: Duration = Duration::from_secs(3);

        let mut client_params = handy::client_parameters();
        client_params
            .set(ParameterId::MaxIdleTimeout, MAX_IDLE)
            .expect("valid idle timeout");
        let mut server_params = handy::server_parameters();
        server_params
            .set(ParameterId::MaxIdleTimeout, MAX_IDLE)
            .expect("valid idle timeout");

        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) = launch_echo_server(router.clone(), server_params).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));
        let gate = Arc::new(NetworkGateFactory::default());
        let client = launch_gated_test_client(
            router,
            client_params,
            DEFER_IDLE,
            gate.clone(),
            [BindUri::from("inet://127.0.0.1:0").alloc_port()],
        )
        .await;
        let connection = client
            .connected_to_with_source(
                "localhost",
                [(Source::System, get_server_addr(&listeners).into())],
            )
            .await?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        gate.disable_all();
        tokio::time::timeout(Duration::from_secs(5), connection.terminated())
            .await
            .expect("one-way PING and recovery traffic must not keep the connection alive forever");

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn keep_alive_is_path_local_and_one_lost_path_does_not_kill_connection() -> Result<(), BoxError> {
    run(async {
        const MAX_IDLE: Duration = Duration::from_secs(1);
        const DEFER_IDLE: Duration = Duration::from_secs(30);

        let mut client_params = handy::client_parameters();
        client_params
            .set(ParameterId::MaxIdleTimeout, MAX_IDLE)
            .expect("valid idle timeout");
        let mut server_params = handy::server_parameters();
        server_params
            .set(ParameterId::MaxIdleTimeout, MAX_IDLE)
            .expect("valid idle timeout");

        let router = Arc::new(QuicRouter::default());
        let listeners = QuicListeners::builder()
            .with_router(router.clone())
            .without_client_cert_verifier()
            .with_parameters(server_params)
            .keep_alive(DEFER_IDLE, TEST_HEARTBEAT_INTERVAL)
            .with_qlog(qlogger())
            .listen(128)?;
        listeners
            .add_server(
                "localhost",
                SERVER_CERT,
                SERVER_KEY,
                [BindUri::from("inet://127.0.0.1:0").alloc_port()],
                None,
            )
            .await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(serve_echo(listeners.clone())));

        let bind_a = BindUri::from("inet://127.0.0.1:0").alloc_port();
        let bind_b = BindUri::from("inet://127.0.0.1:0").alloc_port();
        let gate = Arc::new(NetworkGateFactory::default());
        let client = launch_gated_test_client(
            router,
            client_params,
            DEFER_IDLE,
            gate.clone(),
            [bind_a.clone(), bind_b.clone()],
        )
        .await;
        let connection = client
            .connected_to_with_source(
                "localhost",
                [(Source::System, get_server_addr(&listeners).into())],
            )
            .await?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if connection.path_context().unwrap().paths::<Vec<_>>().len() == 2
                    && gate.sent_packets(&bind_a) > 0
                    && gate.sent_packets(&bind_b) > 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("both client paths should be created and used");

        let sent_a = gate.sent_packets(&bind_a);
        let sent_b = gate.sent_packets(&bind_b);
        tokio::time::sleep(MAX_IDLE / 2 + Duration::from_millis(300)).await;
        assert!(
            gate.sent_packets(&bind_a) > sent_a,
            "path A should schedule its own keep-alive traffic"
        );
        assert!(
            gate.sent_packets(&bind_b) > sent_b,
            "path B should schedule its own keep-alive traffic"
        );
        assert_eq!(connection.path_context()?.paths::<Vec<_>>().len(), 2);

        assert!(gate.disable(&bind_b), "path B gate should exist");
        tokio::time::sleep(Duration::from_millis(500)).await;
        let paths = connection.path_context()?.paths::<Vec<_>>();
        assert!(
            paths.iter().any(|(_, path)| path.bind_uri() == bind_a),
            "healthy path A must not be removed while path B is black-holed"
        );
        assert!(connection.has_viable_path()?);

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn data_on_retired_path_moves_to_surviving_path() -> Result<(), BoxError> {
    run(async {
        const MAX_IDLE: Duration = Duration::from_secs(5);
        const DEFER_IDLE: Duration = Duration::from_secs(30);

        let mut client_params = handy::client_parameters();
        client_params
            .set(ParameterId::MaxIdleTimeout, MAX_IDLE)
            .expect("valid idle timeout");
        let mut server_params = handy::server_parameters();
        server_params
            .set(ParameterId::MaxIdleTimeout, MAX_IDLE)
            .expect("valid idle timeout");

        let router = Arc::new(QuicRouter::default());
        let listeners = QuicListeners::builder()
            .with_router(router.clone())
            .without_client_cert_verifier()
            .with_parameters(server_params)
            .keep_alive(DEFER_IDLE, TEST_HEARTBEAT_INTERVAL)
            .with_qlog(qlogger())
            .listen(128)?;
        listeners
            .add_server(
                "localhost",
                SERVER_CERT,
                SERVER_KEY,
                [BindUri::from("inet://127.0.0.1:0").alloc_port()],
                None,
            )
            .await?;

        let (server_connection_tx, server_connection_rx) = tokio::sync::oneshot::channel();
        let (request_received_tx, request_received_rx) = tokio::sync::oneshot::channel();
        let (write_response_tx, write_response_rx) = tokio::sync::oneshot::channel();
        let server_listeners = listeners.clone();
        let server_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let (connection, _, _, _) = server_listeners.accept().await.unwrap();
            assert!(server_connection_tx.send(connection.clone()).is_ok());
            let (_, (reader, writer)) = connection.accept_bi_stream().await.unwrap();
            echo_stream(reader, writer).await;
            let (_, (mut reader, mut writer)) = connection.accept_bi_stream().await.unwrap();
            let mut request = Vec::new();
            reader.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, TEST_DATA);
            request_received_tx.send(()).unwrap();
            write_response_rx.await.unwrap();
            writer.write_all(TEST_DATA).await.unwrap();
            writer.shutdown().await.unwrap();
        }));

        let bind_a = BindUri::from("inet://127.0.0.1:0").alloc_port();
        let bind_b = BindUri::from("inet://127.0.0.1:0").alloc_port();
        let gate = Arc::new(NetworkGateFactory::default());
        let client = launch_gated_test_client(
            router,
            client_params,
            DEFER_IDLE,
            gate.clone(),
            [bind_a.clone(), bind_b.clone()],
        )
        .await;
        let connection = client
            .connected_to_with_source(
                "localhost",
                [(Source::System, get_server_addr(&listeners).into())],
            )
            .await?;
        let server_connection = server_connection_rx.await?;

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let client_ready = connection.path_context().unwrap().paths::<Vec<_>>().len() == 2;
                let server_ready = server_connection
                    .path_context()
                    .unwrap()
                    .paths::<Vec<_>>()
                    .len()
                    == 2;
                if client_ready && server_ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("both endpoints should have two paths");
        send_and_verify_echo(&connection, TEST_DATA).await?;

        let client_paths = connection.path_context()?.paths::<Vec<_>>();
        let client_a = client_paths
            .iter()
            .find(|(_, path)| path.bind_uri() == bind_a)
            .map(|(pathway, _)| *pathway)
            .expect("client path A");
        let client_b = client_paths
            .iter()
            .find(|(_, path)| path.bind_uri() == bind_b)
            .map(|(pathway, _)| *pathway)
            .expect("client path B");
        let reciprocal = |left: Pathway, right: Pathway| {
            left.local() == right.remote() && left.remote() == right.local()
        };
        let server_paths = server_connection.path_context()?.paths::<Vec<_>>();
        let server_a = server_paths
            .iter()
            .find(|(pathway, _)| reciprocal(*pathway, client_a))
            .map(|(pathway, _)| *pathway)
            .expect("server path A");
        let server_b = server_paths
            .iter()
            .find(|(pathway, _)| reciprocal(*pathway, client_b))
            .map(|(pathway, _)| *pathway)
            .expect("server path B");

        assert!(gate.disable(&bind_b));
        connection.del_path(&client_b)?;

        let (_, (mut response_reader, mut request_writer)) =
            connection.open_bi_stream().await?.unwrap();
        request_writer.write_all(TEST_DATA).await?;
        request_writer.shutdown().await?;
        request_received_rx.await?;

        assert!(gate.disable(&bind_a));
        server_connection.del_path(&server_a)?;
        assert_eq!(server_connection.path_context()?.paths::<Vec<_>>().len(), 1);
        write_response_tx.send(()).unwrap();

        let metrics = server_connection.metrics()?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while metrics.inflight_bytes() < TEST_DATA.len() as u64 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the response should be sent and remain unacknowledged on B");

        assert!(gate.enable(&bind_a));
        let (_, mut probe_writer) = connection.open_uni_stream().await?.unwrap();
        probe_writer.write_all(b"recreate A").await?;
        tokio::time::timeout(Duration::from_secs(2), probe_writer.shutdown())
            .await
            .expect("probe data and FIN should be acknowledged on A")?;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if server_connection
                    .path_context()
                    .unwrap()
                    .paths::<Vec<_>>()
                    .iter()
                    .any(|(pathway, _)| reciprocal(*pathway, client_a))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("new traffic on A should recreate the server path");

        server_connection.del_path(&server_b)?;
        let mut response = Vec::new();
        let read_result = tokio::time::timeout(
            Duration::from_secs(3),
            response_reader.read_to_end(&mut response),
        )
        .await;
        assert!(
            read_result.is_ok(),
            "B-local response should be retransmitted on A; received {} of {} bytes",
            response.len(),
            TEST_DATA.len()
        );
        read_result.unwrap()?;
        assert_eq!(response, TEST_DATA);

        listeners.shutdown();
        server_task.await?;
        Ok(())
    })
}

#[test]
fn unreachable_server_connection_times_out() -> Result<(), BoxError> {
    run(async {
        fn short_idle_client_parameters() -> ClientParameters {
            let mut params = client_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_millis(100))
                .expect("unreachable");
            params
        }

        let router = Arc::new(QuicRouter::default());
        let client = launch_test_client(router, short_idle_client_parameters());

        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let unreachable: SocketAddr = socket.local_addr()?;
        drop(socket);

        let connection = client
            .connected_to_with_source("localhost", [(Source::System, unreachable.into())])
            .await?;

        tokio::time::timeout(Duration::from_secs(5), connection.terminated())
            .await
            .expect("unreachable connection should terminate after its last path times out");

        Ok(())
    })
}

#[test]
fn double_connections() -> Result<(), BoxError> {
    run(async {
        // Use extended timeouts for parallel connection tests on slower CI
        fn client_parameters() -> ClientParameters {
            let mut params = handy::client_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_secs(60))
                .expect("unreachable");
            params
        }

        fn server_parameters() -> ServerParameters {
            let mut params = handy::server_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_secs(60))
                .expect("unreachable");
            params
        }

        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());

        let mut connections = JoinSet::new();

        for conn_idx in 0..2 {
            let connection = client
                .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
                .await?;
            connections.spawn(
                async move { send_and_verify_echo(&connection, TEST_DATA).await }
                    .instrument(tracing::info_span!(target: "dquic", "stream", conn_idx)),
            );
        }

        connections
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), BoxError>>()?;

        listeners.shutdown();
        Ok(())
    })
}

const PARALLEL_ECHO_CONNS: usize = 3;
const PARALLEL_ECHO_STREAMS: usize = 2;

#[test]
fn parallel_stream() -> Result<(), BoxError> {
    run(async {
        fn client_parameters() -> ClientParameters {
            let mut params = handy::client_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_secs(60))
                .expect("unreachable");
            params
        }

        fn server_parameters() -> ServerParameters {
            let mut params = handy::server_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_secs(60))
                .expect("unreachable");
            params
        }

        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());

        let mut streams = JoinSet::new();

        for conn_idx in 0..PARALLEL_ECHO_CONNS {
            tracing::info!(target: "dquic", conn_idx, "starting connection");
            let connection = Arc::new(
                client
                    .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
                    .await?,
            );
            tracing::info!(target: "dquic", conn_idx, "connected");
            for stream_idx in 0..PARALLEL_ECHO_STREAMS {
                let connection = connection.clone();
                streams.spawn(
                    async move { send_and_verify_echo(&connection, TEST_DATA).await }.instrument(
                        tracing::info_span!(target: "dquic", "stream", conn_idx, stream_idx),
                    ),
                );
            }
        }

        streams
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), BoxError>>()?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn parallel_big_stream() -> Result<(), BoxError> {
    run(async {
        fn client_parameters() -> ClientParameters {
            let mut params = handy::client_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_secs(60))
                .expect("unreachable");
            params
        }

        fn server_parameters() -> ServerParameters {
            let mut params = handy::server_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_secs(60))
                .expect("unreachable");
            params
        }

        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);

        let client = launch_test_client(router, client_parameters());

        let mut big_streams = JoinSet::new();
        // Use 4x repeat (~14KB per connection) instead of 32x (~117KB) for CI stability
        let test_data = Arc::new(TEST_DATA.to_vec().repeat(4));

        for conn_idx in 0..PARALLEL_ECHO_CONNS {
            let connection = client
                .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
                .await?;
            let test_data = test_data.clone();
            big_streams.spawn(
                async move { send_and_verify_echo(&connection, &test_data).await }
                    .instrument(tracing::info_span!(target: "dquic", "stream", conn_idx)),
            );
        }

        big_streams
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), BoxError>>()?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn limited_streams() -> Result<(), BoxError> {
    run(async {
        pub fn client_parameters() -> ClientParameters {
            let mut params = ClientParameters::default();

            for (id, value) in [
                (ParameterId::InitialMaxStreamsBidi, 2u32),
                (ParameterId::InitialMaxStreamsUni, 0u32),
                (ParameterId::InitialMaxData, 1u32 << 10),
                (ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 10),
                (ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 10),
                (ParameterId::InitialMaxStreamDataUni, 1u32 << 10),
            ] {
                params.set(id, value).expect("unreachable");
            }

            params
        }

        pub fn server_parameters() -> ServerParameters {
            let mut params = ServerParameters::default();

            for (id, value) in [
                (ParameterId::InitialMaxStreamsBidi, 2u32),
                (ParameterId::InitialMaxStreamsUni, 2u32),
                (ParameterId::InitialMaxData, 1u32 << 20),
                (ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 10),
                (ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 10),
                (ParameterId::InitialMaxStreamDataUni, 1u32 << 10),
            ] {
                params.set(id, value).expect("unreachable");
            }
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_secs(30))
                .expect("unreachable");

            params
        }

        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());

        let mut streams = JoinSet::new();

        for conn_idx in 0..PARALLEL_ECHO_CONNS / 2 {
            let connection = Arc::new(
                client
                    .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
                    .await?,
            );
            for stream_idx in 0..PARALLEL_ECHO_STREAMS / 2 {
                let connection = connection.clone();
                streams.spawn(
                    async move { send_and_verify_echo(&connection, TEST_DATA).await }.instrument(
                        tracing::info_span!(target: "dquic", "stream", conn_idx, stream_idx),
                    ),
                );
            }
        }

        streams
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), BoxError>>()?;

        listeners.shutdown();
        Ok(())
    })
}
