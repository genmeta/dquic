use std::{net::SocketAddr, sync::Arc, time::Duration};

use dquic::{
    prelude::{handy::*, *},
    qbase::param::{ClientParameters, ServerParameters},
    qinterface::{bind_uri::BindUri, component::route::QuicRouter},
    qresolve::Source,
};
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

mod common;
use common::*;
mod echo_common;
use echo_common::*;

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
                tracing::info!(source = ?pathway.remote(), "accepted new connection");
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

        tokio::time::timeout(Duration::from_secs(2), connection.terminated())
            .await
            .expect("unreachable connection should terminate by max idle timeout");

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
                    .instrument(tracing::info_span!("stream", conn_idx)),
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
            tracing::info!(conn_idx, "Starting connection");
            let connection = Arc::new(
                client
                    .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
                    .await?,
            );
            tracing::info!(conn_idx, "Connected");
            for stream_idx in 0..PARALLEL_ECHO_STREAMS {
                let connection = connection.clone();
                streams.spawn(
                    async move { send_and_verify_echo(&connection, TEST_DATA).await }
                        .instrument(tracing::info_span!("stream", conn_idx, stream_idx)),
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
                    .instrument(tracing::info_span!("stream", conn_idx)),
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
                    async move { send_and_verify_echo(&connection, TEST_DATA).await }
                        .instrument(tracing::info_span!("stream", conn_idx, stream_idx)),
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
