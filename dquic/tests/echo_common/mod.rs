// common is submod for echo, auth and traversal
#![allow(unused)]

use std::sync::Arc;

use dquic::{prelude::*, qbase::param::ServerParameters, qinterface::component::route::QuicRouter};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use crate::common::{BoxError, SERVER_CERT, SERVER_KEY, qlogger};

pub async fn echo_stream(mut reader: StreamReader, mut writer: StreamWriter) {
    io::copy(&mut reader, &mut writer).await.unwrap();
    _ = writer.shutdown().await;
    tracing::debug!(target: "dquic", "stream copy done");
}

pub async fn serve_echo(listeners: Arc<QuicListeners>) {
    while let Ok((connection, server, pathway, _link)) = listeners.accept().await {
        assert_eq!(server, "localhost");
        tracing::info!(target: "dquic", source = ?pathway.remote(), "accepted new connection");
        tokio::spawn(async move {
            while let Ok((_sid, (reader, writer))) = connection.accept_bi_stream().await {
                tokio::spawn(echo_stream(reader, writer));
            }
        });
    }
}

pub async fn send_and_verify_echo(connection: &Connection, data: &[u8]) -> Result<(), BoxError> {
    let (_sid, (mut reader, mut writer)) = connection.open_bi_stream().await?.unwrap();
    tracing::debug!(target: "dquic", "stream opened");

    let mut back = Vec::new();
    tokio::try_join!(
        async {
            writer.write_all(data).await?;
            writer.shutdown().await?;
            tracing::info!(target: "dquic", "write done");
            Result::<(), BoxError>::Ok(())
        },
        async {
            reader.read_to_end(&mut back).await?;
            assert_eq!(back, data);
            tracing::info!(target: "dquic", "read done");
            Result::<(), BoxError>::Ok(())
        }
    )
    .map(|_| ())
}

pub async fn launch_echo_server(
    quic_router: Arc<QuicRouter>,
    parameters: ServerParameters,
) -> Result<(Arc<QuicListeners>, impl Future<Output: Send>), BoxError> {
    let listeners = QuicListeners::builder()
        .with_router(quic_router)
        .without_client_cert_verifier()
        .with_parameters(parameters)
        .with_qlog(qlogger())
        .listen(128)
        .unwrap();
    listeners
        .add_server(
            "localhost",
            SERVER_CERT,
            SERVER_KEY,
            [BindUri::from("inet://127.0.0.1:0").alloc_port()],
            None,
        )
        .await?;
    Ok((listeners.clone(), serve_echo(listeners)))
}
