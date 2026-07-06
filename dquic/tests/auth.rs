use std::{future::Future, sync::Arc, time::Duration};

use dquic::{
    prelude::{handy::*, *},
    qbase,
    qresolve::Source,
};
use qbase::param::ServerParameters;
use qconnection::qinterface::{bind_uri::BindUri, component::route::QuicRouter};
use rustls::{
    pki_types::{CertificateDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time,
};
use tokio_util::task::AbortOnDropHandle;

mod common;
use common::*;
mod echo_common;
use echo_common::*;

#[test]
fn client_without_verify() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);

        let client = {
            let parameters = client_parameters();
            let client = QuicClient::builder()
                .with_router(router)
                .without_verifier()
                .with_parameters(parameters)
                .without_cert()
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();
            Arc::new(client)
        };

        let connection = client
            .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
            .await?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        listeners.shutdown();
        Ok(())
    })
}

struct ClientNameAuther<const SILENT_REFUSE: bool>;

impl<const SILENT: bool> AuthClient for ClientNameAuther<SILENT> {
    fn verify_client_name(
        &self,
        _: &LocalAuthority,
        client_name: Option<&str>,
    ) -> ClientNameVerifyResult {
        match matches!(client_name, Some("client")) {
            true => ClientNameVerifyResult::Accept,
            false if !SILENT => ClientNameVerifyResult::Refuse("".to_owned()),
            false => ClientNameVerifyResult::SilentRefuse("Client name ".to_owned()),
        }
    }

    fn verify_client_authority(
        &self,
        _: &LocalAuthority,
        _: &RemoteAuthority,
    ) -> ClientAuthorityVerifyResult {
        ClientAuthorityVerifyResult::Accept
    }
}

async fn launch_client_auth_test_server<const SILENT_REFUSE: bool>(
    quic_router: Arc<QuicRouter>,
    server_parameters: ServerParameters,
) -> Result<(Arc<QuicListeners>, impl Future<Output: Send>), BoxError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap));
    let listeners = QuicListeners::builder()
        .with_router(quic_router)
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
        )
        .with_client_auther(ClientNameAuther::<SILENT_REFUSE>)
        .with_parameters(server_parameters)
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
    Ok((listeners.clone(), serve_echo(listeners)))
}

#[test]
fn auth_client_name() -> Result<(), BoxError> {
    run(async {
        const SILENT_REFUSE: bool = false;

        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_client_auth_test_server::<SILENT_REFUSE>(router.clone(), server_parameters())
                .await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));
        let server_addr = get_server_addr(&listeners);

        let client = {
            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_router(router)
                .with_root_certificates(roots)
                .with_parameters(client_parameters())
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_name("client")
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client
            .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
            .await?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn auth_client_name_incorrect_name() -> Result<(), BoxError> {
    run(async {
        const SILENT_REFUSE: bool = false;

        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_client_auth_test_server::<SILENT_REFUSE>(router.clone(), server_parameters())
                .await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));
        let server_addr = get_server_addr(&listeners);

        let client = {
            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_router(router)
                .with_root_certificates(roots)
                .with_parameters(client_parameters())
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_name("wrong_name")
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client
            .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
            .await?;
        let error = connection.terminated().await;
        // TODO: 偶尔以NoViablePath结束，需要调查原因
        assert_eq!(error.kind(), ErrorKind::ConnectionRefused);

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn auth_client_refuse() -> Result<(), BoxError> {
    run(async {
        const SILENT_REFUSE: bool = false;

        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_client_auth_test_server::<SILENT_REFUSE>(router.clone(), server_parameters())
                .await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));
        let server_addr = get_server_addr(&listeners);

        let client = {
            let parameters = client_parameters();
            // no CLIENT_NAME

            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_router(router)
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client
            .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
            .await?;

        let error = connection.terminated().await;
        // TODO: 偶尔以NoViablePath结束，需要调查原因
        assert_eq!(error.kind(), ErrorKind::ConnectionRefused);

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn auth_client_refuse_silently() -> Result<(), BoxError> {
    run(async {
        const SILENT_REFUSE: bool = true;

        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_client_auth_test_server::<SILENT_REFUSE>(router.clone(), server_parameters())
                .await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));
        let server_addr = get_server_addr(&listeners);

        let client = {
            let parameters = client_parameters();
            // no CLIENT_NAME

            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_router(router)
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client
            .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
            .await?;

        // Silent refuse means server doesn't send CCF, so client should either:
        // 1. Timeout waiting for handshake
        // 2. Fail with NoViablePath when path times out
        let result = time::timeout(Duration::from_secs(1), connection.handshaked()).await;
        match result {
            Err(_timeout) => {}                                     // Expected: timeout
            Ok(Err(e)) if e.kind() == ErrorKind::NoViablePath => {} // Also acceptable: path timeout
            Ok(other) => panic!("Expected timeout or NoViablePath, got {:?}", other),
        }

        listeners.shutdown();
        Ok(())
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Message {
    data: Vec<u8>,
    sign: Vec<u8>,
}

const SIGNATURE_SCHEME: rustls::SignatureScheme = rustls::SignatureScheme::ECDSA_NISTP256_SHA256;

async fn send_and_verify_echo_with_sign_verify(
    connection: &Connection,
    data: &[u8],
) -> Result<(), BoxError> {
    let local = connection.local_authority().await.unwrap().unwrap();
    let remote = connection.remote_authority().await.unwrap().unwrap();
    let (_sid, (mut reader, mut writer)) = connection.open_bi_stream().await?.unwrap();
    tracing::debug!(target: "dquic", "stream opened");

    let write = async {
        let data = data.to_vec();
        let sign = local.sign(SIGNATURE_SCHEME, &data).unwrap();
        let message = postcard::to_stdvec(&Message { data, sign }).unwrap();
        writer.write_all(&message).await?;
        writer.shutdown().await?;
        tracing::info!(target: "dquic", "write done");
        Result::<(), BoxError>::Ok(())
    };
    let read = async {
        let mut message = Vec::new();
        reader.read_to_end(&mut message).await?;
        let message: Message = postcard::from_bytes(&message).unwrap();
        remote
            .verify(SIGNATURE_SCHEME, &message.data, &message.sign)
            .unwrap();
        assert_eq!(message.data, data);
        tracing::info!(target: "dquic", "read done");
        Result::<(), BoxError>::Ok(())
    };

    tokio::try_join!(read, write).map(|_| ())
}

async fn echo_stream_with_sign_verify(
    local: LocalAuthority,
    remote: RemoteAuthority,
    mut reader: StreamReader,
    mut writer: StreamWriter,
) {
    let mut message = Vec::new();
    reader.read_to_end(&mut message).await.unwrap();
    let Message { data, sign } = postcard::from_bytes(&message).unwrap();
    remote.verify(SIGNATURE_SCHEME, &data, &sign).unwrap();
    tracing::debug!(target: "dquic", "message received and verified");

    let sign = local.sign(SIGNATURE_SCHEME, &data).unwrap();
    let message = postcard::to_stdvec(&Message { data, sign }).unwrap();
    writer.write_all(&message).await.unwrap();
    writer.shutdown().await.unwrap();
    tracing::debug!(target: "dquic", "signed echo sent");
}

pub async fn serve_echo_with_sign_verify(listeners: Arc<QuicListeners>) {
    while let Ok((connection, server, pathway, _link)) = listeners.accept().await {
        assert_eq!(server, "localhost");
        let local = connection.local_authority().await.unwrap().unwrap();
        let remote = connection.remote_authority().await.unwrap().unwrap();
        tracing::info!(target: "dquic", source = ?pathway.remote(), "accepted new connection");
        tokio::spawn(async move {
            while let Ok((_sid, (reader, writer))) = connection.accept_bi_stream().await {
                tokio::spawn(echo_stream_with_sign_verify(
                    local.clone(),
                    remote.clone(),
                    reader,
                    writer,
                ));
            }
        });
    }
}

async fn launch_echo_with_sign_verify_server(
    quic_router: Arc<QuicRouter>,
    parameters: ServerParameters,
) -> Result<(Arc<QuicListeners>, impl Future<Output: Send>), BoxError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap));
    let listeners = QuicListeners::builder()
        .with_router(quic_router)
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
        )
        .with_parameters(parameters)
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
    Ok((listeners.clone(), serve_echo_with_sign_verify(listeners)))
}

#[test]
fn sign_and_verify() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(QuicRouter::default());
        let (listeners, server_task) =
            launch_echo_with_sign_verify_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));
        let server_addr = get_server_addr(&listeners);

        let client = {
            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_router(router)
                .with_root_certificates(roots)
                .with_parameters(client_parameters())
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_name("client")
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client
            .connected_to_with_source("localhost", [(Source::System, server_addr.into())])
            .await?;
        send_and_verify_echo_with_sign_verify(&connection, TEST_DATA).await?;

        listeners.shutdown();
        Ok(())
    })
}
