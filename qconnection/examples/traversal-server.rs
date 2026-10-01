//! Scan interfaces, discover public addresses, then serve QUIC echo connections.
#[path = "traversal/network.rs"]
mod network;
use std::io;

use qbase::{endpoint::Endpoint, param::handy::server_parameters};
use qconnection::{ArcConnection, QuicEndpoint, Scopes};
use tls_backend::pki_types::pem::PemObject;
use tokio::{io::AsyncWriteExt, sync::mpsc};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_target(false)
        .init();
    qtls::RootCerts::set([qtls::CertificateDer::from_pem_slice(include_bytes!(
        "../../tests/keychain/localhost/ca.cert"
    ))?])?;
    let identity = Endpoint::new(
        &qtls::default_provider(),
        "localhost",
        vec![qtls::CertificateDer::from_pem_slice(include_bytes!(
            "../../tests/keychain/localhost/server.cert"
        ))?],
        qtls::PrivateKeyDer::from_pem_slice(include_bytes!(
            "../../tests/keychain/localhost/server.key"
        ))?,
        include_bytes!("../../tests/keychain/localhost/server.ocsp").to_vec(),
    )?;
    let mut endpoint = QuicEndpoint::new(identity);
    endpoint.server_parameters = server_parameters();

    let network = network::start(None).await?;

    let (sender, mut incoming) = mpsc::unbounded_channel();
    endpoint.listen(Scopes::ALL, move |connection| {
        let _ = sender.send(connection);
    })?;
    for address in &network.endpoints {
        println!("cargo run -p qconnection --example traversal-client -- \\\n  --server {address}");
    }
    while let Some(connection) = incoming.recv().await {
        match connection {
            Ok((_, _, connection)) => {
                tokio::spawn(async move {
                    if let Err(error) = echo(connection).await {
                        eprintln!("connection ended: {error}");
                    }
                });
            }
            Err(error) => eprintln!("handshake failed: {error}"),
        }
    }

    Err(io::Error::other("listener stopped").into())
}

async fn echo(connection: ArcConnection) -> Result<(), Error> {
    let mut last_bytes = None;
    let mut last_paths = Vec::new();
    loop {
        let (_, (mut reader, mut writer)) = connection.accept_bi_stream().await?;
        let bytes = tokio::io::copy(&mut reader, &mut writer).await?;
        writer.shutdown().await?;
        if last_bytes != Some(bytes) {
            println!("Echoed: {bytes} bytes");
            last_bytes = Some(bytes);
        }
        let mut paths = connection.validated_paths();
        paths.sort_unstable();
        if paths != last_paths {
            for path in &paths {
                println!("{path}");
            }
            last_paths = paths;
        }
    }
}
