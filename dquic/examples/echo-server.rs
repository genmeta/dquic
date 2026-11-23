//! Run: cargo run -p dquic --example echo-server -- [interface]
use std::{num::NonZeroU32, sync::Arc};

use dquic::{ArcConnection, CertificateDer, Dock, Endpoint, PrivateKeyDer, QuicEndpoint, RootCerts, Scope::Loopback, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let interface_name = std::env::args().nth(1);
    let interface = netwatcher::list_interfaces()?
        .into_values()
        .find(|interface| match &interface_name {
            Some(name) => interface.name == *name,
            None => interface.ipv4_ips().any(|ip| ip.is_loopback()),
        })
        .ok_or_else(|| format!("network interface {} not found", interface_name.as_deref().unwrap_or("loopback")))?;
    let ifindex = NonZeroU32::new(interface.index).ok_or("interface index must be non-zero")?;
    RootCerts::set([CertificateDer::from(include_bytes!("keychain/ca.der").as_slice())])?;
    let endpoint = Endpoint::new(
        "localhost",
        vec![CertificateDer::from(include_bytes!("keychain/server.der").as_slice())],
        PrivateKeyDer::try_from(include_bytes!("keychain/server.key.der").as_slice())?,
        include_bytes!("keychain/server.ocsp").to_vec(),
    )?;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:4433".parse()?, ifindex)?);
    Dock::global().add_socket(socket.clone())?;

    let endpoint: QuicEndpoint = endpoint.into();
    endpoint.listen(Loopback, |(_, _, connection)| {
        tokio::spawn(async move {
            if let Err(error) = echo(connection).await {
                eprintln!("Echo failed: {error}");
            }
        });
    })?;
    println!("Listening on localhost:4433 (Ctrl-C to stop)");
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn echo(connection: ArcConnection) -> Result<(), Error> {
    let (_, (mut reader, mut writer)) = connection.accept_bi_stream().await?;
    let mut message = Vec::new();
    reader.read_to_end(&mut message).await?;
    writer.write_all(&message).await?;
    writer.shutdown().await?;
    println!("Echoed {} bytes", message.len());
    drop((reader, writer));
    connection.close(0u32.into(), "echo complete");
    Ok(())
}
