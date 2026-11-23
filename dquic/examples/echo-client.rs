//! Run echo-server first, then: cargo run -p dquic --example echo-client -- [interface-name]
//! The optional argument is a name such as lo (Linux) or lo0 (macOS).
//! Omit it to let the OS choose the outgoing interface.
use std::{error::Error, sync::Arc};

use dquic::{ArcAddrBook, CertificateDer, Dock, QuicEndpoint, Resolver, RootCerts, SystemResolver, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let ifindex = match std::env::args().nth(1) {
        Some(name) => {
            netwatcher::list_interfaces()?
                .into_values()
                .find(|interface| interface.name == name)
                .ok_or_else(|| format!("network interface {name} not found"))?
                .index
        }
        None => 0,
    };
    RootCerts::set([CertificateDer::from(include_bytes!("keychain/ca.der").as_slice())])?;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse()?, ifindex)?);
    Dock::global().add_socket(socket.clone())?;
    ArcAddrBook::global().add_sock_addr(socket.local_addr()?);
    Resolver::add(Arc::new(SystemResolver));

    let endpoint = QuicEndpoint::anonymous();
    let (_, _, connection) = endpoint.connect("localhost:4433".into()).await?;
    let (_, (mut reader, mut writer)) = connection.open_bi_stream().await?.ok_or("stream IDs exhausted")?;

    let message = b"hello, dquic!";
    writer.write_all(message).await?;
    writer.shutdown().await?; // Send FIN; the read half remains open.
    let mut reply = Vec::new();
    reader.read_to_end(&mut reply).await?; // Read through the server's FIN.
    assert_eq!(reply, message);
    println!("Echo: {}", String::from_utf8(reply)?);
    drop((reader, writer));
    connection.close(0u32.into(), "echo complete");
    Ok(())
}
