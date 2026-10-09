//! Run echo-server first, then: cargo run -p dquic --example echo-client
use std::{error::Error, sync::Arc};

use dquic::{
    AddressBook, CertificateDer, Dock, QuicEndpoint, Resolver, RootCerts, SystemResolver, UdpSocket,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    RootCerts::set([CertificateDer::from(
        include_bytes!("keychain/ca.der").as_slice(),
    )])?;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse()?)?);
    Dock::global().add(socket.clone())?;
    AddressBook::global().insert_inner(&socket, socket.local_addr()?.into())?;
    Resolver::add(Arc::new(SystemResolver));

    let endpoint = QuicEndpoint::anonymous();
    let (_, _, connection) = endpoint.connect("localhost:4433".into()).await?;
    let (_, (mut reader, mut writer)) = connection
        .open_bi_stream()
        .await?
        .ok_or("stream IDs exhausted")?;

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
