use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use qtls::{
    CertificateDer, ClientResumptionConfig, ClientStart, ClientTlsConfig, LocalAuthority, PrivateKeyDer, QuicVersion, RootCerts,
    ServerResumptionConfig, ServerTlsConfig, TlsClient, TlsEvent, TlsHandshake, TlsLimits, TlsServer,
};

type Error = Box<dyn std::error::Error + Send + Sync>;

fn main() -> Result<(), Error> {
    dquic_esp_idf::initialize()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().thread_stack_size(8192).build()?;
    runtime.block_on(async {
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        sender.send_to(b"tokio esp-idf", receiver.local_addr()?).await?;
        let mut bytes = [0; 32];
        let (length, _) = tokio::time::timeout(Duration::from_secs(5), receiver.recv_from(&mut bytes)).await??;
        assert_eq!(&bytes[..length], b"tokio esp-idf");
        println!("PASS: Tokio UDP loopback");
        Ok::<(), Error>(())
    })?;
    handshake()?;
    println!("PASS: qtls QUIC TLS handshake");
    dquic_esp_idf::report_heap("dependencies complete");
    Ok(())
}

fn handshake() -> Result<(), Error> {
    RootCerts::set([CertificateDer::from(include_bytes!("../../../examples/keychain/ca.der").as_slice())])?;
    let provider = Arc::new(qtls::default_provider());
    let authority = LocalAuthority::new(
        &provider,
        "localhost".into(),
        vec![CertificateDer::from(include_bytes!("../../../examples/keychain/server.der").as_slice())],
        PrivateKeyDer::try_from(include_bytes!("../../../examples/keychain/server.key.der").as_slice())?,
        include_bytes!("../../../examples/keychain/server.ocsp").to_vec(),
    )?;
    let client = TlsClient::new(ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        authority: None,
        resumption: ClientResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })?;
    let server = TlsServer::new(ServerTlsConfig {
        provider,
        alpn: vec![b"h3".to_vec()],
        authority,
        resumption: ServerResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })?;
    let mut client = client.start(ClientStart {
        server_name: "localhost".try_into()?,
        quic_version: QuicVersion::V1,
        local_transport_parameters: Bytes::new(),
    })?;
    let mut server = server.start(QuicVersion::V1, Bytes::new())?;
    for _ in 0..32 {
        transfer(&mut client, &mut server)?;
        transfer(&mut server, &mut client)?;
        if client.is_complete() && server.is_complete() {
            return Ok(());
        }
    }
    Err("TLS handshake did not complete".into())
}

fn transfer(sender: &mut TlsHandshake, receiver: &mut TlsHandshake) -> Result<(), Error> {
    while let Some(event) = sender.next_event() {
        if let TlsEvent::WriteCrypto { epoch, bytes } = event {
            receiver.receive_crypto(epoch, &bytes)?;
        }
    }
    Ok(())
}
