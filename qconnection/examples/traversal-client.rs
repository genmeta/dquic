//! Connect through a relay, then discover direct public and LAN paths.
#[path = "traversal/network.rs"]
mod network;

use std::{fmt, sync::Arc, time::Duration};

use clap::Parser;
use futures::{FutureExt, StreamExt, stream};
use qbase::{endpoint::Endpoint, param::handy::client_parameters};
use qconnection::QuicEndpoint;
use qresolve::{EndpointAddr, Family, Resolve, ResolveFuture, Resolver, Source};
use tls_backend::pki_types::pem::PemObject;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{interval, timeout},
};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser)]
struct Options {
    /// Copy the relay endpoint printed by traversal-server (agent:port-outer:port).
    #[arg(long)]
    server: EndpointAddr,
}

/// Stand in for DNS: localhost is the name on the bundled server certificate.
#[derive(Debug)]
struct MockResolver(EndpointAddr);
impl fmt::Display for MockResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("example resolver")
    }
}
impl Resolve for MockResolver {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        _: &'a str,
        family: Option<Family>,
    ) -> ResolveFuture<'a> {
        async move {
            let matches = name == "localhost"
                && family.is_none_or(|f| (f == Family::V4) == self.0.addr().is_ipv4());
            Ok(stream::iter(matches.then_some((Source::System, self.0))).boxed())
        }
        .boxed()
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let options = Options::parse();
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
        "client",
        vec![qtls::CertificateDer::from_pem_slice(include_bytes!(
            "../../tests/keychain/localhost/client.cert"
        ))?],
        qtls::PrivateKeyDer::from_pem_slice(include_bytes!(
            "../../tests/keychain/localhost/client.key"
        ))?,
        include_bytes!("../../tests/keychain/localhost/client.ocsp").to_vec(),
    )?;
    let mut endpoint = QuicEndpoint::new(identity);
    endpoint.client_parameters = client_parameters();

    let EndpointAddr::Mediate { agent, .. } = options.server else {
        return Err("--server must be the relay endpoint printed by traversal-server".into());
    };
    network::start(Some(agent)).await?;
    Resolver::add(Arc::new(MockResolver(options.server)));
    let (_, _, connection) = timeout(
        Duration::from_secs(30),
        endpoint.connect("localhost".into()),
    )
    .await??;
    println!(
        "\n[已连接] localhost\n  中转服务器  {agent}\n  服务端映射  {}",
        options.server.addr()
    );

    let mut ticks = interval(Duration::from_secs(2));
    let mut last_reply = None;
    let mut last_paths = Vec::new();
    loop {
        ticks.tick().await;
        let (_, (mut reader, mut writer)) = connection
            .open_bi_stream()
            .await?
            .ok_or("no bidirectional stream available")?;
        writer.write_all(b"hello from client\n").await?;
        writer.shutdown().await?;
        let mut reply = String::new();
        reader.read_to_string(&mut reply).await?;
        if last_reply.as_ref() != Some(&reply) {
            println!("[回显] {}", reply.trim_end());
            last_reply = Some(reply);
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
