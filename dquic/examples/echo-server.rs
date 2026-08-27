use std::{path::PathBuf, sync::Arc, time::Duration};

use clap::Parser;
use dquic::{prelude::*, qinterface::io::IO};
use qevent::telemetry::handy::{LegacySeqLogger, NoopLogger};
use tokio::io::{self, AsyncWriteExt};
use tracing::info;
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug)]
#[command(name = "server")]
struct Options {
    #[arg(long, help = "Save the qlog to a dir", value_name = "PATH")]
    qlog: Option<PathBuf>,
    #[arg(
        short,
        long,
        value_delimiter = ',',
        default_values = ["127.0.0.1:4433", "[::1]:4433"],
        help = "What BindUris to listen for new connections",
    )]
    listen: Vec<BindUri>,
    #[arg(
        long,
        short,
        default_value = "4096",
        help = "Maximum number of requests in the backlog. \
                If the backlog is full, new connections will be refused."
    )]
    backlog: usize,
    #[arg(
        long,
        default_value = "true",
        action = clap::ArgAction::Set,
        help = "Enable ANSI color output in logs"
    )]
    ansi: bool,
    #[command(flatten)]
    certs: Certs,
}

#[derive(Parser, Debug)]
struct Certs {
    #[arg(long, short, default_value = "localhost", help = "Server name.")]
    server_name: String,
    #[arg(
        long,
        short,
        default_value = "tests/keychain/localhost/server.cert",
        help = "Certificate for TLS. If present, `--key` is mandatory."
    )]
    cert: PathBuf,
    #[arg(
        long,
        short,
        default_value = "tests/keychain/localhost/server.key",
        help = "Private key for the certificate."
    )]
    key: PathBuf,
}

#[tokio::main]
async fn main() {
    let options = Options::parse();
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::registry()
        // .with(console_subscriber::spawn())
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(options.ansi)
                .with_filter(
                    tracing_subscriber::EnvFilter::builder()
                        .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
        .init();

    if let Err(error) = run(options).await {
        tracing::info!(target: "dquic", ?error);
        std::process::exit(1);
    }
}

async fn run(options: Options) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let qlogger: Arc<dyn qevent::telemetry::QLog + Send + Sync> = match options.qlog {
        Some(dir) => Arc::new(LegacySeqLogger::new(dir)),
        None => Arc::new(NoopLogger),
    };

    let listeners = QuicListeners::builder()
        .without_client_cert_verifier()
        .with_parameters(handy::server_parameters())
        .with_qlog(qlogger)
        .keep_alive(Duration::from_secs(0), Duration::from_secs(20))
        .enable_0rtt()
        .listen(options.backlog)?;
    listeners
        .add_server(
            options.certs.server_name.as_str(),
            options.certs.cert.as_path(),
            options.certs.key.as_path(),
            options.listen,
            None,
        )
        .await?;

    tracing::info!(
        target: "dquic",
        listen_addr = %listeners
            .get_server(options.certs.server_name.as_str())
            .unwrap()
            .bind_interfaces()
            .iter()
            .next()
            .unwrap()
            .1
            .borrow()
            .bound_addr()?,
        "listening"
    );

    serve_echo(listeners).await?;
    Ok(())
}

async fn serve_echo(listeners: Arc<QuicListeners>) -> Result<(), ListenersShutdown> {
    async fn handle_stream(mut reader: StreamReader, mut writer: StreamWriter) -> io::Result<()> {
        io::copy(&mut reader, &mut writer).await?;
        writer.shutdown().await?;
        tracing::debug!(target: "dquic", "stream copy done");

        io::Result::Ok(())
    }

    loop {
        let (connection, _server, pathway, ..) = listeners.accept().await?;
        info!(target: "dquic", source = ?pathway.remote(), "accepted new connection");
        tokio::spawn(async move {
            while let Ok((_sid, (reader, writer))) = connection.accept_bi_stream().await {
                tokio::spawn(handle_stream(reader, writer));
            }
        });
    }
}
