use std::{path::PathBuf, sync::Arc};

use clap::Parser;
use dquic::{prelude::*, qinterface::io::IO};
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncWriteExt},
};
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug)]
#[command(name = "server")]
struct Options {
    #[arg(
        name = "dir",
        short,
        long,
        help = "Root directory of the files to serve. \
                If omitted, server will respond OK.",
        default_value = "./"
    )]
    root: PathBuf,
    #[arg(long, help = "Save the qlog to a dir", value_name = "PATH")]
    qlog: Option<PathBuf>,
    #[arg(
        short,
        long,
        value_delimiter = ',',
        default_values = ["127.0.0.1:4433", "[::1]:4433"],
        help = "What BindUris to listen for new connections"
    )]
    listen: Vec<BindUri>,
    #[arg(
        long,
        short,
        value_delimiter = ',',
        default_value = "quic",
        help = "ALPNs to use for the connection"
    )]
    alpns: Vec<Vec<u8>>,
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

type Error = Box<dyn std::error::Error + Send + Sync>;

fn main() {
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

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        // default value 512 out of macos ulimit
        .max_blocking_threads(256)
        .build()
        .expect("failed to build tokio runtime");

    if let Err(error) = rt.block_on(run(options)) {
        tracing::info!(?error);
        std::process::exit(1);
    }
}

async fn run(options: Options) -> Result<(), Error> {
    let qlogger: Arc<dyn qevent::telemetry::QLog + Send + Sync> = match options.qlog {
        Some(dir) => Arc::new(handy::LegacySeqLogger::new(dir)),
        None => Arc::new(handy::NoopLogger),
    };

    let listeners = QuicListeners::builder()
        .with_qlog(qlogger)
        .without_client_cert_verifier()
        .with_parameters(handy::server_parameters())
        .with_alpns(options.alpns)
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
        "Listening on {}",
        listeners
            .get_server(options.certs.server_name.as_str())
            .unwrap()
            .bind_interfaces()
            .iter()
            .next()
            .unwrap()
            .1
            .borrow()
            .bound_addr()?
    );

    loop {
        let (connection, _server, _pathway, _link) = listeners.accept().await?;
        tokio::spawn(serve_files(connection));
    }
}

async fn serve_files(connection: Arc<Connection>) -> Result<(), Error> {
    async fn serve_file(mut reader: StreamReader, mut writer: StreamWriter) -> Result<(), Error> {
        let mut request = String::new();
        reader.read_to_string(&mut request).await?;
        tracing::info!("received request: {request}");

        // HTTP/0.9 is very simple - just a GET request with a path
        let serve = async {
            match request.trim().strip_prefix("GET /") {
                Some(path) => {
                    tracing::debug!(?path, "Received HTTP/0.9 request");
                    let mut file = fs::File::open(PathBuf::from_iter(["./", path])).await?;
                    io::copy(&mut file, &mut writer).await.map(|_| ())
                }
                None => Err(io::Error::other(format!(
                    "Invalid HTTP/0.9 request: {request}",
                ))),
            }
        };

        if let Err(error) = serve.await {
            tracing::warn!("failed to serve request: {}", error);
        }

        _ = writer.shutdown().await;

        Ok(())
    }

    loop {
        let (_sid, (reader, writer)) = connection.accept_bi_stream().await?;
        tokio::spawn(serve_file(reader, writer));
    }
}
