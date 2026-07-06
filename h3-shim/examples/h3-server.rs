use std::{ops::Deref, path::PathBuf, sync::Arc};

use bytes::{Bytes, BytesMut};
use clap::Parser;
use dquic::{
    prelude::*,
    qinterface::{bind_uri::BindUri, io::IO},
};
use h3::{quic::BidiStream, server::RequestStream};
use http::{Request, StatusCode};
use tokio::{fs::File, io::AsyncReadExt};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, prelude::*};

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
        default_value = "h3",
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
        action = clap::ArgAction::Set,
        default_value = "true",
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
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
        .init();

    // 测试日志是否工作
    tracing::info!(target: "dquic", "tracing initialized successfully");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        // default value 512 out of macos ulimit
        .max_blocking_threads(256)
        .build()
        .expect("failed to build tokio runtime");

    if let Err(error) = rt.block_on(run(options)) {
        tracing::info!(target: "dquic", ?error);
        std::process::exit(1);
    }
}

async fn run(options: Options) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!(target: "dquic", root = %options.root.display(), "serving files");
    let root = Arc::new(options.root);
    if !root.is_dir() {
        return Err(format!("{}: is not a readable directory", root.display()).into());
    }

    let qlogger: Arc<dyn qevent::telemetry::QLog + Send + Sync> = match options.qlog {
        Some(dir) => Arc::new(handy::LegacySeqLogger::new(dir)),
        None => Arc::new(handy::NoopLogger),
    };

    let Certs {
        server_name,
        cert,
        key,
    } = options.certs;

    let listeners = QuicListeners::builder()
        .with_qlog(qlogger)
        .without_client_cert_verifier()
        .with_parameters(handy::server_parameters())
        .with_alpns(options.alpns)
        .listen(options.backlog)?;
    listeners
        .add_server(
            server_name.as_str(),
            cert.as_path(),
            key.as_path(),
            options.listen,
            None,
        )
        .await?;
    tracing::info!(
        target: "dquic",
        listen_addr = %listeners
            .get_server(server_name.as_str())
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

    // handle incoming connections and requests
    while let Ok((new_conn, _server, _pathway, _link)) = listeners.accept().await {
        let h3_conn =
            match h3::server::Connection::new(h3_shim::QuicConnection::new(new_conn)).await {
                Ok(h3_conn) => {
                    tracing::info!(target: "dquic", "accepted new QUIC connection");
                    h3_conn
                }
                Err(error) => {
                    tracing::error!(target: "dquic", %error, "failed to establish h3 connection");
                    continue;
                }
            };
        let root = root.clone();
        tokio::spawn(handle_connection(root, h3_conn));
    }

    Ok(())
}

async fn handle_connection<T>(
    serve_root: Arc<PathBuf>,
    mut connection: h3::server::Connection<T, Bytes>,
) where
    T: h3::quic::Connection<Bytes> + 'static,
    <T as h3::quic::OpenStreams<Bytes>>::BidiStream: h3::quic::BidiStream<Bytes> + Send + 'static,
{
    loop {
        match connection.accept().await {
            Ok(Some(request_resolver)) => {
                let serve_root = serve_root.clone();
                let handle_request = async move {
                    let (request, stream) = request_resolver.resolve_request().await?;
                    handle_request(request, stream, serve_root).await
                };
                tokio::spawn(async move {
                    if let Err(e) = handle_request.await {
                        tracing::error!(target: "dquic", error = %e, "handling request failed");
                    }
                });
            }
            Ok(None) => break,
            Err(..) => break,
        }
    }
}

#[tracing::instrument(skip_all)]
async fn handle_request<T>(
    request: Request<()>,
    mut stream: RequestStream<T, Bytes>,
    serve_root: Arc<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    let (status, to_serve) = match serve_root.deref() {
        _ if request.uri().path().contains("..") => (StatusCode::NOT_FOUND, None),
        root => {
            let to_serve = root.join(request.uri().path().strip_prefix('/').unwrap_or(""));
            match File::open(&to_serve).await {
                Ok(file) => (StatusCode::OK, Some(file)),
                Err(e) => {
                    tracing::error!(target: "dquic", path = %to_serve.to_string_lossy(), error = %e, "failed to open file");
                    (StatusCode::NOT_FOUND, None)
                }
            }
        }
    };

    let resp = http::Response::builder().status(status).body(())?;
    stream.send_response(resp).await?;

    if let Some(mut file) = to_serve {
        loop {
            let mut buf = BytesMut::with_capacity(4096 * 10);
            if file.read_buf(&mut buf).await? == 0 {
                break;
            }
            stream.send_data(buf.freeze()).await?;
        }
    }

    stream.finish().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_name() {}
}
