use std::{path::PathBuf, sync::Arc};

use clap::Parser;
use dquic::prelude::{handy::ToCertificate, *};
use http::{Uri, uri::Parts};
use qevent::telemetry::handy::{LegacySeqLogger, NoopLogger};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader},
};
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Options {
    #[arg(long, help = "Save the qlog to a dir", value_name = "PATH")]
    qlog: Option<PathBuf>,
    #[arg(
        long,
        short,
        value_delimiter = ',',
        default_value = "tests/keychain/localhost/ca.cert",
        help = "Certificates of CA who issues the server certificate"
    )]
    roots: Vec<PathBuf>,
    #[arg(long, help = "Skip verification of server certificate")]
    skip_verify: bool,
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
        default_value = "true",
        action = clap::ArgAction::Set,
        help = "Enable ANSI color output in logs"
    )]
    ansi: bool,
    #[arg(long, help = "Save the response to a dir", value_name = "PATH")]
    save: Option<PathBuf>,
    #[arg(
        value_delimiter = ',',
        default_value = "http://localhost:4433/",
        help = "Uri to request. If only one uri is present and path is not specified, enter process mode"
    )]
    uris: Vec<Uri>,
}

#[tokio::main]
async fn main() {
    let options = Options::parse();
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::registry()
        // .with(
        //     console_subscriber::ConsoleLayer::builder()
        //         .server_addr("127.0.0.1:6670".parse::<SocketAddr>().unwrap())
        //         .spawn(),
        // )
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
        tracing::error!(target: "dquic", ?error);
        std::process::exit(1);
    }
}

type Error = Box<dyn std::error::Error + Send + Sync>;

async fn run(options: Options) -> Result<(), Error> {
    if options.uris.is_empty() {
        return Err("no uri specified".into());
    }

    let qlogger: Arc<dyn qevent::telemetry::QLog + Send + Sync> = match options.qlog {
        Some(dir) => Arc::new(LegacySeqLogger::new(dir)),
        None => Arc::new(NoopLogger),
    };

    let client_builder = if options.skip_verify {
        tracing::warn!(target: "dquic", "skip server verify");
        QuicClient::builder().without_verifier()
    } else {
        tracing::info!(target: "dquic", "load ca certs");
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        roots
            .add_parsable_certificates(options.roots.iter().flat_map(|path| path.to_certificate()));
        QuicClient::builder().with_root_certificates(roots)
    };

    let client = Arc::new(
        client_builder
            .with_qlog(qlogger)
            .without_cert()
            .with_parameters(handy::client_parameters())
            .with_alpns(options.alpns)
            .enable_sslkeylog()
            .build(),
    );

    if options.uris.len() == 1 && options.uris[0].path() == "/" {
        return process(&client, &options.uris[0], options.save).await;
    } else {
        for uri in options.uris {
            download(&client, uri, options.save.as_ref()).await?;
        }
    }

    Ok(())
}

async fn process(
    client: &Arc<QuicClient>,
    base_uri: &Uri,
    save: Option<PathBuf>,
) -> Result<(), Error> {
    let mut stdin = BufReader::new(io::stdin());
    eprintln!(
        "Enter interactive mode. Input content to request (e.g: Cargo.toml), input `exit` or `quit` to quit."
    );
    loop {
        let mut input = String::new();
        _ = stdin.read_line(&mut input).await?;

        let content = input.trim();
        if content.is_empty() {
            continue;
        }

        if content == "exit" || content == "quit" {
            return Ok(());
        }

        let mut uri_parts = Parts::default();
        uri_parts.scheme = base_uri.scheme().cloned();
        uri_parts.authority = base_uri.authority().cloned();
        uri_parts.path_and_query = Some(format!("/{content}").parse()?);
        download(client, Uri::from_parts(uri_parts)?, save.as_ref()).await?;
    }
}

async fn download(client: &Arc<QuicClient>, uri: Uri, save: Option<&PathBuf>) -> Result<(), Error> {
    let authority = uri.authority().ok_or("authority must be present in uri")?;

    let file_path = uri.path().strip_prefix('/');
    let file_path = file_path.ok_or_else(|| format!("invalid path `{}`", uri.path()))?;

    let connection = client.connect(authority.host()).await?;
    let (_sid, (mut response, mut request)) = connection
        .open_bi_stream()
        .await?
        .expect("very very hard to exhaust the available stream ids");
    request
        .write_all(format!("GET /{file_path}").as_bytes())
        .await?;
    request.shutdown().await?;

    match save.map(|dir| dir.join(file_path)) {
        Some(path) => io::copy(&mut response, &mut fs::File::create(path).await?).await?,
        None => io::copy(&mut response, &mut io::stdout()).await?,
    };

    _ = connection.close("Bye bye", 0);

    tracing::info!(target: "dquic", %file_path, "saved response body to file");
    Ok(())
}
