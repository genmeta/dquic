use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use dquic::prelude::{handy::ToCertificate, *};
use http::uri::Authority;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use qevent::telemetry::handy::{LegacySeqLogger, NoopLogger};
use rustls::RootCertStore;
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncWrite, AsyncWriteExt},
    task::JoinSet,
};
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug)]
#[command(name = "server")]
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
    #[arg(
        long,
        short,
        value_delimiter = ',',
        help = "files that will be sent to server, if not present, stdin will be used"
    )]
    files: Vec<PathBuf>,
    #[arg(
        long,
        short = 'p',
        action = clap::ArgAction::Set,
        help = "enable progress bar",
        default_value = "false",
        value_enum
    )]
    progress: bool,
    #[arg(
        long,
        default_value = "true",
        action = clap::ArgAction::Set,
        help = "Enable ANSI color output in logs"
    )]
    ansi: bool,
    #[arg(default_value = "localhost:4433", help = "Host and port to connect to")]
    auth: Authority,
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
                        .with_default_directive(match options.progress {
                            true => tracing::level_filters::LevelFilter::OFF.into(),
                            false => tracing::level_filters::LevelFilter::INFO.into(),
                        })
                        .from_env_lossy(),
                ),
        )
        .init();

    if let Err(error) = run(options).await {
        tracing::error!(target: "dquic", ?error);
        std::process::exit(1);
    };
}

type Error = Box<dyn std::error::Error + Send + Sync>;

async fn run(options: Options) -> Result<(), Error> {
    let qlogger: Arc<dyn qevent::telemetry::QLog + Send + Sync> = match options.qlog {
        Some(dir) => Arc::new(LegacySeqLogger::new(dir)),
        None => Arc::new(NoopLogger),
    };

    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    roots.add_parsable_certificates(options.roots.iter().flat_map(|path| path.to_certificate()));

    let client = Arc::new(
        QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .with_parameters(handy::client_parameters())
            .with_qlog(qlogger)
            .defer_idle_timeout(Duration::from_secs(60))
            .enable_sslkeylog()
            .enable_0rtt()
            .build(),
    );

    match options.files {
        files if files.is_empty() => process(&client, &options.auth, options.progress).await,
        files => {
            let files = files.iter().map(|p| p.as_path());
            send_and_verify_files(&client, options.auth, files, options.progress).await
        }
    }
}

async fn send_and_verify_files(
    client: &Arc<QuicClient>,
    auth: Authority,
    files: impl Iterator<Item = &Path>,
    progress: bool,
) -> Result<(), Error> {
    let pbs = MultiProgress::new();
    if !progress {
        pbs.set_draw_target(ProgressDrawTarget::hidden());
    }
    let total_tx = pbs.add(new_pb("总↑", 0));
    let total_rx = pbs.add(new_pb("总↓️", 0));

    let mut echos = JoinSet::new();

    for path in files {
        let data = fs::read(path).await?;
        let (total_tx, total_rx) = (total_tx.clone(), total_rx.clone());
        total_tx.inc_length(data.len() as u64);
        total_rx.inc_length(data.len() as u64);

        let client = client.clone();
        let auth = auth.clone();

        let tx_pb = pbs.insert_before(&total_tx, new_pb("↑", data.len() as u64));
        let rx_pb = pbs.insert_before(&total_rx, new_pb("↓", data.len() as u64));
        echos.spawn(async move {
            let mut back = vec![];
            send_and_verify_echo(&client, &auth, &data, tx_pb, rx_pb, &mut back).await?;
            assert_eq!(back, data);
            total_tx.inc(data.len() as u64);
            total_rx.inc(data.len() as u64);
            Result::<(), Error>::Ok(())
        });
    }

    echos
        .join_all()
        .await
        .into_iter()
        .collect::<Result<(), Error>>()?;

    total_tx.finish();
    total_rx.finish();

    Ok(())
}

async fn process(client: &Arc<QuicClient>, auth: &Authority, progress: bool) -> Result<(), Error> {
    eprintln!(
        "Enter interactive mode. Input anything, enter, then server will echo it back. Input `exit` or `quit` to quit."
    );

    let mut stdin = io::BufReader::new(io::stdin());
    let mut stdout = io::stdout();

    loop {
        stdout.write_all(b"\n>").await?;
        stdout.flush().await?;

        let mut line = String::new();
        stdin.read_line(&mut line).await?;
        let line = line.trim();

        if line == "exit" || line == "quit" {
            break Ok(());
        }

        let tx_pb = new_pb("↑", line.len() as u64);
        let rx_pb = new_pb("↓️", line.len() as u64);
        if !progress {
            tx_pb.set_draw_target(ProgressDrawTarget::hidden());
            rx_pb.set_draw_target(ProgressDrawTarget::hidden());
        }
        send_and_verify_echo(client, auth, line.as_bytes(), tx_pb, rx_pb, &mut stdout).await?;
    }
}

fn new_pb(prefix: impl Into<Cow<'static, str>>, len: u64) -> ProgressBar {
    let style = ProgressStyle::default_bar()
        .template("{prefix} {wide_bar} {percent_precise}% {decimal_bytes_per_sec} ETA: {eta} {msg}")
        .unwrap();
    ProgressBar::new(len).with_style(style).with_prefix(prefix)
}

async fn send_and_verify_echo(
    client: &Arc<QuicClient>,
    auth: &Authority,
    data: &[u8],
    tx_pb: ProgressBar,
    rx_pb: ProgressBar,
    dst: &mut (impl AsyncWrite + Unpin),
) -> Result<(), Error> {
    let connection = client.connect(auth.host()).await?;

    let (sid, (reader, writer)) = connection.open_bi_stream().await?.unwrap();
    tracing::debug!(target: "dquic", %sid, "opened stream");

    let mut reader = rx_pb.wrap_async_read(reader);
    let mut writer = tx_pb.wrap_async_write(writer);

    tokio::try_join!(
        async {
            writer.write_all(data).await?;
            writer.shutdown().await?;
            tx_pb.finish();
            Result::<(), Error>::Ok(())
        },
        async {
            io::copy(&mut reader, dst).await?;
            dst.flush().await?;
            rx_pb.finish();
            Result::<(), Error>::Ok(())
        }
    )
    .map(|_| ())
}
