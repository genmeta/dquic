use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Instant};

use clap::Parser;
use dquic::prelude::{
    handy::{ToCertificate, client_parameters},
    *,
};
use http::{
    Uri,
    uri::{Authority, Parts, Scheme},
};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use tokio::{
    fs,
    io::{AsyncWrite, AsyncWriteExt},
    task::JoinSet,
};
use tracing::Instrument;
use tracing_subscriber::prelude::*;

#[derive(Parser, Clone)]
struct Options {
    #[arg(long, help = "Save the qlog to a dir", value_name = "PATH")]
    qlog: Option<PathBuf>,
    #[arg(
        long,
        help = "Certificate of CA who issues the server certificate",
        value_delimiter = ',',
        default_value = "tests/keychain/localhost/ca.cert"
    )]
    roots: Vec<PathBuf>,
    #[arg(
        long,
        default_value = "false",
        help = "Skip verification of server certificate"
    )]
    skip_verify: bool,
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
        short = 'p',
        action = clap::ArgAction::Set,
        help = "enable progress bar",
        default_value = "true",
        value_enum
    )]
    progress: bool,
    #[arg(
        long,
        action = clap::ArgAction::Set,
        help = "enable ansi",
        default_value = "true",
        value_enum
    )]
    ansi: bool,
    #[arg(
        long,
        short = 'r',
        help = "number of requests per connection",
        default_value = "1"
    )]
    reqs: usize,
    #[arg(
        long,
        short = 'c',
        help = "number of connections client initiates",
        default_value = "1"
    )]
    conns: usize,
    #[arg(long, help = "Save the response to a dir", value_name = "PATH")]
    save: Option<PathBuf>,
    #[arg(
        help = "URI to request",
        value_delimiter = ',',
        default_value = "https://localhost:4433/Cargo.lock"
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
                        .with_default_directive(match options.progress {
                            true => tracing::level_filters::LevelFilter::OFF.into(),
                            false => tracing::level_filters::LevelFilter::INFO.into(),
                        })
                        .from_env_lossy(),
                ),
        )
        .init();
    if let Err(error) = run(options).await {
        tracing::error!(?error);
        std::process::exit(1);
    };
}

type Error = Box<dyn std::error::Error + Send + Sync>;

async fn run(options: Options) -> Result<(), Error> {
    let qlogger: Arc<dyn qevent::telemetry::QLog + Send + Sync> = match options.qlog {
        Some(dir) => Arc::new(handy::LegacySeqLogger::new(dir)),
        None => Arc::new(handy::NoopLogger),
    };

    let client_builder = if options.skip_verify {
        tracing::warn!("skip server verify");
        QuicClient::builder().without_verifier()
    } else {
        tracing::info!("load ca certs");
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
            .with_parameters(client_parameters())
            .with_alpns(options.alpns)
            .enable_sslkeylog()
            .build(),
    );

    let pbs = MultiProgress::new();
    if !options.progress {
        pbs.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    }
    let conns_pb = pbs.add(ProgressBar::new(0).with_prefix("connections").with_style(
        ProgressStyle::with_template("{prefix} {wide_bar} {pos}/{len}")?,
    ));
    let total_pb = pbs.add(ProgressBar::new(0).with_prefix("requests").with_style(
        ProgressStyle::with_template("{prefix} {wide_bar} {pos}/{len} {per_sec} {eta}")?,
    ));

    let queries = options
        .uris
        .into_iter()
        // 根据 authority 分组
        .fold(HashMap::<_, Vec<_>>::new(), |mut uris, uri| {
            let auth = uri.authority().expect("uri must have authority");
            uris.entry(auth.to_string())
                .or_default()
                .push(uri.path().to_owned());
            uris
        })
        .into_iter()
        // 压力测试：让uri变多
        .map(|(auth, uris)| {
            let authority = auth.parse::<Authority>().unwrap();
            let totoal_reqs = uris.len() * options.reqs;
            let total_reqs = uris.into_iter().cycle().take(totoal_reqs);
            (authority, total_reqs)
        });

    let start_time = Instant::now();
    let mut connections = JoinSet::new();

    for (authority, paths) in queries {
        for _conn_idx in 0..options.conns {
            conns_pb.inc_length(1);
            connections.spawn(download_files_with_progress(
                client.clone(),
                authority.clone(),
                paths.clone(),
                total_pb.clone(),
                options.save.clone(),
            ));
        }
    }

    let mut success_queries = 0;
    while let Some(res) = connections.join_next().await {
        match res {
            Ok(Ok(queries)) => {
                tracing::info!(target: "counting", queries, "connection finished");
                success_queries += queries;
                conns_pb.inc(1);
            }
            Ok(Err(err)) => {
                tracing::error!(target: "counting", error=?err, "conenction failed");
                conns_pb.dec_length(1);
            }
            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
            Err(err) => panic!("{err}"),
        }
    }

    conns_pb.finish();
    total_pb.finish();

    let total_time = start_time.elapsed().as_secs_f64();
    let qps = success_queries as f64 / total_time;

    tracing::info!(target: "counting", success_queries, total_time, qps, "done!");

    Ok(())
}

async fn download_files_with_progress(
    client: Arc<QuicClient>,
    authority: Authority,
    paths: impl Iterator<Item = String>,
    total_pb: ProgressBar,
    save: Option<PathBuf>,
) -> Result<usize, Error> {
    let quic_connection = client.connect(authority.host()).await?;
    let odcid = quic_connection.origin_dcid()?;
    let span = tracing::info_span!("requests", %odcid, host = authority.host());

    let (mut connection, send_request) =
        h3::client::new(h3_shim::QuicConnection::new(quic_connection.clone()))
            .instrument(span.clone())
            .await?;
    tokio::spawn(async move { connection.wait_idle().await }.instrument(span.clone()));

    let mut requests = JoinSet::new();
    for path in paths {
        total_pb.inc_length(1);
        let uri = {
            let mut parts = Parts::default();
            parts.scheme = Some(Scheme::HTTPS);
            parts.authority = Some(authority.clone());
            parts.path_and_query = Some(path.parse()?);
            Uri::from_parts(parts)?
        };

        let save_to = save
            .as_ref()
            .map(|dir| dir.join(uri.path().strip_prefix('/').unwrap()));

        let request = http::Request::builder().uri(uri).body(())?;
        let mut send_request = send_request.clone();

        requests.spawn(
            async move {
                let mut request_stream = send_request.send_request(request).await?;
                request_stream.finish().await?;

                let resp = request_stream.recv_response().await?;
                if resp.status() != http::StatusCode::OK {
                    return Err(format!("response status: {}", resp.status()).into());
                }

                let mut save_to: Box<dyn AsyncWrite + Send + Unpin> = match save_to {
                    Some(path) => Box::new(fs::File::create(path).await?),
                    None => Box::new(tokio::io::sink()),
                };

                while let Some(mut data) = request_stream.recv_data().await? {
                    save_to.write_all_buf(&mut data).await?;
                }

                Result::<(), Error>::Ok(())
            }
            .instrument(span.clone()),
        );
    }

    let mut error = None;
    let mut success_queries = 0;

    tracing::info!(target: "counting", "Waiting for {} requests to finish", requests.len());
    while let Some(res) = requests.join_next().await {
        match res {
            Ok(Ok(())) => {
                tracing::warn!(target: "counting", "Request success");
                success_queries += 1;
                total_pb.inc(1);
            }
            Ok(Err(err)) => {
                tracing::warn!(target: "counting", ?err, "Request failed");
                total_pb.dec_length(1);
                error = Some(err);
            }
            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
            Err(err) => panic!("{err}"),
        }
    }

    tracing::info!(target: "counting", success_queries, "Requests completed");
    if success_queries != 0 {
        Ok(success_queries)
    } else {
        Err(error.unwrap())
    }
}
