mod http09;

use std::{
    collections::{BTreeMap, HashSet},
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use clap::Parser;
use dquic::{
    ArcAddrBook, ArcConnection, CertificateDer, Dock, Endpoint, ParameterId, PrivateKeyDer, QuicEndpoint, Resolver, Role, RootCerts,
    Scopes, ServerRegistry, SystemResolver, qtls::PemObject,
};
use http09::Request;
use tokio::{fs, task::JoinSet};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser)]
#[command(about = "HTTP/0.9 endpoint for the QUIC Interop Runner")]
struct Options {
    /// Concrete UDP addresses; defaults to the Runner's IPv4 and IPv6 addresses.
    #[arg(long, value_delimiter = ',')]
    bind: Vec<SocketAddr>,
    #[arg(long, default_value = "/certs")]
    certs: PathBuf,
    #[arg(long, default_value = "/www")]
    www: PathBuf,
    #[arg(long, default_value = "/downloads")]
    downloads: PathBuf,
    #[arg(long, value_delimiter = ',', default_value = "server,server4,server6,server46")]
    name: Vec<String>,
    /// Enable QuicEndpoint key logging to SSLKEYLOGFILE.
    #[arg(long)]
    keylog: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let options = Options::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    let testcase = std::env::var("TESTCASE").unwrap_or_default();
    if !matches!(testcase.as_str(), "handshake" | "transfer" | "multiconnect") {
        eprintln!("unsupported test case: {testcase}");
        return ExitCode::from(127);
    }
    match run(options, &testcase).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("interop failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(options: Options, testcase: &str) -> Result<(), Error> {
    let role = match std::env::var("ROLE")?.as_str() {
        "client" => Role::Client,
        "server" => Role::Server,
        _ => return Err("ROLE must be client or server".into()),
    };
    let ca = fs::read(options.certs.join("ca.pem")).await?;
    RootCerts::set(CertificateDer::pem_slice_iter(&ca).collect::<Result<Vec<_>, _>>()?)?;
    Resolver::add(Arc::new(SystemResolver));
    let binds = if options.bind.is_empty() {
        let defaults = match role {
            Role::Client => ["193.167.0.100:0", "[fd00:cafe:cafe:0::100]:0"],
            Role::Server => ["193.167.100.100:443", "[fd00:cafe:cafe:100::100]:443"],
        };
        defaults.into_iter().map(str::parse).collect::<Result<Vec<SocketAddr>, _>>()?
    } else {
        options.bind.clone()
    };
    let mut sockets = Vec::new();
    for bind in binds {
        let socket = Dock::global().ephemeral_socket(bind)?;
        let address = socket.socket().local_addr()?;
        ArcAddrBook::global().add_sock_addr(address);
        sockets.push((address, socket));
    }
    let result = match role {
        Role::Client => run_client(&options, testcase).await,
        Role::Server => run_server(&options).await,
    };
    for (address, _) in &sockets {
        ArcAddrBook::global().del_sock_addr(*address);
    }
    result
}

fn configure(endpoint: &mut QuicEndpoint, role: Role, keylog: bool) -> Result<(), Error> {
    endpoint.set_alpn(vec![http09::ALPN.to_vec()]);
    endpoint.set_keylog(keylog);
    for (id, value) in [
        (ParameterId::InitialMaxData, 1024 * 1024_u32),
        (ParameterId::InitialMaxStreamsBidi, 32_u32),
        (ParameterId::InitialMaxStreamDataBidiLocal, 64 * 1024),
        (ParameterId::InitialMaxStreamDataBidiRemote, 64 * 1024),
    ] {
        endpoint.set_parameters(role, id, value)?;
    }
    Ok(())
}

async fn run_server(options: &Options) -> Result<(), Error> {
    let certificates = fs::read(options.certs.join("cert.pem")).await?;
    let certificates = CertificateDer::pem_slice_iter(&certificates).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(&fs::read(options.certs.join("priv.key")).await?)?;
    let root = Arc::new(fs::canonicalize(&options.www).await?);
    for name in &options.name {
        let identity = Endpoint::new(name, certificates.clone(), key.clone_key(), Vec::new())?;
        let mut endpoint: QuicEndpoint = identity.into();
        configure(&mut endpoint, Role::Server, options.keylog)?;
        let root = root.clone();
        endpoint.listen(Scopes::ALL, move |(_, _, connection)| {
            tokio::spawn(serve_connection(connection, root.clone()));
        })?;
    }
    eprintln!("Serving HTTP/0.9 from {}", root.display());
    tokio::signal::ctrl_c().await?;
    for name in &options.name {
        ServerRegistry::global().remove(name);
    }
    Ok(())
}

async fn serve_connection(connection: ArcConnection, root: Arc<PathBuf>) {
    while let Ok((_, (reader, writer))) = connection.accept_bi_stream().await {
        let root = root.clone();
        let connection = connection.clone();
        tokio::spawn(async move {
            if let Err(error) = http09::serve(reader, writer, &root).await {
                eprintln!("HTTP/0.9 stream failed: {error}");
                connection.close(1u32.into(), "HTTP/0.9 request failed");
            }
        });
    }
}

async fn run_client(options: &Options, testcase: &str) -> Result<(), Error> {
    let requests = std::env::var("REQUESTS")?.split_whitespace().map(Request::parse).collect::<Result<Vec<_>, _>>()?;
    if requests.is_empty() {
        return Err("REQUESTS must contain at least one URL".into());
    }
    let mut filenames = HashSet::new();
    for request in &requests {
        if !filenames.insert(&request.filename) {
            return Err(format!("duplicate download filename: {}", request.filename).into());
        }
    }
    fs::create_dir_all(&options.downloads).await?;
    let mut endpoint = QuicEndpoint::anonymous();
    configure(&mut endpoint, Role::Client, options.keylog)?;
    if testcase == "multiconnect" {
        for request in requests {
            download_files(&endpoint, vec![request], &options.downloads).await?;
        }
    } else {
        let mut origins = BTreeMap::<String, Vec<Request>>::new();
        for request in requests {
            origins.entry(request.authority.clone()).or_default().push(request);
        }
        for requests in origins.into_values() {
            download_files(&endpoint, requests, &options.downloads).await?;
        }
    }
    Ok(())
}

async fn download_files(endpoint: &QuicEndpoint, requests: Vec<Request>, directory: &Path) -> Result<(), Error> {
    let (_, _, connection) = endpoint.connect(requests[0].authority.clone()).await?;
    let mut tasks = JoinSet::new();
    for request in requests {
        let (_, (reader, writer)) =
            connection.open_bi_stream().await?.ok_or_else(|| io::Error::other("bidirectional stream IDs exhausted"))?;
        let path = directory.join(&request.filename);
        let partial = directory.join(format!("{}.part", request.filename));
        tasks.spawn(async move {
            let output = fs::File::create(&partial).await?;
            let bytes = http09::download(reader, writer, &request.path, output).await?;
            fs::rename(partial, path).await?;
            eprintln!("Downloaded {} ({bytes} bytes)", request.filename);
            Ok::<_, Error>(())
        });
    }
    while let Some(result) = tasks.join_next().await {
        result??;
    }
    connection.close(0u32.into(), "downloads complete");
    Ok(())
}
