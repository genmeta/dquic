mod http09;

#[test]
fn requests_reject_invalid_urls_and_paths() {
    for url in [
        "http://server/file",
        "https:///file",
        "https://server/../secret",
        "https://server/a/../../secret",
        "https://server/",
        "https://server/file\r\nGET /other",
        "https://server/file?query",
        "https://user@server/file",
    ] {
        assert!(http09::Request::parse(url).is_err(), "accepted {url:?}");
    }
    let request = http09::Request::parse("https://server4:443/files/test.bin").unwrap();
    assert_eq!(request.authority, "server4:443");
    assert_eq!(request.path, "/files/test.bin");
    assert_eq!(request.filename, "test.bin");
}

#[tokio::test]
async fn files_are_transferred_concurrently_with_fin_and_binary_contents() {
    let root = std::env::temp_dir().join(format!("dquic-http09-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let payload: Vec<_> = (0..256 * 1024).map(|n| (n % 251) as u8).collect();
    std::fs::write(root.join("payload.bin"), &payload).unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let root = root.clone();
        let expected = payload.clone();
        tasks.spawn(async move {
            let (client, server) = tokio::io::duplex(1024);
            let (client_read, client_write) = tokio::io::split(client);
            let (server_read, server_write) = tokio::io::split(server);
            let mut output = Vec::new();
            let (sent, received) = tokio::join!(
                http09::serve(server_read, server_write, &root),
                http09::download(client_read, client_write, "/payload.bin", &mut output),
            );
            assert_eq!(sent.unwrap(), expected.len() as u64);
            assert_eq!(received.unwrap(), expected.len() as u64);
            assert_eq!(output, expected);
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn invalid_or_oversized_requests_are_rejected() {
    for request in [b"POST /file\r\n".to_vec(), b"GET /../secret\r\n".to_vec(), b"GET /file\r\nextra".to_vec(), vec![b'a'; 8193]] {
        assert!(http09::serve(request.as_slice(), tokio::io::sink(), std::path::Path::new(".")).await.is_err());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn symlinks_cannot_escape_the_file_root() {
    let root = std::env::temp_dir().join(format!("dquic-http09-links-{}", std::process::id()));
    std::fs::create_dir_all(root.join("www")).unwrap();
    std::fs::write(root.join("secret"), b"private").unwrap();
    std::os::unix::fs::symlink(root.join("secret"), root.join("www/link")).unwrap();
    assert!(http09::serve(b"GET /link\r\n".as_slice(), tokio::io::sink(), &root.join("www")).await.is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn quic_http09_transfers_with_small_windows() {
    use std::{sync::Arc, time::Duration};

    use dquic::{
        ArcAddrBook, CertificateDer, Dock, Endpoint, ParameterId, PrivateKeyDer, QuicEndpoint, Resolver, Role, RootCerts, Scope,
        ServerRegistry, SystemResolver, qtls::PemObject,
    };

    let root = std::env::temp_dir().join(format!("dquic-quic-http09-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let payload: Vec<_> = (0..64 * 1024 + 17).map(|n| (n % 251) as u8).collect();
    std::fs::write(root.join("payload.bin"), &payload).unwrap();
    RootCerts::set([CertificateDer::from_pem_slice(include_bytes!("../../qtls/tests/keychain/localhost/ca.cert")).unwrap()]).unwrap();
    let identity = Endpoint::new(
        "localhost",
        vec![CertificateDer::from_pem_slice(include_bytes!("../../qtls/tests/keychain/localhost/server.cert")).unwrap()],
        PrivateKeyDer::from_pem_slice(include_bytes!("../../qtls/tests/keychain/localhost/server.key")).unwrap(),
        if cfg!(feature = "ocsp-must-staple") {
            include_bytes!("../../qtls/tests/keychain/localhost/server.ocsp").to_vec()
        } else {
            Vec::new()
        },
    )
    .unwrap();
    let server_socket = Dock::global().ephemeral_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let client_socket = Dock::global().ephemeral_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let client_address = client_socket.socket().local_addr().unwrap();
    ArcAddrBook::global().add_sock_addr(client_address);
    Resolver::add(Arc::new(SystemResolver));
    let mut server: QuicEndpoint = identity.into();
    server.set_alpn(vec![http09::ALPN.to_vec()]);
    let (accepted, mut incoming) = tokio::sync::mpsc::unbounded_channel();
    server
        .listen(Scope::Loopback, move |connection| {
            accepted.send(connection).unwrap();
        })
        .unwrap();
    let mut client = QuicEndpoint::anonymous();
    client.set_alpn(vec![http09::ALPN.to_vec()]);
    client.set_parameters(Role::Client, ParameterId::InitialMaxData, 64 * 1024_u32).unwrap();
    client.set_parameters(Role::Client, ParameterId::InitialMaxStreamDataBidiLocal, 32 * 1024_u32).unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_, authority, client) =
            client.connect(format!("localhost:{}", server_socket.socket().local_addr().unwrap().port())).await.unwrap();
        let (peer, _, server) = incoming.recv().await.unwrap();
        assert_eq!(authority.name(), "localhost");
        assert!(peer.is_none());
        assert_eq!(client.alpn(), http09::ALPN);
        assert_eq!(server.alpn(), http09::ALPN);
        let serve = async {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..128 {
                let (_, (reader, writer)) = server.accept_bi_stream().await.unwrap();
                let root = root.clone();
                tasks.spawn(async move { http09::serve(reader, writer, &root).await.unwrap() });
            }
            while let Some(result) = tasks.join_next().await {
                assert_eq!(result.unwrap(), payload.len() as u64);
            }
        };
        let download = async {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..128 {
                let (_, (reader, writer)) = client.open_bi_stream().await.unwrap().unwrap();
                let expected = payload.clone();
                tasks.spawn(async move {
                    let mut output = Vec::new();
                    let bytes = http09::download(reader, writer, "/payload.bin", &mut output).await.unwrap();
                    assert_eq!(bytes, expected.len() as u64);
                    assert_eq!(output, expected);
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        };
        tokio::join!(serve, download);
        client.close(0u32.into(), "interop test complete");
        server.close(0u32.into(), "interop test complete");
    })
    .await
    .expect("HTTP/0.9 must progress past both stream and connection flow control limits");
    ServerRegistry::global().remove("localhost");
    ArcAddrBook::global().del_sock_addr(client_address);
    drop((client_socket, server_socket));
    std::fs::remove_dir_all(root).unwrap();
}
