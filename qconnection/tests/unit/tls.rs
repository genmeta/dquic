use std::time::Duration;

use qbase::{
    ArcReceiving, Epoch,
    error::{ErrorKind, QuicError},
};
use qtransport::space::Space;

use crate::{
    CloseReason, TlsContext, common,
    tls::{read_space_to_tls, read_tls_to_space},
};

#[tokio::test]
async fn tls_io_exits_naturally_when_the_context_fails() {
    let [_, server] = common::backends(false).map(|tls| TlsContext::new(tls, 256 * 1024).unwrap());
    let spaces = Epoch::EPOCHS.map(|epoch| Space::new(epoch, ()));
    let closed = ArcReceiving::default();
    let reads = spaces
        .iter()
        .map(|space| tokio::spawn(read_space_to_tls(server.clone(), space, closed.clone())))
        .collect::<Vec<_>>();
    let writes = spaces
        .iter()
        .map(|space| tokio::spawn(read_tls_to_space(server.clone(), space, closed.clone())))
        .collect::<Vec<_>>();
    tokio::task::yield_now().await;
    server.on_error(QuicError::with_default_fty(ErrorKind::Internal, "connection ended").into());
    tokio::time::timeout(Duration::from_secs(2), async {
        for write in writes {
            write.await.unwrap();
        }
        for read in reads {
            read.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn crypto_output_failure_stops_tls_and_all_input_tasks() {
    let [client, _] = common::backends(false).map(|tls| TlsContext::new(tls, 256 * 1024).unwrap());
    let spaces = Epoch::EPOCHS.map(|epoch| Space::new(epoch, ()));
    let closed = ArcReceiving::default();
    // ClientHello is still pending, but its destination can no longer accept it.
    spaces[Epoch::Initial].crypto.sender.retire();
    let reads = spaces
        .iter()
        .map(|space| tokio::spawn(read_space_to_tls(client.clone(), space, closed.clone())))
        .collect::<Vec<_>>();
    let writes = spaces
        .iter()
        .map(|space| tokio::spawn(read_tls_to_space(client.clone(), space, closed.clone())))
        .collect::<Vec<_>>();
    tokio::time::timeout(Duration::from_millis(200), async {
        assert!(matches!(
            closed.await.unwrap().unwrap(),
            CloseReason::Internal(_)
        ));
        for write in writes {
            write.await.unwrap();
        }
        for reader in reads {
            reader.await.unwrap();
        }
        assert!(client.read_keys().await.is_err());
    })
    .await
    .unwrap();
}
