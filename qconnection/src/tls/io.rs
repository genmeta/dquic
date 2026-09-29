use qbase::{
    ArcReceiving,
    error::{ErrorKind, QuicError},
};
use qrecovery::crypto::CryptoStream;
use qtls::CryptoLevel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{CloseReason, TlsContext};

/// One detached input coroutine per level. Retiring the reader ends only that level.
pub async fn read_crypto_stream_to_tls(
    tls: TlsContext,
    level: CryptoLevel,
    stream: CryptoStream,
    closed: ArcReceiving<CloseReason>,
) {
    let mut reader = stream.reader();
    let mut buffer = [0; 4096];
    while let Ok(length) = reader.read(&mut buffer).await {
        if length == 0 {
            break;
        }
        if let Err(error) = tls.write_msg(level, &buffer[..length]) {
            closed.with(error.into());
            break;
        }
    }
}

/// One detached TLS output coroutine for one encryption level.
pub(crate) async fn read_tls_to_crypto_stream(
    tls: TlsContext,
    level: CryptoLevel,
    stream: CryptoStream,
    closed: ArcReceiving<CloseReason>,
) {
    loop {
        let bytes = match tls.read_msg_at(level).await {
            Ok(bytes) => bytes,
            Err(error) => {
                stream.on_error(&error);
                closed.with(error.into());
                break;
            }
        };
        if let Err(error) = stream.writer().write_all(&bytes).await {
            tls.on_error(
                QuicError::with_default_fty(ErrorKind::Internal, error.to_string()).into(),
            );
            break;
        }
    }
}

/// One output coroutine for TLS. Buffering a flight never waits for its network ACK.
pub async fn write_crypto(
    tls: TlsContext,
    crypto: [CryptoStream; 3],
    closed: ArcReceiving<CloseReason>,
) {
    let (streams, receiver) = tokio::sync::mpsc::channel(3);
    for (level, stream) in [
        CryptoLevel::Initial,
        CryptoLevel::Handshake,
        CryptoLevel::OneRtt,
    ]
    .into_iter()
    .zip(crypto)
    {
        streams
            .try_send((level, stream))
            .expect("three CRYPTO streams");
    }
    drop(streams);
    write_staged_crypto(tls, receiver, closed).await;
}

/// Growing supplies each stream only after establishing its encryption level.
pub(crate) async fn write_staged_crypto(
    tls: TlsContext,
    mut streams: tokio::sync::mpsc::Receiver<(CryptoLevel, CryptoStream)>,
    closed: ArcReceiving<CloseReason>,
) {
    let mut crypto: [Option<CryptoStream>; 3] = [None, None, None];
    loop {
        let (level, bytes) = match tls.read_msg().await {
            Ok(message) => message,
            Err(error) => {
                for stream in crypto.iter().flatten() {
                    stream.on_error(&error);
                }
                while let Ok((_, stream)) = streams.try_recv() {
                    stream.on_error(&error);
                }
                closed.set(error.into());
                break;
            }
        };
        let index = level_index(level);
        while crypto[index].is_none() {
            let Some((level, stream)) = streams.recv().await else {
                tls.on_error(
                    QuicError::with_default_fty(
                        ErrorKind::Internal,
                        "TLS output has no CRYPTO stream",
                    )
                    .into(),
                );
                break;
            };
            crypto[level_index(level)] = Some(stream);
        }
        let Some(stream) = &crypto[index] else {
            continue;
        };
        if let Err(error) = stream.writer().write_all(&bytes).await {
            tls.on_error(
                QuicError::with_default_fty(ErrorKind::Internal, error.to_string()).into(),
            );
        }
    }
}

fn level_index(level: CryptoLevel) -> usize {
    match level {
        CryptoLevel::Initial => 0,
        CryptoLevel::Handshake => 1,
        CryptoLevel::OneRtt => 2,
    }
}
