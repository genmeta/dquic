mod space;

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use qbase::{
    frame::Frame,
    packet::OneRttHeader,
    param::{
        ParameterId,
        handy::{client_parameters, server_parameters},
    },
    sid::handy::DemandConcurrency,
};
use qrecovery::streams::DataStreams;
use tls_backend::pki_types::pem::PemObject;

use crate::{ArcParameters, ArcReliableFrames, Role, keys::ArcOneRttKeys, space::DataSpace};

pub(crate) fn take_frames(source: &mut impl qbase::packet::Package<BytesMut>) -> Vec<Frame> {
    use qbase::packet::{Constraints, GetType, PacketBuffer};
    let mut bytes = BytesMut::with_capacity(1200);
    let mut frames = Vec::new();
    let mut limits = Constraints {
        flow_ctrl: 1200,
        send_quota: 1200,
        credit: 1200,
        max_size: 1200,
        ..Default::default()
    };
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let result = source.poll_dump(
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
        &mut PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0),
    );
    assert!(!matches!(result, std::task::Poll::Ready(Err(_))));
    frames.into_iter().map(Into::into).collect()
}

const CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/server.cert");
const KEY: &[u8] = include_bytes!("../../../tests/keychain/localhost/server.key");
const CA_CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/ca.cert");
const OCSP: &[u8] = include_bytes!("../../../tests/keychain/localhost/server.ocsp");

fn tls_server(provider: Arc<qtls::CryptoProvider>, alpn: Vec<Vec<u8>>) -> qtls::TlsServer {
    qtls::RootCerts::set([qtls::CertificateDer::from_pem_slice(CA_CERT).unwrap()]).unwrap();
    let local = qtls::LocalAuthority::new(
        &provider,
        "localhost".into(),
        vec![qtls::CertificateDer::from_pem_slice(CERT).unwrap()],
        qtls::PrivateKeyDer::from_pem_slice(KEY).unwrap(),
        OCSP.to_vec(),
    )
    .unwrap();
    qtls::TlsServer::new(qtls::ServerTlsConfig {
        provider,
        alpn,
        local,
        resumption: qtls::ServerResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap()
}

pub(crate) fn handshake() -> ([qtls::OneRttKeyMaterial; 2], [qtls::HandshakeSummary; 2]) {
    let provider = Arc::new(qtls::default_provider());
    qtls::RootCerts::set([qtls::CertificateDer::from_pem_slice(CA_CERT).unwrap()]).unwrap();
    let client = qtls::TlsClient::new(qtls::ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec(), b"ssh".to_vec()],
        local: None,
        resumption: qtls::ClientResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    let server = tls_server(provider, vec![b"ssh".to_vec(), b"h3".to_vec()]);
    let mut peers = [
        client
            .start(qtls::ClientStart {
                server_name: "localhost".try_into().unwrap(),
                quic_version: qtls::QuicVersion::V1,
                local_transport_parameters: Bytes::new(),
            })
            .unwrap(),
        server.start(qtls::QuicVersion::V1, Bytes::new()).unwrap(),
    ];
    let mut keys = [None, None];
    let mut summaries = [None, None];
    for _ in 0..16 {
        for i in 0..2 {
            while let Some(event) = peers[i].next_event() {
                match event {
                    qtls::TlsEvent::WriteCrypto {
                        epoch: level,
                        bytes,
                    } => peers[1 - i].receive_crypto(level, &bytes).unwrap(),
                    qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::OneRtt(key)) => {
                        keys[i] = Some(key)
                    }
                    qtls::TlsEvent::HandshakeComplete(summary) => summaries[i] = Some(summary),
                    _ => {}
                }
            }
        }
        if summaries.iter().all(Option::is_some) {
            break;
        }
    }
    (keys.map(Option::unwrap), summaries.map(Option::unwrap))
}

pub(crate) fn data() -> Arc<DataSpace> {
    let ([keys, _], _) = handshake();
    let client = client_parameters();
    let mut server = server_parameters();
    server
        .set(ParameterId::InitialMaxStreamsBidi, 1u32)
        .unwrap();
    server.set(ParameterId::InitialMaxStreamsUni, 1u32).unwrap();
    let parameters = ArcParameters::new(Role::Client, Arc::new(client), Arc::new(server));
    let reliable = ArcReliableFrames::with_capacity(0);
    let streams = DataStreams::new(
        parameters,
        Box::new(DemandConcurrency),
        reliable.clone(),
        None,
    );
    Arc::new(DataSpace::new(
        Default::default(),
        ArcOneRttKeys::from(keys),
        streams,
        reliable,
    ))
}
