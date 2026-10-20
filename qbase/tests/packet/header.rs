#[path = "header/long.rs"]
mod long;
#[path = "header/short.rs"]
mod short;

use std::ops::Deref;

use qbase::{
    cid::ConnectionId,
    packet::{
        GetDcid, OneRttHeader, SpinBit,
        header::{
            GetScid, Header, LongHeaderBuilder,
            io::{WriteHeader, be_header},
            long::{Handshake, Initial, Retry, VersionNegotiation, ZeroRtt},
        },
        r#type::{
            Type,
            long::{self as packet_type_long, Ver1},
            short::OneRtt,
        },
    },
};

#[test]
fn test_read_header() {
    // VersionNegotiation Header
    let buf = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
    let (remain, vn_long_header) = be_header(
        Type::Long(packet_type_long::Type::VersionNegotiation),
        0,
        &buf,
    )
    .unwrap();
    assert_eq!(remain.len(), 0);
    match vn_long_header {
        Header::VN(vn) => {
            assert_eq!(vn.dcid(), &ConnectionId::default());
            assert_eq!(vn.scid(), &ConnectionId::default());
            assert_eq!(vn.versions(), &vec![0x01, 0x02]);
        }
        _ => panic!("unexpected header type"),
    }

    // Retry Header
    let buf = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let (remain, retry_long_header) =
        be_header(Type::Long(packet_type_long::Type::V1(Ver1::RETRY)), 0, &buf).unwrap();
    assert_eq!(remain.len(), 0);
    match retry_long_header {
        Header::Retry(retry) => {
            assert_eq!(retry.dcid(), &ConnectionId::default());
            assert_eq!(retry.scid(), &ConnectionId::default());
            assert_eq!(retry.token().deref(), &[0x00, 0x00, 0x00]);
            assert_eq!(
                retry.integrity(),
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f
                ]
            );
        }
        _ => panic!("unexpected header type"),
    }

    // Retry Header with invalid length
    let buf = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    match be_header(Type::Long(packet_type_long::Type::V1(Ver1::RETRY)), 0, &buf) {
        Err(e) => assert_eq!(e, nom::Err::Incomplete(nom::Needed::new(16))),
        _ => panic!("unexpected result"),
    }

    // Initial Header
    let buf = vec![0x00, 0x00, 0x03, 0x01, 0x02, 0x03];
    let (remain, initial_long_header) = be_header(
        Type::Long(packet_type_long::Type::V1(Ver1::INITIAL)),
        0,
        &buf,
    )
    .unwrap();
    assert_eq!(remain.len(), 0);
    match initial_long_header {
        Header::Initial(initial) => {
            assert_eq!(initial.dcid(), &ConnectionId::default());
            assert_eq!(initial.scid(), &ConnectionId::default());
            assert_eq!(initial.token().deref(), [0x01, 0x02, 0x03,]);
        }
        _ => panic!("unexpected header type"),
    }

    // ZeroRTT Header
    let buf = vec![0x00, 0x00];
    let (remain, zero_rtt_long_header) = be_header(
        Type::Long(packet_type_long::Type::V1(Ver1::ZERO_RTT)),
        0,
        &buf,
    )
    .unwrap();
    assert_eq!(remain.len(), 0);
    match zero_rtt_long_header {
        Header::ZeroRtt(zero_rtt) => {
            assert_eq!(zero_rtt.dcid(), &ConnectionId::default());
            assert_eq!(zero_rtt.scid(), &ConnectionId::default());
        }
        _ => panic!("unexpected header type"),
    }

    // Handshake Header
    let buf = vec![0x00, 0x00];
    let (remain, handshake_long_header) = be_header(
        Type::Long(packet_type_long::Type::V1(Ver1::HANDSHAKE)),
        0,
        &buf,
    )
    .unwrap();
    assert_eq!(remain.len(), 0);
    match handshake_long_header {
        Header::Handshake(handshake) => {
            assert_eq!(handshake.dcid(), &ConnectionId::default());
            assert_eq!(handshake.scid(), &ConnectionId::default());
        }
        _ => panic!("unexpected header type"),
    }

    // OneRtt Header
    let buf = vec![];
    let (remain, one_rtt_header) = be_header(Type::Short(OneRtt(SpinBit::One)), 0, &buf).unwrap();
    assert_eq!(remain.len(), 0);
    match one_rtt_header {
        Header::OneRtt(one_rtt) => {
            assert_eq!(
                one_rtt,
                OneRttHeader::new(SpinBit::One, ConnectionId::default())
            );
        }
        _ => panic!("unexpected header type"),
    }
}

#[test]
fn test_write_header() {
    // VersionNegotiation Header
    let mut buf = vec![];
    let vn_long_header = Header::VN(
        LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default())
            .wrap(VersionNegotiation::new(vec![0x01, 0x02])),
    );
    buf.put_header(&vn_long_header);
    assert_eq!(
        buf,
        [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x02
        ]
    );

    // Retry Header
    let mut buf = vec![];
    let retry_long_header = Header::Retry(
        LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default()).wrap(
            Retry::new(
                &[0x00, 0x00, 0x00],
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ],
            ),
        ),
    );
    buf.put_header(&retry_long_header);
    assert_eq!(
        buf,
        [
            0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        ]
    );

    // Initial Header
    let mut buf = vec![];
    let initial_header = Header::Initial(
        LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default())
            .wrap(Initial::with_token(vec![0x01, 0x02, 0x03])),
    );
    buf.put_header(&initial_header);
    assert_eq!(
        buf,
        [
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03
        ]
    );

    // ZeroRtt Header
    let mut buf = vec![];
    let zero_rtt_header = Header::ZeroRtt(
        LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default()).wrap(ZeroRtt),
    );
    buf.put_header(&zero_rtt_header);
    assert_eq!(buf, [0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);

    // Handshake Header
    let mut buf = vec![];
    let handshake_header = Header::Handshake(
        LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default())
            .wrap(Handshake),
    );
    buf.put_header(&handshake_header);
    assert_eq!(buf, [0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);

    // OneRtt Header with SpinBit::On
    let mut buf = vec![];
    let one_rtt_header = Header::OneRtt(OneRttHeader::new(SpinBit::One, ConnectionId::default()));
    buf.put_header(&one_rtt_header);
    assert_eq!(buf, [0x60]);

    // OneRtt Header with SpinBit::Off
    let mut buf = vec![];
    let one_rtt_header = Header::OneRtt(OneRttHeader::new(SpinBit::Zero, ConnectionId::default()));
    buf.put_header(&one_rtt_header);
    assert_eq!(buf, [0x40]);
}
