use bytes::BytesMut;
use qbase::{
    datagram::{Datagram as OuterDatagram, Error, be_datagram, forward::*},
    net::{addr::EndpointAddr, route::Pathway},
};

fn pathway() -> Pathway {
    Pathway::new(
        EndpointAddr::mediate(
            "198.51.100.1:3478".parse().unwrap(),
            "192.0.2.1:50000".parse().unwrap(),
        ),
        EndpointAddr::direct("203.0.113.1:4433".parse().unwrap()),
    )
}

#[test]
fn empty_raw_datagram_is_rejected() {
    assert_eq!(
        Payload::from_raw(&pathway(), BytesMut::zeroed(128), 128),
        Err(Error::InvalidForwardDatagram)
    );
}

#[test]
fn insufficient_headroom_is_rejected() {
    assert_eq!(
        Payload::from_raw(&pathway(), BytesMut::zeroed(2), 1),
        Err(Error::InvalidForwardDatagram)
    );
}

fn round_trip(raw: &[u8]) {
    let raw = BytesMut::from(raw);
    let header_len = 2 + pathway().local().encoding_size() + pathway().remote().encoding_size();
    let raw_offset = header_len + 17;
    let mut bytes = BytesMut::zeroed(raw_offset + raw.len());
    bytes[raw_offset..].copy_from_slice(&raw);
    let raw_ptr = bytes[raw_offset..].as_ptr();
    let encoded = Payload::from_raw(&pathway(), bytes, raw_offset).unwrap();
    assert_eq!(encoded.as_ref()[0] & 0b1110_0000, 0b0110_0000);
    assert_eq!(encoded.as_ref().len(), header_len + raw.len());
    assert_eq!(&encoded.as_ref()[header_len..], raw.as_ref());
    assert_eq!(encoded.as_ref()[header_len..].as_ptr(), raw_ptr);

    let mut written = BytesMut::new();
    written.extend_from_slice(encoded.as_ref());
    assert_eq!(written.as_ref(), encoded.as_ref());

    let OuterDatagram::Forward(decoded_pathway, decoded) = be_datagram(written).unwrap() else {
        panic!("expected Forward datagram");
    };
    assert_eq!(decoded_pathway, pathway());
    assert_eq!(decoded.into_raw(), raw);
    let recovered = encoded.into_raw();
    assert_eq!(recovered, raw);
    assert_eq!(recovered.as_ptr(), raw_ptr);
}

#[test]
fn raw_long_datagram_round_trips() {
    round_trip(&[0xc1, 0, 0, 0, 1, 1, 2, 3]);
}

#[test]
fn raw_short_datagram_round_trips() {
    round_trip(&[0x45, 1, 2, 3]);
}
