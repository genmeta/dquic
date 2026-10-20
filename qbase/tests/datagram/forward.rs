use bytes::BytesMut;
use qbase::{
    datagram::{Error, forward::*},
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
