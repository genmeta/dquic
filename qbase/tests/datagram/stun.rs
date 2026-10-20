use bytes::BytesMut;
use qbase::datagram::{
    stun::*,
    r#type::{GetDatagramType, Type as OuterType, v0},
};

#[test]
fn binding_messages_report_their_outer_datagram_type() {
    assert_eq!(
        BindingRequest::default().get_datagram_type(),
        OuterType::V0(v0::Type::Stun(Type::BindingRequest))
    );
    assert_eq!(
        BindingResponse::default().get_datagram_type(),
        OuterType::V0(v0::Type::Stun(Type::BindingResponse))
    );
}

#[test]
fn binding_request_message_round_trips() {
    let message = Message::Request(BindingRequest::change_ip_and_port());
    let mut bytes = BytesMut::new();
    bytes.put_stun_message(&message);

    let (remain, decoded) = be_stun_message(Type::BindingRequest, &bytes).unwrap();
    assert!(remain.is_empty());
    assert_eq!(decoded, message);
}

#[test]
fn binding_response_message_round_trips() {
    let mapped = "203.0.113.1:4433".parse().unwrap();
    let message = Message::Response(BindingResponse::with(vec![Attribute::MappedAddress(
        mapped,
    )]));
    let mut bytes = BytesMut::new();
    bytes.put_stun_message(&message);

    let (remain, decoded) = be_stun_message(Type::BindingResponse, &bytes).unwrap();
    assert!(remain.is_empty());
    assert_eq!(decoded, message);
}
