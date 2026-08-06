pub use qbase::datagram::stun::{
    Attribute as Attr, AttributeType as AttrType, BindingRequest as Request,
    BindingResponse as Response, CHANGE_IP, CHANGE_PORT, InvalidAttributeType as InvalidAttrType,
    TransactionId,
};

#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    Request(Request),
    Response(Response),
}
