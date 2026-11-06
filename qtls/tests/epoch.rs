use qtls::Epoch;

#[test]
fn next_advances_through_packet_number_spaces() {
    assert_eq!(Epoch::Initial.next(), Epoch::Handshake);
    assert_eq!(Epoch::Handshake.next(), Epoch::Data);
}

#[test]
#[should_panic(expected = "Data is the last epoch")]
fn data_has_no_next_epoch() {
    Epoch::Data.next();
}
