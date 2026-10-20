use qbase::param::ClientParameters;

#[test]
fn duplicate_transport_parameters_are_rejected_even_when_unknown() {
    for bytes in [
        vec![15, 0, 15, 0],
        vec![0x40, 0x3f, 0, 0x40, 0x3f, 0, 15, 0],
    ] {
        assert!(ClientParameters::parse_from_bytes(&bytes).is_err());
    }
}

#[test]
fn malformed_parameter_values_return_errors_without_panicking() {
    let mut oversized_cid = vec![15, 21];
    oversized_cid.extend([0; 21]);
    for bytes in [
        vec![4, 2, 1, 2, 15, 0],
        vec![12, 1, 0, 15, 0],
        oversized_cid,
    ] {
        let result = std::panic::catch_unwind(|| ClientParameters::parse_from_bytes(&bytes));
        assert!(result.is_ok(), "malformed parameter panicked");
        assert!(result.unwrap().is_err());
    }
}
