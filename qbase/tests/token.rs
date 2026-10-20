#[test]
fn test_create_token() {
    qbase::token::ResetToken::new(&[0; 16]);
}

#[test]
#[should_panic]
fn test_creat_token_with_less_size() {
    qbase::token::ResetToken::new(&[0; 15]);
}

#[test]
#[should_panic]
fn test_creat_token_with_more_size() {
    qbase::token::ResetToken::new(&[0; 17]);
}

#[test]
fn test_read_reset_token() {
    use nom::error::{Error, ErrorKind};

    let buf = vec![0; 16];
    let (remain, token) = qbase::token::be_reset_token(&buf).unwrap();
    assert_eq!(remain.len(), 0);
    assert_eq!(token, qbase::token::ResetToken::new(&[0; 16]));
    let buf = vec![0; 15];
    assert_eq!(
        qbase::token::be_reset_token(&buf),
        Err(nom::Err::Error(Error::new(&buf[..], ErrorKind::Eof)))
    );
}

#[test]
fn test_write_reset_token() {
    use qbase::token::WriteResetToken;

    let mut buf = vec![];
    let token = qbase::token::ResetToken::new(&[0; 16]);
    buf.put_reset_token(&token);
    assert_eq!(buf, &[0; 16]);
}
