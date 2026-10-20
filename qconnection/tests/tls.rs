use qbase::{
    Close, Epoch,
    error::{ErrorKind, QuicError},
};
use qconnection::TlsContext;

mod common;

#[tokio::test]
async fn closed_tls_ignores_input_and_preserves_the_close_reason() {
    let errors: [qconnection::Error; 3] = [
        QuicError::with_default_fty(ErrorKind::None, "closed").into(),
        QuicError::with_default_fty(ErrorKind::Internal, "failed").into(),
        qbase::error::AppError::new(42u32.into(), "application closed").into(),
    ];
    for error in errors {
        let [_, server] =
            common::backends(false).map(|tls| TlsContext::new(tls, 256 * 1024).unwrap());
        server.close_with_error(error.clone());
        for epoch in Epoch::EPOCHS {
            server.write_msg(epoch, &[1]).unwrap();
            assert_eq!(server.read_msg().await.unwrap_err(), error);
        }
        assert_eq!(server.read_msg().await.unwrap_err(), error);
        assert_eq!(server.read_keys().await.err(), Some(error.clone()));
        assert_eq!(server.finished().await.err(), Some(error));
    }
}
