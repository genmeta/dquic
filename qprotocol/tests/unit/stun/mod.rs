mod client;
mod discovery;
mod server;

use super::*;

#[test]
fn transaction_is_registered_until_drop() {
    let protocol = Arc::new(StunProtocol::new());
    let transaction = protocol.new_transaction();
    let transaction_id = transaction.id();

    assert!(protocol.transactions.contains_key(&transaction_id));

    drop(transaction);

    assert!(!protocol.transactions.contains_key(&transaction_id));
}
