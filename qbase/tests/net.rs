#[path = "net/addr.rs"]
mod addr;
#[path = "net/route.rs"]
mod route;
#[path = "net/tx.rs"]
mod tx;

use qbase::net::*;

#[test]
fn test_ip_family_display_and_parse() {
    assert_eq!(Family::V4.to_string(), "v4");
    assert_eq!(Family::V6.to_string(), "v6");

    assert_eq!("v4".parse::<Family>().unwrap(), Family::V4);
    assert_eq!("V4".parse::<Family>().unwrap(), Family::V4);
    assert_eq!("v6".parse::<Family>().unwrap(), Family::V6);
    assert_eq!("V6".parse::<Family>().unwrap(), Family::V6);

    assert!(matches!("v7".parse::<Family>(), Err(InvalidFamily)));
}
