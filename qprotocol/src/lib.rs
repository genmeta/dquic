macro_rules! debug_assert_or_warn {
    ($condition:expr, $($message:tt)+) => {
        #[cfg(debug_assertions)]
        debug_assert!($condition, $($message)+);

        #[cfg(not(debug_assertions))]
        if !$condition {
            tracing::warn!($($message)+);
        }
    };
}

pub mod addr_book;
pub mod dock;
pub mod protocol;
pub mod socket;
pub mod topology;

pub use addr_book::AddressBook;
pub use dock::Dock;
pub use protocol::{ForwardProtocol, QuicProtocol, StunProtocol};
pub use socket::{EphemeralSocket, QuicSocket, UdpSocket};
