//! Real packet protection with small usage limits for boundary tests.
use std::{
    cell::Cell,
    sync::{Arc, LazyLock},
};

use tls_backend::{
    CipherSuite, SupportedCipherSuite, Tls13CipherSuite,
    crypto::{
        CipherSuiteCommon,
        cipher::{AeadKey, Iv},
    },
    quic::{Algorithm, HeaderProtectionKey, PacketKey, Tag},
};

pub const LIMIT: u64 = 4;

thread_local! {
    static OPENED: Cell<usize> = const { Cell::new(0) };
}

pub fn opened() -> usize {
    OPENED.get()
}

static BASE: LazyLock<&Tls13CipherSuite> = LazyLock::new(|| {
    qtls::default_provider()
        .cipher_suites
        .into_iter()
        .find(|suite| suite.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256)
        .unwrap()
        .tls13()
        .unwrap()
});

static SUITE: LazyLock<Tls13CipherSuite> = LazyLock::new(|| Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: BASE.common.suite,
        hash_provider: BASE.common.hash_provider,
        confidentiality_limit: BASE.common.confidentiality_limit,
    },
    hkdf_provider: BASE.hkdf_provider,
    aead_alg: BASE.aead_alg,
    quic: Some(&LimitedAlgorithm),
});

pub fn provider() -> Arc<qtls::CryptoProvider> {
    let mut provider = qtls::default_provider();
    provider.cipher_suites = vec![SupportedCipherSuite::Tls13(&SUITE)];
    Arc::new(provider)
}

struct LimitedAlgorithm;

impl Algorithm for LimitedAlgorithm {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
        Box::new(LimitedKey(BASE.quic.unwrap().packet_key(key, iv)))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        BASE.quic.unwrap().header_protection_key(key)
    }

    fn aead_key_len(&self) -> usize {
        BASE.quic.unwrap().aead_key_len()
    }

    fn fips(&self) -> bool {
        BASE.quic.unwrap().fips()
    }
}

struct LimitedKey(Box<dyn PacketKey>);

impl PacketKey for LimitedKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, tls_backend::Error> {
        self.0.encrypt_in_place(packet_number, header, payload)
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], tls_backend::Error> {
        OPENED.set(OPENED.get() + 1);
        self.0.decrypt_in_place(packet_number, header, payload)
    }

    fn tag_len(&self) -> usize {
        self.0.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        LIMIT
    }

    fn integrity_limit(&self) -> u64 {
        LIMIT
    }
}
