use qresolve::{EndpointAddr, Family, Resolve, ResolveFuture, Source};

mod sys {
    // Compile the source here to test its private parsing helpers.
    include!("../src/sys.rs");

    #[test]
    fn system_lookup_accepts_service_names_and_family() {
        let addrs = lookup_socket_addrs("localhost", "https", Some(Family::V4)).unwrap();

        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(SocketAddr::is_ipv4));
        assert!(addrs.iter().all(|addr| addr.port() == 443));

        let addrs = lookup_socket_addrs("localhost", "443", Some(Family::V4)).unwrap();
        assert!(addrs.iter().all(|addr| addr.port() == 443));

        let addrs = lookup_socket_addrs("localhost", "", Some(Family::V4)).unwrap();
        assert!(addrs.iter().all(|addr| addr.port() == 443));
    }

    #[test]
    fn hostname_port_overrides_servname() {
        let addrs = lookup_socket_addrs("localhost:8443", "443", Some(Family::V4)).unwrap();

        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|addr| addr.port() == 8443));
    }

    #[test]
    fn splits_host_and_port() {
        assert_eq!(
            split_name_port("example.com:8443"),
            ("example.com", Some("8443"))
        );
        assert_eq!(
            split_name_port("[2001:db8::1]:8443"),
            ("2001:db8::1", Some("8443"))
        );
        assert_eq!(split_name_port("2001:db8::1"), ("2001:db8::1", None));
        assert_eq!(split_name_port("[2001:db8::1]"), ("2001:db8::1", None));
        assert_eq!(split_name_port("example.com"), ("example.com", None));
    }

    #[test]
    fn ipv6_hostname_port_requires_brackets() {
        let addrs = lookup_socket_addrs("[::1]:9443", "8443", Some(Family::V6)).unwrap();
        assert!(addrs.iter().all(|addr| addr.port() == 9443));

        let addrs = lookup_socket_addrs("::443", "8443", Some(Family::V6)).unwrap();
        assert!(addrs.iter().all(|addr| addr.port() == 8443));
    }

    #[tokio::test]
    async fn system_dns_never_treats_certificate_sequence_as_a_port() {
        for name in [
            "dhttp.net",
            "alice.dhttp.net",
            "ALICE.DHTTP.NET.:2",
            "alice.dhttp.net:999999999999999999999",
        ] {
            let result = SystemResolver.lookup(name, "443", None).await;
            assert!(
                matches!(result, Err(error) if error.kind() == io::ErrorKind::NotFound),
                "{name}"
            );
        }
        let records = SystemResolver
            .lookup("127.0.0.1:8080", "443", None)
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        assert!(
            records
                .iter()
                .any(|(_, endpoint)| endpoint.addr().port() == 8080)
        );
    }
}
