// Compile the library source here to keep white-box tests out of src.
include!("../src/lib.rs");

#[cfg(test)]
mod tests {
    use std::{
        any::Any,
        fmt::{self, Debug, Display},
    };

    use futures::FutureExt;

    use super::*;

    #[derive(Debug)]
    struct TestPublisher;

    impl Display for TestPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("test publisher")
        }
    }

    impl Publish for TestPublisher {
        fn publish<'a>(
            &'a self,
            name: &'a str,
            endpoints: &mut dyn Iterator<Item = EndpointAddr>,
        ) -> PublishFuture<'a> {
            let endpoints: Vec<_> = endpoints.collect();
            async move {
                assert_eq!(name, "demo.dhttp.net");
                assert_eq!(endpoints.len(), 1);
                Ok(())
            }
            .boxed()
        }
    }

    #[test]
    fn publish_trait_accepts_endpoint_iterator() {
        let publisher: &dyn Publish = &TestPublisher;
        let endpoint = EndpointAddr::direct("203.0.113.10:4433".parse().unwrap());
        let mut endpoints = std::iter::once(endpoint);

        futures::executor::block_on(publisher.publish("demo.dhttp.net", &mut endpoints))
            .expect("publish succeeds");
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn resolve_trait_objects_upcast_to_any() {
        assert_send_sync::<SystemResolver>();
        let resolver: &dyn Resolve = &SystemResolver;
        let any: &dyn Any = resolver;

        assert!(any.is::<SystemResolver>());
    }

    #[test]
    fn publish_trait_objects_upcast_to_any() {
        assert_send_sync::<TestPublisher>();
        let publisher: &dyn Publish = &TestPublisher;
        let any: &dyn Any = publisher;

        assert!(any.is::<TestPublisher>());
    }

    #[test]
    fn h3_source_display_identifies_h3_dns() {
        let source = Source::H3 {
            server: Arc::from("https://dns.genmeta.net:4433"),
        };

        assert_eq!(
            source.to_string(),
            "H3 DNS Resolver(https://dns.genmeta.net:4433)"
        );
    }
}
