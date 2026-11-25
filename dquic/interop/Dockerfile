FROM martenseemann/quic-network-simulator-endpoint:latest AS build

ARG RUST_VERSION=1.88.0
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION}
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /src
COPY . .
RUN cargo build --release -p dquic --example interop --features interop-test

FROM martenseemann/quic-network-simulator-endpoint:latest
COPY --from=build /src/target/release/examples/interop /usr/local/bin/dquic-interop
COPY --from=build /src/Cargo.lock /usr/local/share/dquic/Cargo.lock
COPY dquic/interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]
