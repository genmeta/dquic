FROM martenseemann/quic-network-simulator-endpoint:latest AS chef

ARG RUST_VERSION=1.88.0
ARG CARGO_CHEF_VERSION=0.1.78
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION}
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cargo-chef --locked --version ${CARGO_CHEF_VERSION}
ENV CARGO_PROFILE_RELEASE_DEBUG=0
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /src/recipe.json recipe.json
# cargo-chef's recipe contains workspace members, not the excluded WebPKI patch.
COPY --from=planner /src/vendor vendor
RUN cargo chef cook --release -p dquic --examples --features interop-test --recipe-path recipe.json
COPY . .
# Restore the original local package versions masked by cargo-chef's recipe.
COPY --from=planner /src/Cargo.lock Cargo.lock
RUN cargo build --locked --release -p dquic --example interop --features interop-test

FROM martenseemann/quic-network-simulator-endpoint:latest
COPY --from=build /src/target/release/examples/interop /usr/local/bin/dquic-interop
COPY --from=build /src/Cargo.lock /usr/local/share/dquic/Cargo.lock
COPY dquic/interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]
