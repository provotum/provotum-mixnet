FROM ekidd/rust-musl-builder:1.50.0 AS build
WORKDIR /usr/src/
USER root

# install rustup/cargo
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH /root/.cargo/bin:$PATH
ENV CARGO_TERM_COLOR=always

# Add compilation target for later scratch container
ENV RUST_TARGETS="x86_64-unknown-linux-musl"
RUN rustup default 1.50
RUN rustup update
RUN rustup toolchain install 1.50
RUN rustup target install x86_64-unknown-linux-musl --toolchain 1.50
ENV RUSTUP_TOOLCHAIN="1.50"

# Add Dependencies
COPY ./crypto ./crypto
COPY ./randomizer/Cargo.lock ./randomizer/Cargo.lock
COPY ./randomizer/Cargo.toml ./randomizer/Cargo.toml

# Caching Dependencies
WORKDIR /usr/src/randomizer
RUN cargo fetch

# Copy the changing code
COPY ./randomizer /usr/src/randomizer

# Only code changes should need to compile
RUN cargo build --target x86_64-unknown-linux-musl --release

# This creates a TINY container with the executable!
FROM scratch
LABEL org.opencontainers.image.source https://github.com/meck93/provotum-mixnet
COPY --from=build /usr/src/randomizer/target/x86_64-unknown-linux-musl/release/randomizer .
USER 1000
CMD ["./randomizer"]