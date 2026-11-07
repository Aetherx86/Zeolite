FROM rust:1 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p zeolite

FROM debian:stable-slim
COPY --from=build /src/target/release/zeolite /usr/local/bin/zeolite
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/zeolite"]
