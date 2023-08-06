FROM messense/rust-musl-cross:x86_64-musl AS builder
WORKDIR /usr/src/auth-microservice
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

#FROM alpine:3.18.0
FROM scratch
COPY --from=builder /usr/src/auth-microservice/target/x86_64-unknown-linux-musl/release/auth .
COPY .env .
EXPOSE 7001
CMD ["./auth"]