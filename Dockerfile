FROM rust:alpine3.18
COPY ./target/release/auth /usr/local/bin/app
COPY .env /usr/local/bin/.env
COPY Cargo.toml /usr/local/bin/app
EXPOSE 7001
CMD ["/usr/local/bin/app"]