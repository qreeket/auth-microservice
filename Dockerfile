#FROM rust:1.72.0-slim-buster as builder
#WORKDIR /usr/src/auth-microservice
#COPY . .
#RUN cargo build --release

#FROM alpine:3.18.0
FROM scratch
COPY target/release/auth .
COPY .env .
EXPOSE 7001
CMD ["./auth"]