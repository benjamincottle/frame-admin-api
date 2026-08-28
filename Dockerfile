FROM rust:1-slim-trixie AS builder

ENV RUSTFLAGS="-C link-arg=-s" \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

WORKDIR /app
COPY . .

RUN cargo build --release && mkdir -p /app/secrets

# --- Final Stage ---
FROM gcr.io/distroless/cc-debian13
WORKDIR /app

COPY --from=builder /app/target/release/admin_api /app/admin_api
COPY public/ /app/public/
COPY templates/ /app/templates/
COPY --from=builder /app/secrets/ /app/secrets/

EXPOSE 5000
CMD ["./admin_api"]
